//! Hardened HTTP REST API daemon with:
//! - Envelope DEK/KEK verification on unseal (`409` if already unsealed, `401` on bad key)
//! - Dual-Mode Authentication:
//!   1. Universal OIDC & RFC 7517/7519 JWT Workload Identity (`RS256`, `ES256`, `EdDSA`)
//!   2. Mandatory default-deny SHA-512 constant-time machine token authentication (`sv_live_*`)
//! - Sliding-window brute-force rate limiting (`429 Too Many Requests`)
//! - Canonical path ACL enforcement with exact trailing-slash directory boundaries
//! - Tamper-evident RFC 2104 HMAC-SHA512 hash-chained audit logging (`GET /v1/sys/audit`) & real-time SIEM streaming
//! - Online encrypted SQLCipher backup snapshots (`POST /v1/sys/backup`) & Prometheus/JSON fleet metrics (`GET /v1/sys/metrics`)
//! - Deadlock-free `RwLock<Option<VaultActiveState>>` concurrency hierarchy

use crate::acl::{
    canonicalize_prefix_filter, canonicalize_secret_path, path_matches_directory_prefix,
    validate_capabilities, validate_identifier, validate_scope_pattern, ScopedToken,
};
use crate::crypto::{
    build_secret_aad, constant_time_str_eq, create_envelope, decrypt_secret_with_aad,
    encrypt_secret_with_aad, generate_unseal_key, hex_decode, hex_encode, mint_machine_token,
    parse_machine_token, unwrap_envelope, verify_token_sha512_ct, LockedKey,
};
use crate::oidc::{
    validate_oidc_binding_fields, verify_oidc_jwt_and_resolve, IssuerRefreshReport, OidcBinding,
    OidcJwksCache, OidcPreset,
};
use crate::storage::{
    database_path, envelope_path, has_partial_initialization, is_vault_initialized,
    now_unix_seconds, read_envelope_header, write_envelope_header, AuditLogEntry, BackupMetadata,
    SecretMetadataItem, Storage, TokenMetadataItem,
};
use crate::telemetry::SiemForwarder;
use axum::{
    extract::{DefaultBodyLimit, Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const DEFAULT_MAX_AUTH_FAILURES_PER_MINUTE: usize = 15;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

/// Active unsealed vault state. Exists in RAM strictly while the vault is unsealed;
/// dropping this struct closes SQLCipher and zeroizes + munlocks `value_aead_key` and `audit_chain_key`.
pub struct VaultActiveState {
    pub storage: Mutex<Storage>,
    pub value_aead_key: LockedKey,
    pub audit_chain_key: LockedKey,
    pub db_memory_locked: bool,
    pub siem_forwarder: Option<SiemForwarder>,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub started_at: Instant,
    pub telemetry_enabled: bool,
    pub oidc_cache: OidcJwksCache,
    pub siem_forwarder: Option<SiemForwarder>,
    pub max_auth_failures_per_window: usize,
    pub auth_failures: Mutex<VecDeque<Instant>>,
    pub token_auth_failures: Mutex<VecDeque<Instant>>,
    pub bootstrap_nonce: Mutex<Option<Zeroizing<String>>>,
    pub active: RwLock<Option<VaultActiveState>>,
}

impl AppState {
    pub fn new(
        data_dir: PathBuf,
        bootstrap_nonce: Option<String>,
        telemetry_enabled: bool,
    ) -> Self {
        Self::with_rate_limit(
            data_dir,
            bootstrap_nonce,
            telemetry_enabled,
            DEFAULT_MAX_AUTH_FAILURES_PER_MINUTE,
        )
    }

    pub fn with_rate_limit(
        data_dir: PathBuf,
        bootstrap_nonce: Option<String>,
        telemetry_enabled: bool,
        max_auth_failures_per_window: usize,
    ) -> Self {
        Self {
            data_dir,
            started_at: Instant::now(),
            telemetry_enabled,
            oidc_cache: OidcJwksCache::new(),
            siem_forwarder: None,
            max_auth_failures_per_window: max_auth_failures_per_window.max(1),
            auth_failures: Mutex::new(VecDeque::new()),
            token_auth_failures: Mutex::new(VecDeque::new()),
            bootstrap_nonce: Mutex::new(bootstrap_nonce.map(Zeroizing::new)),
            active: RwLock::new(None),
        }
    }

    pub fn with_siem_forwarder(mut self, forwarder: Option<SiemForwarder>) -> Self {
        self.siem_forwarder = forwarder;
        self
    }

    fn check_window(queue: &Mutex<VecDeque<Instant>>, max_failures: usize) -> Result<(), ApiError> {
        let mut guard = queue
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Rate limiter lock error"))?;
        let now = Instant::now();
        while let Some(&front) = guard.front() {
            if now.duration_since(front) >= RATE_LIMIT_WINDOW {
                guard.pop_front();
            } else {
                break;
            }
        }
        if guard.len() >= max_failures {
            tracing::warn!(
                failures_in_window = guard.len(),
                "Rate limit exceeded on authentication / unseal window"
            );
            return Err(api_err(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many failed authentication or unseal attempts; retry after 60 seconds",
            ));
        }
        Ok(())
    }

    fn record_in_window(queue: &Mutex<VecDeque<Instant>>) {
        if let Ok(mut guard) = queue.lock() {
            let now = Instant::now();
            while let Some(&front) = guard.front() {
                if now.duration_since(front) >= RATE_LIMIT_WINDOW {
                    guard.pop_front();
                } else {
                    break;
                }
            }
            guard.push_back(now);
        }
    }

    fn check_rate_limit(&self) -> Result<(), ApiError> {
        Self::check_window(&self.auth_failures, self.max_auth_failures_per_window)
    }

    fn record_auth_failure(&self) {
        Self::record_in_window(&self.auth_failures);
    }

    fn check_token_rate_limit(&self) -> Result<(), ApiError> {
        Self::check_window(&self.token_auth_failures, self.max_auth_failures_per_window)
    }

    fn record_token_auth_failure(&self) {
        Self::record_in_window(&self.token_auth_failures);
    }
}

#[derive(Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub initialized: bool,
    pub sealed: bool,
    pub memory_locked: bool,
    pub telemetry_enabled: bool,
    pub version: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct UnsealRequest {
    pub unseal_key: String,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct SecretResponse {
    #[zeroize(skip)]
    pub path: String,
    #[zeroize(skip)]
    pub project: String,
    #[zeroize(skip)]
    pub version: i64,
    pub value: String,
}

#[derive(Deserialize, Default)]
pub struct GetSecretQuery {
    pub version: Option<i64>,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PutSecretRequest {
    #[zeroize(skip)]
    pub project: String,
    pub value: String,
}

#[derive(Deserialize, Default)]
pub struct ListSecretsQuery {
    pub prefix: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct ListSecretsResponse {
    pub secrets: Vec<SecretMetadataItem>,
}

#[derive(Serialize, Deserialize)]
pub struct ListTokensResponse {
    pub tokens: Vec<TokenMetadataItem>,
}

#[derive(Deserialize, Default)]
pub struct AuditQuery {
    pub limit: Option<usize>,
}

#[derive(Serialize, Deserialize)]
pub struct AuditLogResponse {
    pub chain_verified: bool,
    pub total_events: u64,
    pub events: Vec<AuditLogEntry>,
}

#[derive(Deserialize)]
pub struct EnrollTokenRequest {
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct EnrollTokenResponse {
    #[zeroize(skip)]
    pub token_id: String,
    pub token: String,
    #[zeroize(skip)]
    pub project: String,
    #[zeroize(skip)]
    pub name: String,
    #[zeroize(skip)]
    pub allowed_paths: Vec<String>,
    #[zeroize(skip)]
    pub capabilities: Vec<String>,
    #[zeroize(skip)]
    pub expires_at: Option<i64>,
}

#[derive(Deserialize)]
pub struct EnrollOidcBindingRequest {
    #[serde(default)]
    pub preset: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub audience: Option<String>,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub inline_jwks_json: Option<String>,
    pub name: String,
    pub project: String,
    #[serde(default)]
    pub subject_claim: Option<String>,
    pub subject_pattern: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Serialize, Deserialize)]
pub struct EnrollOidcBindingResponse {
    pub binding: OidcBinding,
    pub jwks_refresh: Vec<IssuerRefreshReport>,
    pub total_cached_keys: usize,
}

#[derive(Serialize, Deserialize)]
pub struct ListOidcBindingsResponse {
    pub bindings: Vec<OidcBinding>,
    pub total_cached_keys: usize,
}

#[derive(Serialize, Deserialize)]
pub struct RefreshOidcResponse {
    pub refreshed_issuers: Vec<IssuerRefreshReport>,
    pub total_cached_keys: usize,
}

#[derive(Deserialize, Default)]
pub struct MetricsQuery {
    pub format: Option<String>,
}

#[derive(Serialize, Deserialize)]
pub struct VaultMetricsResponse {
    pub version: String,
    pub status: String,
    pub initialized: bool,
    pub sealed: bool,
    pub memory_locked: bool,
    pub telemetry_enabled: bool,
    pub siem_forwarding_enabled: bool,
    pub uptime_seconds: u64,
    pub total_secrets_count: u64,
    pub active_tokens_count: u64,
    pub active_oidc_bindings_count: u64,
    pub jwks_cached_keys_count: u64,
    pub audit_seq: u64,
    pub storage_bytes: u64,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/sys/health", get(health_handler))
        .route("/v1/sys/metrics", get(metrics_handler))
        .route("/v1/sys/init", post(init_handler))
        .route("/v1/sys/unseal", post(unseal_handler))
        .route("/v1/sys/seal", post(seal_handler))
        .route("/v1/sys/backup", post(backup_handler))
        .route("/v1/sys/audit", get(audit_log_handler))
        .route("/v1/sys/enroll", post(enroll_handler))
        .route("/v1/sys/tokens", get(list_tokens_handler))
        .route("/v1/sys/tokens/:token_id", delete(revoke_token_handler))
        .route(
            "/v1/sys/oidc/bindings",
            post(enroll_oidc_binding_handler).get(list_oidc_bindings_handler),
        )
        .route(
            "/v1/sys/oidc/bindings/:binding_id",
            delete(revoke_oidc_binding_handler),
        )
        .route("/v1/sys/oidc/refresh", post(refresh_oidc_jwks_handler))
        .route("/v1/secrets", get(list_secrets_handler))
        .route(
            "/v1/secret/*path",
            get(get_secret_handler)
                .put(put_secret_handler)
                .delete(delete_secret_handler),
        )
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

type ApiError = (StatusCode, Json<serde_json::Value>);

fn api_err(code: StatusCode, msg: &'static str) -> ApiError {
    (code, Json(serde_json::json!({ "error": msg })))
}

fn record_audit(
    active: &VaultActiveState,
    event_type: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
) {
    if let Ok(mut db) = active.storage.lock() {
        if let Ok(entry) = db.append_audit_event(
            &active.audit_chain_key,
            event_type,
            actor,
            resource,
            outcome,
        ) {
            if let Some(ref forwarder) = active.siem_forwarder {
                forwarder.emit(entry);
            }
        }
    }
}

/// Extract raw bearer token strictly from `X-Vault-Token` or `Authorization: Bearer ...`.
/// Default-deny: missing or malformed headers ALWAYS fail with `401 Unauthorized`.
fn extract_raw_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    if let Some(raw_val) = headers.get("X-Vault-Token") {
        let s = raw_val
            .to_str()
            .map_err(|_| api_err(StatusCode::UNAUTHORIZED, "Malformed X-Vault-Token header"))?
            .trim();
        if s.is_empty() {
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "Empty X-Vault-Token header",
            ));
        }
        return Ok(s);
    }

    if let Some(auth_val) = headers.get(AUTHORIZATION) {
        let s = auth_val
            .to_str()
            .map_err(|_| api_err(StatusCode::UNAUTHORIZED, "Malformed Authorization header"))?
            .trim();
        if let Some(bearer) = s.strip_prefix("Bearer ") {
            let trimmed = bearer.trim();
            if !trimmed.is_empty() {
                return Ok(trimmed);
            }
        }
        return Err(api_err(
            StatusCode::UNAUTHORIZED,
            "Expected Authorization: Bearer <oidc_jwt_or_sv_live_token>",
        ));
    }

    Err(api_err(
        StatusCode::UNAUTHORIZED,
        "Missing authentication token (provide Authorization: Bearer <jwt> or X-Vault-Token header)",
    ))
}

/// Dual-Mode Authentication:
/// 1. If the bearer credential is a 3-segment RFC 7519 JWT (`header.payload.signature`),
///    verify its cryptographic signature against the in-memory OIDC JWKS cache and evaluate
///    SQLCipher `oidc_bindings` claim rules.
/// 2. Otherwise, authenticate as a `sv_live_*` / `sv_admin_*` machine token against SQLCipher
///    using SHA-512 constant-time verification.
fn authenticate_caller(
    state: &AppState,
    active: &VaultActiveState,
    headers: &HeaderMap,
) -> Result<ScopedToken, ApiError> {
    let raw_tok = match extract_raw_token(headers) {
        Ok(t) => t,
        Err(e) => {
            state.check_token_rate_limit()?;
            state.record_token_auth_failure();
            return Err(e);
        }
    };

    // Route 1: OIDC JWT Workload Identity (3 dot-separated Base64URL segments)
    if !raw_tok.starts_with("sv_live_")
        && !raw_tok.starts_with("sv_admin_")
        && raw_tok.split('.').count() == 3
    {
        let bindings = {
            let db = active
                .storage
                .lock()
                .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
            db.list_oidc_bindings().map_err(|_| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "OIDC binding lookup error",
                )
            })?
        };

        let now = now_unix_seconds();
        match verify_oidc_jwt_and_resolve(raw_tok, &bindings, &state.oidc_cache, now) {
            Ok(scoped_tok) => {
                record_audit(
                    active,
                    "auth.oidc",
                    &scoped_tok.token_id,
                    "sys/auth/oidc",
                    "verified",
                );
                return Ok(scoped_tok);
            }
            Err(oidc_err) => {
                state.check_token_rate_limit()?;
                state.record_token_auth_failure();
                let err_msg = oidc_err.to_string();
                record_audit(
                    active,
                    "auth.oidc.failed",
                    "oidc:unverified",
                    "sys/auth/oidc",
                    "rejected",
                );
                return Err((
                    StatusCode::UNAUTHORIZED,
                    Json(serde_json::json!({ "error": err_msg })),
                ));
            }
        }
    }

    // Route 2: SHA-512 Constant-Time Scoped Machine Token (`sv_live_*` / `sv_admin_*`)
    let (token_id, candidate_secret) = match parse_machine_token(raw_tok) {
        Ok(parsed) => parsed,
        Err(_) => {
            state.check_token_rate_limit()?;
            state.record_token_auth_failure();
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "Invalid machine token or OIDC JWT format",
            ));
        }
    };

    let stored_tok = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.get_token_by_id(&token_id)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Token lookup error"))?
    };

    let tok = match stored_tok {
        Some(t) => t,
        None => {
            state.check_token_rate_limit()?;
            state.record_token_auth_failure();
            record_audit(
                active,
                "auth.failed",
                &token_id,
                "sys/auth",
                "unknown_token",
            );
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "Unknown or revoked machine token",
            ));
        }
    };

    if !verify_token_sha512_ct(&candidate_secret, &tok.token_hash_sha512) {
        state.check_token_rate_limit()?;
        state.record_token_auth_failure();
        record_audit(active, "auth.failed", &token_id, "sys/auth", "bad_secret");
        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid machine token"));
    }

    let now = now_unix_seconds();
    if let Some(exp) = tok.expires_at {
        if now >= exp {
            state.check_token_rate_limit()?;
            state.record_token_auth_failure();
            record_audit(active, "auth.failed", &token_id, "sys/auth", "expired");
            return Err(api_err(
                StatusCode::UNAUTHORIZED,
                "Machine token has expired",
            ));
        }
    }

    Ok(tok)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let initialized = is_vault_initialized(&state.data_dir);
    let active_guard = state.active.read().await;
    let (sealed, memory_locked) = match active_guard.as_ref() {
        Some(a) => (
            false,
            a.db_memory_locked
                && a.value_aead_key.is_memory_locked()
                && a.audit_chain_key.is_memory_locked(),
        ),
        None => (true, false),
    };

    Json(HealthResponse {
        status: if sealed {
            "sealed".to_string()
        } else {
            "active".to_string()
        },
        initialized,
        sealed,
        memory_locked,
        telemetry_enabled: state.telemetry_enabled,
        version: env!("CARGO_PKG_VERSION").to_string(),
    })
}

async fn init_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    state.check_rate_limit()?;

    let supplied_nonce = headers
        .get("X-Vault-Bootstrap-Nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| {
            state.record_auth_failure();
            api_err(StatusCode::FORBIDDEN, "Missing bootstrap nonce")
        })?;

    // Acquire write guard first to prevent concurrent initialization races
    let mut active_guard = state.active.write().await;
    if is_vault_initialized(&state.data_dir) || active_guard.is_some() {
        return Err(api_err(
            StatusCode::CONFLICT,
            "Vault is already initialized",
        ));
    }
    if has_partial_initialization(&state.data_dir) {
        return Err(api_err(
            StatusCode::CONFLICT,
            "Partial vault initialization detected (mismatched vault.db / vault.envelope); clean volume before re-initializing",
        ));
    }

    let mut nonce_guard = state
        .bootstrap_nonce
        .lock()
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Bootstrap lock error"))?;
    let expected = nonce_guard.as_ref().ok_or_else(|| {
        state.record_auth_failure();
        api_err(
            StatusCode::FORBIDDEN,
            "Bootstrap nonce already consumed or unavailable",
        )
    })?;
    if !constant_time_str_eq(supplied_nonce, expected.as_str()) {
        state.record_auth_failure();
        tracing::warn!("Rejected /v1/sys/init with invalid bootstrap nonce");
        return Err(api_err(StatusCode::FORBIDDEN, "Invalid bootstrap nonce"));
    }

    let unseal_key = generate_unseal_key();
    let (envelope_hdr, db_key, value_aead_key, audit_chain_key) = create_envelope(&unseal_key)
        .map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Envelope generation failed",
            )
        })?;

    let db_locked = db_key.is_memory_locked();
    let mut storage = Storage::open_encrypted(&state.data_dir, &db_key).map_err(|_| {
        let _ = std::fs::remove_file(database_path(&state.data_dir));
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to initialize SQLCipher DB",
        )
    })?;

    // Mint initial Root Admin token (SHA-512 hashed at rest) so subsequent enrollments require admin auth
    let (admin_token_id, raw_admin_token, admin_hash_sha512) = mint_machine_token();
    let root_paths = vec!["*".to_string()];
    let root_caps = vec![
        "admin".to_string(),
        "read".to_string(),
        "write".to_string(),
        "delete".to_string(),
    ];
    if storage
        .put_token(
            &admin_token_id,
            &admin_hash_sha512,
            "root",
            "initial-root-admin",
            &root_paths,
            &root_caps,
            None,
        )
        .is_err()
        || storage
            .append_audit_event(
                &audit_chain_key,
                "sys.init",
                &admin_token_id,
                "sys/vault",
                "initialized",
            )
            .is_err()
        || write_envelope_header(&state.data_dir, &envelope_hdr).is_err()
    {
        drop(storage);
        let _ = std::fs::remove_file(database_path(&state.data_dir));
        let _ = std::fs::remove_file(envelope_path(&state.data_dir));
        return Err(api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to persist initial vault state",
        ));
    }

    // Burn nonce strictly AFTER both SQLCipher DB and envelope header are durably persisted (`FM-06`)
    *nonce_guard = None;
    drop(nonce_guard);

    let unseal_key_hex = Zeroizing::new(hex_encode(unseal_key.as_ref()));

    *active_guard = Some(VaultActiveState {
        storage: Mutex::new(storage),
        value_aead_key,
        audit_chain_key,
        db_memory_locked: db_locked,
        siem_forwarder: state.siem_forwarder.clone(),
    });

    tracing::info!(
        admin_token_id = %admin_token_id,
        "Vault initialized with SQLCipher + HKDF-SHA512 envelope and unsealed."
    );

    Ok(Json(serde_json::json!({
        "status": "initialized",
        "unseal_key": unseal_key_hex.as_str(),
        "admin_token_id": admin_token_id,
        "admin_token": raw_admin_token.as_str(),
        "warning": "Store both unseal_key and admin_token in Ubuntu Secret Service (keyring) or 1Password immediately. Neither is ever stored in plaintext or displayed again."
    })))
}

async fn unseal_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UnsealRequest>,
) -> Result<impl IntoResponse, ApiError> {
    state.check_rate_limit()?;

    if !is_vault_initialized(&state.data_dir) {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Vault is not initialized yet",
        ));
    }

    let mut active_guard = state.active.write().await;
    if active_guard.is_some() {
        return Err(api_err(StatusCode::CONFLICT, "Vault is already unsealed"));
    }

    let decoded = Zeroizing::new(hex_decode(payload.unseal_key.trim()).map_err(|_| {
        state.record_auth_failure();
        api_err(StatusCode::BAD_REQUEST, "Invalid hex-encoded unseal key")
    })?);
    if decoded.len() != 32 {
        state.record_auth_failure();
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Unseal key must be exactly 32 bytes (64 hex characters)",
        ));
    }

    let mut key_arr = Zeroizing::new([0u8; 32]);
    key_arr.copy_from_slice(&decoded);

    let header = read_envelope_header(&state.data_dir).map_err(|_| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to read vault envelope",
        )
    })?;

    // Cryptographically verify AEAD tag on wrapped DEK BEFORE opening DB or touching state!
    let (db_key, value_aead_key, audit_chain_key) =
        unwrap_envelope(&key_arr, &header).map_err(|_| {
            state.record_auth_failure();
            tracing::warn!("Rejected /v1/sys/unseal: AEAD verification failed for supplied key");
            api_err(StatusCode::UNAUTHORIZED, "Invalid unseal key")
        })?;

    let db_locked = db_key.is_memory_locked();
    let mut storage = Storage::open_encrypted(&state.data_dir, &db_key).map_err(|_| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SQLCipher verification failed",
        )
    })?;
    let _ = storage.operational_counts().map_err(|_| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "SQLCipher page authentication failed",
        )
    })?;
    let existing_bindings = storage.list_oidc_bindings().unwrap_or_default();
    if let Ok(entry) = storage.append_audit_event(
        &audit_chain_key,
        "sys.unseal",
        "unseal-operator",
        "sys/vault",
        "unsealed",
    ) {
        if let Some(ref forwarder) = state.siem_forwarder {
            forwarder.emit(entry);
        }
    }

    *active_guard = Some(VaultActiveState {
        storage: Mutex::new(storage),
        value_aead_key,
        audit_chain_key,
        db_memory_locked: db_locked,
        siem_forwarder: state.siem_forwarder.clone(),
    });
    drop(active_guard);

    // Pre-populate in-memory OIDC JWKS cache immediately upon unsealing
    if !existing_bindings.is_empty() {
        let _ = state.oidc_cache.refresh_bindings(&existing_bindings).await;
    }

    tracing::info!("Vault unsealed successfully after cryptographic envelope verification.");
    Ok(Json(serde_json::json!({
        "status": "active",
        "sealed": false
    })))
}

async fn metrics_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<MetricsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/metrics",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to inspect fleet metrics",
        ));
    }

    let initialized = is_vault_initialized(&state.data_dir);
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let memory_locked = active.db_memory_locked
        && active.value_aead_key.is_memory_locked()
        && active.audit_chain_key.is_memory_locked();
    let jwks_cached_keys_count = state.oidc_cache.total_cached_keys() as u64;

    let (counts, oidc_count, audit_seq) = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        let c = db.operational_counts().unwrap_or((0, 0, 0));
        let o = db.count_oidc_bindings().unwrap_or(0);
        let a = db.latest_audit_seq().unwrap_or(0);
        (c, o, a)
    };

    if query
        .format
        .as_deref()
        .map(|f| f.eq_ignore_ascii_case("prometheus"))
        .unwrap_or(false)
    {
        let prom = format!(
            "# HELP vault_sealed Whether Sovereign Vault is currently sealed (0=active, 1=sealed)\n\
             # TYPE vault_sealed gauge\n\
             vault_sealed 0\n\
             # HELP vault_memory_locked Whether mlockall/mlock RAM pinning is active (1=locked)\n\
             # TYPE vault_memory_locked gauge\n\
             vault_memory_locked {}\n\
             # HELP vault_uptime_seconds Process uptime in seconds\n\
             # TYPE vault_uptime_seconds counter\n\
             vault_uptime_seconds {}\n\
             # HELP vault_secrets_total Total encrypted secrets stored in SQLCipher\n\
             # TYPE vault_secrets_total gauge\n\
             vault_secrets_total {}\n\
             # HELP vault_tokens_active Total active unexpired SHA-512 machine tokens\n\
             # TYPE vault_tokens_active gauge\n\
             vault_tokens_active {}\n\
             # HELP vault_oidc_bindings_active Total configured OIDC workload identity bindings\n\
             # TYPE vault_oidc_bindings_active gauge\n\
             vault_oidc_bindings_active {}\n\
             # HELP vault_oidc_jwks_keys_cached Total OIDC JWKS public keys cached in RAM\n\
             # TYPE vault_oidc_jwks_keys_cached gauge\n\
             vault_oidc_jwks_keys_cached {}\n\
             # HELP vault_audit_seq Latest HMAC-SHA512 audit log sequence number\n\
             # TYPE vault_audit_seq counter\n\
             vault_audit_seq {}\n\
             # HELP vault_storage_bytes Encrypted SQLCipher database size in bytes\n\
             # TYPE vault_storage_bytes gauge\n\
             vault_storage_bytes {}\n",
            if memory_locked { 1 } else { 0 },
            uptime_seconds,
            counts.0,
            counts.1,
            oidc_count,
            jwks_cached_keys_count,
            audit_seq,
            counts.2,
        );
        return Ok((
            StatusCode::OK,
            [("content-type", "text/plain; version=0.0.4")],
            prom,
        )
            .into_response());
    }

    Ok(Json(VaultMetricsResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        status: "active".to_string(),
        initialized,
        sealed: false,
        memory_locked,
        telemetry_enabled: state.telemetry_enabled,
        siem_forwarding_enabled: state.siem_forwarder.is_some(),
        uptime_seconds,
        total_secrets_count: counts.0,
        active_tokens_count: counts.1,
        active_oidc_bindings_count: oidc_count,
        jwks_cached_keys_count,
        audit_seq,
        storage_bytes: counts.2,
    })
    .into_response())
}

async fn enroll_oidc_binding_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnrollOidcBindingRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_admin(now) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/oidc/bindings",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to configure OIDC workload bindings",
        ));
    }

    let preset = match payload.preset.as_deref() {
        Some(raw) if !raw.trim().is_empty() => OidcPreset::from_str_opt(raw).ok_or_else(|| {
            api_err(
                StatusCode::BAD_REQUEST,
                "Invalid OIDC preset (supported: github, gitlab, google, azure, kubernetes, authelia, dex, custom)",
            )
        })?,
        _ => OidcPreset::Custom,
    };

    let (default_issuer, default_jwks_uri, default_claim) = preset
        .resolve_defaults(payload.issuer.as_deref(), payload.tenant_id.as_deref())
        .map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    let resolved_issuer = payload
        .issuer
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_issuer);
    let resolved_jwks_uri = payload
        .jwks_uri
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_jwks_uri)
        .to_string();
    let resolved_aud = payload
        .audience
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or("sovereign-vault");
    let resolved_claim = payload
        .subject_claim
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(&default_claim);

    let (
        clean_name,
        clean_project,
        clean_issuer,
        clean_aud,
        clean_claim,
        clean_pattern,
        clean_paths,
    ) = validate_oidc_binding_fields(
        &payload.name,
        &payload.project,
        resolved_issuer,
        resolved_aud,
        resolved_claim,
        &payload.subject_pattern,
        &payload.allowed_paths,
        &payload.capabilities,
    )
    .map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    // Validate inline_jwks_json if supplied
    let inline_jwks = match payload.inline_jwks_json {
        Some(raw) if !raw.trim().is_empty() => {
            let doc: crate::oidc::JwksDocument = serde_json::from_str(&raw).map_err(|_| {
                api_err(
                    StatusCode::BAD_REQUEST,
                    "Invalid inline_jwks_json (expected RFC 7517 {\"keys\": [...]})",
                )
            })?;
            if doc.keys.is_empty() {
                return Err(api_err(
                    StatusCode::BAD_REQUEST,
                    "inline_jwks_json must contain at least one key",
                ));
            }
            Some(raw)
        }
        _ => None,
    };

    let binding_id = format!("oidc_{}_{}", clean_project, clean_name);
    let binding = OidcBinding {
        binding_id: binding_id.clone(),
        name: clean_name,
        project: clean_project,
        issuer: clean_issuer,
        audience: clean_aud,
        jwks_uri: resolved_jwks_uri,
        subject_claim: clean_claim,
        subject_pattern: clean_pattern,
        allowed_paths: clean_paths,
        capabilities: payload.capabilities,
        inline_jwks_json: inline_jwks,
        created_at: now,
    };

    let all_bindings = {
        let mut db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.put_oidc_binding(&binding).map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to persist OIDC binding",
            )
        })?;
        if let Ok(entry) = db.append_audit_event(
            &active.audit_chain_key,
            "oidc.binding.enroll",
            &caller.token_id,
            &binding_id,
            "created",
        ) {
            if let Some(ref forwarder) = active.siem_forwarder {
                forwarder.emit(entry);
            }
        }
        db.list_oidc_bindings().unwrap_or_default()
    };

    // Automatically refresh in-memory JWKS cache immediately when an admin adds/updates a provider!
    let jwks_refresh = state.oidc_cache.refresh_bindings(&all_bindings).await;
    let total_cached_keys = state.oidc_cache.total_cached_keys();

    Ok((
        StatusCode::CREATED,
        Json(EnrollOidcBindingResponse {
            binding,
            jwks_refresh,
            total_cached_keys,
        }),
    ))
}

async fn list_oidc_bindings_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/oidc/bindings",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to list OIDC bindings",
        ));
    }

    let bindings = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.list_oidc_bindings().map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "OIDC binding query failed",
            )
        })?
    };

    Ok(Json(ListOidcBindingsResponse {
        bindings,
        total_cached_keys: state.oidc_cache.total_cached_keys(),
    }))
}

async fn revoke_oidc_binding_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(target_binding_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            &target_binding_id,
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to revoke OIDC bindings",
        ));
    }

    let (existed, remaining) = {
        let mut db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        let ok = db.delete_oidc_binding(&target_binding_id).map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "OIDC binding deletion failed",
            )
        })?;
        if ok {
            if let Ok(entry) = db.append_audit_event(
                &active.audit_chain_key,
                "oidc.binding.revoke",
                &caller.token_id,
                &target_binding_id,
                "revoked",
            ) {
                if let Some(ref forwarder) = active.siem_forwarder {
                    forwarder.emit(entry);
                }
            }
        }
        let rem = db.list_oidc_bindings().unwrap_or_default();
        (ok, rem)
    };

    if !existed {
        return Err(api_err(StatusCode::NOT_FOUND, "OIDC binding ID not found"));
    }

    let _ = state.oidc_cache.refresh_bindings(&remaining).await;
    Ok(StatusCode::NO_CONTENT)
}

async fn refresh_oidc_jwks_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/oidc/refresh",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to refresh OIDC JWKS cache",
        ));
    }

    let bindings = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.list_oidc_bindings().map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "OIDC binding query failed",
            )
        })?
    };

    let refreshed_issuers = state.oidc_cache.refresh_bindings(&bindings).await;
    let total_cached_keys = state.oidc_cache.total_cached_keys();
    record_audit(
        active,
        "oidc.jwks.refresh",
        &caller.token_id,
        "sys/oidc/refresh",
        "ok",
    );

    Ok(Json(RefreshOidcResponse {
        refreshed_issuers,
        total_cached_keys,
    }))
}

async fn seal_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let mut active_guard = state.active.write().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is already sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/seal",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to seal vault",
        ));
    }

    let caller_id = caller.token_id.clone();
    record_audit(active, "sys.seal", &caller_id, "sys/vault", "sealed");
    *active_guard = None;

    tracing::warn!(token_id = %caller_id, "Vault sealed via administrative request; RAM keys zeroized and unlocked.");
    Ok(Json(serde_json::json!({
        "status": "sealed",
        "sealed": true
    })))
}

async fn backup_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/backup",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to create encrypted backups",
        ));
    }

    let meta: BackupMetadata = {
        let mut db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        let m = db
            .create_encrypted_backup()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Encrypted backup failed"))?;
        let _ = db.append_audit_event(
            &active.audit_chain_key,
            "sys.backup",
            &caller.token_id,
            &m.snapshot_id,
            "created",
        );
        m
    };

    tracing::info!(
        admin_token_id = %caller.token_id,
        snapshot_id = %meta.snapshot_id,
        bytes = meta.total_bytes,
        "Created online encrypted SQLCipher snapshot"
    );

    Ok((StatusCode::CREATED, Json(meta)))
}

async fn audit_log_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<AuditQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/audit",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to inspect audit log",
        ));
    }

    let limit = query.limit.unwrap_or(100);
    let (chain_verified, total_events, events) = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.verify_and_list_audit_log(&active.audit_chain_key, limit)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Audit query failed"))?
    };

    Ok(Json(AuditLogResponse {
        chain_verified,
        total_events,
        events,
    }))
}

async fn list_tokens_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/tokens",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to list enrolled tokens",
        ));
    }

    let tokens = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.list_tokens_metadata()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Token list query failed"))?
    };

    Ok(Json(ListTokensResponse { tokens }))
}

async fn list_secrets_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Query(query): Query<ListSecretsQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    let now = now_unix_seconds();

    let canonical_prefix = match query.prefix.as_deref() {
        Some(raw) if !raw.trim().is_empty() => Some(
            canonicalize_prefix_filter(raw).map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?,
        ),
        _ => None,
    };

    let all_items = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.list_secrets_metadata().map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Secret list query failed",
            )
        })?
    };

    let is_admin = caller.is_admin(now);
    let visible: Vec<SecretMetadataItem> = all_items
        .into_iter()
        .filter(|item| {
            if let Some(ref pref) = canonical_prefix {
                if !path_matches_directory_prefix(&item.path, pref) {
                    return false;
                }
            }
            caller.is_path_allowed(&item.path, "read", now)
                && (is_admin || caller.project == item.project)
        })
        .collect();

    Ok(Json(ListSecretsResponse { secrets: visible }))
}

async fn enroll_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnrollTokenRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_admin(now) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            "sys/enroll",
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to enroll machine tokens",
        ));
    }

    let valid_project = validate_identifier(&payload.project)
        .map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;
    let valid_name =
        validate_identifier(&payload.name).map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    if payload.allowed_paths.is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "allowed_paths must contain at least one pattern",
        ));
    }

    let mut validated_paths = Vec::with_capacity(payload.allowed_paths.len());
    for pat in &payload.allowed_paths {
        let valid =
            validate_scope_pattern(pat).map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;
        validated_paths.push(valid);
    }
    validate_capabilities(&payload.capabilities)
        .map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    let expires_at = payload
        .ttl_seconds
        .filter(|&ttl| ttl > 0)
        .map(|ttl| now.saturating_add(ttl as i64));

    let (token_id, raw_token, token_hash_sha512) = mint_machine_token();

    {
        let mut db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.put_token(
            &token_id,
            &token_hash_sha512,
            &valid_project,
            &valid_name,
            &validated_paths,
            &payload.capabilities,
            expires_at,
        )
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to persist token"))?;
        db.append_audit_event(
            &active.audit_chain_key,
            "token.enroll",
            &caller.token_id,
            &token_id,
            "created",
        )
        .map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to persist audit event",
            )
        })?;
    }

    tracing::info!(
        admin_token_id = %caller.token_id,
        enrolled_token_id = %token_id,
        project = %valid_project,
        name = %valid_name,
        "Enrolled new SHA-512 scoped machine token"
    );

    Ok((
        StatusCode::CREATED,
        Json(EnrollTokenResponse {
            token_id,
            token: raw_token.as_str().to_string(),
            project: valid_project,
            name: valid_name,
            allowed_paths: validated_paths,
            capabilities: payload.capabilities,
            expires_at,
        }),
    ))
}

async fn revoke_token_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(target_token_id): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            &target_token_id,
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to revoke tokens",
        ));
    }

    let existed = {
        let mut db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        let ok = db
            .delete_token(&target_token_id)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Token deletion failed"))?;
        if ok {
            db.append_audit_event(
                &active.audit_chain_key,
                "token.revoke",
                &caller.token_id,
                &target_token_id,
                "revoked",
            )
            .map_err(|_| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to persist audit event",
                )
            })?;
        }
        ok
    };

    if !existed {
        return Err(api_err(StatusCode::NOT_FOUND, "Token ID not found"));
    }

    tracing::info!(
        admin_token_id = %caller.token_id,
        revoked_token_id = %target_token_id,
        "Revoked machine token"
    );

    Ok(StatusCode::NO_CONTENT)
}

async fn get_secret_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
    Query(query): Query<GetSecretQuery>,
) -> Result<impl IntoResponse, ApiError> {
    let canon_path =
        canonicalize_secret_path(&raw_path).map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_path_allowed(&canon_path, "read", now) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            &canon_path,
            "forbidden",
        );
        tracing::warn!(
            token_id = %caller.token_id,
            path = %canon_path,
            "Access denied: read outside permitted scope"
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Access forbidden: path or capability outside token scope",
        ));
    }

    let record = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.get_secret_version(&canon_path, query.version)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Secret query failed"))?
    };

    let rec = match record {
        Some(r) => r,
        None => {
            return Err(api_err(
                StatusCode::NOT_FOUND,
                "Secret path or version not found",
            ))
        }
    };

    // Non-admin tokens must also match the secret's owning project
    if !caller.is_admin(now) && caller.project != rec.project {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            &canon_path,
            "project_mismatch",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Access forbidden: project mismatch",
        ));
    }

    let aad = build_secret_aad(&rec.project, &canon_path, rec.version);
    let plaintext =
        decrypt_secret_with_aad(&active.value_aead_key, &rec.ciphertext, &rec.nonce, &aad)
            .map_err(|_| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "AEAD authentication failed (tampered ciphertext or AAD mismatch)",
                )
            })?;

    let val = std::str::from_utf8(plaintext.as_slice())
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Corrupt UTF-8 secret"))?
        .to_string();

    record_audit(active, "secret.get", &caller.token_id, &canon_path, "ok");
    tracing::info!(token_id = %caller.token_id, path = %canon_path, version = rec.version, "Secret read");

    Ok(Json(SecretResponse {
        path: canon_path,
        project: rec.project,
        version: rec.version,
        value: val,
    }))
}

async fn put_secret_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
    Json(payload): Json<PutSecretRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let canon_path =
        canonicalize_secret_path(&raw_path).map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;
    let project = validate_identifier(&payload.project)
        .map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_path_allowed(&canon_path, "write", now) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            &canon_path,
            "forbidden",
        );
        tracing::warn!(
            token_id = %caller.token_id,
            path = %canon_path,
            "Access denied: write outside permitted scope"
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Access forbidden: write outside permitted token scope",
        ));
    }

    if !caller.is_admin(now) && caller.project != project {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            &canon_path,
            "project_mismatch",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Access forbidden: cannot write secrets under a different project",
        ));
    }

    let version = {
        let mut db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;

        // Prevent cross-project clobbering (`FM-02`): if a secret already exists at `canon_path`,
        // non-admin callers cannot overwrite or hijack a secret owned by another project.
        if let Some(existing) = db
            .get_secret(&canon_path)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Secret lookup failed"))?
        {
            if !caller.is_admin(now) && existing.project != project {
                let _ = db.append_audit_event(
                    &active.audit_chain_key,
                    "acl.denied",
                    &caller.token_id,
                    &canon_path,
                    "project_mismatch",
                );
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Access forbidden: secret path is already owned by another project",
                ));
            }
        }

        let next_ver = db
            .next_secret_version(&canon_path)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Version lookup failed"))?;
        let aad = build_secret_aad(&project, &canon_path, next_ver);
        let (ct, nonce) =
            encrypt_secret_with_aad(&active.value_aead_key, payload.value.as_bytes(), &aad)
                .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed"))?;
        db.put_secret_versioned(&canon_path, &project, next_ver, &ct, &nonce)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Persistence failed"))?;
        db.append_audit_event(
            &active.audit_chain_key,
            "secret.put",
            &caller.token_id,
            &canon_path,
            &format!("v{next_ver}"),
        )
        .map_err(|_| {
            api_err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to persist audit event",
            )
        })?;
        next_ver
    };

    tracing::info!(
        token_id = %caller.token_id,
        path = %canon_path,
        version,
        "Secret persisted"
    );

    Ok(Json(serde_json::json!({
        "status": "persisted",
        "path": canon_path,
        "project": project,
        "version": version
    })))
}

async fn delete_secret_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(raw_path): Path<String>,
) -> Result<impl IntoResponse, ApiError> {
    let canon_path =
        canonicalize_secret_path(&raw_path).map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(&state, active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_path_allowed(&canon_path, "delete", now) {
        record_audit(
            active,
            "acl.denied",
            &caller.token_id,
            &canon_path,
            "forbidden",
        );
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Access forbidden: delete outside permitted token scope",
        ));
    }

    let deleted = {
        let mut db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;

        // Enforce project ownership before deleting (`FM-01`)
        if let Some(existing) = db
            .get_secret(&canon_path)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Secret lookup failed"))?
        {
            if !caller.is_admin(now) && caller.project != existing.project {
                let _ = db.append_audit_event(
                    &active.audit_chain_key,
                    "acl.denied",
                    &caller.token_id,
                    &canon_path,
                    "project_mismatch",
                );
                return Err(api_err(
                    StatusCode::FORBIDDEN,
                    "Access forbidden: project mismatch on delete",
                ));
            }
        } else {
            return Err(api_err(StatusCode::NOT_FOUND, "Secret path not found"));
        }

        let ok = db
            .delete_secret(&canon_path)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Secret deletion failed"))?;
        if ok {
            db.append_audit_event(
                &active.audit_chain_key,
                "secret.delete",
                &caller.token_id,
                &canon_path,
                "deleted",
            )
            .map_err(|_| {
                api_err(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Failed to persist audit event",
                )
            })?;
        }
        ok
    };

    if !deleted {
        return Err(api_err(StatusCode::NOT_FOUND, "Secret path not found"));
    }

    tracing::info!(token_id = %caller.token_id, path = %canon_path, "Secret deleted");
    Ok(StatusCode::NO_CONTENT)
}
