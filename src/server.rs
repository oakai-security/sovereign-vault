//! Hardened HTTP REST API daemon with:
//! - Envelope DEK/KEK verification on unseal (`409` if already unsealed, `401` on bad key)
//! - Mandatory default-deny SHA-512 constant-time machine token authentication
//! - Canonical path ACL enforcement with exact trailing-slash directory boundaries
//! - Deadlock-free `RwLock<Option<VaultActiveState>>` concurrency hierarchy

use crate::acl::{
    canonicalize_secret_path, validate_capabilities, validate_scope_pattern, ScopedToken,
};
use crate::crypto::{
    build_secret_aad, constant_time_str_eq, create_envelope, decrypt_secret_with_aad,
    encrypt_secret_with_aad, generate_unseal_key, hex_decode, hex_encode, mint_machine_token,
    parse_machine_token, unwrap_envelope, verify_token_sha512_ct, LockedKey,
};
use crate::storage::{
    is_vault_initialized, now_unix_seconds, read_envelope_header, write_envelope_header, Storage,
};
use axum::{
    extract::{DefaultBodyLimit, Path, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::RwLock;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Active unsealed vault state. Exists in RAM strictly while the vault is unsealed;
/// dropping this struct closes SQLCipher and zeroizes + munlocks `value_aead_key`.
pub struct VaultActiveState {
    pub storage: Mutex<Storage>,
    pub value_aead_key: LockedKey,
    pub db_memory_locked: bool,
}

pub struct AppState {
    pub data_dir: PathBuf,
    pub started_at: Instant,
    pub telemetry_enabled: bool,
    pub bootstrap_nonce: Mutex<Option<Zeroizing<String>>>,
    pub active: RwLock<Option<VaultActiveState>>,
}

impl AppState {
    pub fn new(data_dir: PathBuf, bootstrap_nonce: Option<String>, telemetry_enabled: bool) -> Self {
        Self {
            data_dir,
            started_at: Instant::now(),
            telemetry_enabled,
            bootstrap_nonce: Mutex::new(bootstrap_nonce.map(Zeroizing::new)),
            active: RwLock::new(None),
        }
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

#[derive(Serialize, Deserialize)]
pub struct SecretResponse {
    pub path: String,
    pub project: String,
    pub version: i64,
    pub value: String,
}

#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct PutSecretRequest {
    #[zeroize(skip)]
    pub project: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct EnrollTokenRequest {
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub ttl_seconds: Option<u64>,
}

#[derive(Serialize, Deserialize)]
pub struct EnrollTokenResponse {
    pub token_id: String,
    pub token: String,
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub expires_at: Option<i64>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/sys/health", get(health_handler))
        .route("/v1/sys/init", post(init_handler))
        .route("/v1/sys/unseal", post(unseal_handler))
        .route("/v1/sys/seal", post(seal_handler))
        .route("/v1/sys/enroll", post(enroll_handler))
        .route("/v1/sys/tokens/:token_id", delete(revoke_token_handler))
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

/// Extract raw bearer token strictly from `X-Vault-Token` or `Authorization: Bearer ...`.
/// Default-deny: missing or malformed headers ALWAYS fail with `401 Unauthorized`.
fn extract_raw_token(headers: &HeaderMap) -> Result<&str, ApiError> {
    if let Some(raw_val) = headers.get("X-Vault-Token") {
        let s = raw_val
            .to_str()
            .map_err(|_| api_err(StatusCode::UNAUTHORIZED, "Malformed X-Vault-Token header"))?
            .trim();
        if s.is_empty() {
            return Err(api_err(StatusCode::UNAUTHORIZED, "Empty X-Vault-Token header"));
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
            "Expected Authorization: Bearer <sv_live_token>",
        ));
    }

    Err(api_err(
        StatusCode::UNAUTHORIZED,
        "Missing authentication token (provide X-Vault-Token header)",
    ))
}

/// Authenticate a machine token against SQLCipher using SHA-512 constant-time verification.
fn authenticate_caller(
    active: &VaultActiveState,
    headers: &HeaderMap,
) -> Result<ScopedToken, ApiError> {
    let raw_tok = extract_raw_token(headers)?;
    let (token_id, candidate_secret) = parse_machine_token(raw_tok)
        .map_err(|_| api_err(StatusCode::UNAUTHORIZED, "Invalid machine token format"))?;

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
        None => return Err(api_err(StatusCode::UNAUTHORIZED, "Unknown or revoked machine token")),
    };

    if !verify_token_sha512_ct(&candidate_secret, &tok.token_hash_sha512) {
        return Err(api_err(StatusCode::UNAUTHORIZED, "Invalid machine token"));
    }

    let now = now_unix_seconds();
    if let Some(exp) = tok.expires_at {
        if now >= exp {
            return Err(api_err(StatusCode::UNAUTHORIZED, "Machine token has expired"));
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
            a.db_memory_locked && a.value_aead_key.is_memory_locked(),
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
    let supplied_nonce = headers
        .get("X-Vault-Bootstrap-Nonce")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| api_err(StatusCode::FORBIDDEN, "Missing bootstrap nonce"))?;

    // Acquire write guard first to prevent concurrent initialization races
    let mut active_guard = state.active.write().await;
    if is_vault_initialized(&state.data_dir) || active_guard.is_some() {
        return Err(api_err(StatusCode::CONFLICT, "Vault is already initialized"));
    }

    {
        let mut nonce_guard = state
            .bootstrap_nonce
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Bootstrap lock error"))?;
        let expected = nonce_guard.as_ref().ok_or_else(|| {
            api_err(
                StatusCode::FORBIDDEN,
                "Bootstrap nonce already consumed or unavailable",
            )
        })?;
        if !constant_time_str_eq(supplied_nonce, expected.as_str()) {
            tracing::warn!("Rejected /v1/sys/init with invalid bootstrap nonce");
            return Err(api_err(StatusCode::FORBIDDEN, "Invalid bootstrap nonce"));
        }
        // Burn nonce immediately upon verified match
        *nonce_guard = None;
    }

    let unseal_key = generate_unseal_key();
    let (envelope_hdr, db_key, value_aead_key) = create_envelope(&unseal_key)
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Envelope generation failed"))?;

    let db_locked = db_key.is_memory_locked();
    let storage = Storage::open_encrypted(&state.data_dir, &db_key)
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to initialize SQLCipher DB"))?;

    // Mint initial Root Admin token (SHA-512 hashed at rest) so subsequent enrollments require admin auth
    let (admin_token_id, raw_admin_token, admin_hash_sha512) = mint_machine_token();
    let root_paths = vec!["*".to_string()];
    let root_caps = vec![
        "admin".to_string(),
        "read".to_string(),
        "write".to_string(),
        "delete".to_string(),
    ];
    storage
        .put_token(
            &admin_token_id,
            &admin_hash_sha512,
            "root",
            "initial-root-admin",
            &root_paths,
            &root_caps,
            None,
        )
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to persist root admin token"))?;

    write_envelope_header(&state.data_dir, &envelope_hdr)
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to persist envelope header"))?;

    let unseal_key_hex = Zeroizing::new(hex_encode(unseal_key.as_ref()));

    *active_guard = Some(VaultActiveState {
        storage: Mutex::new(storage),
        value_aead_key,
        db_memory_locked: db_locked,
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

    let decoded = Zeroizing::new(
        hex_decode(payload.unseal_key.trim())
            .map_err(|_| api_err(StatusCode::BAD_REQUEST, "Invalid hex-encoded unseal key"))?,
    );
    if decoded.len() != 32 {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "Unseal key must be exactly 32 bytes (64 hex characters)",
        ));
    }

    let mut key_arr = Zeroizing::new([0u8; 32]);
    key_arr.copy_from_slice(&decoded);

    let header = read_envelope_header(&state.data_dir)
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to read vault envelope"))?;

    // Cryptographically verify AEAD tag on wrapped DEK BEFORE opening DB or touching state!
    let (db_key, value_aead_key) = unwrap_envelope(&key_arr, &header).map_err(|_| {
        tracing::warn!("Rejected /v1/sys/unseal: AEAD verification failed for supplied key");
        api_err(StatusCode::UNAUTHORIZED, "Invalid unseal key")
    })?;

    let db_locked = db_key.is_memory_locked();
    let storage = Storage::open_encrypted(&state.data_dir, &db_key).map_err(|_| {
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

    *active_guard = Some(VaultActiveState {
        storage: Mutex::new(storage),
        value_aead_key,
        db_memory_locked: db_locked,
    });

    tracing::info!("Vault unsealed successfully after cryptographic envelope verification.");
    Ok(Json(serde_json::json!({
        "status": "active",
        "sealed": false
    })))
}

async fn seal_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, ApiError> {
    let mut active_guard = state.active.write().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is already sealed"))?;

    let caller = authenticate_caller(active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to seal vault",
        ));
    }

    let caller_id = caller.token_id.clone();
    *active_guard = None;

    tracing::warn!(token_id = %caller_id, "Vault sealed via administrative request; RAM keys zeroized and unlocked.");
    Ok(Json(serde_json::json!({
        "status": "sealed",
        "sealed": true
    })))
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

    let caller = authenticate_caller(active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_admin(now) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to enroll machine tokens",
        ));
    }

    if payload.project.trim().is_empty() || payload.name.trim().is_empty() {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "project and name must be non-empty",
        ));
    }
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
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.put_token(
            &token_id,
            &token_hash_sha512,
            payload.project.trim(),
            payload.name.trim(),
            &validated_paths,
            &payload.capabilities,
            expires_at,
        )
        .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to persist token"))?;
    }

    tracing::info!(
        admin_token_id = %caller.token_id,
        enrolled_token_id = %token_id,
        project = %payload.project,
        name = %payload.name,
        "Enrolled new SHA-512 scoped machine token"
    );

    Ok((
        StatusCode::CREATED,
        Json(EnrollTokenResponse {
            token_id,
            token: raw_token.as_str().to_string(),
            project: payload.project,
            name: payload.name,
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

    let caller = authenticate_caller(active, &headers)?;
    if !caller.is_admin(now_unix_seconds()) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Admin capability required to revoke tokens",
        ));
    }

    let existed = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.delete_token(&target_token_id)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Token deletion failed"))?
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
) -> Result<impl IntoResponse, ApiError> {
    let canon_path =
        canonicalize_secret_path(&raw_path).map_err(|msg| api_err(StatusCode::BAD_REQUEST, msg))?;

    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_path_allowed(&canon_path, "read", now) {
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
        db.get_secret(&canon_path)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Secret query failed"))?
    };

    let rec = match record {
        Some(r) => r,
        None => return Err(api_err(StatusCode::NOT_FOUND, "Secret path not found")),
    };

    // Non-admin tokens must also match the secret's owning project
    if !caller.is_admin(now) && caller.project != rec.project {
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
    let project = payload.project.trim();
    if project.is_empty() {
        return Err(api_err(StatusCode::BAD_REQUEST, "project must be non-empty"));
    }

    let active_guard = state.active.read().await;
    let active = active_guard
        .as_ref()
        .ok_or_else(|| api_err(StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"))?;

    let caller = authenticate_caller(active, &headers)?;
    let now = now_unix_seconds();
    if !caller.is_path_allowed(&canon_path, "write", now) {
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
        let next_ver = db
            .next_secret_version(&canon_path)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Version lookup failed"))?;
        let aad = build_secret_aad(project, &canon_path, next_ver);
        let (ct, nonce) =
            encrypt_secret_with_aad(&active.value_aead_key, payload.value.as_bytes(), &aad)
                .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed"))?;
        db.put_secret_versioned(&canon_path, project, next_ver, &ct, &nonce)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Persistence failed"))?;
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

    let caller = authenticate_caller(active, &headers)?;
    if !caller.is_path_allowed(&canon_path, "delete", now_unix_seconds()) {
        return Err(api_err(
            StatusCode::FORBIDDEN,
            "Access forbidden: delete outside permitted token scope",
        ));
    }

    let deleted = {
        let db = active
            .storage
            .lock()
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Storage lock error"))?;
        db.delete_secret(&canon_path)
            .map_err(|_| api_err(StatusCode::INTERNAL_SERVER_ERROR, "Secret deletion failed"))?
    };

    if !deleted {
        return Err(api_err(StatusCode::NOT_FOUND, "Secret path not found"));
    }

    tracing::info!(token_id = %caller.token_id, path = %canon_path, "Secret deleted");
    Ok(StatusCode::NO_CONTENT)
}
