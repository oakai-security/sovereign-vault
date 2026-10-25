//! HTTP REST API daemon with first-boot nonce validation and unsealing state machine.

use crate::crypto::{decrypt_secret, encrypt_secret, LockedKey};
use crate::storage::Storage;
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post, put},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

pub struct AppState {
    pub storage: Mutex<Storage>,
    pub bootstrap_nonce: String,
    pub master_key: Mutex<Option<LockedKey>>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub initialized: bool,
    pub sealed: bool,
    pub version: &'static str,
}

#[derive(Deserialize)]
pub struct UnsealRequest {
    pub unseal_key: String,
}

#[derive(Serialize)]
pub struct SecretResponse {
    pub path: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct PutSecretRequest {
    pub project: String,
    pub value: String,
}

#[derive(Deserialize)]
pub struct EnrollTokenRequest {
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
}

#[derive(Serialize)]
pub struct EnrollTokenResponse {
    pub token_id: String,
    pub token: String,
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
}

pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/v1/sys/health", get(health_handler))
        .route("/v1/sys/init", post(init_handler))
        .route("/v1/sys/unseal", post(unseal_handler))
        .route("/v1/sys/enroll", post(enroll_handler))
        .route("/v1/secret/*path", get(get_secret_handler).put(put_secret_handler))
        .with_state(state)
}

async fn health_handler(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    let storage = state.storage.lock().unwrap();
    let initialized = storage.is_initialized().unwrap_or(false);
    let key_guard = state.master_key.lock().unwrap();
    let sealed = key_guard.is_none();

    Json(HealthResponse {
        status: if sealed { "sealed" } else { "active" },
        initialized,
        sealed,
        version: "0.1.0",
    })
}

async fn init_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let nonce_hdr = headers
        .get("X-Vault-Bootstrap-Nonce")
        .and_then(|h| h.to_str().ok());

    if nonce_hdr != Some(&state.bootstrap_nonce) {
        return Err((StatusCode::FORBIDDEN, "Invalid or missing bootstrap nonce"));
    }

    let storage = state.storage.lock().unwrap();
    if storage.is_initialized().unwrap_or(false) {
        return Err((StatusCode::CONFLICT, "Vault is already initialized"));
    }

    // Generate fresh 256-bit unseal key
    let mut raw_key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut raw_key);
    let key_hex = hex::encode(raw_key);

    storage.set_initialized(&key_hex).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Failed to initialize storage")
    })?;

    // Unseal immediately for the initializing admin
    let locked = LockedKey::new(raw_key);
    *state.master_key.lock().unwrap() = Some(locked);

    Ok(Json(serde_json::json!({
        "status": "initialized",
        "unseal_key": key_hex,
        "warning": "Save this key into your personal vault (keyring/Bitwarden). It will never be displayed again."
    })))
}

async fn unseal_handler(
    State(state): State<Arc<AppState>>,
    Json(payload): Json<UnsealRequest>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let key_bytes = hex::decode(&payload.unseal_key)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex-encoded key"))?;

    if key_bytes.len() != 32 {
        return Err((StatusCode::BAD_REQUEST, "Key must be exactly 32 bytes (64 hex characters)"));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&key_bytes);

    let locked = LockedKey::new(arr);
    *state.master_key.lock().unwrap() = Some(locked);

    tracing::info!("Vault unsealed successfully.");
    Ok(Json(serde_json::json!({ "status": "unsealed", "sealed": false })))
}

async fn enroll_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Json(payload): Json<EnrollTokenRequest>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let key_guard = state.master_key.lock().unwrap();
    if key_guard.is_none() {
        return Err((StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed"));
    }

    // Generate random 128-bit token ID and 256-bit secret token
    let mut tok_bytes = [0u8; 16];
    let mut sec_bytes = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut tok_bytes);
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut sec_bytes);

    let token_id = format!("tok_{}", hex::encode(tok_bytes));
    let raw_token = format!("sv_live_{}", hex::encode(sec_bytes));
    let token_hash = hex::encode(sec_bytes);

    let paths_json = serde_json::to_string(&payload.allowed_paths).unwrap_or_else(|_| "[]".into());
    let caps_json = serde_json::to_string(&payload.capabilities).unwrap_or_else(|_| "[]".into());

    let storage = state.storage.lock().unwrap();
    storage
        .put_token(&token_id, &token_hash, &payload.project, &payload.name, &paths_json, &caps_json)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Failed to persist token"))?;

    Ok(Json(EnrollTokenResponse {
        token_id,
        token: raw_token,
        project: payload.project,
        name: payload.name,
        allowed_paths: payload.allowed_paths,
    }))
}

async fn get_secret_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let key_guard = state.master_key.lock().unwrap();
    let key = match key_guard.as_ref() {
        Some(k) => k,
        None => return Err((StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed")),
    };

    // If an X-Vault-Token header is provided, enforce project/path scoping
    if let Some(tok_hdr) = headers.get("X-Vault-Token").and_then(|h| h.to_str().ok()) {
        let raw_token_hex = tok_hdr.trim_start_matches("sv_live_");
        let storage = state.storage.lock().unwrap();
        match storage.get_token_by_hash(raw_token_hex).map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Token query error")
        })? {
            Some(tok) => {
                if !tok.is_path_allowed(&path, "read") {
                    return Err((StatusCode::FORBIDDEN, "Access forbidden: Path outside permitted token scope"));
                }
            }
            None => return Err((StatusCode::UNAUTHORIZED, "Invalid machine token")),
        }
    }

    let storage = state.storage.lock().unwrap();
    let (ct, nonce_bytes) = match storage.get_secret(&path).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Storage query failed")
    })? {
        Some(res) => res,
        None => return Err((StatusCode::NOT_FOUND, "Secret path not found")),
    };

    let mut nonce_arr = [0u8; 12];
    nonce_arr.copy_from_slice(&nonce_bytes);

    let plaintext = decrypt_secret(key, &ct, &nonce_arr).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Cryptographic decryption failed")
    })?;

    let val = String::from_utf8(plaintext)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Corrupt UTF-8 secret"))?;

    Ok(Json(SecretResponse { path, value: val }))
}

async fn put_secret_handler(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Json(payload): Json<PutSecretRequest>,
) -> Result<impl IntoResponse, (StatusCode, &'static str)> {
    let key_guard = state.master_key.lock().unwrap();
    let key = match key_guard.as_ref() {
        Some(k) => k,
        None => return Err((StatusCode::SERVICE_UNAVAILABLE, "Vault is sealed")),
    };

    // If X-Vault-Token provided, verify write permission
    if let Some(tok_hdr) = headers.get("X-Vault-Token").and_then(|h| h.to_str().ok()) {
        let raw_token_hex = tok_hdr.trim_start_matches("sv_live_");
        let storage = state.storage.lock().unwrap();
        match storage.get_token_by_hash(raw_token_hex).map_err(|_| {
            (StatusCode::INTERNAL_SERVER_ERROR, "Token query error")
        })? {
            Some(tok) => {
                if !tok.is_path_allowed(&path, "write") {
                    return Err((StatusCode::FORBIDDEN, "Access forbidden: Write outside permitted token scope"));
                }
            }
            None => return Err((StatusCode::UNAUTHORIZED, "Invalid machine token")),
        }
    }

    let (ct, nonce) = encrypt_secret(key, payload.value.as_bytes()).map_err(|_| {
        (StatusCode::INTERNAL_SERVER_ERROR, "Cryptographic encryption failed")
    })?;

    let storage = state.storage.lock().unwrap();
    storage
        .put_secret(&path, &payload.project, &ct, &nonce)
        .map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "Storage persist failed"))?;

    Ok(Json(serde_json::json!({ "status": "persisted", "path": path })))
}

mod hex {
    pub fn encode<T: AsRef<[u8]>>(data: T) -> String {
        data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }

    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 {
            return Err(());
        }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|_| ()))
            .collect()
    }
}
