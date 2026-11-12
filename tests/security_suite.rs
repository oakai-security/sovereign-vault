//! Integration test suite verifying Sovereign Vault v1.0 cryptographic, authentication,
//! path-boundary ACL, seal/unseal verification, and air-gapped telemetry guarantees.

use axum::{
    body::{to_bytes, Body},
    http::{Method, Request, StatusCode},
    Router,
};
use serde_json::{json, Value};
use sovereign_vault::{
    server::{create_router, AppState},
    storage::{database_path, envelope_path},
    telemetry::{build_telemetry_ping, TelemetryConfig},
};
use std::sync::Arc;
use tempfile::TempDir;
use tower::ServiceExt;

async fn send_json(
    app: &Router,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }

    let req_body = match body {
        Some(val) => {
            builder = builder.header("Content-Type", "application/json");
            Body::from(serde_json::to_vec(&val).expect("serialize request json"))
        }
        None => Body::empty(),
    };

    let req = builder.body(req_body).expect("build http request");
    let resp = app.clone().oneshot(req).await.expect("dispatch request");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read response body");
    if bytes.is_empty() {
        (status, Value::Null)
    } else {
        let parsed = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
        (status, parsed)
    }
}

async fn bootstrap_test_vault() -> (TempDir, Arc<AppState>, Router, String, String) {
    let dir = TempDir::new().expect("create tempdir");
    let nonce = "init_0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    let state = Arc::new(AppState::new(
        dir.path().to_path_buf(),
        Some(nonce.to_string()),
        false,
    ));
    let app = create_router(state.clone());

    // Wrong nonce must be rejected without burning the real nonce
    let (bad_status, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/init",
        &[("X-Vault-Bootstrap-Nonce", "init_wrong")],
        None,
    )
    .await;
    assert_eq!(bad_status, StatusCode::FORBIDDEN);

    // Valid bootstrap nonce initializes envelope + SQLCipher + root admin token
    let (status, body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/init",
        &[("X-Vault-Bootstrap-Nonce", nonce)],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Replaying init must return 409 Conflict
    let (replay_status, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/init",
        &[("X-Vault-Bootstrap-Nonce", nonce)],
        None,
    )
    .await;
    assert_eq!(replay_status, StatusCode::CONFLICT);

    let unseal_key = body["unseal_key"]
        .as_str()
        .expect("unseal_key string")
        .to_string();
    let admin_token = body["admin_token"]
        .as_str()
        .expect("admin_token string")
        .to_string();

    assert_eq!(unseal_key.len(), 64);
    assert!(admin_token.starts_with("sv_live_"));

    (dir, state, app, unseal_key, admin_token)
}

#[tokio::test]
async fn test_envelope_and_sqlcipher_encrypt_at_rest() {
    let (dir, _state, app, unseal_key, admin_token) = bootstrap_test_vault().await;

    let secret_marker = "super-sensitive-db-secret-value-998877";
    let (put_status, put_body) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/jellyfin/db_password",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "project": "jellyfin",
            "value": secret_marker
        })),
    )
    .await;
    assert_eq!(put_status, StatusCode::OK);
    assert_eq!(put_body["version"], 1);

    // 1. Inspect /data/vault.envelope: 0600 permissions, zero plaintext unseal key
    let env_file = envelope_path(dir.path());
    let env_contents = std::fs::read_to_string(&env_file).expect("read vault.envelope");
    assert!(
        !env_contents.contains(&unseal_key),
        "vault.envelope must never contain the raw unseal key"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let env_mode = std::fs::metadata(&env_file)
            .expect("envelope metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(env_mode, 0o600, "vault.envelope must be chmod 0600");
    }

    // 2. Inspect /data/vault.db (and WAL if present): encrypted SQLCipher pages, no SQLite header or plaintext leaks
    let db_file = database_path(dir.path());
    let db_bytes = std::fs::read(&db_file).expect("read vault.db");
    assert!(
        !db_bytes.starts_with(b"SQLite format 3\0"),
        "vault.db must be encrypted via SQLCipher, not plaintext SQLite"
    );

    let mut combined_disk_bytes = db_bytes;
    let wal_path = dir.path().join("vault.db-wal");
    if wal_path.exists() {
        combined_disk_bytes.extend_from_slice(&std::fs::read(&wal_path).expect("read wal"));
    }

    let disk_lossy = String::from_utf8_lossy(&combined_disk_bytes);
    assert!(
        !disk_lossy.contains(secret_marker),
        "Secret value leaked on disk"
    );
    assert!(
        !disk_lossy.contains("apps/jellyfin/db_password"),
        "Secret path metadata leaked in plaintext on disk"
    );
}

#[tokio::test]
async fn test_mandatory_default_deny_authentication() {
    let (_dir, _state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;

    // Seed a secret as admin
    let (st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/infra/dns/api_token",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "infra", "value": "cf_tok_123" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Every data & admin endpoint MUST reject unauthenticated requests with 401
    let (get_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/infra/dns/api_token",
        &[],
        None,
    )
    .await;
    assert_eq!(get_st, StatusCode::UNAUTHORIZED);

    let (put_st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/infra/dns/api_token",
        &[],
        Some(json!({ "project": "infra", "value": "overwrite" })),
    )
    .await;
    assert_eq!(put_st, StatusCode::UNAUTHORIZED);

    let (del_st, _) = send_json(
        &app,
        Method::DELETE,
        "/v1/secret/infra/dns/api_token",
        &[],
        None,
    )
    .await;
    assert_eq!(del_st, StatusCode::UNAUTHORIZED);

    let (enroll_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/enroll",
        &[],
        Some(json!({
            "project": "infra",
            "name": "rogue",
            "allowed_paths": ["*"],
            "capabilities": ["admin"]
        })),
    )
    .await;
    assert_eq!(enroll_st, StatusCode::UNAUTHORIZED);

    let (seal_st, _) = send_json(&app, Method::POST, "/v1/sys/seal", &[], None).await;
    assert_eq!(seal_st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_seal_and_verified_unseal_flow() {
    let (_dir, _state, app, unseal_key, admin_token) = bootstrap_test_vault().await;

    let (st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/prod/stripe/webhook_secret",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "prod", "value": "whsec_verified_roundtrip" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    // Unseal while already active MUST fail with 409 Conflict (never overwrite active key)
    let bogus_key = "ff".repeat(32);
    let (conflict_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": bogus_key })),
    )
    .await;
    assert_eq!(conflict_st, StatusCode::CONFLICT);

    // Admin seals the vault -> drops SQLCipher handle & zeroizes/munlocks RAM keys
    let (seal_st, seal_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/seal",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(seal_st, StatusCode::OK);
    assert_eq!(seal_body["sealed"], true);

    // Reads while sealed fail with 503 Service Unavailable
    let (sealed_get, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/prod/stripe/webhook_secret",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(sealed_get, StatusCode::SERVICE_UNAVAILABLE);

    // Bogus 32-byte key MUST fail AEAD envelope check with 401 Unauthorized
    let (bad_unseal, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": bogus_key })),
    )
    .await;
    assert_eq!(bad_unseal, StatusCode::UNAUTHORIZED);

    // Genuine unseal key succeeds and restores access to existing encrypted secrets
    let (good_unseal, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": unseal_key })),
    )
    .await;
    assert_eq!(good_unseal, StatusCode::OK);

    let (read_st, read_body) = send_json(
        &app,
        Method::GET,
        "/v1/secret/prod/stripe/webhook_secret",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(read_st, StatusCode::OK);
    assert_eq!(read_body["value"], "whsec_verified_roundtrip");
}

#[tokio::test]
async fn test_scoped_acl_boundary_versioning_and_revocation() {
    let (_dir, _state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;

    // Seed sibling project secret that `apps/jellyfin/*` MUST NOT be allowed to read
    let (seed_st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/jellyfin-prod/master_key",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "jellyfin", "value": "prod_crown_jewels" })),
    )
    .await;
    assert_eq!(seed_st, StatusCode::OK);

    // Enroll a machine token scoped strictly to `apps/jellyfin/*`
    let (en_st, en_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/enroll",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "project": "jellyfin",
            "name": "jellyfin-media-worker",
            "allowed_paths": ["apps/jellyfin/*"],
            "capabilities": ["read", "write"]
        })),
    )
    .await;
    assert_eq!(en_st, StatusCode::CREATED);
    let worker_token = en_body["token"].as_str().expect("worker token").to_string();
    let worker_id = en_body["token_id"]
        .as_str()
        .expect("worker token_id")
        .to_string();

    // Non-admin worker cannot enroll other tokens (privilege escalation blocked)
    let (esc_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/enroll",
        &[("X-Vault-Token", &worker_token)],
        Some(json!({
            "project": "root",
            "name": "escalated",
            "allowed_paths": ["*"],
            "capabilities": ["admin"]
        })),
    )
    .await;
    assert_eq!(esc_st, StatusCode::FORBIDDEN);

    // Sibling prefix `apps/jellyfin-prod/master_key` MUST return 403 Forbidden
    let (sib_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/jellyfin-prod/master_key",
        &[("X-Vault-Token", &worker_token)],
        None,
    )
    .await;
    assert_eq!(sib_st, StatusCode::FORBIDDEN);

    // Path traversal / malformed segment MUST return 400 Bad Request
    let (trav_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/jellyfin/bad$char",
        &[("X-Vault-Token", &worker_token)],
        None,
    )
    .await;
    assert_eq!(trav_st, StatusCode::BAD_REQUEST);

    // Valid write v1 -> v2 within scope succeeds and increments version monotonically
    let (w1_st, w1_body) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/jellyfin/transcode_key",
        &[("X-Vault-Token", &worker_token)],
        Some(json!({ "project": "jellyfin", "value": "v1_val" })),
    )
    .await;
    assert_eq!(w1_st, StatusCode::OK);
    assert_eq!(w1_body["version"], 1);

    let (w2_st, w2_body) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/jellyfin/transcode_key",
        &[("X-Vault-Token", &worker_token)],
        Some(json!({ "project": "jellyfin", "value": "v2_val" })),
    )
    .await;
    assert_eq!(w2_st, StatusCode::OK);
    assert_eq!(w2_body["version"], 2);

    // Authorization: Bearer <sv_live_...> header is also supported
    let bearer = format!("Bearer {worker_token}");
    let (g_st, g_body) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/jellyfin/transcode_key",
        &[("Authorization", &bearer)],
        None,
    )
    .await;
    assert_eq!(g_st, StatusCode::OK);
    assert_eq!(g_body["version"], 2);
    assert_eq!(g_body["value"], "v2_val");

    // Admin revokes worker token -> immediate 401 on subsequent read
    let (rev_st, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/sys/tokens/{worker_id}"),
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(rev_st, StatusCode::NO_CONTENT);

    let (post_rev_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/jellyfin/transcode_key",
        &[("X-Vault-Token", &worker_token)],
        None,
    )
    .await;
    assert_eq!(post_rev_st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_telemetry_air_gapped_by_default_and_privacy_preserving() {
    // 1. Default standalone lookup (no env vars) is strictly air-gapped (None)
    assert!(
        TelemetryConfig::from_lookup(|_| None).is_none(),
        "Standalone container must default to air-gapped mode (TelemetryConfig = None)"
    );

    // 2. Enabling OAKAI_TELEMETRY_ENABLED=true WITHOUT OAKAI_ENTERPRISE_LICENSE still stays disabled
    assert!(
        TelemetryConfig::from_lookup(|k| match k {
            "OAKAI_TELEMETRY_ENABLED" => Some("true".to_string()),
            _ => None,
        })
        .is_none(),
        "Telemetry must remain disabled without OAKAI_ENTERPRISE_LICENSE"
    );

    // 3. Providing OAKAI_ENTERPRISE_LICENSE WITHOUT OAKAI_TELEMETRY_ENABLED=true stays disabled
    assert!(
        TelemetryConfig::from_lookup(|k| match k {
            "OAKAI_ENTERPRISE_LICENSE" => Some("oakai_ent_live_123".to_string()),
            _ => None,
        })
        .is_none(),
        "Telemetry must remain disabled unless OAKAI_TELEMETRY_ENABLED=true"
    );

    // 4. Both present -> activates with privacy-preserving operational counts only
    let cfg = TelemetryConfig::from_lookup(|k| match k {
        "OAKAI_TELEMETRY_ENABLED" => Some("true".to_string()),
        "OAKAI_ENTERPRISE_LICENSE" => Some("oakai_ent_live_123".to_string()),
        "OAKAI_CLUSTER_ID" => Some("cls_enterprise_01".to_string()),
        _ => None,
    })
    .expect("Enterprise opt-in config should parse");
    assert_eq!(cfg.cluster_id, "cls_enterprise_01");

    let (_dir, state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;
    let (st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/corp/erp/sap_password",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "corp", "value": "ultra_confidential_sap_pw" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let ping = build_telemetry_ping(&state, "cls_enterprise_01").await;
    assert_eq!(ping.total_secrets_count, 1);
    assert_eq!(ping.active_tokens_count, 1);
    assert!(!ping.sealed);
    assert!(ping.storage_bytes > 0);

    let serialized = serde_json::to_string(&ping).expect("serialize telemetry ping");
    assert!(!serialized.contains("sap_password"));
    assert!(!serialized.contains("ultra_confidential_sap_pw"));
}

#[tokio::test]
async fn test_tamper_evident_audit_chain_and_acl_filtered_listing() {
    let (_dir, _state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;

    // Seed two secrets under different projects/prefixes
    let (s1, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/alpha/db_url",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "alpha", "value": "postgres://alpha" })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/beta/db_url",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "beta", "value": "postgres://beta" })),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // Enroll a worker scoped strictly to `apps/alpha/*`
    let (en_st, en_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/enroll",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "project": "alpha",
            "name": "alpha-reader",
            "allowed_paths": ["apps/alpha/*"],
            "capabilities": ["read"]
        })),
    )
    .await;
    assert_eq!(en_st, StatusCode::CREATED);
    let alpha_token = en_body["token"].as_str().unwrap().to_string();

    // Scoped worker lists secrets -> sees ONLY `apps/alpha/db_url`, NEVER `apps/beta/db_url` or values
    let (list_st, list_body) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[("X-Vault-Token", &alpha_token)],
        None,
    )
    .await;
    assert_eq!(list_st, StatusCode::OK);
    let visible = list_body["secrets"].as_array().expect("secrets array");
    assert_eq!(visible.len(), 1);
    assert_eq!(visible[0]["path"], "apps/alpha/db_url");
    assert!(visible[0].get("value").is_none());

    // Scoped worker attempts denied read on `apps/beta/db_url` -> recorded in tamper-evident audit log
    let (den_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/beta/db_url",
        &[("X-Vault-Token", &alpha_token)],
        None,
    )
    .await;
    assert_eq!(den_st, StatusCode::FORBIDDEN);

    // Scoped worker cannot read `/v1/sys/audit` or `/v1/sys/tokens`
    let (aud_forb, _) = send_json(
        &app,
        Method::GET,
        "/v1/sys/audit",
        &[("X-Vault-Token", &alpha_token)],
        None,
    )
    .await;
    assert_eq!(aud_forb, StatusCode::FORBIDDEN);

    // Admin queries `/v1/sys/tokens` (no hashes exposed) and `/v1/sys/audit` (HMAC-SHA512 chain verified)
    let (tok_st, tok_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/tokens",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(tok_st, StatusCode::OK);
    assert_eq!(tok_body["tokens"].as_array().unwrap().len(), 2);
    assert!(!tok_body.to_string().contains("token_hash"));

    let (aud_st, aud_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/audit?limit=50",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(aud_st, StatusCode::OK);
    assert_eq!(aud_body["chain_verified"], true);
    assert!(aud_body["total_events"].as_u64().unwrap() >= 5);
}

#[tokio::test]
async fn test_online_encrypted_backup_and_restore() {
    let (_dir, _state, app, unseal_key, admin_token) = bootstrap_test_vault().await;

    let (st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/dr/vault/recovery_seed",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "dr", "value": "seed-intact-after-online-backup" })),
    )
    .await;
    assert_eq!(st, StatusCode::OK);

    let (bk_st, bk_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/backup",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(bk_st, StatusCode::CREATED);
    let backup_dir = std::path::PathBuf::from(bk_body["backup_dir"].as_str().unwrap());
    assert!(backup_dir.join("vault.db").is_file());
    assert!(backup_dir.join("vault.envelope").is_file());
    assert!(backup_dir.join("vault.audit_anchor").is_file());

    // Restore snapshot into a brand-new directory and unseal a fresh daemon instance
    let restore_dir = TempDir::new().expect("restore tempdir");
    std::fs::copy(
        backup_dir.join("vault.db"),
        restore_dir.path().join("vault.db"),
    )
    .unwrap();
    std::fs::copy(
        backup_dir.join("vault.envelope"),
        restore_dir.path().join("vault.envelope"),
    )
    .unwrap();
    std::fs::copy(
        backup_dir.join("vault.audit_anchor"),
        restore_dir.path().join("vault.audit_anchor"),
    )
    .unwrap();

    let restored_state = Arc::new(AppState::new(restore_dir.path().to_path_buf(), None, false));
    let restored_app = create_router(restored_state);

    let (un_st, _) = send_json(
        &restored_app,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": unseal_key })),
    )
    .await;
    assert_eq!(un_st, StatusCode::OK);

    let (get_st, get_body) = send_json(
        &restored_app,
        Method::GET,
        "/v1/secret/dr/vault/recovery_seed",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(get_st, StatusCode::OK);
    assert_eq!(get_body["value"], "seed-intact-after-online-backup");
}

#[tokio::test]
async fn test_rate_limiting_blocks_repeated_auth_or_unseal_failures() {
    let dir = TempDir::new().expect("tempdir");
    let nonce = "init_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let state = Arc::new(AppState::with_rate_limit(
        dir.path().to_path_buf(),
        Some(nonce.to_string()),
        false,
        3,
    ));
    let app = create_router(state);

    for _ in 0..3 {
        let (st, _) = send_json(
            &app,
            Method::POST,
            "/v1/sys/init",
            &[("X-Vault-Bootstrap-Nonce", "init_bad")],
            None,
        )
        .await;
        assert_eq!(st, StatusCode::FORBIDDEN);
    }

    // 4th attempt within the 60s window MUST be throttled with 429 Too Many Requests
    let (throttled_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/init",
        &[("X-Vault-Bootstrap-Nonce", nonce)],
        None,
    )
    .await;
    assert_eq!(throttled_st, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn test_concurrent_health_and_secret_read_write_stress() {
    let (_dir, _state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;

    let mut handles = Vec::new();
    for i in 0..24usize {
        let router = app.clone();
        let tok = admin_token.clone();
        handles.push(tokio::spawn(async move {
            let path = format!("/v1/secret/stress/worker/{i}");
            let (p_st, _) = send_json(
                &router,
                Method::PUT,
                &path,
                &[("X-Vault-Token", &tok)],
                Some(json!({ "project": "stress", "value": format!("val-{i}") })),
            )
            .await;
            assert_eq!(p_st, StatusCode::OK);

            let (h_st, h_body) = send_json(&router, Method::GET, "/v1/sys/health", &[], None).await;
            assert_eq!(h_st, StatusCode::OK);
            assert_eq!(h_body["sealed"], false);

            let (g_st, g_body) = send_json(
                &router,
                Method::GET,
                &path,
                &[("X-Vault-Token", &tok)],
                None,
            )
            .await;
            assert_eq!(g_st, StatusCode::OK);
            assert_eq!(g_body["value"], format!("val-{i}"));
        }));
    }

    for h in handles {
        h.await.expect("concurrent worker panicked or deadlocked");
    }
}

#[tokio::test]
async fn test_cross_project_isolation_version_shredding_and_rate_limit_no_self_dos() {
    let (_dir, state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;

    // 1. Seed a secret owned by project "prod" at `shared/db/password` (v1 and v2)
    let (p1_st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/shared/db/password",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "prod", "value": "prod-secret-v1" })),
    )
    .await;
    assert_eq!(p1_st, StatusCode::OK);

    let (p2_st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/shared/db/password",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "prod", "value": "prod-secret-v2" })),
    )
    .await;
    assert_eq!(p2_st, StatusCode::OK);

    // Historical version v1 can be retrieved via `?version=1`
    let (v1_st, v1_body) = send_json(
        &app,
        Method::GET,
        "/v1/secret/shared/db/password?version=1",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(v1_st, StatusCode::OK);
    assert_eq!(v1_body["version"], 1);
    assert_eq!(v1_body["value"], "prod-secret-v1");

    // 2. Enroll a non-admin token in project "staging" with broad `shared/*` read/write/delete scope
    let (en_st, en_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/enroll",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "project": "staging",
            "name": "staging-broad-worker",
            "allowed_paths": ["shared/*"],
            "capabilities": ["read", "write", "delete"]
        })),
    )
    .await;
    assert_eq!(en_st, StatusCode::CREATED);
    let staging_token = en_body["token"].as_str().unwrap().to_string();

    // FM-02: "staging" token MUST NOT be able to overwrite/hijack "prod"'s secret at `shared/db/password`
    let (clobber_st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/shared/db/password",
        &[("X-Vault-Token", &staging_token)],
        Some(json!({ "project": "staging", "value": "hijacked-by-staging" })),
    )
    .await;
    assert_eq!(clobber_st, StatusCode::FORBIDDEN);

    // FM-01: "staging" token MUST NOT be able to delete "prod"'s secret at `shared/db/password`
    let (del_forb_st, _) = send_json(
        &app,
        Method::DELETE,
        "/v1/secret/shared/db/password",
        &[("X-Vault-Token", &staging_token)],
        None,
    )
    .await;
    assert_eq!(del_forb_st, StatusCode::FORBIDDEN);

    // 3. FM-05: Admin deletes `shared/db/password` -> both `secrets` and `secret_versions` are shredded
    let (del_ok_st, _) = send_json(
        &app,
        Method::DELETE,
        "/v1/secret/shared/db/password",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(del_ok_st, StatusCode::NO_CONTENT);

    {
        let active_guard = state.active.read().await;
        let active = active_guard.as_ref().expect("vault active");
        let db = active.storage.lock().expect("lock db");
        let remaining_versions = db
            .count_secret_versions("shared/db/password")
            .expect("count versions");
        assert_eq!(
            remaining_versions, 0,
            "DELETE must purge all historical rows in secret_versions"
        );
    }

    // 4. FM-13: Exhaust token_auth_failures with 15 bad token attempts; valid tokens must STILL work!
    for _ in 0..15 {
        let (bad_st, _) = send_json(
            &app,
            Method::GET,
            "/v1/secrets",
            &[("X-Vault-Token", "sv_live_00000000000000000000000000000000_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")],
            None,
        )
        .await;
        assert_eq!(bad_st, StatusCode::UNAUTHORIZED);
    }

    // 16th bad token attempt is rate-limited with 429 Too Many Requests
    let (bad_429, _) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[("X-Vault-Token", "sv_live_00000000000000000000000000000000_ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")],
        None,
    )
    .await;
    assert_eq!(bad_429, StatusCode::TOO_MANY_REQUESTS);

    // Valid admin_token is NEVER self-DoS'd by noisy unauthenticated token failures!
    let (valid_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(valid_st, StatusCode::OK);
}

#[tokio::test]
async fn test_v0_3_dual_mode_oidc_jwt_auth_presets_refresh_and_metrics() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let (_dir, _state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;

    // 1. Seed secrets under `apps/jellyfin/api_key` and `apps/other/secret`
    let (s1, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/jellyfin/api_key",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "jellyfin", "value": "jf-oidc-zero-secret-999" })),
    )
    .await;
    assert_eq!(s1, StatusCode::OK);

    let (s2, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/apps/other/secret",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "other", "value": "forbidden-to-jellyfin-jwt" })),
    )
    .await;
    assert_eq!(s2, StatusCode::OK);

    // 2. Generate an Ed25519 (EdDSA) keypair representing a homelab/cloud OIDC identity provider
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate ed25519 pkcs8");
    let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse ed25519 keypair");
    let pub_x = URL_SAFE_NO_PAD.encode(key_pair.public_key().as_ref());

    let inline_jwks = json!({
        "keys": [
            {
                "kty": "OKP",
                "crv": "Ed25519",
                "alg": "EdDSA",
                "use": "sig",
                "kid": "dex-ed25519-01",
                "x": pub_x
            }
        ]
    })
    .to_string();

    // 3. Enroll OIDC binding using the `dex` preset with inline JWKS -> auto-refreshes JWKS cache immediately
    let (enroll_st, enroll_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/oidc/bindings",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "preset": "dex",
            "project": "jellyfin",
            "name": "baseline-jellyfin-oidc",
            "issuer": "https://dex.homelab.local",
            "audience": "sovereign-vault",
            "subject_pattern": "system:node:baseline:*",
            "allowed_paths": ["apps/jellyfin/*"],
            "capabilities": ["read"],
            "inline_jwks_json": inline_jwks
        })),
    )
    .await;
    assert_eq!(enroll_st, StatusCode::CREATED);
    assert_eq!(enroll_body["total_cached_keys"], 1);
    let binding_id = enroll_body["binding"]["binding_id"]
        .as_str()
        .expect("binding_id")
        .to_string();

    // 4. Sign a valid EdDSA OIDC JWT matching issuer, audience, and subject_pattern
    let now = sovereign_vault::storage::now_unix_seconds();
    let header_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": "dex-ed25519-01"
        }))
        .unwrap(),
    );
    let claims_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": "https://dex.homelab.local",
            "sub": "system:node:baseline:jellyfin",
            "aud": ["sovereign-vault"],
            "iat": now - 10,
            "exp": now + 600
        }))
        .unwrap(),
    );
    let signing_input = format!("{header_b64}.{claims_b64}");
    let sig = key_pair.sign(signing_input.as_bytes());
    let valid_jwt = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()));

    // 5. Dual-Mode Auth: Present the 3-part OIDC JWT via `Authorization: Bearer <jwt>` to read `apps/jellyfin/api_key`
    let bearer_jwt = format!("Bearer {valid_jwt}");
    let (jwt_get_st, jwt_get_body) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/jellyfin/api_key",
        &[("Authorization", &bearer_jwt)],
        None,
    )
    .await;
    assert_eq!(jwt_get_st, StatusCode::OK);
    assert_eq!(jwt_get_body["value"], "jf-oidc-zero-secret-999");

    // 6. Dual-Mode Auth: Verify path ACL enforcement on OIDC JWT (`apps/other/secret` -> 403 Forbidden)
    let (jwt_forb_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/other/secret",
        &[("Authorization", &bearer_jwt)],
        None,
    )
    .await;
    assert_eq!(jwt_forb_st, StatusCode::FORBIDDEN);

    // 7. Ad-hoc JWKS cache refresh endpoint (`POST /v1/sys/oidc/refresh`) succeeds and reports cached keys
    let (ref_st, ref_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/oidc/refresh",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(ref_st, StatusCode::OK);
    assert_eq!(ref_body["refreshed_issuers"].as_array().unwrap().len(), 1);
    assert_eq!(ref_body["total_cached_keys"], 1);

    // 8. Fleet Metrics endpoint (`GET /v1/sys/metrics` JSON & `?format=prometheus` requires admin auth)
    let (unauth_met_st, _) = send_json(&app, Method::GET, "/v1/sys/metrics", &[], None).await;
    assert_eq!(unauth_met_st, StatusCode::UNAUTHORIZED);

    let (met_st, met_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/metrics",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(met_st, StatusCode::OK);
    assert_eq!(met_body["active_oidc_bindings_count"], 1);
    assert_eq!(met_body["jwks_cached_keys_count"], 1);
    assert_eq!(met_body["total_secrets_count"], 2);

    let (prom_st, prom_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/metrics?format=prometheus",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(prom_st, StatusCode::OK);
    let prom_raw = prom_body["raw"].as_str().expect("prometheus text");
    assert!(prom_raw.contains("vault_oidc_bindings_active 1"));
    assert!(prom_raw.contains("vault_oidc_jwks_keys_cached 1"));

    // 9. Revoking the OIDC binding immediately invalidates the JWT (`401 Unauthorized`) and purges cached keys
    let (del_oid_st, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/sys/oidc/bindings/{binding_id}"),
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(del_oid_st, StatusCode::NO_CONTENT);

    let (post_list_st, post_list_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/oidc/bindings",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(post_list_st, StatusCode::OK);
    assert_eq!(post_list_body["total_cached_keys"], 0);

    let (post_del_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/apps/jellyfin/api_key",
        &[("Authorization", &bearer_jwt)],
        None,
    )
    .await;
    assert_eq!(post_del_st, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn test_native_tls_rustls_encryption_in_transit() {
    let _ = rustls::crypto::ring::default_provider().install_default();
    let (_dir, _state, app, _unseal_key, _admin_token) = bootstrap_test_vault().await;

    // 1. Generate autonomous 397-day self-signed certificate for localhost/127.0.0.1
    let (cert_pem, key_pem, fp) = sovereign_vault::crypto::generate_self_signed_tls_cert(&[
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .expect("generate test tls cert");
    assert_eq!(fp.split(':').count(), 32);

    let strict_tls13 = sovereign_vault::crypto::build_strict_tls13_server_config(
        cert_pem.as_bytes(),
        key_pem.as_bytes(),
    )
    .expect("strict tls13 server config");
    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_config(strict_tls13);

    // 2. Bind to an ephemeral port on 127.0.0.1
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("get local addr");
    drop(listener); // Free for axum-server

    let server_handle = tokio::spawn(async move {
        let _ = axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await;
    });

    // Wait briefly for server startup
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 3. Client connecting with CA cert verification over TLS 1.3 succeeds
    let root_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("parse root cert");
    let trusted_client = reqwest::Client::builder()
        .add_root_certificate(root_cert.clone())
        .min_tls_version(reqwest::tls::Version::TLS_1_3)
        .build()
        .expect("build client");

    let resp = trusted_client
        .get(format!("https://localhost:{}/v1/sys/health", addr.port()))
        .send()
        .await
        .expect("https request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 4. Client forcing TLS 1.2 max version MUST be rejected by strict TLS 1.3 ServerConfig
    let tls12_only_client = reqwest::Client::builder()
        .add_root_certificate(root_cert)
        .max_tls_version(reqwest::tls::Version::TLS_1_2)
        .build()
        .expect("build tls12 client");
    let tls12_res = tls12_only_client
        .get(format!("https://localhost:{}/v1/sys/health", addr.port()))
        .send()
        .await;
    assert!(
        tls12_res.is_err(),
        "TLS 1.2 downgrade attempt must fail handshake against strict TLS 1.3 ServerConfig"
    );

    // 5. Plain HTTP request to TLS port is rejected / fails handshake
    let plain_client = reqwest::Client::new();
    let plain_fail = plain_client
        .get(format!("http://127.0.0.1:{}/v1/sys/health", addr.port()))
        .send()
        .await;
    assert!(plain_fail.is_err(), "Cleartext HTTP to TLS port must fail");

    server_handle.abort();
}

async fn send_json_from_ip(
    app: &Router,
    peer: std::net::SocketAddr,
    method: Method,
    uri: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut builder = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req_body = match body {
        Some(val) => {
            builder = builder.header("Content-Type", "application/json");
            Body::from(serde_json::to_vec(&val).expect("serialize request json"))
        }
        None => Body::empty(),
    };
    let mut req = builder.body(req_body).expect("build http request");
    req.extensions_mut()
        .insert(axum::extract::ConnectInfo(peer));

    let resp = app.clone().oneshot(req).await.expect("dispatch request");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), 1024 * 1024)
        .await
        .expect("read response body");
    if bytes.is_empty() {
        (status, Value::Null)
    } else {
        let parsed = serde_json::from_slice(&bytes)
            .unwrap_or_else(|_| json!({ "raw": String::from_utf8_lossy(&bytes).to_string() }));
        (status, parsed)
    }
}

#[tokio::test]
async fn test_per_ip_rate_limiter_isolates_attacker_from_legitimate_operator() {
    let dir = TempDir::new().expect("tempdir");
    let nonce = "init_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    let state = Arc::new(AppState::with_rate_limit(
        dir.path().to_path_buf(),
        Some(nonce.to_string()),
        false,
        3,
    ));
    let app = create_router(state);

    let local_op: std::net::SocketAddr = "127.0.0.1:45000".parse().unwrap();
    let attacker_ip: std::net::SocketAddr = "203.0.113.99:51234".parse().unwrap();

    // Initialize and immediately seal the vault
    let (init_st, init_body) = send_json_from_ip(
        &app,
        local_op,
        Method::POST,
        "/v1/sys/init",
        &[("X-Vault-Bootstrap-Nonce", nonce)],
        None,
    )
    .await;
    assert_eq!(init_st, StatusCode::OK);
    let unseal_key = init_body["unseal_key"].as_str().unwrap().to_string();
    let admin_token = init_body["admin_token"].as_str().unwrap().to_string();

    let (seal_st, _) = send_json_from_ip(
        &app,
        local_op,
        Method::POST,
        "/v1/sys/seal",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(seal_st, StatusCode::OK);

    // Attacker sends 3 invalid unseal keys -> 401, then 4th is throttled with 429
    let wrong_key = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
    for _ in 0..3 {
        let (st, _) = send_json_from_ip(
            &app,
            attacker_ip,
            Method::POST,
            "/v1/sys/unseal",
            &[],
            Some(json!({ "unseal_key": wrong_key })),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);
    }
    let (throttled_st, _) = send_json_from_ip(
        &app,
        attacker_ip,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": wrong_key })),
    )
    .await;
    assert_eq!(throttled_st, StatusCode::TOO_MANY_REQUESTS);

    // Legitimate localhost operator is completely unaffected by attacker's rate-limit bucket!
    let (unseal_st, _) = send_json_from_ip(
        &app,
        local_op,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": unseal_key })),
    )
    .await;
    assert_eq!(unseal_st, StatusCode::OK);
}

#[tokio::test]
async fn test_oidc_ssrf_block_and_cross_project_inline_jwks_isolation() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ring::signature::{Ed25519KeyPair, KeyPair};

    let (_dir, _state, app, _unseal_key, admin_token) = bootstrap_test_vault().await;

    // 1. SSRF checks at enrollment time: cleartext HTTP, cloud IMDS 169.254.169.254, and loopback jwks_uri must fail 400
    for (bad_issuer, bad_jwks) in [
        ("http://idp.example.com", "https://idp.example.com/jwks"),
        (
            "https://169.254.169.254/latest",
            "https://169.254.169.254/latest/meta-data",
        ),
        (
            "https://idp.example.com",
            "https://127.0.0.1:8080/.well-known/jwks.json",
        ),
        (
            "https://idp.example.com",
            "https://10.0.0.5/.well-known/jwks.json",
        ),
    ] {
        let (st, _) = send_json(
            &app,
            Method::POST,
            "/v1/sys/oidc/bindings",
            &[("X-Vault-Token", &admin_token)],
            Some(json!({
                "preset": "custom",
                "project": "secops",
                "name": "ssrf-attempt",
                "issuer": bad_issuer,
                "jwks_uri": bad_jwks,
                "subject_pattern": "*",
                "allowed_paths": ["secops/*"],
                "capabilities": ["read"]
            })),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::BAD_REQUEST,
            "Expected SSRF rejection for ({bad_issuer}, {bad_jwks})"
        );
    }

    // 2. Cross-project inline JWKS isolation: two bindings share the exact same `issuer`,
    //    each with its own Ed25519 keypair. Key B must NEVER verify against Binding A!
    let rng = ring::rand::SystemRandom::new();
    let pkcs8_a = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp_a = Ed25519KeyPair::from_pkcs8(pkcs8_a.as_ref()).unwrap();
    let pkcs8_b = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp_b = Ed25519KeyPair::from_pkcs8(pkcs8_b.as_ref()).unwrap();

    let jwks_a = json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "shared-kid",
            "x": URL_SAFE_NO_PAD.encode(kp_a.public_key().as_ref())
        }]
    })
    .to_string();
    let jwks_b = json!({
        "keys": [{
            "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": "shared-kid",
            "x": URL_SAFE_NO_PAD.encode(kp_b.public_key().as_ref())
        }]
    })
    .to_string();

    let _ = send_json(
        &app,
        Method::PUT,
        "/v1/secret/alpha/db_pass",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "alpha", "value": "alpha-crown-jewel" })),
    )
    .await;

    let (st_a, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/oidc/bindings",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "preset": "custom",
            "project": "alpha",
            "name": "alpha-idp",
            "issuer": "https://shared-idp.example.com",
            "audience": "sovereign-vault",
            "subject_pattern": "svc:alpha:*",
            "allowed_paths": ["alpha/*"],
            "capabilities": ["read"],
            "inline_jwks_json": jwks_a
        })),
    )
    .await;
    assert_eq!(st_a, StatusCode::CREATED);

    let (st_b, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/oidc/bindings",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "preset": "custom",
            "project": "beta",
            "name": "beta-idp",
            "issuer": "https://shared-idp.example.com",
            "audience": "sovereign-vault",
            "subject_pattern": "svc:beta:*",
            "allowed_paths": ["beta/*"],
            "capabilities": ["read"],
            "inline_jwks_json": jwks_b
        })),
    )
    .await;
    assert_eq!(st_b, StatusCode::CREATED);

    // Forged token signed with kp_b claiming `sub: "svc:alpha:api"` must fail 401!
    let now = sovereign_vault::storage::now_unix_seconds();
    let hdr_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({"alg": "EdDSA", "typ": "JWT", "kid": "shared-kid"})).unwrap(),
    );
    let forged_claims_b64 = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": "https://shared-idp.example.com",
            "sub": "svc:alpha:api",
            "aud": "sovereign-vault",
            "iat": now - 5,
            "exp": now + 300
        }))
        .unwrap(),
    );
    let forged_input = format!("{hdr_b64}.{forged_claims_b64}");
    let forged_sig = kp_b.sign(forged_input.as_bytes());
    let forged_jwt = format!(
        "Bearer {forged_input}.{}",
        URL_SAFE_NO_PAD.encode(forged_sig.as_ref())
    );

    let (forged_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secret/alpha/db_pass",
        &[("Authorization", &forged_jwt)],
        None,
    )
    .await;
    assert_eq!(forged_st, StatusCode::UNAUTHORIZED);

    // Legitimate token signed with kp_a succeeds 200 OK
    let valid_sig = kp_a.sign(forged_input.as_bytes());
    let valid_jwt = format!(
        "Bearer {forged_input}.{}",
        URL_SAFE_NO_PAD.encode(valid_sig.as_ref())
    );
    let (ok_st, ok_body) = send_json(
        &app,
        Method::GET,
        "/v1/secret/alpha/db_pass",
        &[("Authorization", &valid_jwt)],
        None,
    )
    .await;
    assert_eq!(ok_st, StatusCode::OK);
    assert_eq!(ok_body["value"], "alpha-crown-jewel");
}

#[tokio::test]
async fn test_audit_log_anchor_detects_tail_truncation_and_full_wipe() {
    let (dir, _state, app, unseal_key, admin_token) = bootstrap_test_vault().await;

    let (put_st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/audit/test_key",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "audit", "value": "val-1" })),
    )
    .await;
    assert_eq!(put_st, StatusCode::OK);

    // Baseline audit chain is valid and anchor file exists on disk
    let anchor_file = sovereign_vault::storage::audit_anchor_path(dir.path());
    assert!(anchor_file.is_file(), "vault.audit_anchor must exist");
    let (aud_st, aud_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/audit",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(aud_st, StatusCode::OK);
    assert_eq!(aud_body["chain_verified"], true);

    // Seal vault, open SQLCipher directly using the legitimate key, and truncate the latest row
    let _ = send_json(
        &app,
        Method::POST,
        "/v1/sys/seal",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;

    let key_bytes = sovereign_vault::crypto::hex_decode(&unseal_key).unwrap();
    let mut key_arr = [0u8; 32];
    key_arr.copy_from_slice(&key_bytes);
    let hdr = sovereign_vault::storage::read_envelope_header(dir.path()).unwrap();
    let (db_key, _, _) = sovereign_vault::crypto::unwrap_envelope(&key_arr, &hdr).unwrap();
    {
        let conn = rusqlite::Connection::open(database_path(dir.path())).unwrap();
        let hex_db_key = sovereign_vault::crypto::hex_encode(db_key.as_bytes());
        conn.execute_batch(&format!(
            "PRAGMA key = \"x'{hex_db_key}'\";
             PRAGMA cipher_page_size = 4096;
             PRAGMA kdf_iter = 256000;
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
             DELETE FROM audit_log WHERE seq = (SELECT MAX(seq) FROM audit_log);"
        ))
        .expect("tail-truncate audit_log");
    }

    // Note: unseal appends a new `sys.unseal` row and re-anchors IF unsealed, so let's verify
    // `Storage::verify_and_list_audit_log` directly BEFORE unsealing (simulating an attacker
    // truncating the live or offline DB without updating the HMAC-protected anchor)!
    {
        let (_, _, audit_key) = sovereign_vault::crypto::unwrap_envelope(&key_arr, &hdr).unwrap();
        let storage =
            sovereign_vault::storage::Storage::open_encrypted(dir.path(), &db_key).unwrap();
        let (valid_after_tail_delete, _, _) =
            storage.verify_and_list_audit_log(&audit_key, 50).unwrap();
        assert!(
            !valid_after_tail_delete,
            "External vault.audit_anchor MUST catch tail-truncation of audit_log"
        );
    }

    // SV-AUD-01: Unsealing after an offline tail-truncation MUST NOT overwrite/heal vault.audit_anchor!
    let (unseal_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": unseal_key })),
    )
    .await;
    assert_eq!(unseal_st, StatusCode::OK);

    let (aud_post_unseal_st, aud_post_unseal_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/audit",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(aud_post_unseal_st, StatusCode::OK);
    assert_eq!(
        aud_post_unseal_body["chain_verified"], false,
        "SV-AUD-01: sys.unseal MUST NOT heal/re-anchor a tail-truncated audit_log"
    );

    std::fs::remove_file(&anchor_file).expect("delete anchor file to simulate attacker rollback");
    let (aud2_st, aud2_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/audit",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(aud2_st, StatusCode::OK);
    assert_eq!(
        aud2_body["chain_verified"], false,
        "Deleting vault.audit_anchor must immediately invalidate chain_verified"
    );
}

#[tokio::test]
async fn test_online_rotate_unseal_key_invalidates_old_key_and_preserves_secrets() {
    let (dir, _state, app, old_unseal_key, admin_token) = bootstrap_test_vault().await;

    // 1. Persist a secret and create a backup (verifying sha256 digest field on BackupMetadata)
    let (put_st, _) = send_json(
        &app,
        Method::PUT,
        "/v1/secret/prod/stripe/webhook_secret",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "project": "prod", "value": "whsec_live_super_secret_rotate_test" })),
    )
    .await;
    assert_eq!(put_st, StatusCode::OK);

    let (bak_st, bak_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/backup",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(bak_st, StatusCode::CREATED);
    let snap_sha = bak_body["sha256"].as_str().expect("backup sha256");
    assert_eq!(snap_sha.len(), 64);

    // 2. Wrong current_unseal_key is rejected with 401
    let (bad_rot_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/rotate-unseal-key",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "current_unseal_key": "0000000000000000000000000000000000000000000000000000000000000000"
        })),
    )
    .await;
    assert_eq!(bad_rot_st, StatusCode::UNAUTHORIZED);

    // 3. Valid online KEK rotation succeeds and returns a brand-new 64-hex unseal key
    let (rot_st, rot_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/rotate-unseal-key",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "current_unseal_key": old_unseal_key })),
    )
    .await;
    assert_eq!(rot_st, StatusCode::OK);
    let new_unseal_key = rot_body["new_unseal_key"]
        .as_str()
        .expect("new_unseal_key")
        .to_string();
    assert_eq!(new_unseal_key.len(), 64);
    assert_ne!(new_unseal_key, old_unseal_key);

    // 4. Seal vault -> old unseal key MUST fail with 401 -> new unseal key unseals 200 OK!
    let (seal_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/seal",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(seal_st, StatusCode::OK);

    let (old_unseal_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": old_unseal_key })),
    )
    .await;
    assert_eq!(old_unseal_st, StatusCode::UNAUTHORIZED);

    let (new_unseal_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/unseal",
        &[],
        Some(json!({ "unseal_key": new_unseal_key })),
    )
    .await;
    assert_eq!(new_unseal_st, StatusCode::OK);

    // 5. Existing secret and HMAC-SHA512 audit chain + anchor remain 100% intact
    let (get_st, get_body) = send_json(
        &app,
        Method::GET,
        "/v1/secret/prod/stripe/webhook_secret",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(get_st, StatusCode::OK);
    assert_eq!(get_body["value"], "whsec_live_super_secret_rotate_test");

    let (aud_st, aud_body) = send_json(
        &app,
        Method::GET,
        "/v1/sys/audit",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(aud_st, StatusCode::OK);
    assert_eq!(aud_body["chain_verified"], true);
    let _ = envelope_path(dir.path());
}

#[tokio::test]
async fn test_sv_aud_regressions_backup_rewrap_oidc_jti_nat64_glob_and_enroll() {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use sovereign_vault::oidc::{claim_matches_pattern, is_disallowed_oidc_ip};
    use std::net::IpAddr;

    let (_dir, _state, app, old_unseal_key, admin_token) = bootstrap_test_vault().await;

    // 1. SV-AUD-05: IPv6 NAT64 (64:ff9b::/96 and 64:ff9b:1::/48) & IPv4-compatible SSRF checks
    let nat64_imds: IpAddr = "64:ff9b::a9fe:a9fe".parse().unwrap(); // 169.254.169.254
    let nat64_rfc1918: IpAddr = "64:ff9b::0a00:0001".parse().unwrap(); // 10.0.0.1
    let nat64_local: IpAddr = "64:ff9b:1::7f00:0001".parse().unwrap(); // 127.0.0.1
    let public_v6: IpAddr = "2606:4700:4700::1111".parse().unwrap();
    assert!(
        is_disallowed_oidc_ip(nat64_imds, false, false),
        "SV-AUD-05: NAT64 cloud metadata IP must be blocked"
    );
    assert!(
        is_disallowed_oidc_ip(nat64_rfc1918, false, false),
        "SV-AUD-05: NAT64 RFC1918 IP must be blocked"
    );
    assert!(
        is_disallowed_oidc_ip(nat64_local, false, false),
        "SV-AUD-05: RFC 8215 NAT64 loopback IP must be blocked"
    );
    assert!(!is_disallowed_oidc_ip(public_v6, false, false));

    // 2. SV-AUD-06: Backtracking glob matcher & cross-colon hierarchy delimiter protection
    assert!(
        claim_matches_pattern("aaab", "*a*ab"),
        "SV-AUD-06: backtracking glob must match *a*ab against aaab"
    );
    assert!(claim_matches_pattern(
        "repo:oakai-sec/vault:ref:refs/heads/main",
        "repo:oakai-sec/*:ref:refs/heads/main"
    ));
    assert!(
        !claim_matches_pattern(
            "repo:oakai-sec/other:environment:prod:ref:refs/heads/main",
            "repo:oakai-sec/*:ref:refs/heads/main"
        ),
        "SV-AUD-06: interior '*:' wildcard must not span across ':' claim delimiters"
    );
    assert!(
        !claim_matches_pattern("repo:oakai\n/vault", "repo:*"),
        "SV-AUD-06: control characters in claim values must be rejected"
    );

    // 3. SV-AUD-13: POST /v1/sys/enroll rejects ttl_seconds = 0 and ttl_seconds > 10 years
    let (ttl0_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/enroll",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "project": "ops",
            "name": "zero-ttl-worker",
            "allowed_paths": ["ops/*"],
            "capabilities": ["read"],
            "ttl_seconds": 0
        })),
    )
    .await;
    assert_eq!(
        ttl0_st,
        StatusCode::BAD_REQUEST,
        "SV-AUD-13: ttl_seconds=0 must be rejected with 400 Bad Request"
    );

    let (ttl_huge_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/enroll",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "project": "ops",
            "name": "huge-ttl-worker",
            "allowed_paths": ["ops/*"],
            "capabilities": ["read"],
            "ttl_seconds": 9_999_999_999u64
        })),
    )
    .await;
    assert_eq!(ttl_huge_st, StatusCode::BAD_REQUEST);

    // 4. SV-AUD-11: Uniform 401 error messages across unknown token_id and bad token secret
    let (unk_st, unk_body) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[(
            "X-Vault-Token",
            "sv_live_11111111111111111111111111111111_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )],
        None,
    )
    .await;
    assert_eq!(unk_st, StatusCode::UNAUTHORIZED);

    // Extract admin_token's valid ID and pair it with a wrong secret
    let parts: Vec<&str> = admin_token.split('_').collect();
    let valid_id_bad_secret = format!(
        "sv_live_{}_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        parts[2]
    );
    let (bad_sec_st, bad_sec_body) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[("X-Vault-Token", &valid_id_bad_secret)],
        None,
    )
    .await;
    assert_eq!(bad_sec_st, StatusCode::UNAUTHORIZED);
    assert_eq!(
        unk_body["error"], bad_sec_body["error"],
        "SV-AUD-11: unknown token_id and bad secret must return identical error message"
    );

    // 5. SV-AUD-02 & SV-AUD-14: Backup includes sys.backup in its own audit log & KEK rotation re-wraps backup envelopes
    let (bk_st, bk_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/backup",
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(bk_st, StatusCode::CREATED);
    let backup_dir = std::path::PathBuf::from(bk_body["backup_dir"].as_str().unwrap());

    // Rotate the unseal key online
    let (rot_st, rot_body) = send_json(
        &app,
        Method::POST,
        "/v1/sys/rotate-unseal-key",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({ "current_unseal_key": old_unseal_key })),
    )
    .await;
    assert_eq!(rot_st, StatusCode::OK);
    let new_unseal_key = rot_body["new_unseal_key"].as_str().unwrap().to_string();

    // Verify that the backup snapshot's vault.envelope can NO LONGER be unwrapped with old_unseal_key,
    // and CAN be unwrapped with new_unseal_key (`SV-AUD-02`)!
    let backup_hdr = sovereign_vault::storage::read_envelope_header(&backup_dir).unwrap();
    let old_bytes = sovereign_vault::crypto::hex_decode(&old_unseal_key).unwrap();
    let mut old_arr = [0u8; 32];
    old_arr.copy_from_slice(&old_bytes);
    assert!(
        sovereign_vault::crypto::unwrap_envelope(&old_arr, &backup_hdr).is_err(),
        "SV-AUD-02: rotated-out unseal key must not unwrap historical backup envelopes"
    );

    let new_bytes = sovereign_vault::crypto::hex_decode(&new_unseal_key).unwrap();
    let mut new_arr = [0u8; 32];
    new_arr.copy_from_slice(&new_bytes);
    let (bak_db_key, _, bak_audit_key) =
        sovereign_vault::crypto::unwrap_envelope(&new_arr, &backup_hdr)
            .expect("new unseal key must unwrap re-wrapped backup envelope");

    // Verify `SV-AUD-14`: the backup DB's audit chain is verified and already contains `sys.backup`
    let bak_storage =
        sovereign_vault::storage::Storage::open_encrypted(&backup_dir, &bak_db_key).unwrap();
    let (bak_chain_ok, _, bak_events) = bak_storage
        .verify_and_list_audit_log(&bak_audit_key, 50)
        .unwrap();
    assert!(
        bak_chain_ok,
        "SV-AUD-14: backup snapshot audit chain + anchor must verify cleanly"
    );
    assert!(
        bak_events.iter().any(|e| e.event_type == "sys.backup"),
        "SV-AUD-14: backup snapshot must include its own sys.backup audit entry"
    );

    // 6. SV-AUD-03: OIDC JWT without `iat` exceeding max lifetime & `jti` replay protection
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
    let kp = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
    let pub_b64 = URL_SAFE_NO_PAD.encode(kp.public_key().as_ref());
    let inline_jwks = json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "kid": "aud-ed-1",
            "alg": "EdDSA",
            "use": "sig",
            "x": pub_b64
        }]
    })
    .to_string();

    let (ob_st, _) = send_json(
        &app,
        Method::POST,
        "/v1/sys/oidc/bindings",
        &[("X-Vault-Token", &admin_token)],
        Some(json!({
            "project": "prod",
            "name": "aud-oidc-worker",
            "issuer": "https://oidc.aud.internal",
            "audience": "sovereign-vault",
            "subject_claim": "sub",
            "subject_pattern": "system:serviceaccount:prod:*",
            "allowed_paths": ["prod/*"],
            "capabilities": ["read"],
            "inline_jwks_json": inline_jwks
        })),
    )
    .await;
    assert_eq!(ob_st, StatusCode::CREATED);

    let now = sovereign_vault::storage::now_unix_seconds();
    let sign_jwt = |claims: serde_json::Value| -> String {
        let hdr_b64 = URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&json!({"alg": "EdDSA", "kid": "aud-ed-1"})).unwrap());
        let pay_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
        let signing_input = format!("{hdr_b64}.{pay_b64}");
        let sig = kp.sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.as_ref()))
    };

    // (a) JWT omitting `iat` with `exp = now + 90_000` (> 86400s) MUST be rejected (`SV-AUD-03`)
    let long_lived_no_iat = sign_jwt(json!({
        "iss": "https://oidc.aud.internal",
        "sub": "system:serviceaccount:prod:api",
        "aud": "sovereign-vault",
        "exp": now + 90_000
    }));
    let (no_iat_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[("Authorization", &format!("Bearer {long_lived_no_iat}"))],
        None,
    )
    .await;
    assert_eq!(
        no_iat_st,
        StatusCode::UNAUTHORIZED,
        "SV-AUD-03: OIDC JWT without iat exceeding 24h remaining lifetime must be rejected"
    );

    // (b) JWT with `jti` succeeds on first use and fails with 401 on replay (`SV-AUD-03`)
    let jti_jwt = sign_jwt(json!({
        "iss": "https://oidc.aud.internal",
        "sub": "system:serviceaccount:prod:api",
        "aud": "sovereign-vault",
        "iat": now,
        "exp": now + 600,
        "jti": "unique-jwt-id-12345"
    }));
    let (first_st, _) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[("Authorization", &format!("Bearer {jti_jwt}"))],
        None,
    )
    .await;
    assert_eq!(first_st, StatusCode::OK);

    let (replay_st, replay_body) = send_json(
        &app,
        Method::GET,
        "/v1/secrets",
        &[("Authorization", &format!("Bearer {jti_jwt}"))],
        None,
    )
    .await;
    assert_eq!(
        replay_st,
        StatusCode::UNAUTHORIZED,
        "SV-AUD-03: Replaying an OIDC JWT with a consumed jti must fail with 401"
    );
    assert!(replay_body["error"]
        .as_str()
        .unwrap_or("")
        .contains("replay"));
}
