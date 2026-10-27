//! Integration test suite verifying Sovereign Vault v0.2 cryptographic, authentication,
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

    // 9. Revoking the OIDC binding immediately invalidates the JWT (`401 Unauthorized`)
    let (del_oid_st, _) = send_json(
        &app,
        Method::DELETE,
        &format!("/v1/sys/oidc/bindings/{binding_id}"),
        &[("X-Vault-Token", &admin_token)],
        None,
    )
    .await;
    assert_eq!(del_oid_st, StatusCode::NO_CONTENT);

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

    // 1. Generate autonomous self-signed certificate for localhost/127.0.0.1
    let (cert_pem, key_pem, fp) = sovereign_vault::crypto::generate_self_signed_tls_cert(&[
        "localhost".to_string(),
        "127.0.0.1".to_string(),
    ])
    .expect("generate test tls cert");
    assert_eq!(fp.split(':').count(), 32);

    let rustls_config = axum_server::tls_rustls::RustlsConfig::from_pem(
        cert_pem.as_bytes().to_vec(),
        key_pem.as_bytes().to_vec(),
    )
    .await
    .expect("load rustls config");

    // 2. Bind to an ephemeral port on 127.0.0.1
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("get local addr");
    drop(listener); // Free for axum-server

    let server_handle = tokio::spawn(async move {
        let _ = axum_server::bind_rustls(addr, rustls_config)
            .serve(app.into_make_service())
            .await;
    });

    // Wait briefly for server startup
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;

    // 3. Client connecting with CA cert verification succeeds
    let root_cert = reqwest::Certificate::from_pem(cert_pem.as_bytes()).expect("parse root cert");
    let trusted_client = reqwest::Client::builder()
        .add_root_certificate(root_cert)
        .build()
        .expect("build client");

    let resp = trusted_client
        .get(format!("https://localhost:{}/v1/sys/health", addr.port()))
        .send()
        .await
        .expect("https request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // 4. Client connecting with -k / danger_accept_invalid_certs succeeds
    let insecure_client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .expect("build insecure client");

    let resp2 = insecure_client
        .get(format!("https://127.0.0.1:{}/v1/sys/health", addr.port()))
        .send()
        .await
        .expect("https request");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);

    // 5. Plain HTTP request to TLS port is rejected / fails handshake
    let plain_client = reqwest::Client::new();
    let plain_fail = plain_client
        .get(format!("http://127.0.0.1:{}/v1/sys/health", addr.port()))
        .send()
        .await;
    assert!(plain_fail.is_err(), "Cleartext HTTP to TLS port must fail");

    server_handle.abort();
}
