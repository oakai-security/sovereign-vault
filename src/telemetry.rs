//! Opt-in Enterprise Fleet Telemetry, Real-Time SIEM Audit Log Streaming & JWKS Refresh Workers.
//!
//! **Golden Rule**: Standalone OSS containers are 100% air-gapped by default and NEVER
//! initiate outbound network connections unless explicitly configured:
//! - Fleet Telemetry activates strictly when BOTH `OAKAI_ENTERPRISE_LICENSE` and `OAKAI_TELEMETRY_ENABLED=true` are set.
//! - SIEM Audit Log Streaming activates strictly when `OAKAI_SIEM_WEBHOOK_URL` is set.
//! - OIDC JWKS Refresh activates strictly for OIDC bindings that configure remote `jwks_uri` endpoints.

use crate::oidc::DEFAULT_JWKS_REFRESH_INTERVAL_SECS;
use crate::server::AppState;
use crate::storage::AuditLogEntry;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use zeroize::Zeroizing;

const DEFAULT_TELEMETRY_URL: &str = "https://telemetry.oakai-security.com/v1/ping";
const DEFAULT_INTERVAL_SECS: u64 = 21_600; // 6 hours
const SIEM_CHANNEL_CAPACITY: usize = 1024;

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub license_key: Zeroizing<String>,
    pub cluster_id: String,
    pub endpoint_url: String,
    pub interval: Duration,
}

#[derive(Debug, Clone)]
pub struct SiemForwarderConfig {
    pub webhook_url: String,
    pub bearer_token: Option<Zeroizing<String>>,
    pub cluster_id: String,
}

/// Non-blocking real-time SIEM audit event sender.
#[derive(Clone)]
pub struct SiemForwarder {
    tx: mpsc::Sender<AuditLogEntry>,
}

impl SiemForwarder {
    /// Enqueue a tamper-evident HMAC-SHA512 chained audit event for asynchronous SIEM delivery.
    /// Never blocks the caller (`try_send`).
    pub fn emit(&self, entry: AuditLogEntry) {
        let _ = self.tx.try_send(entry);
    }
}

/// Real-time SIEM webhook envelope containing the cluster identity and the hash-chained audit entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiemAuditPayload {
    pub cluster_id: String,
    pub version: String,
    pub event: AuditLogEntry,
}

/// Privacy-preserving operational heartbeat payload.
/// Contains strictly aggregate counts — NEVER secret names, paths, tokens, or values.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TelemetryPing {
    pub cluster_id: String,
    pub version: String,
    pub initialized: bool,
    pub sealed: bool,
    pub uptime_seconds: u64,
    pub total_secrets_count: u64,
    pub active_tokens_count: u64,
    #[serde(default)]
    pub active_oidc_bindings_count: u64,
    #[serde(default)]
    pub jwks_cached_keys_count: u64,
    #[serde(default)]
    pub audit_seq: u64,
    pub storage_bytes: u64,
}

impl TelemetryConfig {
    /// Inspect environment variables and return `Some(TelemetryConfig)` ONLY if
    /// explicit enterprise opt-in is configured.
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Thread-safe configuration parser accepting any key-value lookup closure.
    pub fn from_lookup<F>(get_var: F) -> Option<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let enabled = get_var("OAKAI_TELEMETRY_ENABLED")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        if !enabled {
            return None;
        }

        let license_key = get_var("OAKAI_ENTERPRISE_LICENSE")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;

        let cluster_id = get_var("OAKAI_CLUSTER_ID")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "cls_unassigned".to_string());

        let endpoint_url = get_var("OAKAI_TELEMETRY_URL")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_TELEMETRY_URL.to_string());

        let interval_secs = get_var("OAKAI_TELEMETRY_INTERVAL_SECS")
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|&s| s >= 5)
            .unwrap_or(DEFAULT_INTERVAL_SECS);

        Some(Self {
            license_key: Zeroizing::new(license_key),
            cluster_id,
            endpoint_url,
            interval: Duration::from_secs(interval_secs),
        })
    }
}

impl SiemForwarderConfig {
    pub fn from_env() -> Option<Self> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup<F>(get_var: F) -> Option<Self>
    where
        F: Fn(&str) -> Option<String>,
    {
        let webhook_url = get_var("OAKAI_SIEM_WEBHOOK_URL")
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())?;
        let bearer_token = get_var("OAKAI_SIEM_BEARER_TOKEN")
            .or_else(|| get_var("OAKAI_ENTERPRISE_LICENSE"))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(Zeroizing::new);
        let cluster_id = get_var("OAKAI_CLUSTER_ID")
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| "cls_unassigned".to_string());

        Some(Self {
            webhook_url,
            bearer_token,
            cluster_id,
        })
    }
}

/// Spawn an asynchronous SIEM audit log forwarder if `SiemForwarderConfig` is present.
pub fn maybe_spawn_siem_forwarder(
    cfg: Option<SiemForwarderConfig>,
) -> Option<(SiemForwarder, tokio::task::JoinHandle<()>)> {
    let cfg = cfg?;
    let (tx, mut rx) = mpsc::channel::<AuditLogEntry>(SIEM_CHANNEL_CAPACITY);

    tracing::info!(
        cluster_id = %cfg.cluster_id,
        webhook_url = %cfg.webhook_url,
        "Enterprise SIEM Audit Forwarder: ENABLED (streaming HMAC-SHA512 hash-chained events)"
    );

    let handle = tokio::spawn(async move {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        while let Some(entry) = rx.recv().await {
            let payload = SiemAuditPayload {
                cluster_id: cfg.cluster_id.clone(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                event: entry,
            };
            let mut req = client.post(&cfg.webhook_url).json(&payload);
            if let Some(tok) = &cfg.bearer_token {
                req = req.bearer_auth(tok.as_str());
            }
            if let Err(e) = req.send().await {
                tracing::debug!("SIEM audit event delivery skipped/failed: {}", e);
            }
        }
    });

    Some((SiemForwarder { tx }, handle))
}

/// Spawn background worker that refreshes OIDC JWKS public keys every 15 minutes (`900s` default).
pub fn spawn_oidc_jwks_refresh_worker(
    state: Arc<AppState>,
    interval: Duration,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(15)));
        loop {
            ticker.tick().await;
            let bindings = {
                let active_guard = state.active.read().await;
                let Some(active) = active_guard.as_ref() else {
                    continue;
                };
                let Ok(db) = active.storage.lock() else {
                    continue;
                };
                db.list_oidc_bindings().unwrap_or_default()
            };
            if !bindings.is_empty() {
                let _ = state.oidc_cache.refresh_bindings(&bindings).await;
            }
        }
    })
}

/// Build a privacy-preserving telemetry snapshot from current `AppState`.
pub async fn build_telemetry_ping(state: &AppState, cluster_id: &str) -> TelemetryPing {
    let initialized = crate::storage::is_vault_initialized(&state.data_dir);
    let uptime_seconds = state.started_at.elapsed().as_secs();
    let jwks_cached_keys_count = state.oidc_cache.total_cached_keys() as u64;

    let active_guard = state.active.read().await;
    match active_guard.as_ref() {
        Some(active) => {
            let (counts, oidc_count, audit_seq) = active
                .storage
                .lock()
                .ok()
                .map(|db| {
                    let c = db.operational_counts().unwrap_or((0, 0, 0));
                    let o = db.count_oidc_bindings().unwrap_or(0);
                    let a = db.latest_audit_seq().unwrap_or(0);
                    (c, o, a)
                })
                .unwrap_or(((0, 0, 0), 0, 0));
            TelemetryPing {
                cluster_id: cluster_id.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                initialized,
                sealed: false,
                uptime_seconds,
                total_secrets_count: counts.0,
                active_tokens_count: counts.1,
                active_oidc_bindings_count: oidc_count,
                jwks_cached_keys_count,
                audit_seq,
                storage_bytes: counts.2,
            }
        }
        None => TelemetryPing {
            cluster_id: cluster_id.to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            initialized,
            sealed: true,
            uptime_seconds,
            total_secrets_count: 0,
            active_tokens_count: 0,
            active_oidc_bindings_count: 0,
            jwks_cached_keys_count,
            audit_seq: 0,
            storage_bytes: 0,
        },
    }
}

/// Spawn background telemetry worker ONLY when `TelemetryConfig::from_env()` is `Some`.
pub fn maybe_spawn_telemetry_worker(
    state: Arc<AppState>,
    cfg: Option<TelemetryConfig>,
) -> Option<tokio::task::JoinHandle<()>> {
    let cfg = match cfg {
        Some(c) => c,
        None => {
            tracing::info!(
                "Enterprise telemetry: DISABLED (standalone air-gapped mode — zero outbound connections)"
            );
            return None;
        }
    };

    tracing::info!(
        cluster_id = %cfg.cluster_id,
        endpoint = %cfg.endpoint_url,
        interval_secs = cfg.interval.as_secs(),
        "Enterprise telemetry: ENABLED (privacy-preserving operational counts only)"
    );

    let handle = tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Failed to initialize enterprise telemetry HTTP client: {}", e);
                return;
            }
        };

        let mut ticker = tokio::time::interval(cfg.interval);
        loop {
            ticker.tick().await;
            let payload = build_telemetry_ping(&state, &cfg.cluster_id).await;
            if let Err(err) = client
                .post(&cfg.endpoint_url)
                .bearer_auth(cfg.license_key.as_str())
                .json(&payload)
                .send()
                .await
            {
                tracing::debug!("Enterprise telemetry ping skipped/failed: {}", err);
            }
        }
    });

    Some(handle)
}

/// Resolve OIDC JWKS background refresh interval from `VAULT_OIDC_REFRESH_SECS` (defaults to 900s / 15m).
pub fn resolve_oidc_refresh_interval() -> Duration {
    let secs = std::env::var("VAULT_OIDC_REFRESH_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|&s| s >= 15)
        .unwrap_or(DEFAULT_JWKS_REFRESH_INTERVAL_SECS);
    Duration::from_secs(secs)
}
