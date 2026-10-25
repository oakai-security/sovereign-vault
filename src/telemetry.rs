//! Opt-in Enterprise Fleet Telemetry.
//!
//! **Golden Rule**: Standalone OSS containers are 100% air-gapped by default and NEVER
//! initiate outbound network connections. Telemetry activates strictly when BOTH
//! `OAKAI_ENTERPRISE_LICENSE` (non-empty) and `OAKAI_TELEMETRY_ENABLED=true` are set.

use crate::server::AppState;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::Duration;

const DEFAULT_TELEMETRY_URL: &str = "https://telemetry.oakai-security.com/v1/ping";
const DEFAULT_INTERVAL_SECS: u64 = 21_600; // 6 hours

#[derive(Debug, Clone)]
pub struct TelemetryConfig {
    pub license_key: String,
    pub cluster_id: String,
    pub endpoint_url: String,
    pub interval: Duration,
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
            license_key,
            cluster_id,
            endpoint_url,
            interval: Duration::from_secs(interval_secs),
        })
    }
}

/// Build a privacy-preserving telemetry snapshot from current `AppState`.
pub async fn build_telemetry_ping(state: &AppState, cluster_id: &str) -> TelemetryPing {
    let initialized = crate::storage::is_vault_initialized(&state.data_dir);
    let uptime_seconds = state.started_at.elapsed().as_secs();

    let active_guard = state.active.read().await;
    match active_guard.as_ref() {
        Some(active) => {
            let counts = active
                .storage
                .lock()
                .ok()
                .and_then(|db| db.operational_counts().ok())
                .unwrap_or((0, 0, 0));
            TelemetryPing {
                cluster_id: cluster_id.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                initialized,
                sealed: false,
                uptime_seconds,
                total_secrets_count: counts.0,
                active_tokens_count: counts.1,
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
                .bearer_auth(&cfg.license_key)
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
