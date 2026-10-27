//! Sovereign Vault v1.0: Single-binary Micro-KMS Daemon, Universal OIDC Broker, and Zero-History CLI.
//!
//! All sensitive CLI inputs (bootstrap nonces, unseal keys, machine tokens, OIDC JWTs, and secret values)
//! are collected exclusively via hidden `/dev/tty` prompts (`rpassword`), `--stdin` pipes, or `0600`
//! projected files so pasted credentials NEVER enter `~/.bash_history` or `ps aux` process arguments.

#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::explicit_counter_loop,
    clippy::result_unit_err,
    clippy::manual_is_multiple_of,
    clippy::large_enum_variant
)]

use clap::{Parser, Subcommand};
use rand::RngCore;
use sovereign_vault::{
    crypto::{
        compute_pem_fingerprint, generate_self_signed_tls_cert, hex_encode, lock_process_memory,
    },
    server::{
        self, AppState, AuditLogResponse, EnrollOidcBindingResponse, EnrollTokenResponse,
        HealthResponse, ListOidcBindingsResponse, ListSecretsResponse, ListTokensResponse,
        RefreshOidcResponse, SecretResponse,
    },
    storage::{is_vault_initialized, BackupMetadata},
    telemetry::{
        maybe_spawn_siem_forwarder, maybe_spawn_telemetry_worker, resolve_oidc_refresh_interval,
        spawn_oidc_jwks_refresh_worker, SiemForwarderConfig, TelemetryConfig,
    },
};
use std::io::Read;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "sovereign-vault")]
#[command(author = "Oakai Security <security@oakai-security.com>")]
#[command(version)]
#[command(
    about = "Sovereign Micro-KMS: Zero-account, SQLCipher-encrypted secrets container & history-safe CLI"
)]
struct Cli {
    /// Skip TLS certificate verification (insecure; for local self-signed dev/testing)
    #[arg(short = 'k', long, global = true)]
    insecure: bool,

    /// Path to a custom CA certificate PEM to trust when verifying daemon TLS
    #[arg(long, global = true)]
    ca_cert: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Sovereign Vault Micro-KMS daemon (defaults to native TLS 1.3)
    Daemon {
        #[arg(long, default_value = "/data")]
        data_dir: PathBuf,

        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: String,

        /// Path to custom X.509 certificate PEM (or env SOVEREIGN_VAULT_TLS_CERT). If omitted, an autonomous self-signed ECDSA certificate is generated.
        #[arg(long, env = "SOVEREIGN_VAULT_TLS_CERT")]
        tls_cert: Option<PathBuf>,

        /// Path to custom PKCS#8 or SEC1 private key PEM (or env SOVEREIGN_VAULT_TLS_KEY)
        #[arg(long, env = "SOVEREIGN_VAULT_TLS_KEY")]
        tls_key: Option<PathBuf>,

        /// Comma-separated Subject Alternative Names (DNS names or IP addresses) for auto-generated self-signed cert
        #[arg(long, env = "SOVEREIGN_VAULT_TLS_SANS")]
        tls_sans: Option<String>,

        /// Fall back to unencrypted cleartext HTTP (INSECURE: only for debugging or loopback legacy testing)
        #[arg(long, env = "SOVEREIGN_VAULT_INSECURE_HTTP")]
        insecure_http: bool,
    },

    /// Query daemon initialization, seal, and RAM-lock status
    Status {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,
    },

    /// Initialize a fresh vault (prompts hidden TTY for bootstrap nonce; never exposes args in history)
    Init {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Read bootstrap nonce from stdin instead of interactive hidden TTY prompt
        #[arg(long)]
        nonce_stdin: bool,
    },

    /// Unseal the vault (prompts hidden TTY for unseal key or reads --stdin; no --key CLI flag exists)
    Unseal {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Read 64-hex unseal key from stdin (e.g., piped from Ubuntu Secret Service)
        #[arg(long)]
        stdin: bool,
    },

    /// Seal the vault immediately and scrub RAM keys (requires admin token)
    Seal {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Read admin token from stdin instead of hidden TTY prompt
        #[arg(long)]
        token_stdin: bool,
    },

    /// Create an online encrypted SQLCipher snapshot backup (requires admin token)
    Backup {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        token_stdin: bool,
    },

    /// Inspect and cryptographically verify the HMAC-SHA512 hash-chained audit log (requires admin token)
    Audit {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long, default_value_t = 50)]
        limit: usize,

        #[arg(long)]
        token_stdin: bool,
    },

    /// Fetch secrets in memory and inject them as environment variables into a child process (zero .env files)
    Run {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Mapping in `ENV_VAR=secret/path` format (repeatable)
        #[arg(long = "map", required = true)]
        mappings: Vec<String>,

        #[arg(long)]
        token_stdin: bool,

        /// Optional path to a file containing the caller's machine token or projected OIDC JWT
        #[arg(long)]
        token_file: Option<PathBuf>,

        /// Child command and arguments after `--`
        #[arg(last = true, required = true)]
        cmd: Vec<String>,
    },

    /// Fetch secrets using a machine token or OIDC JWT and write a `0600` `.env` file (e.g., to in-memory `/secrets/.env` tmpfs in an init-container)
    Export {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Mapping in `ENV_VAR=secret/path` format (repeatable)
        #[arg(long = "map", required = true)]
        mappings: Vec<String>,

        /// Destination file path (recommended: in-memory tmpfs `/secrets/.env`; written with `0600` permissions)
        #[arg(long, default_value = "/secrets/.env")]
        output: PathBuf,

        #[arg(long)]
        token_stdin: bool,

        /// Optional path to a file containing the caller's machine token or projected OIDC JWT
        #[arg(long)]
        token_file: Option<PathBuf>,
    },

    /// Query operational fleet metrics (JSON or Prometheus text exposition format; requires admin token)
    Metrics {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Output Prometheus text exposition format instead of JSON
        #[arg(long)]
        prometheus: bool,

        #[arg(long)]
        token_stdin: bool,
    },

    /// Enroll, list, or revoke SHA-512 path-scoped machine tokens
    Token {
        #[command(subcommand)]
        action: TokenCommands,
    },

    /// Enroll, list, revoke, or refresh OpenID Connect (OIDC) JWT workload trust bindings
    Oidc {
        #[command(subcommand)]
        action: OidcCommands,
    },

    /// Read, write, list, or delete encrypted secrets
    Secret {
        #[command(subcommand)]
        action: SecretCommands,
    },

    /// Poll vault health and auto-unseal via external keyring command when sealed
    Watcher {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Poll interval in seconds
        #[arg(long, default_value_t = 10)]
        interval_secs: u64,

        /// Shell command whose stdout outputs the 64-hex unseal key (e.g. python3 -m keyring get sovereign-vault unseal-key)
        #[arg(
            long,
            default_value = "python3 -m keyring get sovereign-vault unseal-key"
        )]
        key_cmd: String,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Mint a new path-scoped machine token (requires admin token)
    Enroll {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        project: String,

        #[arg(long)]
        name: String,

        /// Allowed path pattern(s), e.g. `apps/jellyfin/*` (repeatable)
        #[arg(long = "path", required = true)]
        paths: Vec<String>,

        /// Capability (`read`, `write`, `delete`, `admin`; repeatable)
        #[arg(long = "cap", default_value = "read")]
        caps: Vec<String>,

        /// Optional time-to-live in seconds
        #[arg(long)]
        ttl_seconds: Option<u64>,

        /// Read admin token from stdin instead of hidden TTY prompt
        #[arg(long)]
        token_stdin: bool,

        /// Optional `0600` file path to write the minted token directly without printing to stdout
        #[arg(long)]
        output_file: Option<PathBuf>,
    },

    /// List enrolled machine token metadata (admin-only; never exposes raw tokens or hashes)
    List {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        token_stdin: bool,
    },

    /// Immediately revoke an enrolled machine token by ID (`tok_...`)
    Revoke {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        token_id: String,

        #[arg(long)]
        token_stdin: bool,
    },
}

#[derive(Subcommand)]
enum OidcCommands {
    /// Enroll an OIDC trust binding using a built-in provider preset (`github`, `gitlab`, `google`, `azure`, `kubernetes`, `authelia`, `dex`, `custom`)
    Enroll {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Provider preset (`github`, `gitlab`, `google`, `azure`, `kubernetes`, `authelia`, `dex`, `custom`)
        #[arg(long, default_value = "custom")]
        preset: String,

        #[arg(long)]
        project: String,

        #[arg(long)]
        name: String,

        /// Optional OIDC issuer URL (auto-populated for `github`, `gitlab`, `google`, `kubernetes`)
        #[arg(long)]
        issuer: Option<String>,

        /// Optional tenant ID (used by `--preset azure` to build the Entra ID v2.0 issuer URL)
        #[arg(long)]
        tenant_id: Option<String>,

        /// Required JWT audience (`aud`) claim
        #[arg(long, default_value = "sovereign-vault")]
        audience: String,

        /// JWT claim name to match against `--subject-pattern` (default: `sub`)
        #[arg(long)]
        subject_claim: Option<String>,

        /// Glob pattern for the JWT subject claim (e.g. `repo:org/app:ref:refs/heads/main` or `system:serviceaccount:prod:api`)
        #[arg(long, default_value = "*")]
        subject_pattern: String,

        /// Allowed secret path pattern(s), e.g. `apps/jellyfin/*` (repeatable)
        #[arg(long = "path", required = true)]
        paths: Vec<String>,

        /// Capability (`read`, `write`, `delete`, `admin`; repeatable)
        #[arg(long = "cap", default_value = "read")]
        caps: Vec<String>,

        /// Optional explicit JWKS URI override
        #[arg(long)]
        jwks_uri: Option<String>,

        /// Optional path to a static JWKS JSON file (for air-gapped / local homelab issuers without remote HTTPS discovery)
        #[arg(long)]
        inline_jwks_file: Option<PathBuf>,

        #[arg(long)]
        token_stdin: bool,
    },

    /// List enrolled OIDC workload trust bindings (admin-only)
    List {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        token_stdin: bool,
    },

    /// Revoke an enrolled OIDC trust binding by ID (`oidc_...`) and immediately purge its cached JWKS keys
    Revoke {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        binding_id: String,

        #[arg(long)]
        token_stdin: bool,
    },

    /// Trigger an immediate ad-hoc refresh of the in-memory OIDC JWKS public key cache (admin-only)
    Refresh {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        token_stdin: bool,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Encrypt and persist a secret (reads secret value from hidden TTY or --value-stdin)
    Put {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        /// Canonical secret path (e.g. `apps/jellyfin/db_password`)
        path: String,

        #[arg(long)]
        project: String,

        /// Read secret value from stdin (use `VAULT_TOKEN`, `--token-file`, or `VAULT_TOKEN_FILE` for headless auth)
        #[arg(long)]
        value_stdin: bool,

        /// Optional path to a `0600` file containing the caller's machine token (for headless `--value-stdin` pipelines)
        #[arg(long)]
        token_file: Option<PathBuf>,
    },

    /// Retrieve and decrypt a secret
    Get {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        path: String,

        /// Optional historical version number (`1..=N`); defaults to latest active version
        #[arg(long)]
        version: Option<i64>,

        #[arg(long)]
        token_stdin: bool,

        /// Print raw value only (suitable for piping)
        #[arg(long)]
        raw: bool,
    },

    /// List secret paths & versions visible to the caller's token (never exposes values)
    List {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        prefix: Option<String>,

        #[arg(long)]
        token_stdin: bool,
    },

    /// Delete a secret path
    Delete {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        url: String,

        path: String,

        #[arg(long)]
        token_stdin: bool,
    },
}

/// Validate that the target Vault URL uses `https://` or targets a local loopback interface (`127.0.0.1`, `localhost`, `[::1]`).
/// Refuses transmitting unseal keys, tokens, or secrets over remote cleartext `http://` unless `VAULT_ALLOW_INSECURE_HTTP=true`.
fn validate_transport_url(raw_url: &str) -> Result<String, String> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    if trimmed.starts_with("https://") {
        return Ok(trimmed.to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("http://") {
        let host_port = rest.split('/').next().unwrap_or("");
        let is_loopback = host_port.starts_with("127.")
            || host_port == "localhost"
            || host_port.starts_with("localhost:")
            || host_port.starts_with("[::1]");
        let allow_insecure = std::env::var("VAULT_ALLOW_INSECURE_HTTP")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);
        if is_loopback || allow_insecure {
            return Ok(trimmed.to_string());
        }
        return Err(format!(
            "Refusing to transmit credentials over remote cleartext HTTP ('{trimmed}'). Target must use https:// (native TLS 1.3 enabled by default) or set VAULT_ALLOW_INSECURE_HTTP=true for unencrypted loopback testing."
        ));
    }
    Err(format!(
        "Unsupported URL scheme in '{trimmed}' (expected https:// or http://127.0.0.1:8443)"
    ))
}

fn build_http_client(
    insecure: bool,
    ca_cert: Option<&PathBuf>,
    timeout: Option<Duration>,
) -> Result<reqwest::Client, String> {
    let mut builder = reqwest::Client::builder();
    if insecure {
        builder = builder.danger_accept_invalid_certs(true);
    }
    if let Some(ca_path) = ca_cert {
        let ca_bytes = std::fs::read(ca_path)
            .map_err(|e| format!("Failed reading CA certificate at {ca_path:?}: {e}"))?;
        let cert = reqwest::Certificate::from_pem(&ca_bytes)
            .map_err(|e| format!("Failed parsing CA certificate at {ca_path:?}: {e}"))?;
        builder = builder.add_root_certificate(cert);
    }
    if let Some(t) = timeout {
        builder = builder.timeout(t);
    }
    builder
        .build()
        .map_err(|e| format!("Failed constructing HTTP client: {e}"))
}

async fn resolve_tls_config(
    data_dir: &std::path::Path,
    custom_cert: Option<PathBuf>,
    custom_key: Option<PathBuf>,
    custom_sans: Option<String>,
) -> Result<axum_server::tls_rustls::RustlsConfig, Box<dyn std::error::Error>> {
    let (cert_bytes, key_bytes, fp) = match (custom_cert, custom_key) {
        (Some(cert_path), Some(key_path)) => {
            tracing::info!(
                "Loading custom TLS certificate from {:?} and private key from {:?}",
                cert_path,
                key_path
            );
            let c_bytes = tokio::fs::read(&cert_path).await?;
            let k_bytes = tokio::fs::read(&key_path).await?;
            let pem_str = String::from_utf8_lossy(&c_bytes);
            let fp = compute_pem_fingerprint(&pem_str)
                .unwrap_or_else(|| "UNKNOWN (could not parse PEM DER)".to_string());
            (c_bytes, k_bytes, fp)
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err("Both --tls-cert and --tls-key must be provided together.".into());
        }
        (None, None) => {
            let tls_dir = data_dir.join("tls");
            tokio::fs::create_dir_all(&tls_dir).await?;
            let cert_file = tls_dir.join("cert.pem");
            let key_file = tls_dir.join("key.pem");

            if cert_file.exists() && key_file.exists() {
                tracing::info!(
                    "Reusing existing self-signed TLS credentials in {:?}",
                    tls_dir
                );
                let c_bytes = tokio::fs::read(&cert_file).await?;
                let k_bytes = tokio::fs::read(&key_file).await?;
                let pem_str = String::from_utf8_lossy(&c_bytes);
                let fp = compute_pem_fingerprint(&pem_str).unwrap_or_else(|| "UNKNOWN".to_string());
                (c_bytes, k_bytes, fp)
            } else {
                tracing::info!(
                    "Generating autonomous zero-config self-signed ECDSA TLS certificate..."
                );
                let mut sans: Vec<String> = vec![
                    "localhost".to_string(),
                    "127.0.0.1".to_string(),
                    "::1".to_string(),
                ];
                if let Some(extra_sans) = custom_sans {
                    for s in extra_sans.split(',') {
                        let trimmed = s.trim();
                        if !trimmed.is_empty() && !sans.iter().any(|x| x == trimmed) {
                            sans.push(trimmed.to_string());
                        }
                    }
                }
                let (cert_pem, key_pem, fp) = generate_self_signed_tls_cert(&sans)
                    .map_err(|e| format!("Failed generating self-signed TLS cert: {e}"))?;
                tokio::fs::write(&cert_file, &cert_pem).await?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut opts = std::fs::OpenOptions::new();
                    opts.write(true).create(true).truncate(true).mode(0o600);
                    use std::io::Write;
                    let mut f = opts.open(&key_file)?;
                    f.write_all(key_pem.as_bytes())?;
                }
                #[cfg(not(unix))]
                {
                    tokio::fs::write(&key_file, &key_pem).await?;
                }

                (cert_pem.into_bytes(), key_pem.into_bytes(), fp)
            }
        }
    };

    tracing::info!(
        "================================================================================"
    );
    tracing::info!("TLS 1.3 ACTIVE: Encrypted in transit by default (NIC-to-NIC wire encryption)");
    tracing::info!("Certificate SHA-256 Fingerprint: {}", fp);
    tracing::info!(
        "================================================================================"
    );

    let config = axum_server::tls_rustls::RustlsConfig::from_pem(cert_bytes, key_bytes).await?;
    Ok(config)
}

fn read_secret_input(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>, String> {
    if from_stdin {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed reading secret from stdin: {e}"))?;
        let trimmed = Zeroizing::new(buf.trim().to_string());
        if trimmed.is_empty() {
            return Err("Received empty secret on stdin".to_string());
        }
        Ok(trimmed)
    } else {
        let val = Zeroizing::new(rpassword::prompt_password(prompt).map_err(|e| {
            format!("Hidden TTY prompt failed (use --stdin for non-interactive pipes): {e}")
        })?);
        let trimmed = Zeroizing::new(val.trim().to_string());
        if trimmed.is_empty() {
            return Err("Empty input aborted".to_string());
        }
        Ok(trimmed)
    }
}

/// Read a secret payload value without stripping intentional leading/trailing spaces or internal multiline newlines (`FM-17`).
fn read_secret_value_input(prompt: &str, from_stdin: bool) -> Result<Zeroizing<String>, String> {
    if from_stdin {
        let mut buf = Zeroizing::new(String::new());
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("Failed reading secret value from stdin: {e}"))?;
        let cleaned = Zeroizing::new(buf.trim_end_matches(&['\r', '\n'][..]).to_string());
        if cleaned.trim().is_empty() {
            return Err("Received empty secret value on stdin".to_string());
        }
        Ok(cleaned)
    } else {
        let val = Zeroizing::new(rpassword::prompt_password(prompt).map_err(|e| {
            format!("Hidden TTY prompt failed (use --value-stdin for non-interactive pipes): {e}")
        })?);
        let cleaned = Zeroizing::new(val.trim_end_matches(&['\r', '\n'][..]).to_string());
        if cleaned.trim().is_empty() {
            return Err("Empty secret value aborted".to_string());
        }
        Ok(cleaned)
    }
}

fn resolve_caller_token(from_stdin: bool) -> Result<Zeroizing<String>, String> {
    resolve_caller_token_with_file(from_stdin, None)
}

fn resolve_caller_token_with_file(
    from_stdin: bool,
    token_file: Option<&PathBuf>,
) -> Result<Zeroizing<String>, String> {
    if from_stdin {
        return read_secret_input("", true);
    }
    if let Some(path) = token_file {
        let raw = Zeroizing::new(
            std::fs::read_to_string(path)
                .map_err(|e| format!("Failed reading token file {:?}: {e}", path))?,
        );
        let t = Zeroizing::new(raw.trim().to_string());
        if !t.is_empty() {
            return Ok(t);
        }
    }
    if let Ok(file_env) = std::env::var("VAULT_TOKEN_FILE") {
        let p = PathBuf::from(file_env.trim());
        if p.is_file() {
            let raw = Zeroizing::new(
                std::fs::read_to_string(&p)
                    .map_err(|e| format!("Failed reading VAULT_TOKEN_FILE {:?}: {e}", p))?,
            );
            let t = Zeroizing::new(raw.trim().to_string());
            if !t.is_empty() {
                return Ok(t);
            }
        }
    }
    if let Ok(env_tok) = std::env::var("VAULT_TOKEN") {
        let t = Zeroizing::new(env_tok.trim().to_string());
        if !t.is_empty() {
            return Ok(t);
        }
    }
    read_secret_input("Paste Vault Token (hidden): ", false)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Install Ring crypto provider for rustls
    let _ = rustls::crypto::ring::default_provider().install_default();

    // Disable process tracing / core dumps immediately on startup
    #[cfg(unix)]
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0);
        libc::umask(0o077);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon {
            data_dir,
            bind,
            tls_cert,
            tls_key,
            tls_sans,
            insecure_http,
        } => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();

            std::fs::create_dir_all(&data_dir)?;
            if lock_process_memory() {
                tracing::info!(
                    "Process address space pinned via mlockall(MCL_CURRENT | MCL_FUTURE)."
                );
            }
            let is_init = is_vault_initialized(&data_dir);

            let bootstrap_nonce = if !is_init {
                let mut nonce_bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let n = format!("init_{}", hex_encode(nonce_bytes));
                tracing::warn!(
                    "================================================================================"
                );
                tracing::warn!(
                    "VAULT UNINITIALIZED: Use this single-use ephemeral bootstrap nonce to initialize:"
                );
                tracing::warn!("Nonce: {}", n);
                tracing::warn!(
                    "================================================================================"
                );
                Some(n)
            } else {
                tracing::info!("Encrypted SQLCipher vault detected. Starting in SEALED mode.");
                None
            };

            let telemetry_cfg = TelemetryConfig::from_env();
            let siem_forwarder = maybe_spawn_siem_forwarder(SiemForwarderConfig::from_env())
                .map(|(fwd, _handle)| fwd);
            let state = Arc::new(
                AppState::new(data_dir.clone(), bootstrap_nonce, telemetry_cfg.is_some())
                    .with_siem_forwarder(siem_forwarder),
            );

            let _telemetry_handle = maybe_spawn_telemetry_worker(state.clone(), telemetry_cfg);
            let _oidc_refresh_handle =
                spawn_oidc_jwks_refresh_worker(state.clone(), resolve_oidc_refresh_interval());

            let app = server::create_router(state);
            let addr: std::net::SocketAddr = bind.parse().map_err(|e| {
                format!("Failed parsing bind address '{bind}' (expected IP:PORT): {e}")
            })?;

            if insecure_http {
                tracing::warn!(
                    "================================================================================"
                );
                tracing::warn!(
                    "INSECURE HTTP MODE ENABLED: Wire encryption is DISABLED on {bind}."
                );
                tracing::warn!(
                    "Do NOT use insecure cleartext HTTP across untrusted network interfaces!"
                );
                tracing::warn!(
                    "================================================================================"
                );
                let listener = tokio::net::TcpListener::bind(addr).await?;
                axum::serve(listener, app).await?;
            } else {
                let rustls_config =
                    resolve_tls_config(&data_dir, tls_cert, tls_key, tls_sans).await?;
                tracing::info!(
                    "Sovereign Vault v{} listening on https://{} (Native Rustls TLS 1.3)",
                    env!("CARGO_PKG_VERSION"),
                    bind
                );
                axum_server::bind_rustls(addr, rustls_config)
                    .serve(app.into_make_service())
                    .await?;
            }
        }

        Commands::Status { url } => {
            let base = validate_transport_url(&url)?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
            let resp: HealthResponse = client
                .get(format!("{base}/v1/sys/health"))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Init { url, nonce_stdin } => {
            let base = validate_transport_url(&url)?;
            let nonce = read_secret_input("Paste Bootstrap Nonce (hidden): ", nonce_stdin)?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
            let resp = client
                .post(format!("{base}/v1/sys/init"))
                .header("X-Vault-Bootstrap-Nonce", nonce.as_str())
                .send()
                .await?;
            let status = resp.status();
            let body: serde_json::Value = resp.json().await?;
            if !status.is_success() {
                eprintln!("Init failed ({status}): {}", body);
                std::process::exit(1);
            }
            println!("{}", serde_json::to_string_pretty(&body)?);
        }

        Commands::Unseal { url, stdin } => {
            let base = validate_transport_url(&url)?;
            let key = read_secret_input("Paste 64-hex Unseal Key (hidden): ", stdin)?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
            let resp = client
                .post(format!("{base}/v1/sys/unseal"))
                .json(&serde_json::json!({ "unseal_key": key.as_str() }))
                .send()
                .await?;
            let status = resp.status();
            let body: serde_json::Value = resp.json().await?;
            if !status.is_success() {
                eprintln!("Unseal failed ({status}): {}", body);
                std::process::exit(1);
            }
            println!("{}", serde_json::to_string_pretty(&body)?);
        }

        Commands::Seal { url, token_stdin } => {
            let base = validate_transport_url(&url)?;
            let tok = resolve_caller_token(token_stdin)?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
            let resp = client
                .post(format!("{base}/v1/sys/seal"))
                .header("X-Vault-Token", tok.as_str())
                .send()
                .await?;
            let status = resp.status();
            let body: serde_json::Value = resp.json().await?;
            if !status.is_success() {
                eprintln!("Seal failed ({status}): {}", body);
                std::process::exit(1);
            }
            println!("{}", serde_json::to_string_pretty(&body)?);
        }

        Commands::Backup { url, token_stdin } => {
            let base = validate_transport_url(&url)?;
            let tok = resolve_caller_token(token_stdin)?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
            let resp = client
                .post(format!("{base}/v1/sys/backup"))
                .header("X-Vault-Token", tok.as_str())
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let err_body: serde_json::Value = resp.json().await?;
                eprintln!("Backup failed ({status}): {}", err_body);
                std::process::exit(1);
            }
            let meta: BackupMetadata = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&meta)?);
        }

        Commands::Audit {
            url,
            limit,
            token_stdin,
        } => {
            let base = validate_transport_url(&url)?;
            let tok = resolve_caller_token(token_stdin)?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
            let resp = client
                .get(format!("{base}/v1/sys/audit?limit={limit}"))
                .header("X-Vault-Token", tok.as_str())
                .send()
                .await?;
            if !resp.status().is_success() {
                let status = resp.status();
                let err_body: serde_json::Value = resp.json().await?;
                eprintln!("Audit query failed ({status}): {}", err_body);
                std::process::exit(1);
            }
            let report: AuditLogResponse = resp.json().await?;
            println!("{}", serde_json::to_string_pretty(&report)?);
            if !report.chain_verified {
                eprintln!("CRITICAL: Audit HMAC-SHA512 hash chain verification FAILED!");
                std::process::exit(2);
            }
        }

        Commands::Run {
            url,
            mappings,
            token_stdin,
            token_file,
            cmd,
        } => {
            let base = validate_transport_url(&url)?;
            let tok = resolve_caller_token_with_file(token_stdin, token_file.as_ref())?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;

            let mut resolved_envs: Vec<(String, Zeroizing<String>)> =
                Vec::with_capacity(mappings.len());
            for item in &mappings {
                let (env_key, secret_path) = item.split_once('=').ok_or_else(|| {
                    format!("Invalid --map '{item}': expected ENV_VAR=secret/path")
                })?;
                if env_key.trim().is_empty() {
                    return Err("Environment variable name in --map cannot be empty".into());
                }
                let resp = client
                    .get(format!(
                        "{base}/v1/secret/{}",
                        secret_path.trim_start_matches('/')
                    ))
                    .header("X-Vault-Token", tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("Failed fetching '{secret_path}' ({status}): {err_body}");
                    std::process::exit(1);
                }
                let sec: SecretResponse = resp.json().await?;
                resolved_envs.push((
                    env_key.trim().to_string(),
                    Zeroizing::new(sec.value.clone()),
                ));
            }
            drop(tok);

            let mut child_cmd = Command::new(&cmd[0]);
            if cmd.len() > 1 {
                child_cmd.args(&cmd[1..]);
            }
            // Scrub VAULT_TOKEN and VAULT_TOKEN_FILE from child environment unless explicitly mapped
            child_cmd.env_remove("VAULT_TOKEN");
            child_cmd.env_remove("VAULT_TOKEN_FILE");
            for (k, v) in &resolved_envs {
                child_cmd.env(k, v.as_str());
            }

            let mut child = child_cmd.spawn()?;
            // Scrub parent secret buffers immediately while child executes
            drop(resolved_envs);

            let status = child.wait()?;
            std::process::exit(status.code().unwrap_or(1));
        }

        Commands::Export {
            url,
            mappings,
            output,
            token_stdin,
            token_file,
        } => {
            let base = validate_transport_url(&url)?;
            let tok = resolve_caller_token_with_file(token_stdin, token_file.as_ref())?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;

            let mut dotenv_buf = Zeroizing::new(String::new());
            for item in &mappings {
                let (env_key, secret_path) = item.split_once('=').ok_or_else(|| {
                    format!("Invalid --map '{item}': expected ENV_VAR=secret/path")
                })?;
                let key_trimmed = env_key.trim();
                if key_trimmed.is_empty() {
                    return Err("Environment variable name in --map cannot be empty".into());
                }
                let resp = client
                    .get(format!(
                        "{base}/v1/secret/{}",
                        secret_path.trim_start_matches('/')
                    ))
                    .header("X-Vault-Token", tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("Failed fetching '{secret_path}' ({status}): {err_body}");
                    std::process::exit(1);
                }
                let sec: SecretResponse = resp.json().await?;
                let escaped_val = sec
                    .value
                    .replace('\\', "\\\\")
                    .replace('"', "\\\"")
                    .replace('\n', "\\n");
                dotenv_buf.push_str(&format!("{key_trimmed}=\"{escaped_val}\"\n"));
            }
            drop(tok);

            if let Some(parent) = output.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            std::fs::write(&output, dotenv_buf.as_bytes())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&output, std::fs::Permissions::from_mode(0o600))?;
            }
            println!(
                "Exported {} secret(s) securely (0600) to {:?}",
                mappings.len(),
                output
            );
        }

        Commands::Metrics {
            url,
            prometheus,
            token_stdin,
        } => {
            let base = validate_transport_url(&url)?;
            let tok = resolve_caller_token(token_stdin)?;
            let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
            let endpoint = if prometheus {
                format!("{base}/v1/sys/metrics?format=prometheus")
            } else {
                format!("{base}/v1/sys/metrics")
            };
            let resp = client
                .get(endpoint)
                .header("X-Vault-Token", tok.as_str())
                .send()
                .await?
                .error_for_status()?;
            let text = resp.text().await?;
            print!("{text}");
            if !text.ends_with('\n') {
                println!();
            }
        }

        Commands::Token { action } => match action {
            TokenCommands::Enroll {
                url,
                project,
                name,
                paths,
                caps,
                ttl_seconds,
                token_stdin,
                output_file,
            } => {
                let base = validate_transport_url(&url)?;
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .post(format!("{base}/v1/sys/enroll"))
                    .header("X-Vault-Token", admin_tok.as_str())
                    .json(&serde_json::json!({
                        "project": project,
                        "name": name,
                        "allowed_paths": paths,
                        "capabilities": caps,
                        "ttl_seconds": ttl_seconds,
                    }))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("Token enroll failed ({status}): {}", err_body);
                    std::process::exit(1);
                }
                let enrolled: EnrollTokenResponse = resp.json().await?;
                if let Some(out_path) = output_file {
                    std::fs::write(&out_path, enrolled.token.as_bytes())?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            &out_path,
                            std::fs::Permissions::from_mode(0o600),
                        )?;
                    }
                    println!(
                        "Enrolled token '{}' written securely (0600) to {:?}",
                        enrolled.token_id, out_path
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&enrolled)?);
                }
            }

            TokenCommands::List { url, token_stdin } => {
                let base = validate_transport_url(&url)?;
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .get(format!("{base}/v1/sys/tokens"))
                    .header("X-Vault-Token", admin_tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("Token list failed ({status}): {}", err_body);
                    std::process::exit(1);
                }
                let list: ListTokensResponse = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&list)?);
            }

            TokenCommands::Revoke {
                url,
                token_id,
                token_stdin,
            } => {
                let base = validate_transport_url(&url)?;
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .delete(format!("{base}/v1/sys/tokens/{token_id}"))
                    .header("X-Vault-Token", admin_tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    eprintln!("Revoke failed ({})", resp.status());
                    std::process::exit(1);
                }
                println!("Revoked token {token_id}");
            }
        },

        Commands::Oidc { action } => match action {
            OidcCommands::Enroll {
                url,
                preset,
                project,
                name,
                issuer,
                tenant_id,
                audience,
                subject_claim,
                subject_pattern,
                paths,
                caps,
                jwks_uri,
                inline_jwks_file,
                token_stdin,
            } => {
                let base = validate_transport_url(&url)?;
                let admin_tok = resolve_caller_token(token_stdin)?;
                let inline_jwks_json =
                    match inline_jwks_file {
                        Some(p) => Some(std::fs::read_to_string(&p).map_err(|e| {
                            format!("Failed reading --inline-jwks-file {:?}: {e}", p)
                        })?),
                        None => None,
                    };
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .post(format!("{base}/v1/sys/oidc/bindings"))
                    .header("X-Vault-Token", admin_tok.as_str())
                    .json(&serde_json::json!({
                        "preset": preset,
                        "project": project,
                        "name": name,
                        "issuer": issuer,
                        "tenant_id": tenant_id,
                        "audience": audience,
                        "subject_claim": subject_claim,
                        "subject_pattern": subject_pattern,
                        "allowed_paths": paths,
                        "capabilities": caps,
                        "jwks_uri": jwks_uri,
                        "inline_jwks_json": inline_jwks_json,
                    }))
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("OIDC enroll failed ({status}): {}", err_body);
                    std::process::exit(1);
                }
                let enrolled: EnrollOidcBindingResponse = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&enrolled)?);
            }

            OidcCommands::List { url, token_stdin } => {
                let base = validate_transport_url(&url)?;
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .get(format!("{base}/v1/sys/oidc/bindings"))
                    .header("X-Vault-Token", admin_tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("OIDC list failed ({status}): {}", err_body);
                    std::process::exit(1);
                }
                let list: ListOidcBindingsResponse = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&list)?);
            }

            OidcCommands::Revoke {
                url,
                binding_id,
                token_stdin,
            } => {
                let base = validate_transport_url(&url)?;
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .delete(format!("{base}/v1/sys/oidc/bindings/{binding_id}"))
                    .header("X-Vault-Token", admin_tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    eprintln!("OIDC revoke failed ({})", resp.status());
                    std::process::exit(1);
                }
                println!("Revoked OIDC binding {binding_id}");
            }

            OidcCommands::Refresh { url, token_stdin } => {
                let base = validate_transport_url(&url)?;
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .post(format!("{base}/v1/sys/oidc/refresh"))
                    .header("X-Vault-Token", admin_tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("OIDC JWKS refresh failed ({status}): {}", err_body);
                    std::process::exit(1);
                }
                let summary: RefreshOidcResponse = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&summary)?);
            }
        },

        Commands::Secret { action } => match action {
            SecretCommands::Put {
                url,
                path,
                project,
                value_stdin,
                token_file,
            } => {
                let base = validate_transport_url(&url)?;
                let tok = resolve_caller_token_with_file(false, token_file.as_ref())?;
                let secret_val =
                    read_secret_value_input("Paste Secret Value (hidden): ", value_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .put(format!("{base}/v1/secret/{}", path.trim_start_matches('/')))
                    .header("X-Vault-Token", tok.as_str())
                    .json(&serde_json::json!({
                        "project": project,
                        "value": secret_val.as_str(),
                    }))
                    .send()
                    .await?;
                let status = resp.status();
                let body: serde_json::Value = resp.json().await?;
                if !status.is_success() {
                    eprintln!("Secret put failed ({status}): {}", body);
                    std::process::exit(1);
                }
                println!("{}", serde_json::to_string_pretty(&body)?);
            }

            SecretCommands::Get {
                url,
                path,
                version,
                token_stdin,
                raw,
            } => {
                let base = validate_transport_url(&url)?;
                let tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let mut req = client
                    .get(format!("{base}/v1/secret/{}", path.trim_start_matches('/')))
                    .header("X-Vault-Token", tok.as_str());
                if let Some(ver) = version {
                    req = req.query(&[("version", ver)]);
                }
                let resp = req.send().await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("Secret get failed ({status}): {}", err_body);
                    std::process::exit(1);
                }
                let secret: SecretResponse = resp.json().await?;
                if raw {
                    print!("{}", secret.value);
                } else {
                    println!("{}", serde_json::to_string_pretty(&secret)?);
                }
            }

            SecretCommands::List {
                url,
                prefix,
                token_stdin,
            } => {
                let base = validate_transport_url(&url)?;
                let tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let mut req = client
                    .get(format!("{base}/v1/secrets"))
                    .header("X-Vault-Token", tok.as_str());
                if let Some(pref) = prefix {
                    req = req.query(&[("prefix", pref)]);
                }
                let resp = req.send().await?;
                if !resp.status().is_success() {
                    let status = resp.status();
                    let err_body: serde_json::Value = resp.json().await?;
                    eprintln!("Secret list failed ({status}): {}", err_body);
                    std::process::exit(1);
                }
                let list: ListSecretsResponse = resp.json().await?;
                println!("{}", serde_json::to_string_pretty(&list)?);
            }

            SecretCommands::Delete {
                url,
                path,
                token_stdin,
            } => {
                let base = validate_transport_url(&url)?;
                let tok = resolve_caller_token(token_stdin)?;
                let client = build_http_client(cli.insecure, cli.ca_cert.as_ref(), None)?;
                let resp = client
                    .delete(format!("{base}/v1/secret/{}", path.trim_start_matches('/')))
                    .header("X-Vault-Token", tok.as_str())
                    .send()
                    .await?;
                if !resp.status().is_success() {
                    eprintln!("Delete failed ({})", resp.status());
                    std::process::exit(1);
                }
                println!("Deleted secret {path}");
            }
        },

        Commands::Watcher {
            url,
            interval_secs,
            key_cmd,
        } => {
            let base = validate_transport_url(&url)?;
            let client = build_http_client(
                cli.insecure,
                cli.ca_cert.as_ref(),
                Some(Duration::from_secs(10)),
            )?;
            eprintln!("Watcher monitoring {base}/v1/sys/health every {interval_secs}s...");
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(2)));
            loop {
                ticker.tick().await;
                let health_res = client.get(format!("{base}/v1/sys/health")).send().await;
                if let Ok(resp) = health_res {
                    if let Ok(health) = resp.json::<HealthResponse>().await {
                        if health.initialized && health.sealed {
                            eprintln!(
                                "Vault detected in SEALED state; retrieving key via OS Secret Service..."
                            );
                            let out = Command::new("sh").arg("-c").arg(&key_cmd).output();
                            match out {
                                Ok(o) if o.status.success() => {
                                    let key_str = Zeroizing::new(
                                        String::from_utf8_lossy(&o.stdout).trim().to_string(),
                                    );
                                    let unseal_res = client
                                        .post(format!("{base}/v1/sys/unseal"))
                                        .json(
                                            &serde_json::json!({ "unseal_key": key_str.as_str() }),
                                        )
                                        .send()
                                        .await;
                                    match unseal_res {
                                        Ok(r) if r.status().is_success() => {
                                            eprintln!("Vault auto-unsealed successfully.");
                                        }
                                        Ok(r) => {
                                            eprintln!("Auto-unseal rejected ({})", r.status());
                                        }
                                        Err(e) => {
                                            eprintln!("Auto-unseal request error: {e}");
                                        }
                                    }
                                }
                                _ => {
                                    eprintln!("Key retrieval command failed; retrying next cycle.");
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
