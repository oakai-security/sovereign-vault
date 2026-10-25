//! Sovereign Vault v0.2: Single-binary Micro-KMS Daemon and Zero-History Admin CLI.
//!
//! All sensitive CLI inputs (bootstrap nonces, unseal keys, machine tokens, and secret values)
//! are collected exclusively via hidden `/dev/tty` prompts (`rpassword`) or `--stdin` pipes
//! so pasted credentials NEVER enter `~/.bash_history` or `ps aux` process arguments.

use clap::{Parser, Subcommand};
use rand::RngCore;
use sovereign_vault::{
    crypto::hex_encode,
    server::{self, AppState, EnrollTokenResponse, HealthResponse, SecretResponse},
    storage::is_vault_initialized,
    telemetry::{maybe_spawn_telemetry_worker, TelemetryConfig},
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
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Sovereign Vault Micro-KMS daemon (binds behind reverse proxy / loopback)
    Daemon {
        #[arg(long, default_value = "/data")]
        data_dir: PathBuf,

        #[arg(long, default_value = "127.0.0.1:8443")]
        bind: String,
    },

    /// Query daemon initialization, seal, and RAM-lock status
    Status {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,
    },

    /// Initialize a fresh vault (prompts hidden TTY for bootstrap nonce; never exposes args in history)
    Init {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        /// Read bootstrap nonce from stdin instead of interactive hidden TTY prompt
        #[arg(long)]
        nonce_stdin: bool,
    },

    /// Unseal the vault (prompts hidden TTY for unseal key or reads --stdin; no --key CLI flag exists)
    Unseal {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        /// Read 64-hex unseal key from stdin (e.g., piped from Ubuntu Secret Service)
        #[arg(long)]
        stdin: bool,
    },

    /// Seal the vault immediately and scrub RAM keys (requires admin token)
    Seal {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        /// Read admin token from stdin instead of hidden TTY prompt
        #[arg(long)]
        token_stdin: bool,
    },

    /// Enroll or revoke SHA-512 path-scoped machine tokens
    Token {
        #[command(subcommand)]
        action: TokenCommands,
    },

    /// Read, write, or delete encrypted secrets
    Secret {
        #[command(subcommand)]
        action: SecretCommands,
    },

    /// Poll vault health and auto-unseal via external keyring command when sealed
    Watcher {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        /// Poll interval in seconds
        #[arg(long, default_value_t = 10)]
        interval_secs: u64,

        /// Shell command whose stdout outputs the 64-hex unseal key (e.g. secret_service.py get sovereign-vault unseal-key)
        #[arg(
            long,
            default_value = "python3 python3 -m keyring get sovereign-vault unseal-key"
        )]
        key_cmd: String,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    /// Mint a new path-scoped machine token (requires admin token)
    Enroll {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
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

    /// Immediately revoke an enrolled machine token by ID (`tok_...`)
    Revoke {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        #[arg(long)]
        token_id: String,

        #[arg(long)]
        token_stdin: bool,
    },
}

#[derive(Subcommand)]
enum SecretCommands {
    /// Encrypt and persist a secret (reads secret value from hidden TTY or --value-stdin)
    Put {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        /// Canonical secret path (e.g. `apps/jellyfin/db_password`)
        path: String,

        #[arg(long)]
        project: String,

        /// Read secret value from stdin (requires `VAULT_TOKEN` env var or interactive token prompt)
        #[arg(long)]
        value_stdin: bool,
    },

    /// Retrieve and decrypt a secret
    Get {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        path: String,

        #[arg(long)]
        token_stdin: bool,

        /// Print raw value only (suitable for piping)
        #[arg(long)]
        raw: bool,
    },

    /// Delete a secret path
    Delete {
        #[arg(long, default_value = "http://127.0.0.1:8443")]
        url: String,

        path: String,

        #[arg(long)]
        token_stdin: bool,
    },
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
        let val = Zeroizing::new(
            rpassword::prompt_password(prompt)
                .map_err(|e| format!("Hidden TTY prompt failed (use --stdin for non-interactive pipes): {e}"))?,
        );
        let trimmed = Zeroizing::new(val.trim().to_string());
        if trimmed.is_empty() {
            return Err("Empty input aborted".to_string());
        }
        Ok(trimmed)
    }
}

fn resolve_caller_token(from_stdin: bool) -> Result<Zeroizing<String>, String> {
    if from_stdin {
        return read_secret_input("", true);
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
    // Disable process tracing / core dumps immediately on startup
    #[cfg(unix)]
    unsafe {
        let _ = libc::prctl(libc::PR_SET_DUMPABLE, 0);
        libc::umask(0o077);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { data_dir, bind } => {
            tracing_subscriber::registry()
                .with(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| "info".into()),
                )
                .with(tracing_subscriber::fmt::layer())
                .init();

            std::fs::create_dir_all(&data_dir)?;
            let is_init = is_vault_initialized(&data_dir);

            let bootstrap_nonce = if !is_init {
                let mut nonce_bytes = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut nonce_bytes);
                let n = format!("init_{}", hex_encode(nonce_bytes));
                tracing::warn!("================================================================================");
                tracing::warn!("VAULT UNINITIALIZED: Use this single-use ephemeral bootstrap nonce to initialize:");
                tracing::warn!("Nonce: {}", n);
                tracing::warn!("================================================================================");
                Some(n)
            } else {
                tracing::info!("Encrypted SQLCipher vault detected. Starting in SEALED mode.");
                None
            };

            let telemetry_cfg = TelemetryConfig::from_env();
            let state = Arc::new(AppState::new(
                data_dir.clone(),
                bootstrap_nonce,
                telemetry_cfg.is_some(),
            ));

            let _telemetry_handle = maybe_spawn_telemetry_worker(state.clone(), telemetry_cfg);

            let app = server::create_router(state);
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!(
                "Sovereign Vault v{} listening on http://{} (terminate TLS at Caddy/Nginx reverse proxy)",
                env!("CARGO_PKG_VERSION"),
                bind
            );
            axum::serve(listener, app).await?;
        }

        Commands::Status { url } => {
            let client = reqwest::Client::new();
            let resp: HealthResponse = client
                .get(format!("{}/v1/sys/health", url.trim_end_matches('/')))
                .send()
                .await?
                .error_for_status()?
                .json()
                .await?;
            println!("{}", serde_json::to_string_pretty(&resp)?);
        }

        Commands::Init { url, nonce_stdin } => {
            let nonce = read_secret_input("Paste Bootstrap Nonce (hidden): ", nonce_stdin)?;
            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/v1/sys/init", url.trim_end_matches('/')))
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
            let key = read_secret_input("Paste 64-hex Unseal Key (hidden): ", stdin)?;
            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/v1/sys/unseal", url.trim_end_matches('/')))
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
            let tok = resolve_caller_token(token_stdin)?;
            let client = reqwest::Client::new();
            let resp = client
                .post(format!("{}/v1/sys/seal", url.trim_end_matches('/')))
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
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = reqwest::Client::new();
                let resp = client
                    .post(format!("{}/v1/sys/enroll", url.trim_end_matches('/')))
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
                        std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(0o600))?;
                    }
                    println!(
                        "Enrolled token '{}' written securely (0600) to {:?}",
                        enrolled.token_id, out_path
                    );
                } else {
                    println!("{}", serde_json::to_string_pretty(&enrolled)?);
                }
            }

            TokenCommands::Revoke {
                url,
                token_id,
                token_stdin,
            } => {
                let admin_tok = resolve_caller_token(token_stdin)?;
                let client = reqwest::Client::new();
                let resp = client
                    .delete(format!(
                        "{}/v1/sys/tokens/{}",
                        url.trim_end_matches('/'),
                        token_id
                    ))
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

        Commands::Secret { action } => match action {
            SecretCommands::Put {
                url,
                path,
                project,
                value_stdin,
            } => {
                let tok = resolve_caller_token(false)?;
                let secret_val = read_secret_input("Paste Secret Value (hidden): ", value_stdin)?;
                let client = reqwest::Client::new();
                let resp = client
                    .put(format!(
                        "{}/v1/secret/{}",
                        url.trim_end_matches('/'),
                        path.trim_start_matches('/')
                    ))
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
                token_stdin,
                raw,
            } => {
                let tok = resolve_caller_token(token_stdin)?;
                let client = reqwest::Client::new();
                let resp = client
                    .get(format!(
                        "{}/v1/secret/{}",
                        url.trim_end_matches('/'),
                        path.trim_start_matches('/')
                    ))
                    .header("X-Vault-Token", tok.as_str())
                    .send()
                    .await?;
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

            SecretCommands::Delete {
                url,
                path,
                token_stdin,
            } => {
                let tok = resolve_caller_token(token_stdin)?;
                let client = reqwest::Client::new();
                let resp = client
                    .delete(format!(
                        "{}/v1/secret/{}",
                        url.trim_end_matches('/'),
                        path.trim_start_matches('/')
                    ))
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
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(10))
                .build()?;
            let base = url.trim_end_matches('/').to_string();
            eprintln!("Watcher monitoring {base}/v1/sys/health every {interval_secs}s...");
            let mut ticker = tokio::time::interval(Duration::from_secs(interval_secs.max(2)));
            loop {
                ticker.tick().await;
                let health_res = client.get(format!("{base}/v1/sys/health")).send().await;
                if let Ok(resp) = health_res {
                    if let Ok(health) = resp.json::<HealthResponse>().await {
                        if health.initialized && health.sealed {
                            eprintln!("Vault detected in SEALED state; retrieving key via OS Secret Service...");
                            let out = Command::new("sh").arg("-c").arg(&key_cmd).output();
                            match out {
                                Ok(o) if o.status.success() => {
                                    let key_str = Zeroizing::new(
                                        String::from_utf8_lossy(&o.stdout).trim().to_string(),
                                    );
                                    let unseal_res = client
                                        .post(format!("{base}/v1/sys/unseal"))
                                        .json(&serde_json::json!({ "unseal_key": key_str.as_str() }))
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
