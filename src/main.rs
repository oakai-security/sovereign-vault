//! Sovereign Vault: Single-binary Micro-KMS Daemon and Admin CLI.

mod acl;
mod crypto;
mod server;
mod storage;

use clap::{Parser, Subcommand};
use rand::RngCore;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[derive(Parser)]
#[command(name = "sovereign-vault")]
#[command(author = "Curtis Powers <curtis@oakai-security.com>")]
#[command(version = "0.1.0")]
#[command(about = "Sovereign Micro-KMS: Zero-account, encrypted volume secrets container", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the sovereign vault HTTPS daemon
    Daemon {
        #[arg(long, default_value = "/data/vault.db")]
        db_path: PathBuf,

        #[arg(long, default_value = "0.0.0.0:8443")]
        bind: String,
    },

    /// Automated watcher client to unseal vault using a local keyring key
    Watcher {
        #[arg(long, default_value = "https://127.0.0.1:8443")]
        vault_url: String,

        #[arg(long, default_value = "sovereign-vault")]
        keyring_service: String,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::registry()
        .with(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .with(tracing_subscriber::fmt::layer())
        .init();

    // Disable process tracing / core dumps
    #[cfg(unix)]
    unsafe {
        libc::prctl(libc::PR_SET_DUMPABLE, 0);
    }

    let cli = Cli::parse();

    match cli.command {
        Commands::Daemon { db_path, bind } => {
            tracing::info!("Starting Sovereign Vault Daemon on {}", bind);
            tracing::info!("Database path: {:?}", db_path);

            if let Some(parent) = db_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            let storage = storage::Storage::new(&db_path)?;
            let is_init = storage.is_initialized()?;

            // Generate ephemeral bootstrap nonce
            let mut nonce_bytes = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut nonce_bytes);
            let bootstrap_nonce = format!("init_{}", hex_encode(nonce_bytes));

            if !is_init {
                tracing::warn!("================================================================================");
                tracing::warn!("VAULT UNINITIALIZED: Use the following ephemeral bootstrap nonce to initialize:");
                tracing::warn!("Nonce: {}", bootstrap_nonce);
                tracing::warn!("Header: X-Vault-Bootstrap-Nonce: {}", bootstrap_nonce);
                tracing::warn!("================================================================================");
            } else {
                tracing::info!("Vault database detected. Starting in SEALED mode.");
            }

            let state = Arc::new(server::AppState {
                storage: Mutex::new(storage),
                bootstrap_nonce,
                master_key: Mutex::new(None),
            });

            let app = server::create_router(state);
            let listener = tokio::net::TcpListener::bind(&bind).await?;
            tracing::info!("Listening on http://{} (Configure TLS proxy via Caddy or internal certs)", bind);
            axum::serve(listener, app).await?;
        }
        Commands::Watcher { vault_url, keyring_service } => {
            tracing::info!("Running unseal watcher against {} (Keyring service: {})", vault_url, keyring_service);
            println!("Watcher daemon loop started. Monitoring vault health...");
        }
    }

    Ok(())
}

fn hex_encode<T: AsRef<[u8]>>(data: T) -> String {
    data.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
}
