//! SQLCipher 256-bit full-page encrypted SQLite persistence engine and `0600` envelope file I/O.

use crate::acl::ScopedToken;
use crate::crypto::{
    compute_audit_chain_mac, constant_time_str_eq, hex_encode, EnvelopeHeader, LockedKey,
};
use crate::oidc::OidcBinding;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

const ENVELOPE_FILENAME: &str = "vault.envelope";
const DB_FILENAME: &str = "vault.db";
const AUDIT_GENESIS_MAC: &str = "GENESIS_SOVEREIGN_VAULT_V2";
const MAX_BACKUP_SNAPSHOTS: usize = 20;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Envelope serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SQLCipher database error: {0}")]
    Sql(#[from] rusqlite::Error),
}

pub struct StoredSecretRecord {
    pub project: String,
    pub version: i64,
    pub ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretMetadataItem {
    pub path: String,
    pub project: String,
    pub version: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenMetadataItem {
    pub token_id: String,
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub seq: i64,
    pub timestamp: i64,
    pub event_type: String,
    pub actor: String,
    pub resource: String,
    pub outcome: String,
    pub prev_mac_sha512: String,
    pub entry_mac_sha512: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    pub snapshot_id: String,
    pub backup_dir: String,
    pub total_bytes: u64,
}

pub struct Storage {
    conn: Connection,
    data_dir: PathBuf,
    db_path: PathBuf,
}

pub fn now_unix_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

pub fn envelope_path(data_dir: &Path) -> PathBuf {
    data_dir.join(ENVELOPE_FILENAME)
}

pub fn database_path(data_dir: &Path) -> PathBuf {
    data_dir.join(DB_FILENAME)
}

pub fn is_vault_initialized(data_dir: &Path) -> bool {
    envelope_path(data_dir).is_file() && database_path(data_dir).is_file()
}

/// Detect split-file partial initialization (`vault.envelope` exists without `vault.db`, or vice versa).
pub fn has_partial_initialization(data_dir: &Path) -> bool {
    envelope_path(data_dir).is_file() ^ database_path(data_dir).is_file()
}

/// Atomically persist `/data/vault.envelope` with strict `0600` permissions.
pub fn write_envelope_header(data_dir: &Path, header: &EnvelopeHeader) -> Result<(), StorageError> {
    ensure_secure_dir(data_dir)?;
    let tmp_path = data_dir.join("vault.envelope.tmp");
    let final_path = envelope_path(data_dir);
    let payload = serde_json::to_vec_pretty(header)?;

    let mut file = fs::File::create(&tmp_path)?;
    set_mode_0600(&tmp_path)?;
    file.write_all(&payload)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp_path, &final_path)?;
    set_mode_0600(&final_path)?;
    Ok(())
}

pub fn read_envelope_header(data_dir: &Path) -> Result<EnvelopeHeader, StorageError> {
    let bytes = fs::read(envelope_path(data_dir))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn ensure_secure_dir(dir: &Path) -> std::io::Result<()> {
    fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir, fs::Permissions::from_mode(0o700));
    }
    Ok(())
}

fn set_mode_0600(path: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
    }
    Ok(())
}

impl Storage {
    /// Open or create the SQLCipher-encrypted database inside `data_dir` using the 256-bit `sqlcipher_key`.
    /// Every 4KB database page (including table schemas, path indices, and WAL frames) is encrypted
    /// via AES-256 and authenticated with `HMAC_SHA512`.
    pub fn open_encrypted(data_dir: &Path, sqlcipher_key: &LockedKey) -> Result<Self, StorageError> {
        ensure_secure_dir(data_dir)?;
        let db_path = database_path(data_dir);
        let conn = Connection::open(&db_path)?;
        set_mode_0600(&db_path)?;

        let raw_hex = Zeroizing::new(hex_encode(sqlcipher_key.as_bytes()));
        let key_pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", raw_hex.as_str()));
        conn.execute_batch(key_pragma.as_str())?;

        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
             PRAGMA cipher_kdf_algorithm = PBKDF2_HMAC_SHA512;
             PRAGMA cipher_memory_security = ON;
             PRAGMA secure_delete = ON;
             PRAGMA journal_mode = WAL;
             PRAGMA synchronous = FULL;
             PRAGMA foreign_keys = ON;
             PRAGMA busy_timeout = 5000;

             CREATE TABLE IF NOT EXISTS secrets (
                 path TEXT PRIMARY KEY,
                 project TEXT NOT NULL,
                 current_version INTEGER NOT NULL,
                 ciphertext BLOB NOT NULL,
                 nonce BLOB NOT NULL,
                 updated_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS secret_versions (
                 path TEXT NOT NULL,
                 version INTEGER NOT NULL,
                 project TEXT NOT NULL,
                 ciphertext BLOB NOT NULL,
                 nonce BLOB NOT NULL,
                 created_at INTEGER NOT NULL,
                 PRIMARY KEY (path, version)
             );

             CREATE TABLE IF NOT EXISTS tokens (
                 token_id TEXT PRIMARY KEY,
                 token_hash_sha512 TEXT NOT NULL,
                 project TEXT NOT NULL,
                 name TEXT NOT NULL,
                 allowed_paths TEXT NOT NULL,
                 capabilities TEXT NOT NULL,
                 expires_at INTEGER,
                 created_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS oidc_bindings (
                 binding_id TEXT PRIMARY KEY,
                 name TEXT NOT NULL,
                 project TEXT NOT NULL,
                 issuer TEXT NOT NULL,
                 audience TEXT NOT NULL,
                 jwks_uri TEXT NOT NULL,
                 subject_claim TEXT NOT NULL,
                 subject_pattern TEXT NOT NULL,
                 allowed_paths TEXT NOT NULL,
                 capabilities TEXT NOT NULL,
                 inline_jwks_json TEXT,
                 created_at INTEGER NOT NULL
             );

             CREATE TABLE IF NOT EXISTS audit_log (
                 seq INTEGER PRIMARY KEY,
                 timestamp INTEGER NOT NULL,
                 event_type TEXT NOT NULL,
                 actor TEXT NOT NULL,
                 resource TEXT NOT NULL,
                 outcome TEXT NOT NULL,
                 prev_mac_sha512 TEXT NOT NULL,
                 entry_mac_sha512 TEXT NOT NULL
             );",
        )?;

        // Tighten permissions on WAL/SHM sidecar files if created
        let _ = set_mode_0600(&data_dir.join("vault.db-wal"));
        let _ = set_mode_0600(&data_dir.join("vault.db-shm"));

        Ok(Self {
            conn,
            data_dir: data_dir.to_path_buf(),
            db_path,
        })
    }

    /// Return the next monotonic version number for `path` (starts at `1`).
    pub fn next_secret_version(&self, path: &str) -> Result<i64, StorageError> {
        let current: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(version) FROM secret_versions WHERE path = ?",
                params![path],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(current.unwrap_or(0) + 1)
    }

    /// Atomically persist a new secret version and update the active pointer row.
    pub fn put_secret_versioned(
        &mut self,
        path: &str,
        project: &str,
        version: i64,
        ciphertext: &[u8],
        nonce: &[u8; 12],
    ) -> Result<(), StorageError> {
        let now = now_unix_seconds();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO secret_versions (path, version, project, ciphertext, nonce, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![path, version, project, ciphertext, nonce.as_slice(), now],
        )?;
        tx.execute(
            "INSERT INTO secrets (path, project, current_version, ciphertext, nonce, updated_at)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT(path) DO UPDATE SET
                 project = excluded.project,
                 current_version = excluded.current_version,
                 ciphertext = excluded.ciphertext,
                 nonce = excluded.nonce,
                 updated_at = excluded.updated_at",
            params![path, project, version, ciphertext, nonce.as_slice(), now],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn get_secret(&self, path: &str) -> Result<Option<StoredSecretRecord>, StorageError> {
        self.get_secret_version(path, None)
    }

    /// Retrieve either the active version (`version = None`) or a specific historical version (`Some(v)`)
    /// for an active secret path.
    pub fn get_secret_version(
        &self,
        path: &str,
        version: Option<i64>,
    ) -> Result<Option<StoredSecretRecord>, StorageError> {
        let row: Option<(String, i64, Vec<u8>, Vec<u8>)> = match version {
            None => self
                .conn
                .query_row(
                    "SELECT project, current_version, ciphertext, nonce FROM secrets WHERE path = ?",
                    params![path],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?,
            Some(ver) => self
                .conn
                .query_row(
                    "SELECT sv.project, sv.version, sv.ciphertext, sv.nonce
                     FROM secret_versions sv
                     INNER JOIN secrets s ON s.path = sv.path
                     WHERE sv.path = ? AND sv.version = ?",
                    params![path, ver],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?,
        };

        match row {
            Some((project, version, ciphertext, nonce_vec)) => {
                let nonce: [u8; 12] = nonce_vec.as_slice().try_into().map_err(|_| {
                    rusqlite::Error::InvalidColumnType(
                        3,
                        "nonce".to_string(),
                        rusqlite::types::Type::Blob,
                    )
                })?;
                Ok(Some(StoredSecretRecord {
                    project,
                    version,
                    ciphertext,
                    nonce,
                }))
            }
            None => Ok(None),
        }
    }

    /// Cryptographically shred a secret path from both `secrets` and `secret_versions`
    /// inside an atomic transaction (`PRAGMA secure_delete = ON` overwrites freed SQLCipher pages).
    pub fn delete_secret(&mut self, path: &str) -> Result<bool, StorageError> {
        let tx = self.conn.transaction()?;
        let _ = tx.execute("DELETE FROM secret_versions WHERE path = ?", params![path])?;
        let affected = tx.execute("DELETE FROM secrets WHERE path = ?", params![path])?;
        tx.commit()?;
        Ok(affected > 0)
    }

    pub fn put_token(
        &self,
        token_id: &str,
        token_hash_sha512: &str,
        project: &str,
        name: &str,
        allowed_paths: &[String],
        capabilities: &[String],
        expires_at: Option<i64>,
    ) -> Result<(), StorageError> {
        let paths_json = serde_json::to_string(allowed_paths)?;
        let caps_json = serde_json::to_string(capabilities)?;
        let now = now_unix_seconds();

        self.conn.execute(
            "INSERT INTO tokens (token_id, token_hash_sha512, project, name, allowed_paths, capabilities, expires_at, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                token_id,
                token_hash_sha512,
                project,
                name,
                paths_json,
                caps_json,
                expires_at,
                now
            ],
        )?;
        Ok(())
    }

    pub fn get_token_by_id(&self, token_id: &str) -> Result<Option<ScopedToken>, StorageError> {
        let row: Option<(String, String, String, String, String, String, Option<i64>)> = self
            .conn
            .query_row(
                "SELECT token_id, token_hash_sha512, project, name, allowed_paths, capabilities, expires_at
                 FROM tokens WHERE token_id = ?",
                params![token_id],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get(1)?,
                        r.get(2)?,
                        r.get(3)?,
                        r.get(4)?,
                        r.get(5)?,
                        r.get(6)?,
                    ))
                },
            )
            .optional()?;

        match row {
            Some((id, hash, project, name, paths_str, caps_str, expires_at)) => {
                let allowed_paths: Vec<String> = serde_json::from_str(&paths_str)?;
                let capabilities: Vec<String> = serde_json::from_str(&caps_str)?;
                Ok(Some(ScopedToken {
                    token_id: id,
                    token_hash_sha512: hash,
                    project,
                    name,
                    allowed_paths,
                    capabilities,
                    expires_at,
                }))
            }
            None => Ok(None),
        }
    }

    pub fn delete_token(&self, token_id: &str) -> Result<bool, StorageError> {
        let affected = self
            .conn
            .execute("DELETE FROM tokens WHERE token_id = ?", params![token_id])?;
        Ok(affected > 0)
    }

    /// Persist a new OIDC Workload Identity Binding into SQLCipher.
    pub fn put_oidc_binding(&self, binding: &OidcBinding) -> Result<(), StorageError> {
        let paths_json = serde_json::to_string(&binding.allowed_paths)?;
        let caps_json = serde_json::to_string(&binding.capabilities)?;
        self.conn.execute(
            "INSERT INTO oidc_bindings (
                 binding_id, name, project, issuer, audience, jwks_uri,
                 subject_claim, subject_pattern, allowed_paths, capabilities,
                 inline_jwks_json, created_at
             ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT(binding_id) DO UPDATE SET
                 name = excluded.name,
                 project = excluded.project,
                 issuer = excluded.issuer,
                 audience = excluded.audience,
                 jwks_uri = excluded.jwks_uri,
                 subject_claim = excluded.subject_claim,
                 subject_pattern = excluded.subject_pattern,
                 allowed_paths = excluded.allowed_paths,
                 capabilities = excluded.capabilities,
                 inline_jwks_json = excluded.inline_jwks_json",
            params![
                binding.binding_id,
                binding.name,
                binding.project,
                binding.issuer,
                binding.audience,
                binding.jwks_uri,
                binding.subject_claim,
                binding.subject_pattern,
                paths_json,
                caps_json,
                binding.inline_jwks_json,
                binding.created_at,
            ],
        )?;
        Ok(())
    }

    /// List all configured OIDC Workload Identity Bindings.
    pub fn list_oidc_bindings(&self) -> Result<Vec<OidcBinding>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT binding_id, name, project, issuer, audience, jwks_uri,
                    subject_claim, subject_pattern, allowed_paths, capabilities,
                    inline_jwks_json, created_at
             FROM oidc_bindings ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            let paths_str: String = r.get(8)?;
            let caps_str: String = r.get(9)?;
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, String>(6)?,
                r.get::<_, String>(7)?,
                paths_str,
                caps_str,
                r.get::<_, Option<String>>(10)?,
                r.get::<_, i64>(11)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (
                binding_id,
                name,
                project,
                issuer,
                audience,
                jwks_uri,
                subject_claim,
                subject_pattern,
                paths_str,
                caps_str,
                inline_jwks_json,
                created_at,
            ) = row?;
            out.push(OidcBinding {
                binding_id,
                name,
                project,
                issuer,
                audience,
                jwks_uri,
                subject_claim,
                subject_pattern,
                allowed_paths: serde_json::from_str(&paths_str)?,
                capabilities: serde_json::from_str(&caps_str)?,
                inline_jwks_json,
                created_at,
            });
        }
        Ok(out)
    }

    /// Delete an OIDC Workload Identity Binding by `binding_id`.
    pub fn delete_oidc_binding(&self, binding_id: &str) -> Result<bool, StorageError> {
        let affected = self.conn.execute(
            "DELETE FROM oidc_bindings WHERE binding_id = ?",
            params![binding_id],
        )?;
        Ok(affected > 0)
    }

    /// Count active OIDC Workload Identity Bindings.
    pub fn count_oidc_bindings(&self) -> Result<u64, StorageError> {
        let count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM oidc_bindings", [], |r| r.get(0))?;
        Ok(count as u64)
    }

    /// Return the latest audit sequence number (`0` if empty).
    pub fn latest_audit_seq(&self) -> Result<u64, StorageError> {
        let seq: Option<i64> = self
            .conn
            .query_row("SELECT MAX(seq) FROM audit_log", [], |r| r.get(0))
            .optional()?
            .flatten();
        Ok(seq.unwrap_or(0) as u64)
    }

    /// Return aggregate operational counts `(total_secrets, active_unexpired_tokens, db_bytes)`
    /// for opt-in Enterprise Telemetry (never exposes secret names, paths, or values).
    pub fn operational_counts(&self) -> Result<(u64, u64, u64), StorageError> {
        let now = now_unix_seconds();
        let secrets_count: i64 =
            self.conn
                .query_row("SELECT COUNT(*) FROM secrets", [], |r| r.get(0))?;
        let tokens_count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM tokens WHERE expires_at IS NULL OR expires_at > ?",
            params![now],
            |r| r.get(0),
        )?;
        let db_bytes = fs::metadata(&self.db_path).map(|m| m.len()).unwrap_or(0);
        Ok((secrets_count as u64, tokens_count as u64, db_bytes))
    }

    /// List secret metadata rows (`path`, `project`, `version`, `updated_at`) without loading ciphertexts.
    pub fn list_secrets_metadata(&self) -> Result<Vec<SecretMetadataItem>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT path, project, current_version, updated_at FROM secrets ORDER BY path ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SecretMetadataItem {
                path: r.get(0)?,
                project: r.get(1)?,
                version: r.get(2)?,
                updated_at: r.get(3)?,
            })
        })?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    /// List enrolled machine token metadata without exposing SHA-512 digests.
    pub fn list_tokens_metadata(&self) -> Result<Vec<TokenMetadataItem>, StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT token_id, project, name, allowed_paths, capabilities, expires_at, created_at
             FROM tokens ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |r| {
            let paths_str: String = r.get(3)?;
            let caps_str: String = r.get(4)?;
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                paths_str,
                caps_str,
                r.get::<_, Option<i64>>(5)?,
                r.get::<_, i64>(6)?,
            ))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (token_id, project, name, paths_str, caps_str, expires_at, created_at) = row?;
            out.push(TokenMetadataItem {
                token_id,
                project,
                name,
                allowed_paths: serde_json::from_str(&paths_str)?,
                capabilities: serde_json::from_str(&caps_str)?,
                expires_at,
                created_at,
            });
        }
        Ok(out)
    }

    /// Append a tamper-evident, HMAC-SHA512 hash-chained audit event inside SQLCipher.
    pub fn append_audit_event(
        &mut self,
        audit_key: &LockedKey,
        event_type: &str,
        actor: &str,
        resource: &str,
        outcome: &str,
    ) -> Result<AuditLogEntry, StorageError> {
        let now = now_unix_seconds();
        let tx = self.conn.transaction()?;
        let last: Option<(i64, String)> = tx
            .query_row(
                "SELECT seq, entry_mac_sha512 FROM audit_log ORDER BY seq DESC LIMIT 1",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;

        let (seq, prev_mac) = match last {
            Some((last_seq, last_mac)) => (last_seq + 1, last_mac),
            None => (1, AUDIT_GENESIS_MAC.to_string()),
        };

        let entry_mac = compute_audit_chain_mac(
            audit_key,
            &prev_mac,
            seq,
            now,
            event_type,
            actor,
            resource,
            outcome,
        );

        tx.execute(
            "INSERT INTO audit_log (seq, timestamp, event_type, actor, resource, outcome, prev_mac_sha512, entry_mac_sha512)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![seq, now, event_type, actor, resource, outcome, prev_mac, entry_mac],
        )?;
        tx.commit()?;
        Ok(AuditLogEntry {
            seq,
            timestamp: now,
            event_type: event_type.to_string(),
            actor: actor.to_string(),
            resource: resource.to_string(),
            outcome: outcome.to_string(),
            prev_mac_sha512: prev_mac,
            entry_mac_sha512: entry_mac,
        })
    }

    /// Recompute and verify the entire HMAC-SHA512 hash chain from genesis (`seq = 1..=N`),
    /// returning `(chain_verified, total_events, tail_events)`.
    pub fn verify_and_list_audit_log(
        &self,
        audit_key: &LockedKey,
        limit: usize,
    ) -> Result<(bool, u64, Vec<AuditLogEntry>), StorageError> {
        let mut stmt = self.conn.prepare(
            "SELECT seq, timestamp, event_type, actor, resource, outcome, prev_mac_sha512, entry_mac_sha512
             FROM audit_log ORDER BY seq ASC",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(AuditLogEntry {
                seq: r.get(0)?,
                timestamp: r.get(1)?,
                event_type: r.get(2)?,
                actor: r.get(3)?,
                resource: r.get(4)?,
                outcome: r.get(5)?,
                prev_mac_sha512: r.get(6)?,
                entry_mac_sha512: r.get(7)?,
            })
        })?;

        let cap = limit.clamp(1, 500);
        let mut tail_ring: VecDeque<AuditLogEntry> = VecDeque::with_capacity(cap);
        let mut expected_seq = 1i64;
        let mut expected_prev = AUDIT_GENESIS_MAC.to_string();
        let mut valid = true;
        let mut total = 0u64;

        for row in rows {
            let entry = row?;
            if entry.seq != expected_seq
                || !constant_time_str_eq(&entry.prev_mac_sha512, &expected_prev)
            {
                valid = false;
            }
            let recomputed = compute_audit_chain_mac(
                audit_key,
                &entry.prev_mac_sha512,
                entry.seq,
                entry.timestamp,
                &entry.event_type,
                &entry.actor,
                &entry.resource,
                &entry.outcome,
            );
            if !constant_time_str_eq(&entry.entry_mac_sha512, &recomputed) {
                valid = false;
            }
            expected_seq += 1;
            expected_prev = entry.entry_mac_sha512.clone();
            total += 1;
            if tail_ring.len() == cap {
                tail_ring.pop_front();
            }
            tail_ring.push_back(entry);
        }

        Ok((valid, total, tail_ring.into_iter().collect()))
    }

    /// Count historical rows in `secret_versions` for a given `path`.
    pub fn count_secret_versions(&self, path: &str) -> Result<i64, StorageError> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM secret_versions WHERE path = ?",
            params![path],
            |r| r.get(0),
        )?;
        Ok(count)
    }

    /// Perform an online encrypted backup by checkpointing WAL frames into `vault.db`
    /// and streaming `vault.db` + `vault.envelope` into a `0700`/`0600` snapshot directory.
    /// Automatically prunes oldest snapshots beyond `MAX_BACKUP_SNAPSHOTS`.
    pub fn create_encrypted_backup(&self) -> Result<BackupMetadata, StorageError> {
        self.conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")?;

        let now = now_unix_seconds();
        let mut suffix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut suffix);
        let snapshot_id = format!("snap_{}_{}", now, hex_encode(suffix));

        let backups_root = self.data_dir.join("backups");
        ensure_secure_dir(&backups_root)?;
        let snap_dir = backups_root.join(&snapshot_id);
        ensure_secure_dir(&snap_dir)?;

        let dst_db = snap_dir.join(DB_FILENAME);
        let dst_env = snap_dir.join(ENVELOPE_FILENAME);

        let db_bytes = copy_file_0600_synced(&self.db_path, &dst_db)?;
        let env_bytes = copy_file_0600_synced(&envelope_path(&self.data_dir), &dst_env)?;

        prune_excess_backups(&backups_root, MAX_BACKUP_SNAPSHOTS);

        Ok(BackupMetadata {
            snapshot_id,
            backup_dir: snap_dir.to_string_lossy().to_string(),
            total_bytes: db_bytes + env_bytes,
        })
    }
}

fn copy_file_0600_synced(src: &Path, dst: &Path) -> std::io::Result<u64> {
    let mut src_file = fs::File::open(src)?;
    let mut dst_file = fs::File::create(dst)?;
    set_mode_0600(dst)?;
    let copied = std::io::copy(&mut src_file, &mut dst_file)?;
    dst_file.flush()?;
    dst_file.sync_all()?;
    Ok(copied)
}

fn prune_excess_backups(backups_root: &Path, keep_max: usize) {
    let Ok(entries) = fs::read_dir(backups_root) else {
        return;
    };
    let mut dirs: Vec<PathBuf> = entries
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.is_dir())
        .collect();
    if dirs.len() <= keep_max {
        return;
    }
    dirs.sort();
    let remove_count = dirs.len().saturating_sub(keep_max);
    for old_dir in dirs.into_iter().take(remove_count) {
        let _ = fs::remove_dir_all(old_dir);
    }
}
