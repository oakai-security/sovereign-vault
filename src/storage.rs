//! SQLCipher 256-bit full-page encrypted SQLite persistence engine, atomic single-transaction
//! HMAC-SHA512 audit chaining with external tail-truncation anchoring, and `0600` envelope file I/O.

use crate::acl::ScopedToken;
use crate::crypto::{
    compute_audit_chain_mac, constant_time_str_eq, hex_encode, EnvelopeHeader, LockedKey,
};
use crate::oidc::OidcBinding;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension, Transaction};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use zeroize::Zeroizing;

const ENVELOPE_FILENAME: &str = "vault.envelope";
const DB_FILENAME: &str = "vault.db";
const AUDIT_ANCHOR_FILENAME: &str = "vault.audit_anchor";
const AUDIT_GENESIS_MAC: &str = "GENESIS_SOVEREIGN_VAULT_V2";
const MAX_BACKUP_SNAPSHOTS: usize = 20;
const MAX_SECRET_VERSIONS_PER_PATH: i64 = 20;

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("Filesystem I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Envelope serialization error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("SQLCipher database error: {0}")]
    Sql(#[from] rusqlite::Error),
    #[error("Audit chain or external anchor integrity violation: {0}")]
    AuditIntegrityViolation(&'static str),
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
    pub sha256: String,
}

/// External HMAC-SHA512 authenticated high-water mark stored at `/data/vault.audit_anchor` (`0600`).
/// Prevents an attacker with SQLite write access from truncating tail rows (`seq > K`) or wiping `audit_log`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct AuditChainAnchor {
    seq: i64,
    entry_mac_sha512: String,
    anchor_mac_sha512: String,
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

pub fn audit_anchor_path(data_dir: &Path) -> PathBuf {
    data_dir.join(AUDIT_ANCHOR_FILENAME)
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

/// Re-persist a rotated `EnvelopeHeader` across all retained backup snapshots on `/data/backups/`
/// (`SV-AUD-02`), ensuring a rotated unseal key can no longer unwrap `master_dek` from older snapshots.
pub fn update_backup_envelopes(
    data_dir: &Path,
    new_header: &EnvelopeHeader,
) -> Result<(), StorageError> {
    let backups_root = data_dir.join("backups");
    if !backups_root.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(&backups_root)? {
        let entry = entry?;
        let snap_dir = entry.path();
        if snap_dir.is_dir() && envelope_path(&snap_dir).is_file() {
            write_envelope_header(&snap_dir, new_header)?;
        }
    }
    Ok(())
}

pub fn read_envelope_header(data_dir: &Path) -> Result<EnvelopeHeader, StorageError> {
    let bytes = fs::read(envelope_path(data_dir))?;
    Ok(serde_json::from_slice(&bytes)?)
}

fn compute_anchor_mac(audit_key: &LockedKey, seq: i64, entry_mac_sha512: &str) -> String {
    compute_audit_chain_mac(
        audit_key,
        entry_mac_sha512,
        seq,
        0,
        "sys.audit.anchor",
        "vault",
        "audit_anchor",
        "ok",
    )
}

fn verify_audit_anchor_continuity(
    data_dir: &Path,
    audit_key: &LockedKey,
    seq: i64,
    prev_mac_sha512: &str,
) -> Result<(), StorageError> {
    let final_path = audit_anchor_path(data_dir);
    // SV-AUD-01 & SV-V2-02: Verify continuity with the existing anchor before committing so that
    // a truncated or wiped `audit_log` (or deleted anchor file) can NEVER be silently re-anchored
    // and any secret read/mutation fails closed (`Err(StorageError::AuditIntegrityViolation)`).
    if final_path.exists() {
        match read_audit_anchor(data_dir) {
            Ok(Some(existing)) => {
                let expected_existing_mac =
                    compute_anchor_mac(audit_key, existing.seq, &existing.entry_mac_sha512);
                let anchor_authentic =
                    constant_time_str_eq(&existing.anchor_mac_sha512, &expected_existing_mac);
                let chain_continuous = existing.seq + 1 == seq
                    && constant_time_str_eq(&existing.entry_mac_sha512, prev_mac_sha512);
                if !anchor_authentic || !chain_continuous {
                    tracing::error!(
                        anchor_seq = existing.seq,
                        new_seq = seq,
                        "Audit chain continuity violation: refusing to overwrite high-water audit anchor"
                    );
                    return Err(StorageError::AuditIntegrityViolation(
                        "Audit chain continuity violation against vault.audit_anchor",
                    ));
                }
            }
            Ok(None) | Err(_) => {
                tracing::error!(
                    "Corrupt vault.audit_anchor detected: refusing to overwrite tamper state"
                );
                return Err(StorageError::AuditIntegrityViolation(
                    "Corrupt vault.audit_anchor file",
                ));
            }
        }
    } else if seq != 1 || !constant_time_str_eq(prev_mac_sha512, AUDIT_GENESIS_MAC) {
        tracing::error!(
            new_seq = seq,
            "Missing vault.audit_anchor for non-genesis audit event: refusing to recreate anchor"
        );
        return Err(StorageError::AuditIntegrityViolation(
            "Missing vault.audit_anchor for non-genesis audit event",
        ));
    }
    Ok(())
}

fn commit_audit_anchor_file(
    data_dir: &Path,
    audit_key: &LockedKey,
    seq: i64,
    entry_mac_sha512: &str,
) -> Result<(), StorageError> {
    let final_path = audit_anchor_path(data_dir);
    let anchor = AuditChainAnchor {
        seq,
        entry_mac_sha512: entry_mac_sha512.to_string(),
        anchor_mac_sha512: compute_anchor_mac(audit_key, seq, entry_mac_sha512),
    };
    let tmp_path = data_dir.join("vault.audit_anchor.tmp");
    let payload = serde_json::to_vec(&anchor)?;

    let mut file = fs::File::create(&tmp_path)?;
    set_mode_0600(&tmp_path)?;
    file.write_all(&payload)?;
    file.sync_all()?;
    drop(file);

    fs::rename(&tmp_path, &final_path)?;
    set_mode_0600(&final_path)?;
    Ok(())
}

fn read_audit_anchor(data_dir: &Path) -> Result<Option<AuditChainAnchor>, StorageError> {
    let p = audit_anchor_path(data_dir);
    if !p.exists() {
        return Ok(None);
    }
    let bytes = fs::read(p)?;
    let anchor: AuditChainAnchor = serde_json::from_slice(&bytes)?;
    Ok(Some(anchor))
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

fn append_audit_in_tx(
    tx: &Transaction<'_>,
    data_dir: &Path,
    audit_key: &LockedKey,
    event_type: &str,
    actor: &str,
    resource: &str,
    outcome: &str,
) -> Result<AuditLogEntry, StorageError> {
    let now = now_unix_seconds();
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
        audit_key, &prev_mac, seq, now, event_type, actor, resource, outcome,
    );

    tx.execute(
        "INSERT INTO audit_log (seq, timestamp, event_type, actor, resource, outcome, prev_mac_sha512, entry_mac_sha512)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        params![seq, now, event_type, actor, resource, outcome, prev_mac, entry_mac],
    )?;

    // SV-V2-02: Verify existing anchor continuity BEFORE tx.commit(), then persist anchor file
    // immediately after tx.commit() so failed SQLite commits cannot advance or desynchronize anchor.
    verify_audit_anchor_continuity(data_dir, audit_key, seq, &prev_mac)?;

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

impl Storage {
    /// Open or create the SQLCipher-encrypted database inside `data_dir` using the 256-bit HKDF-derived `sqlcipher_key`.
    /// Enables `cipher_memory_security = ON` BEFORE `PRAGMA key` so SQLCipher's initial key schedule
    /// and page-cache allocations use sanitized memory hooks from inception.
    pub fn open_encrypted(
        data_dir: &Path,
        sqlcipher_key: &LockedKey,
    ) -> Result<Self, StorageError> {
        ensure_secure_dir(data_dir)?;
        let db_path = database_path(data_dir);
        let conn = Connection::open(&db_path)?;
        set_mode_0600(&db_path)?;

        // Must precede `PRAGMA key` so internal SQLCipher cipher contexts are memory-sanitized.
        conn.execute_batch("PRAGMA cipher_memory_security = ON;")?;

        // Pass the 256-bit HKDF-SHA512 subkey directly via SQLCipher raw-key hex syntax (`x'<64-hex>'`).
        let raw_hex = Zeroizing::new(hex_encode(sqlcipher_key.as_bytes()));
        let key_pragma = Zeroizing::new(format!("PRAGMA key = \"x'{}'\";", raw_hex.as_str()));
        conn.execute_batch(key_pragma.as_str())?;

        conn.execute_batch(
            "PRAGMA cipher_page_size = 4096;
             PRAGMA cipher_hmac_algorithm = HMAC_SHA512;
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

             CREATE TABLE IF NOT EXISTS secret_version_watermarks (
                 path TEXT PRIMARY KEY,
                 max_version INTEGER NOT NULL
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

        let _ = set_mode_0600(&data_dir.join("vault.db-wal"));
        let _ = set_mode_0600(&data_dir.join("vault.db-shm"));

        Ok(Self {
            conn,
            data_dir: data_dir.to_path_buf(),
            db_path,
        })
    }

    /// Return the next monotonic version number for `path` (starts at `1` and never resets after delete, `SV-V2-03`).
    pub fn next_secret_version(&self, path: &str) -> Result<i64, StorageError> {
        let current: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(v) FROM (
                     SELECT MAX(version) AS v FROM secret_versions WHERE path = ?1
                     UNION ALL
                     SELECT max_version AS v FROM secret_version_watermarks WHERE path = ?1
                 )",
                params![path],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        Ok(current.unwrap_or(0) + 1)
    }

    /// Atomically persist a new secret version, update the active pointer row, and append the
    /// HMAC-SHA512 `secret.put` audit record in a single SQLite transaction.
    pub fn put_secret_versioned_audited(
        &mut self,
        path: &str,
        project: &str,
        version: i64,
        ciphertext: &[u8],
        nonce: &[u8; 12],
        audit_key: &LockedKey,
        actor: &str,
    ) -> Result<AuditLogEntry, StorageError> {
        let now = now_unix_seconds();
        let outcome = format!("v{version}");
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO secret_versions (path, version, project, ciphertext, nonce, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![path, version, project, ciphertext, nonce.as_slice(), now],
        )?;
        tx.execute(
            "INSERT INTO secret_version_watermarks (path, max_version)
             VALUES (?1, ?2)
             ON CONFLICT(path) DO UPDATE SET max_version = MAX(secret_version_watermarks.max_version, excluded.max_version)",
            params![path, version],
        )?;
        tx.execute(
            "DELETE FROM secret_versions WHERE path = ?1 AND version <= (?2 - ?3)",
            params![path, version, MAX_SECRET_VERSIONS_PER_PATH],
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
        let entry = append_audit_in_tx(
            &tx,
            &self.data_dir,
            audit_key,
            "secret.put",
            actor,
            path,
            &outcome,
        )?;
        tx.commit()?;
        commit_audit_anchor_file(
            &self.data_dir,
            audit_key,
            entry.seq,
            &entry.entry_mac_sha512,
        )?;
        Ok(entry)
    }

    /// Atomically persist a new secret version without an audit row (kept for direct storage callers).
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
            "INSERT INTO secret_version_watermarks (path, max_version)
             VALUES (?1, ?2)
             ON CONFLICT(path) DO UPDATE SET max_version = MAX(secret_version_watermarks.max_version, excluded.max_version)",
            params![path, version],
        )?;
        tx.execute(
            "DELETE FROM secret_versions WHERE path = ?1 AND version <= (?2 - ?3)",
            params![path, version, MAX_SECRET_VERSIONS_PER_PATH],
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
                     WHERE sv.path = ? AND sv.version = ? AND s.project = sv.project",
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

    /// Cryptographically shred a secret path and record `secret.delete` atomically in a single transaction.
    pub fn delete_secret_audited(
        &mut self,
        path: &str,
        audit_key: &LockedKey,
        actor: &str,
    ) -> Result<Option<AuditLogEntry>, StorageError> {
        let tx = self.conn.transaction()?;
        let _ = tx.execute("DELETE FROM secret_versions WHERE path = ?", params![path])?;
        let affected = tx.execute("DELETE FROM secrets WHERE path = ?", params![path])?;
        if affected == 0 {
            return Ok(None);
        }
        let entry = append_audit_in_tx(
            &tx,
            &self.data_dir,
            audit_key,
            "secret.delete",
            actor,
            path,
            "deleted",
        )?;
        tx.commit()?;
        commit_audit_anchor_file(
            &self.data_dir,
            audit_key,
            entry.seq,
            &entry.entry_mac_sha512,
        )?;
        Ok(Some(entry))
    }

    /// Cryptographically shred a secret path from both `secrets` and `secret_versions`.
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

    /// Persist a machine token and append `token.enroll` atomically in a single SQLite transaction.
    pub fn put_token_audited(
        &mut self,
        token_id: &str,
        token_hash_sha512: &str,
        project: &str,
        name: &str,
        allowed_paths: &[String],
        capabilities: &[String],
        expires_at: Option<i64>,
        audit_key: &LockedKey,
        actor: &str,
    ) -> Result<AuditLogEntry, StorageError> {
        let paths_json = serde_json::to_string(allowed_paths)?;
        let caps_json = serde_json::to_string(capabilities)?;
        let now = now_unix_seconds();

        let tx = self.conn.transaction()?;
        tx.execute(
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
        let entry = append_audit_in_tx(
            &tx,
            &self.data_dir,
            audit_key,
            "token.enroll",
            actor,
            token_id,
            "created",
        )?;
        tx.commit()?;
        commit_audit_anchor_file(
            &self.data_dir,
            audit_key,
            entry.seq,
            &entry.entry_mac_sha512,
        )?;
        Ok(entry)
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
            None => {
                // SV-V2-11: Equalize JSON array deserialization allocations on token_id miss
                let _ = std::hint::black_box(serde_json::from_str::<Vec<String>>("[\"*\"]"));
                let _ = std::hint::black_box(serde_json::from_str::<Vec<String>>("[\"read\"]"));
                Ok(None)
            }
        }
    }

    pub fn delete_token_audited(
        &mut self,
        token_id: &str,
        audit_key: &LockedKey,
        actor: &str,
    ) -> Result<Option<AuditLogEntry>, StorageError> {
        let tx = self.conn.transaction()?;
        let affected = tx.execute("DELETE FROM tokens WHERE token_id = ?", params![token_id])?;
        if affected == 0 {
            return Ok(None);
        }
        let entry = append_audit_in_tx(
            &tx,
            &self.data_dir,
            audit_key,
            "token.revoke",
            actor,
            token_id,
            "revoked",
        )?;
        tx.commit()?;
        commit_audit_anchor_file(
            &self.data_dir,
            audit_key,
            entry.seq,
            &entry.entry_mac_sha512,
        )?;
        Ok(Some(entry))
    }

    pub fn delete_token(&self, token_id: &str) -> Result<bool, StorageError> {
        let affected = self
            .conn
            .execute("DELETE FROM tokens WHERE token_id = ?", params![token_id])?;
        Ok(affected > 0)
    }

    /// Persist a new OIDC Workload Identity Binding and append `oidc.binding.enroll` atomically.
    pub fn put_oidc_binding_audited(
        &mut self,
        binding: &OidcBinding,
        audit_key: &LockedKey,
        actor: &str,
    ) -> Result<AuditLogEntry, StorageError> {
        let paths_json = serde_json::to_string(&binding.allowed_paths)?;
        let caps_json = serde_json::to_string(&binding.capabilities)?;
        let tx = self.conn.transaction()?;
        tx.execute(
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
        let entry = append_audit_in_tx(
            &tx,
            &self.data_dir,
            audit_key,
            "oidc.binding.enroll",
            actor,
            &binding.binding_id,
            "created",
        )?;
        tx.commit()?;
        commit_audit_anchor_file(
            &self.data_dir,
            audit_key,
            entry.seq,
            &entry.entry_mac_sha512,
        )?;
        Ok(entry)
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

    /// Delete an OIDC Workload Identity Binding and append `oidc.binding.revoke` atomically.
    pub fn delete_oidc_binding_audited(
        &mut self,
        binding_id: &str,
        audit_key: &LockedKey,
        actor: &str,
    ) -> Result<Option<AuditLogEntry>, StorageError> {
        let tx = self.conn.transaction()?;
        let affected = tx.execute(
            "DELETE FROM oidc_bindings WHERE binding_id = ?",
            params![binding_id],
        )?;
        if affected == 0 {
            return Ok(None);
        }
        let entry = append_audit_in_tx(
            &tx,
            &self.data_dir,
            audit_key,
            "oidc.binding.revoke",
            actor,
            binding_id,
            "revoked",
        )?;
        tx.commit()?;
        commit_audit_anchor_file(
            &self.data_dir,
            audit_key,
            entry.seq,
            &entry.entry_mac_sha512,
        )?;
        Ok(Some(entry))
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
        let count: i64 = self
            .conn
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
        let secrets_count: i64 = self
            .conn
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

    /// Append a tamper-evident, HMAC-SHA512 hash-chained audit event inside SQLCipher
    /// and update the external HMAC-signed high-water anchor (`vault.audit_anchor`).
    pub fn append_audit_event(
        &mut self,
        audit_key: &LockedKey,
        event_type: &str,
        actor: &str,
        resource: &str,
        outcome: &str,
    ) -> Result<AuditLogEntry, StorageError> {
        let tx = self.conn.transaction()?;
        let entry = append_audit_in_tx(
            &tx,
            &self.data_dir,
            audit_key,
            event_type,
            actor,
            resource,
            outcome,
        )?;
        tx.commit()?;
        commit_audit_anchor_file(
            &self.data_dir,
            audit_key,
            entry.seq,
            &entry.entry_mac_sha512,
        )?;
        Ok(entry)
    }

    /// Recompute and verify the entire HMAC-SHA512 hash chain from genesis (`seq = 1..=N`)
    /// AND verify the external tail anchor (`/data/vault.audit_anchor`) to detect tail truncation
    /// or full-table deletion.
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

        // An initialized vault MUST always have at least `seq = 1` (`sys.init`).
        if total == 0 {
            valid = false;
        }

        // Verify against external high-water anchor to catch tail-row deletion (`seq > K`)
        // or attacker deletion/corruption of the anchor file itself.
        match read_audit_anchor(&self.data_dir) {
            Ok(Some(anchor)) => {
                let expected_anchor_mac =
                    compute_anchor_mac(audit_key, anchor.seq, &anchor.entry_mac_sha512);
                if !constant_time_str_eq(&anchor.anchor_mac_sha512, &expected_anchor_mac)
                    || (total as i64) != anchor.seq
                    || !constant_time_str_eq(&expected_prev, &anchor.entry_mac_sha512)
                {
                    valid = false;
                }
            }
            Ok(None) | Err(_) => {
                valid = false;
            }
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

    /// Perform an online encrypted backup by verifying non-busy WAL checkpoint truncation,
    /// copying `vault.db` + `vault.envelope` (+ `vault.audit_anchor` if present) into a `0700`/`0600`
    /// snapshot directory, and computing a length-framed streaming SHA-256 digest of the snapshot (`SV-AUD-14`).
    pub fn create_encrypted_backup(&self) -> Result<BackupMetadata, StorageError> {
        let now = now_unix_seconds();
        let mut suffix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut suffix);
        let snapshot_id = format!("snap_{}_{}", now, hex_encode(suffix));
        self.create_encrypted_backup_with_id(&snapshot_id)
    }

    /// Perform an online encrypted backup after recording `sys.backup` so the snapshot itself
    /// includes its creation audit record and synchronized `vault.audit_anchor` (`SV-AUD-14`).
    pub fn create_encrypted_backup_audited(
        &mut self,
        audit_key: &LockedKey,
        actor: &str,
    ) -> Result<(BackupMetadata, AuditLogEntry), StorageError> {
        let now = now_unix_seconds();
        let mut suffix = [0u8; 4];
        rand::thread_rng().fill_bytes(&mut suffix);
        let snapshot_id = format!("snap_{}_{}", now, hex_encode(suffix));

        let entry =
            self.append_audit_event(audit_key, "sys.backup", actor, &snapshot_id, "created")?;
        let meta = self.create_encrypted_backup_with_id(&snapshot_id)?;
        Ok((meta, entry))
    }

    fn create_encrypted_backup_with_id(
        &self,
        snapshot_id: &str,
    ) -> Result<BackupMetadata, StorageError> {
        let busy_flag: i64 = self
            .conn
            .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |r| r.get(0))?;
        if busy_flag != 0 {
            return Err(StorageError::Io(std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "SQLCipher WAL checkpoint busy; retry backup when concurrent reader finishes",
            )));
        }

        let backups_root = self.data_dir.join("backups");
        ensure_secure_dir(&backups_root)?;
        let snap_dir = backups_root.join(snapshot_id);
        ensure_secure_dir(&snap_dir)?;

        let dst_db = snap_dir.join(DB_FILENAME);
        let dst_env = snap_dir.join(ENVELOPE_FILENAME);

        let mut hasher = Sha256::new();
        let db_bytes = copy_and_hash_file_0600_synced(&self.db_path, &dst_db, &mut hasher)?;
        let env_bytes =
            copy_and_hash_file_0600_synced(&envelope_path(&self.data_dir), &dst_env, &mut hasher)?;

        let anchor_src = audit_anchor_path(&self.data_dir);
        let anchor_bytes = if anchor_src.is_file() {
            copy_and_hash_file_0600_synced(
                &anchor_src,
                &snap_dir.join(AUDIT_ANCHOR_FILENAME),
                &mut hasher,
            )?
        } else {
            hasher.update(0u64.to_be_bytes());
            0
        };

        let sha256 = hex_encode(hasher.finalize());

        prune_excess_backups(&backups_root, MAX_BACKUP_SNAPSHOTS);

        Ok(BackupMetadata {
            snapshot_id: snapshot_id.to_string(),
            backup_dir: snap_dir.to_string_lossy().to_string(),
            total_bytes: db_bytes + env_bytes + anchor_bytes,
            sha256,
        })
    }
}

fn copy_and_hash_file_0600_synced(
    src: &Path,
    dst: &Path,
    hasher: &mut Sha256,
) -> std::io::Result<u64> {
    use std::io::Read;
    let mut src_file = fs::File::open(src)?;
    let file_len = src_file.metadata()?.len();
    hasher.update(file_len.to_be_bytes());

    let mut dst_file = fs::File::create(dst)?;
    set_mode_0600(dst)?;

    let mut buf = [0u8; 16 * 1024];
    let mut copied = 0u64;
    loop {
        let n = src_file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        dst_file.write_all(&buf[..n])?;
        hasher.update(&buf[..n]);
        copied += n as u64;
    }
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
    dirs.sort();
    if dirs.len() > keep_max {
        let remove_count = dirs.len() - keep_max;
        for old in dirs.into_iter().take(remove_count) {
            let _ = fs::remove_dir_all(old);
        }
    }
}
