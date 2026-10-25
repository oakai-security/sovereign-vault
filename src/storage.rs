//! SQLite storage engine persisting encrypted blobs to attached volume.

use rusqlite::{params, Connection, Result};
use std::path::Path;

pub struct Storage {
    conn: Connection,
}

impl Storage {
    /// Initialize or open the SQLite database at the specified volume path.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self> {
        let conn = Connection::open(path)?;
        
        // Optimize for concurrent readers and atomic writes
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             CREATE TABLE IF NOT EXISTS meta (
                 key TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS secrets (
                 path TEXT PRIMARY KEY,
                 project TEXT NOT NULL,
                 ciphertext BLOB NOT NULL,
                 nonce BLOB NOT NULL,
                 updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
             );
             CREATE TABLE IF NOT EXISTS tokens (
                 token_id TEXT PRIMARY KEY,
                 token_hash TEXT NOT NULL,
                 project TEXT NOT NULL,
                 name TEXT NOT NULL,
                 allowed_paths TEXT NOT NULL,
                 capabilities TEXT NOT NULL,
                 created_at DATETIME DEFAULT CURRENT_TIMESTAMP
             );"
        )?;

        Ok(Self { conn })
    }

    pub fn is_initialized(&self) -> Result<bool> {
        let mut stmt = self.conn.prepare("SELECT count(*) FROM meta WHERE key = 'initialized'")?;
        let count: i64 = stmt.query_row([], |row| row.get(0))?;
        Ok(count > 0)
    }

    pub fn set_initialized(&self, salt_hex: &str) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO meta (key, value) VALUES ('initialized', 'true'), ('salt', ?)",
            params![salt_hex],
        )?;
        Ok(())
    }

    pub fn put_secret(&self, path: &str, project: &str, ciphertext: &[u8], nonce: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO secrets (path, project, ciphertext, nonce) VALUES (?, ?, ?, ?)",
            params![path, project, ciphertext, nonce],
        )?;
        Ok(())
    }

    pub fn get_secret(&self, path: &str) -> Result<Option<(Vec<u8>, Vec<u8>)>> {
        let mut stmt = self.conn.prepare("SELECT ciphertext, nonce FROM secrets WHERE path = ?")?;
        let mut rows = stmt.query(params![path])?;
        if let Some(row) = rows.next()? {
            let ct: Vec<u8> = row.get(0)?;
            let nonce: Vec<u8> = row.get(1)?;
            Ok(Some((ct, nonce)))
        } else {
            Ok(None)
        }
    }
}
