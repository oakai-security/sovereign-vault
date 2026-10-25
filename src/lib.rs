//! Sovereign Vault v0.2 Core Library.
//!
//! Exposes cryptographic envelope key management, page-encrypted SQLCipher storage,
//! path-canonicalized ACLs, opt-in enterprise telemetry, and the Axum HTTP API router.

pub mod acl;
pub mod crypto;
pub mod server;
pub mod storage;
pub mod telemetry;
