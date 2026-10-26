//! Sovereign Vault v0.3 Core Library.
//!
//! Exposes cryptographic envelope key management, page-encrypted SQLCipher storage,
//! path-canonicalized ACLs, Universal OIDC & JWT workload identity verification,
//! opt-in enterprise telemetry + SIEM audit streaming, and the Axum HTTP API router.

pub mod acl;
pub mod crypto;
pub mod oidc;
pub mod server;
pub mod storage;
pub mod telemetry;
