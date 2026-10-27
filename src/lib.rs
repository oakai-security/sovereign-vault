//! Sovereign Vault v1.0 Core Library.
//!
//! Exposes cryptographic envelope key management, page-encrypted SQLCipher storage,
//! path-canonicalized ACLs, Universal OIDC & JWT workload identity verification,
//! opt-in enterprise telemetry + SIEM audit streaming, and the Axum HTTP API router.

#![allow(
    clippy::too_many_arguments,
    clippy::type_complexity,
    clippy::explicit_counter_loop,
    clippy::result_unit_err,
    clippy::manual_is_multiple_of
)]

pub mod acl;
pub mod crypto;
pub mod oidc;
pub mod server;
pub mod storage;
pub mod telemetry;
