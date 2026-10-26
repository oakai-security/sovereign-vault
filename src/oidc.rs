//! Universal OpenID Connect (OIDC) & RFC 7517/7519 JWT Workload Identity Engine.
//!
//! Enables zero-secret machine authentication ("Solving Secret Zero") across:
//! - GitHub Actions (`https://token.actions.githubusercontent.com`)
//! - GitLab CI/CD (`https://gitlab.com`)
//! - Microsoft Azure Entra ID / Managed Identities
//! - Google Cloud Workload Identity (`https://accounts.google.com`)
//! - Kubernetes ServiceAccount Projected Tokens
//! - Homelab / Bare-Metal OIDC Providers (`Authelia`, `Dex`, `Authentik`, `Keycloak`)
//!
//! Cryptographic verification uses pure-Rust `ring::signature` (`RS256`, `RS384`, `RS512`,
//! `ES256`, `ES384`, and `EdDSA` / Ed25519) with zero OpenSSL or C library bloat.

use crate::acl::{
    validate_capabilities, validate_identifier, validate_scope_pattern, ScopedToken,
};
use crate::storage::now_unix_seconds;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{
    RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::Duration;
use thiserror::Error;

/// Default background JWKS refresh interval: 15 minutes (900 seconds).
pub const DEFAULT_JWKS_REFRESH_INTERVAL_SECS: u64 = 900;
/// Maximum allowed clock skew when validating `nbf` / `exp` claims (30 seconds).
const CLOCK_SKEW_LEEWAY_SECS: i64 = 30;

#[derive(Debug, Error)]
pub enum OidcError {
    #[error("Malformed JWT format (expected 3 dot-separated Base64URL segments)")]
    MalformedJwt,
    #[error("Invalid Base64URL encoding in JWT segment")]
    InvalidBase64,
    #[error("Invalid JSON in JWT header or claims: {0}")]
    InvalidJson(String),
    #[error("Unsupported or disallowed JWT signing algorithm '{0}' (allowed: RS256, RS384, RS512, ES256, ES384, EdDSA)")]
    UnsupportedAlgorithm(String),
    #[error("JWT is missing required '{0}' claim")]
    MissingClaim(&'static str),
    #[error("JWT has expired (exp={0}, now={1})")]
    TokenExpired(i64, i64),
    #[error("JWT is not yet valid (nbf={0}, now={1})")]
    TokenNotYetValid(i64, i64),
    #[error("Untrusted OIDC issuer '{0}' (no matching OIDC binding configured)")]
    UntrustedIssuer(String),
    #[error("No matching JWKS public key found for issuer '{0}' (kid={1:?})")]
    SigningKeyNotFound(String, Option<String>),
    #[error("Cryptographic JWT signature verification failed")]
    SignatureVerificationFailed,
    #[error("JWT claims did not match any configured OIDC workload binding for issuer '{0}'")]
    NoMatchingBinding(String),
    #[error("OIDC discovery / JWKS fetch failed: {0}")]
    DiscoveryFailed(String),
}

/// Built-in OIDC provider presets for 1-command onboarding without manual URL lookups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OidcPreset {
    Github,
    Gitlab,
    Google,
    Azure,
    Kubernetes,
    Authelia,
    Dex,
    Custom,
}

impl OidcPreset {
    pub fn from_str_opt(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "github" | "github-actions" => Some(Self::Github),
            "gitlab" | "gitlab-ci" => Some(Self::Gitlab),
            "google" | "gcp" => Some(Self::Google),
            "azure" | "entra" | "entraid" => Some(Self::Azure),
            "kubernetes" | "k8s" => Some(Self::Kubernetes),
            "authelia" => Some(Self::Authelia),
            "dex" => Some(Self::Dex),
            "custom" => Some(Self::Custom),
            _ => None,
        }
    }

    /// Resolve default `(issuer, jwks_uri, default_subject_claim)` for a preset.
    pub fn resolve_defaults(
        &self,
        custom_issuer: Option<&str>,
        tenant_id: Option<&str>,
    ) -> Result<(String, String, String), &'static str> {
        match self {
            Self::Github => Ok((
                "https://token.actions.githubusercontent.com".to_string(),
                "https://token.actions.githubusercontent.com/.well-known/jwks".to_string(),
                "sub".to_string(),
            )),
            Self::Gitlab => Ok((
                "https://gitlab.com".to_string(),
                "https://gitlab.com/oauth/discovery/keys".to_string(),
                "sub".to_string(),
            )),
            Self::Google => Ok((
                "https://accounts.google.com".to_string(),
                "https://www.googleapis.com/oauth2/v3/certs".to_string(),
                "sub".to_string(),
            )),
            Self::Azure => {
                let tenant = tenant_id
                    .map(|t| t.trim())
                    .filter(|t| !t.is_empty())
                    .ok_or("Azure preset requires tenant_id (or explicit issuer URL)")?;
                Ok((
                    format!("https://login.microsoftonline.com/{tenant}/v2.0"),
                    format!("https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys"),
                    "sub".to_string(),
                ))
            }
            Self::Kubernetes => {
                let iss = custom_issuer
                    .map(|s| s.trim().trim_end_matches('/'))
                    .filter(|s| !s.is_empty())
                    .unwrap_or("https://kubernetes.default.svc.cluster.local");
                Ok((
                    iss.to_string(),
                    format!("{iss}/openid/v1/jwks"),
                    "sub".to_string(),
                ))
            }
            Self::Authelia => {
                let iss = custom_issuer
                    .map(|s| s.trim().trim_end_matches('/'))
                    .filter(|s| !s.is_empty())
                    .ok_or("Authelia preset requires --issuer URL (e.g. https://auth.chesty.home)")?;
                Ok((
                    iss.to_string(),
                    format!("{iss}/jwks.json"),
                    "sub".to_string(),
                ))
            }
            Self::Dex => {
                let iss = custom_issuer
                    .map(|s| s.trim().trim_end_matches('/'))
                    .filter(|s| !s.is_empty())
                    .ok_or("Dex preset requires --issuer URL (e.g. https://dex.chesty.home)")?;
                Ok((iss.to_string(), format!("{iss}/keys"), "sub".to_string()))
            }
            Self::Custom => {
                let iss = custom_issuer
                    .map(|s| s.trim().trim_end_matches('/'))
                    .filter(|s| !s.is_empty())
                    .ok_or("Custom OIDC binding requires --issuer URL")?;
                Ok((
                    iss.to_string(),
                    format!("{iss}/.well-known/jwks.json"),
                    "sub".to_string(),
                ))
            }
        }
    }
}

/// Persisted OIDC Workload Identity Binding stored inside SQLCipher `oidc_bindings`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcBinding {
    pub binding_id: String,
    pub name: String,
    pub project: String,
    pub issuer: String,
    pub audience: String,
    pub jwks_uri: String,
    pub subject_claim: String,
    pub subject_pattern: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inline_jwks_json: Option<String>,
    pub created_at: i64,
}

/// RFC 7517 JSON Web Key (JWK) public key entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwkKey {
    pub kty: String,
    #[serde(default)]
    pub kid: Option<String>,
    #[serde(default)]
    pub alg: Option<String>,
    #[serde(rename = "use", default)]
    pub key_use: Option<String>,
    #[serde(default)]
    pub crv: Option<String>,
    /// RSA modulus (Base64URL)
    #[serde(default)]
    pub n: Option<String>,
    /// RSA public exponent (Base64URL)
    #[serde(default)]
    pub e: Option<String>,
    /// EC / OKP X coordinate (Base64URL)
    #[serde(default)]
    pub x: Option<String>,
    /// EC Y coordinate (Base64URL)
    #[serde(default)]
    pub y: Option<String>,
}

/// RFC 7517 JSON Web Key Set (`{"keys": [...]}`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JwksDocument {
    pub keys: Vec<JwkKey>,
}

/// Standard OIDC Discovery Document (`/.well-known/openid-configuration`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OidcDiscoveryDocument {
    pub issuer: String,
    pub jwks_uri: String,
}

#[derive(Debug, Deserialize)]
struct JwtHeader {
    alg: String,
    #[serde(default)]
    kid: Option<String>,
}

/// Cached JWKS state for a single OIDC issuer.
#[derive(Debug, Clone)]
pub struct CachedIssuerKeys {
    pub issuer: String,
    pub jwks_uri: String,
    pub keys: Vec<JwkKey>,
    pub last_refreshed_unix: i64,
}

/// Thread-safe in-memory OIDC JWKS cache.
/// Refreshed automatically every 15 minutes, on binding creation, and on ad-hoc `/v1/sys/oidc/refresh`.
#[derive(Default, Clone)]
pub struct OidcJwksCache {
    inner: Arc<RwLock<HashMap<String, CachedIssuerKeys>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerRefreshReport {
    pub issuer: String,
    pub jwks_uri: String,
    pub keys_loaded: usize,
    pub status: String,
}

impl OidcJwksCache {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Seed or update an issuer's JWKS directly from a JSON string (`{"keys": [...]}`).
    pub fn upsert_from_json(
        &self,
        issuer: &str,
        jwks_uri: &str,
        jwks_json: &str,
    ) -> Result<usize, OidcError> {
        let doc: JwksDocument = serde_json::from_str(jwks_json)
            .map_err(|e| OidcError::InvalidJson(format!("Invalid JWKS JSON: {e}")))?;
        let count = doc.keys.len();
        let norm_iss = normalize_issuer(issuer);
        if let Ok(mut guard) = self.inner.write() {
            guard.insert(
                norm_iss.clone(),
                CachedIssuerKeys {
                    issuer: norm_iss,
                    jwks_uri: jwks_uri.to_string(),
                    keys: doc.keys,
                    last_refreshed_unix: now_unix_seconds(),
                },
            );
        }
        Ok(count)
    }

    /// Return total number of public keys currently cached across all issuers.
    pub fn total_cached_keys(&self) -> usize {
        self.inner
            .read()
            .map(|g| g.values().map(|v| v.keys.len()).sum())
            .unwrap_or(0)
    }

    /// Retrieve cached keys for a normalized issuer.
    pub fn get_issuer_keys(&self, issuer: &str) -> Option<CachedIssuerKeys> {
        let norm = normalize_issuer(issuer);
        self.inner.read().ok()?.get(&norm).cloned()
    }

    /// Refresh all unique issuers from the provided `OidcBinding` list.
    /// Inline JWKS bindings are loaded directly in memory; remote `jwks_uri` bindings are fetched via HTTPS/HTTP.
    pub async fn refresh_bindings(
        &self,
        bindings: &[OidcBinding],
    ) -> Vec<IssuerRefreshReport> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap_or_default();

        // Deduplicate by normalized issuer, merging any inline keys first
        let mut by_issuer: HashMap<String, (String, Vec<String>)> = HashMap::new();
        for b in bindings {
            let norm = normalize_issuer(&b.issuer);
            let entry = by_issuer
                .entry(norm)
                .or_insert_with(|| (b.jwks_uri.clone(), Vec::new()));
            if let Some(inline) = &b.inline_jwks_json {
                if !inline.trim().is_empty() {
                    entry.1.push(inline.clone());
                }
            }
        }

        let mut reports = Vec::with_capacity(by_issuer.len());
        for (issuer, (jwks_uri, inline_jsons)) in by_issuer {
            let mut merged_keys: Vec<JwkKey> = Vec::new();
            for raw in &inline_jsons {
                if let Ok(doc) = serde_json::from_str::<JwksDocument>(raw) {
                    merged_keys.extend(doc.keys);
                }
            }

            if !merged_keys.is_empty() {
                let count = merged_keys.len();
                if let Ok(mut guard) = self.inner.write() {
                    guard.insert(
                        issuer.clone(),
                        CachedIssuerKeys {
                            issuer: issuer.clone(),
                            jwks_uri: jwks_uri.clone(),
                            keys: merged_keys,
                            last_refreshed_unix: now_unix_seconds(),
                        },
                    );
                }
                reports.push(IssuerRefreshReport {
                    issuer,
                    jwks_uri,
                    keys_loaded: count,
                    status: "loaded_inline".to_string(),
                });
                continue;
            }

            // Remote fetch (supports direct jwks_uri or .well-known/openid-configuration fallback)
            match fetch_remote_jwks(&client, &issuer, &jwks_uri).await {
                Ok((resolved_uri, doc)) => {
                    let count = doc.keys.len();
                    if let Ok(mut guard) = self.inner.write() {
                        guard.insert(
                            issuer.clone(),
                            CachedIssuerKeys {
                                issuer: issuer.clone(),
                                jwks_uri: resolved_uri.clone(),
                                keys: doc.keys,
                                last_refreshed_unix: now_unix_seconds(),
                            },
                        );
                    }
                    reports.push(IssuerRefreshReport {
                        issuer,
                        jwks_uri: resolved_uri,
                        keys_loaded: count,
                        status: "refreshed_remote".to_string(),
                    });
                }
                Err(e) => {
                    // Preserve any existing cached keys on transient network error (Offline Resilience!)
                    let existing_count = self
                        .get_issuer_keys(&issuer)
                        .map(|c| c.keys.len())
                        .unwrap_or(0);
                    reports.push(IssuerRefreshReport {
                        issuer,
                        jwks_uri,
                        keys_loaded: existing_count,
                        status: format!("retained_cache ({e})"),
                    });
                }
            }
        }

        reports
    }
}

async fn fetch_remote_jwks(
    client: &reqwest::Client,
    issuer: &str,
    jwks_uri: &str,
) -> Result<(String, JwksDocument), OidcError> {
    if !jwks_uri.is_empty() {
        if let Ok(resp) = client.get(jwks_uri).send().await {
            if resp.status().is_success() {
                if let Ok(doc) = resp.json::<JwksDocument>().await {
                    if !doc.keys.is_empty() {
                        return Ok((jwks_uri.to_string(), doc));
                    }
                }
            }
        }
    }

    // Fallback: auto-discover via /.well-known/openid-configuration
    let well_known = format!("{}/.well-known/openid-configuration", issuer.trim_end_matches('/'));
    let disc_resp = client
        .get(&well_known)
        .send()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;
    if !disc_resp.status().is_success() {
        return Err(OidcError::DiscoveryFailed(format!(
            "HTTP {} from {}",
            disc_resp.status(),
            well_known
        )));
    }
    let disc: OidcDiscoveryDocument = disc_resp
        .json()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;
    let keys_resp = client
        .get(&disc.jwks_uri)
        .send()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;
    if !keys_resp.status().is_success() {
        return Err(OidcError::DiscoveryFailed(format!(
            "HTTP {} from {}",
            keys_resp.status(),
            disc.jwks_uri
        )));
    }
    let doc: JwksDocument = keys_resp
        .json()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;
    Ok((disc.jwks_uri, doc))
}

pub fn normalize_issuer(iss: &str) -> String {
    iss.trim().trim_end_matches('/').to_string()
}

/// Validate a subject/claim string against a binding pattern.
/// Supports:
/// - `"*"` (matches any non-empty claim value)
/// - Prefix/suffix/middle `*` glob wildcards (e.g. `"repo:oakai/api:*"`, `"system:serviceaccount:prod:*"`)
/// - Exact string equality
pub fn claim_matches_pattern(value: &str, pattern: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return value == pattern;
    }

    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.is_empty() {
        return true;
    }

    let mut pos = 0usize;
    for (idx, part) in parts.iter().enumerate() {
        if part.is_empty() {
            continue;
        }
        if idx == 0 && !pattern.starts_with('*') {
            if !value.starts_with(part) {
                return false;
            }
            pos = part.len();
            continue;
        }
        if idx == parts.len() - 1 && !pattern.ends_with('*') {
            return value[pos..].ends_with(part);
        }
        match value[pos..].find(part) {
            Some(found) => pos += found + part.len(),
            None => return false,
        }
    }
    true
}

/// Validate OIDC binding configuration fields prior to SQLCipher persistence.
pub fn validate_oidc_binding_fields(
    name: &str,
    project: &str,
    issuer: &str,
    audience: &str,
    subject_claim: &str,
    subject_pattern: &str,
    allowed_paths: &[String],
    capabilities: &[String],
) -> Result<(String, String, String, String, String, String, Vec<String>), &'static str> {
    let clean_name = validate_identifier(name)?;
    let clean_project = validate_identifier(project)?;
    let clean_issuer = normalize_issuer(issuer);
    if clean_issuer.is_empty() || clean_issuer.len() > 256 {
        return Err("OIDC issuer URL must be 1..=256 characters");
    }
    if !clean_issuer.starts_with("https://") && !clean_issuer.starts_with("http://") {
        return Err("OIDC issuer must start with https:// (or http:// for local loopback)");
    }

    let clean_aud = audience.trim();
    if clean_aud.is_empty() || clean_aud.len() > 128 {
        return Err("OIDC audience must be 1..=128 characters");
    }

    let clean_claim = subject_claim.trim();
    if clean_claim.is_empty() || clean_claim.len() > 64 {
        return Err("OIDC subject_claim must be 1..=64 characters");
    }

    let clean_pattern = subject_pattern.trim();
    if clean_pattern.is_empty() || clean_pattern.len() > 256 {
        return Err("OIDC subject_pattern must be 1..=256 characters");
    }

    if allowed_paths.is_empty() {
        return Err("allowed_paths must contain at least one path pattern");
    }
    let mut clean_paths = Vec::with_capacity(allowed_paths.len());
    for p in allowed_paths {
        clean_paths.push(validate_scope_pattern(p)?);
    }
    validate_capabilities(capabilities)?;

    Ok((
        clean_name,
        clean_project,
        clean_issuer,
        clean_aud.to_string(),
        clean_claim.to_string(),
        clean_pattern.to_string(),
        clean_paths,
    ))
}

/// Verify a single JWK against `signing_input` (`header_b64.payload_b64`) and `sig_bytes`.
pub fn verify_jwk_signature(
    jwk: &JwkKey,
    jwt_alg: &str,
    signing_input: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OidcError> {
    // If the JWK specifies an explicit algorithm, ensure it matches the JWT header `alg`
    if let Some(key_alg) = &jwk.alg {
        if !key_alg.is_empty() && key_alg != jwt_alg {
            return Err(OidcError::SignatureVerificationFailed);
        }
    }

    match jwt_alg {
        "RS256" | "RS384" | "RS512" => {
            if jwk.kty != "RSA" {
                return Err(OidcError::SignatureVerificationFailed);
            }
            let n_b64 = jwk
                .n
                .as_deref()
                .ok_or(OidcError::SignatureVerificationFailed)?;
            let e_b64 = jwk
                .e
                .as_deref()
                .ok_or(OidcError::SignatureVerificationFailed)?;
            let n_bytes = URL_SAFE_NO_PAD
                .decode(n_b64.trim())
                .map_err(|_| OidcError::InvalidBase64)?;
            let e_bytes = URL_SAFE_NO_PAD
                .decode(e_b64.trim())
                .map_err(|_| OidcError::InvalidBase64)?;

            let params = match jwt_alg {
                "RS256" => &RSA_PKCS1_2048_8192_SHA256,
                "RS384" => &RSA_PKCS1_2048_8192_SHA384,
                _ => &RSA_PKCS1_2048_8192_SHA512,
            };
            let pub_key = RsaPublicKeyComponents {
                n: &n_bytes,
                e: &e_bytes,
            };
            pub_key
                .verify(params, signing_input, sig_bytes)
                .map_err(|_| OidcError::SignatureVerificationFailed)
        }
        "ES256" | "ES384" => {
            if jwk.kty != "EC" {
                return Err(OidcError::SignatureVerificationFailed);
            }
            let x_b64 = jwk
                .x
                .as_deref()
                .ok_or(OidcError::SignatureVerificationFailed)?;
            let y_b64 = jwk
                .y
                .as_deref()
                .ok_or(OidcError::SignatureVerificationFailed)?;
            let x_bytes = URL_SAFE_NO_PAD
                .decode(x_b64.trim())
                .map_err(|_| OidcError::InvalidBase64)?;
            let y_bytes = URL_SAFE_NO_PAD
                .decode(y_b64.trim())
                .map_err(|_| OidcError::InvalidBase64)?;

            // Uncompressed ANSI X9.62 point format: 0x04 || X || Y
            let mut uncompressed = Vec::with_capacity(1 + x_bytes.len() + y_bytes.len());
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x_bytes);
            uncompressed.extend_from_slice(&y_bytes);

            let alg = if jwt_alg == "ES256" {
                &ECDSA_P256_SHA256_FIXED
            } else {
                &ECDSA_P384_SHA384_FIXED
            };
            let pub_key = UnparsedPublicKey::new(alg, &uncompressed);
            pub_key
                .verify(signing_input, sig_bytes)
                .map_err(|_| OidcError::SignatureVerificationFailed)
        }
        "EdDSA" => {
            if jwk.kty != "OKP" {
                return Err(OidcError::SignatureVerificationFailed);
            }
            let x_b64 = jwk
                .x
                .as_deref()
                .ok_or(OidcError::SignatureVerificationFailed)?;
            let x_bytes = URL_SAFE_NO_PAD
                .decode(x_b64.trim())
                .map_err(|_| OidcError::InvalidBase64)?;
            let pub_key = UnparsedPublicKey::new(&ED25519, &x_bytes);
            pub_key
                .verify(signing_input, sig_bytes)
                .map_err(|_| OidcError::SignatureVerificationFailed)
        }
        other => Err(OidcError::UnsupportedAlgorithm(other.to_string())),
    }
}

/// Cryptographically verify an OIDC JWT and resolve it to a least-privilege `ScopedToken`.
pub fn verify_oidc_jwt_and_resolve(
    raw_jwt: &str,
    bindings: &[OidcBinding],
    cache: &OidcJwksCache,
    now_unix: i64,
) -> Result<ScopedToken, OidcError> {
    let mut iter = raw_jwt.trim().split('.');
    let header_b64 = iter.next().ok_or(OidcError::MalformedJwt)?;
    let payload_b64 = iter.next().ok_or(OidcError::MalformedJwt)?;
    let sig_b64 = iter.next().ok_or(OidcError::MalformedJwt)?;
    if iter.next().is_some()
        || header_b64.is_empty()
        || payload_b64.is_empty()
        || sig_b64.is_empty()
    {
        return Err(OidcError::MalformedJwt);
    }

    let header_bytes = URL_SAFE_NO_PAD
        .decode(header_b64)
        .map_err(|_| OidcError::InvalidBase64)?;
    let header: JwtHeader = serde_json::from_slice(&header_bytes)
        .map_err(|e| OidcError::InvalidJson(e.to_string()))?;

    // Strict algorithm allowlist — block `none` and symmetric `HS*` key confusion attacks
    if !matches!(
        header.alg.as_str(),
        "RS256" | "RS384" | "RS512" | "ES256" | "ES384" | "EdDSA"
    ) {
        return Err(OidcError::UnsupportedAlgorithm(header.alg));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .map_err(|_| OidcError::InvalidBase64)?;
    let claims: serde_json::Value = serde_json::from_slice(&payload_bytes)
        .map_err(|e| OidcError::InvalidJson(e.to_string()))?;

    let raw_iss = claims
        .get("iss")
        .and_then(|v| v.as_str())
        .ok_or(OidcError::MissingClaim("iss"))?;
    let norm_iss = normalize_issuer(raw_iss);

    let exp = claims
        .get("exp")
        .and_then(|v| v.as_i64())
        .ok_or(OidcError::MissingClaim("exp"))?;
    if now_unix >= exp {
        return Err(OidcError::TokenExpired(exp, now_unix));
    }

    if let Some(nbf) = claims.get("nbf").and_then(|v| v.as_i64()) {
        if now_unix + CLOCK_SKEW_LEEWAY_SECS < nbf {
            return Err(OidcError::TokenNotYetValid(nbf, now_unix));
        }
    }

    // Filter bindings for this issuer
    let issuer_bindings: Vec<&OidcBinding> = bindings
        .iter()
        .filter(|b| normalize_issuer(&b.issuer) == norm_iss)
        .collect();
    if issuer_bindings.is_empty() {
        return Err(OidcError::UntrustedIssuer(norm_iss));
    }

    // Gather candidate JWKs from cache + any inline JWKs on bindings
    let mut candidate_keys: Vec<JwkKey> = Vec::new();
    if let Some(cached) = cache.get_issuer_keys(&norm_iss) {
        candidate_keys.extend(cached.keys);
    }
    for b in &issuer_bindings {
        if let Some(inline_json) = &b.inline_jwks_json {
            if let Ok(doc) = serde_json::from_str::<JwksDocument>(inline_json) {
                candidate_keys.extend(doc.keys);
            }
        }
    }

    if candidate_keys.is_empty() {
        return Err(OidcError::SigningKeyNotFound(norm_iss, header.kid));
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| OidcError::InvalidBase64)?;
    let signing_input = format!("{header_b64}.{payload_b64}");

    // Verify signature against matching `kid` (or any candidate key if `kid` is omitted)
    let mut sig_verified = false;
    let mut matched_kid = false;
    for jwk in &candidate_keys {
        if let (Some(jwt_kid), Some(key_kid)) = (&header.kid, &jwk.kid) {
            if jwt_kid != key_kid {
                continue;
            }
        }
        matched_kid = true;
        if verify_jwk_signature(jwk, &header.alg, signing_input.as_bytes(), &sig_bytes).is_ok() {
            sig_verified = true;
            break;
        }
    }

    if !matched_kid {
        return Err(OidcError::SigningKeyNotFound(norm_iss, header.kid));
    }
    if !sig_verified {
        return Err(OidcError::SignatureVerificationFailed);
    }

    // Evaluate audience (`aud` may be a string or an array of strings per RFC 7519)
    // and match `subject_claim` against `subject_pattern`
    for binding in issuer_bindings {
        if !jwt_audience_matches(&claims, &binding.audience) {
            continue;
        }
        let Some(claim_val) = claims.get(&binding.subject_claim).and_then(|v| v.as_str()) else {
            continue;
        };
        if claim_matches_pattern(claim_val, &binding.subject_pattern) {
            let safe_sub: String = claim_val
                .chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-' {
                        c
                    } else {
                        '_'
                    }
                })
                .take(48)
                .collect();

            return Ok(ScopedToken {
                token_id: format!("oidc:{}:{}", binding.name, safe_sub),
                token_hash_sha512: String::new(),
                project: binding.project.clone(),
                name: binding.name.clone(),
                allowed_paths: binding.allowed_paths.clone(),
                capabilities: binding.capabilities.clone(),
                expires_at: Some(exp),
            });
        }
    }

    Err(OidcError::NoMatchingBinding(norm_iss))
}

fn jwt_audience_matches(claims: &serde_json::Value, expected_aud: &str) -> bool {
    if expected_aud == "*" {
        return true;
    }
    match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == expected_aud,
        Some(serde_json::Value::Array(arr)) => {
            arr.iter().any(|v| v.as_str() == Some(expected_aud))
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};

    #[test]
    fn test_glob_claim_matching() {
        assert!(claim_matches_pattern(
            "repo:oakai/sovereign-vault:ref:refs/heads/main",
            "repo:oakai/sovereign-vault:*"
        ));
        assert!(!claim_matches_pattern(
            "repo:evil/sovereign-vault:ref:refs/heads/main",
            "repo:oakai/sovereign-vault:*"
        ));
        assert!(claim_matches_pattern(
            "system:serviceaccount:prod:backend-api",
            "system:serviceaccount:prod:*"
        ));
        assert!(claim_matches_pattern("basilone-gpu", "basilone-gpu"));
        assert!(!claim_matches_pattern("basilone-gpu-2", "basilone-gpu"));
    }

    #[test]
    fn test_eddsa_oidc_jwt_verification_and_acl_resolution() {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let keypair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let pub_x = URL_SAFE_NO_PAD.encode(keypair.public_key().as_ref());

        let jwks_json = serde_json::json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "kid": "chesty-key-1",
                "alg": "EdDSA",
                "use": "sig",
                "x": pub_x
            }]
        })
        .to_string();

        let cache = OidcJwksCache::new();
        cache
            .upsert_from_json(
                "https://auth.chesty.home",
                "https://auth.chesty.home/jwks.json",
                &jwks_json,
            )
            .unwrap();

        let now = 1_750_000_000i64;
        let binding = OidcBinding {
            binding_id: "oidc_basilone".to_string(),
            name: "basilone-worker".to_string(),
            project: "homelab-ai".to_string(),
            issuer: "https://auth.chesty.home".to_string(),
            audience: "sovereign-vault".to_string(),
            jwks_uri: "https://auth.chesty.home/jwks.json".to_string(),
            subject_claim: "sub".to_string(),
            subject_pattern: "node:basilone:*".to_string(),
            allowed_paths: vec!["models/*".to_string()],
            capabilities: vec!["read".to_string()],
            inline_jwks_json: None,
            created_at: now,
        };

        let hdr = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "EdDSA",
                "kid": "chesty-key-1",
                "typ": "JWT"
            }))
            .unwrap(),
        );
        let payload = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "iss": "https://auth.chesty.home/",
                "sub": "node:basilone:ollama",
                "aud": "sovereign-vault",
                "exp": now + 3600,
                "iat": now
            }))
            .unwrap(),
        );
        let signing_input = format!("{hdr}.{payload}");
        let sig = URL_SAFE_NO_PAD.encode(keypair.sign(signing_input.as_bytes()).as_ref());
        let jwt = format!("{signing_input}.{sig}");

        let resolved =
            verify_oidc_jwt_and_resolve(&jwt, &[binding], &cache, now).expect("valid OIDC JWT");
        assert_eq!(resolved.project, "homelab-ai");
        assert!(resolved.is_path_allowed("models/openai_key", "read", now));
        assert!(!resolved.is_path_allowed("billing/stripe_key", "read", now));
    }
}
