//! Universal OpenID Connect (OIDC) & RFC 7517/7519 JWT Workload Identity Engine.
//!
//! Hardened against SSRF (strict `https://`, redirect blocking, DNS-resolved private/IMDS IP filtering),
//! cross-project JWKS cache poisoning (per-`binding_id` key isolation & immediate revocation eviction),
//! elliptic curve / key-use confusion (`crv`, coordinate byte lengths, `use == "sig"`), and `kid` stripping.

use crate::acl::{validate_capabilities, validate_identifier, validate_scope_pattern, ScopedToken};
use crate::storage::now_unix_seconds;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ring::signature::{
    RsaPublicKeyComponents, UnparsedPublicKey, ECDSA_P256_SHA256_FIXED, ECDSA_P384_SHA384_FIXED,
    ED25519, RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512,
};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use thiserror::Error;

/// Default background JWKS refresh interval: 15 minutes (900 seconds).
pub const DEFAULT_JWKS_REFRESH_INTERVAL_SECS: u64 = 900;
/// Maximum allowed clock skew when validating `nbf` / `iat` claims (30 seconds).
const CLOCK_SKEW_LEEWAY_SECS: i64 = 30;
/// Maximum accepted OIDC JWT validity window (`exp - iat` and `exp - now`): 24 hours.
const MAX_OIDC_TOKEN_LIFETIME_SECS: i64 = 86_400;
/// Maximum outbound OIDC Discovery / JWKS HTTP response size (256 KiB, `SV-AUD-05`).
const MAX_OIDC_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
/// Maximum tracked `jti` anti-replay entries in RAM (`SV-AUD-03`).
const MAX_TRACKED_JTIS: usize = 16_384;

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
    #[error("JWT is not yet valid or exceeds max token lifetime (claim={0}, now={1})")]
    TokenNotYetValid(i64, i64),
    #[error("JWT jti replay detected (jti='{0}' already consumed)")]
    TokenReplayed(String),
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
                if !tenant
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
                {
                    return Err("Azure tenant_id contains invalid characters");
                }
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
                    .ok_or(
                        "Authelia preset requires --issuer URL (e.g. https://auth.chesty.home)",
                    )?;
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

/// Cached JWKS state isolated per `binding_id` (or manual issuer test seed).
#[derive(Debug, Clone)]
pub struct CachedIssuerKeys {
    pub issuer: String,
    pub jwks_uri: String,
    pub keys: Vec<JwkKey>,
    pub last_refreshed_unix: i64,
}

#[derive(Default)]
struct CacheStore {
    by_binding: HashMap<String, CachedIssuerKeys>,
    manual_by_issuer: HashMap<String, CachedIssuerKeys>,
    consumed_jtis: HashMap<(String, String), i64>,
}

/// Thread-safe in-memory OIDC JWKS cache isolated by `binding_id` to prevent cross-project
/// inline JWKS poisoning and ensure immediate key eviction upon binding revocation.
#[derive(Default, Clone)]
pub struct OidcJwksCache {
    inner: Arc<RwLock<CacheStore>>,
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
            inner: Arc::new(RwLock::new(CacheStore::default())),
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
            guard.manual_by_issuer.insert(
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

    /// Return total number of public keys currently cached across all active bindings and manual seeds.
    pub fn total_cached_keys(&self) -> usize {
        self.inner
            .read()
            .map(|g| {
                let binding_keys: usize = g.by_binding.values().map(|v| v.keys.len()).sum();
                let manual_keys: usize = g.manual_by_issuer.values().map(|v| v.keys.len()).sum();
                binding_keys + manual_keys
            })
            .unwrap_or(0)
    }

    /// Retrieve cached keys for a specific `binding_id`.
    pub fn get_binding_keys(&self, binding_id: &str) -> Option<CachedIssuerKeys> {
        self.inner.read().ok()?.by_binding.get(binding_id).cloned()
    }

    /// Retrieve manual test-seeded keys for a normalized issuer (never crosses `by_binding` isolation boundaries, `SV-V2-01`).
    pub fn get_issuer_keys(&self, issuer: &str) -> Option<CachedIssuerKeys> {
        let norm = normalize_issuer(issuer);
        let guard = self.inner.read().ok()?;
        guard.manual_by_issuer.get(&norm).cloned()
    }

    /// Purge all cached JWKS keys and replay entries on vault seal (`SV-V2-06`).
    pub fn clear_all(&self) {
        if let Ok(mut guard) = self.inner.write() {
            guard.by_binding.clear();
            guard.manual_by_issuer.clear();
            guard.consumed_jtis.clear();
        }
    }

    /// Check and atomically record an OIDC JWT `jti` claim inside the bounded anti-replay cache (`SV-AUD-03`, `SV-V2-08`).
    pub fn check_and_record_jti(
        &self,
        normalized_issuer: &str,
        jti: &str,
        exp_unix: i64,
        now_unix: i64,
    ) -> Result<(), OidcError> {
        let mut guard = self
            .inner
            .write()
            .map_err(|_| OidcError::DiscoveryFailed("JWKS cache lock poisoned".to_string()))?;
        let key = (normalized_issuer.to_string(), jti.to_string());
        if let Some(&existing_exp) = guard.consumed_jtis.get(&key) {
            if existing_exp > now_unix {
                return Err(OidcError::TokenReplayed(jti.to_string()));
            }
        }
        if guard.consumed_jtis.len() >= MAX_TRACKED_JTIS {
            guard.consumed_jtis.retain(|_, &mut exp| exp > now_unix);
            if guard.consumed_jtis.len() >= MAX_TRACKED_JTIS {
                return Err(OidcError::DiscoveryFailed(
                    "OIDC JTI anti-replay cache saturated; retry after token expiry".to_string(),
                ));
            }
        }
        guard.consumed_jtis.insert(key, exp_unix);
        Ok(())
    }

    /// Refresh all bindings in `bindings` with strict per-`binding_id` isolation, deduplicating
    /// identical `(issuer, jwks_uri)` network fetches within the pass and immediately purging
    /// any revoked `binding_id` entries from RAM.
    pub async fn refresh_bindings(&self, bindings: &[OidcBinding]) -> Vec<IssuerRefreshReport> {
        let active_ids: HashSet<String> = bindings.iter().map(|b| b.binding_id.clone()).collect();
        if let Ok(mut guard) = self.inner.write() {
            guard.by_binding.retain(|id, _| active_ids.contains(id));
        }

        let mut remote_memo: HashMap<(String, String), Result<(String, JwksDocument), OidcError>> =
            HashMap::new();
        let mut reports = Vec::with_capacity(bindings.len());

        for b in bindings {
            let norm_issuer = normalize_issuer(&b.issuer);

            // 1. Inline JWKS is isolated strictly to THIS binding_id (never poisons sibling bindings)
            if let Some(inline_raw) = b.inline_jwks_json.as_deref() {
                if !inline_raw.trim().is_empty() {
                    match serde_json::from_str::<JwksDocument>(inline_raw) {
                        Ok(doc) => {
                            let count = doc.keys.len();
                            if let Ok(mut guard) = self.inner.write() {
                                guard.by_binding.insert(
                                    b.binding_id.clone(),
                                    CachedIssuerKeys {
                                        issuer: norm_issuer.clone(),
                                        jwks_uri: b.jwks_uri.clone(),
                                        keys: doc.keys,
                                        last_refreshed_unix: now_unix_seconds(),
                                    },
                                );
                            }
                            reports.push(IssuerRefreshReport {
                                issuer: norm_issuer,
                                jwks_uri: b.jwks_uri.clone(),
                                keys_loaded: count,
                                status: "loaded_inline".to_string(),
                            });
                            continue;
                        }
                        Err(e) => {
                            tracing::warn!(
                                binding_id = %b.binding_id,
                                error = %e,
                                "Invalid inline_jwks_json on OIDC binding"
                            );
                            reports.push(IssuerRefreshReport {
                                issuer: norm_issuer,
                                jwks_uri: b.jwks_uri.clone(),
                                keys_loaded: 0,
                                status: "invalid_inline_jwks".to_string(),
                            });
                            continue;
                        }
                    }
                }
            }

            // 2. Remote HTTPS JWKS fetch (SSRF-hardened, no redirects, DNS-validated)
            let memo_key = (norm_issuer.clone(), b.jwks_uri.clone());
            let fetch_result = if let Some(existing) = remote_memo.get(&memo_key) {
                match existing {
                    Ok((u, d)) => Ok((u.clone(), d.clone())),
                    Err(e) => Err(OidcError::DiscoveryFailed(e.to_string())),
                }
            } else {
                let res = fetch_remote_jwks(&norm_issuer, &b.jwks_uri).await;
                let cloned = match &res {
                    Ok((u, d)) => Ok((u.clone(), d.clone())),
                    Err(e) => Err(OidcError::DiscoveryFailed(e.to_string())),
                };
                remote_memo.insert(memo_key, res);
                cloned
            };

            match fetch_result {
                Ok((resolved_uri, doc)) => {
                    let count = doc.keys.len();
                    if let Ok(mut guard) = self.inner.write() {
                        guard.by_binding.insert(
                            b.binding_id.clone(),
                            CachedIssuerKeys {
                                issuer: norm_issuer.clone(),
                                jwks_uri: resolved_uri.clone(),
                                keys: doc.keys,
                                last_refreshed_unix: now_unix_seconds(),
                            },
                        );
                    }
                    reports.push(IssuerRefreshReport {
                        issuer: norm_issuer,
                        jwks_uri: resolved_uri,
                        keys_loaded: count,
                        status: "refreshed_remote".to_string(),
                    });
                }
                Err(e) => {
                    tracing::warn!(
                        binding_id = %b.binding_id,
                        issuer = %norm_issuer,
                        error = %e,
                        "Remote OIDC JWKS refresh failed"
                    );
                    let existing_count = self
                        .get_binding_keys(&b.binding_id)
                        .map(|c| c.keys.len())
                        .unwrap_or(0);
                    let status_label = if existing_count > 0 {
                        "retained_cache"
                    } else {
                        "fetch_failed"
                    };
                    reports.push(IssuerRefreshReport {
                        issuer: norm_issuer,
                        jwks_uri: b.jwks_uri.clone(),
                        keys_loaded: existing_count,
                        status: status_label.to_string(),
                    });
                }
            }
        }

        reports
    }
}

fn env_flag_enabled(var_name: &str) -> bool {
    std::env::var(var_name)
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false)
}

/// Evaluate whether an IP address is disallowed as an outbound OIDC target.
/// Cloud metadata / link-local (`169.254.0.0/16`, `fe80::/10`), unspecified, broadcast, and multicast
/// ranges are UNCONDITIONALLY blocked under all flags. Loopback and RFC1918/ULA private ranges are
/// blocked unless explicitly opted into via `allow_loopback` / `allow_private`.
pub fn is_disallowed_oidc_ip(ip: IpAddr, allow_loopback: bool, allow_private: bool) -> bool {
    let v4 = match ip {
        IpAddr::V4(v4) => Some(v4),
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            // SV-AUD-05: Extract embedded IPv4 from ::ffff:0:0/96, IPv4-compatible ::a.b.c.d,
            // or RFC 6052 / RFC 8215 NAT64 prefixes (64:ff9b::/96 and 64:ff9b:1::/48).
            if let Some(mapped) = v6.to_ipv4() {
                if !v6.is_unspecified() && !v6.is_loopback() {
                    Some(mapped)
                } else {
                    None
                }
            } else if segs[0] == 0x0064 && segs[1] == 0xff9b && (segs[2] == 0 || segs[2] == 1) {
                let hi = segs[6].to_be_bytes();
                let lo = segs[7].to_be_bytes();
                Some(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]))
            } else if segs[0] == 0x2002 {
                // RFC 3056 6to4 prefix (2002::/16) embeds IPv4 in segments 1 and 2 (`SV-V2-12`)
                let hi = segs[1].to_be_bytes();
                let lo = segs[2].to_be_bytes();
                Some(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]))
            } else if segs[0] == 0x2001 && segs[1] == 0x0000 {
                // RFC 4380 Teredo prefix (2001:0000::/32) embeds XOR-inverted IPv4 in segments 6 and 7 (`SV-V2-12`)
                let hi = (!segs[6]).to_be_bytes();
                let lo = (!segs[7]).to_be_bytes();
                Some(Ipv4Addr::new(hi[0], hi[1], lo[0], lo[1]))
            } else {
                None
            }
        }
    };

    if let Some(ipv4) = v4 {
        let oct = ipv4.octets();
        // Unconditionally block cloud IMDS link-local (169.254.0.0/16), 0.0.0.0/8, multicast (224.0.0.0/4), broadcast, CGNAT metadata
        if oct[0] == 0
            || (oct[0] == 169 && oct[1] == 254)
            || (oct[0] >= 224)
            || ipv4 == Ipv4Addr::BROADCAST
        {
            return true;
        }
        if ipv4.is_loopback() {
            return !allow_loopback;
        }
        if ipv4.is_private()
            || (oct[0] == 100 && (oct[1] & 0b1100_0000) == 0b0100_0000)
            || (oct[0] == 192 && oct[1] == 0 && oct[2] == 0)
            || (oct[0] == 198 && (oct[1] == 18 || oct[1] == 19))
        {
            return !allow_private;
        }
        return false;
    }

    match ip {
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            // Unconditionally block unspecified (::), link-local (fe80::/10), and multicast (ff00::/8)
            if v6.is_unspecified() || (seg0 & 0xffc0) == 0xfe80 || (seg0 & 0xff00) == 0xff00 {
                return true;
            }
            if v6.is_loopback() {
                return !allow_loopback;
            }
            // Unique Local Addresses (fc00::/7)
            if (seg0 & 0xfe00) == 0xfc00 {
                return !allow_private;
            }
            false
        }
        IpAddr::V4(_) => unreachable!(),
    }
}

/// Parse and validate an OIDC issuer or JWKS URL, enforcing `https://` and SSRF host rules.
/// Returns `(normalized_url, host_without_brackets, port)`.
pub fn parse_and_validate_oidc_url(
    raw_url: &str,
    allow_loopback_http: bool,
    allow_private_ips: bool,
) -> Result<(String, String, u16), &'static str> {
    let trimmed = raw_url.trim().trim_end_matches('/');
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err("OIDC URL must be 1..=256 characters");
    }
    if trimmed
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '#' || c == '@')
    {
        return Err(
            "OIDC URL must not contain whitespace, control characters, fragments, or userinfo",
        );
    }

    let (is_https, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        (true, r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        (false, r)
    } else {
        return Err("OIDC URL must use https://");
    };

    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() {
        return Err("OIDC URL is missing host authority");
    }

    let (host, port) = if let Some(after_bracket) = authority.strip_prefix('[') {
        let (v6_host, rem) = after_bracket
            .split_once(']')
            .ok_or("Malformed IPv6 host in OIDC URL")?;
        let p = if let Some(port_str) = rem.strip_prefix(':') {
            port_str
                .parse::<u16>()
                .map_err(|_| "Invalid port in OIDC URL")?
        } else if rem.is_empty() {
            if is_https {
                443
            } else {
                80
            }
        } else {
            return Err("Invalid authority suffix in OIDC URL");
        };
        (v6_host.to_string(), p)
    } else if let Some((h, port_str)) = authority.rsplit_once(':') {
        let p = port_str
            .parse::<u16>()
            .map_err(|_| "Invalid port in OIDC URL")?;
        (h.to_string(), p)
    } else {
        (authority.to_string(), if is_https { 443 } else { 80 })
    };

    if host.is_empty() || port == 0 {
        return Err("OIDC URL host or port cannot be empty");
    }

    let is_loopback_host =
        host.eq_ignore_ascii_case("localhost") || host == "127.0.0.1" || host == "::1";
    if !is_https && !(allow_loopback_http && is_loopback_host) {
        return Err(
            "OIDC URL must use https:// (cleartext http:// is forbidden unless SV_ALLOW_INSECURE_OIDC_LOOPBACK=true on loopback)",
        );
    }

    if is_loopback_host && !allow_loopback_http && !allow_private_ips {
        return Err("Loopback OIDC endpoints are blocked by default SSRF policy");
    }

    if let Ok(literal_ip) = host.parse::<IpAddr>() {
        if is_disallowed_oidc_ip(literal_ip, allow_loopback_http, allow_private_ips) {
            return Err(
                "OIDC URL targets a disallowed loopback, link-local metadata (169.254.0.0/16), or private IP address",
            );
        }
    }

    Ok((trimmed.to_string(), host, port))
}

async fn safe_get_json<T: serde::de::DeserializeOwned>(raw_url: &str) -> Result<T, OidcError> {
    let allow_loopback = env_flag_enabled("SV_ALLOW_INSECURE_OIDC_LOOPBACK");
    let allow_private = env_flag_enabled("SV_ALLOW_PRIVATE_OIDC_ENDPOINTS");

    let (clean_url, host, port) =
        parse_and_validate_oidc_url(raw_url, allow_loopback, allow_private)
            .map_err(|msg| OidcError::DiscoveryFailed(msg.to_string()))?;

    let mut validated_addrs: Vec<SocketAddr> = Vec::new();
    if let Ok(ip) = host.parse::<IpAddr>() {
        if is_disallowed_oidc_ip(ip, allow_loopback, allow_private) {
            return Err(OidcError::DiscoveryFailed(
                "Blocked SSRF target IP address".to_string(),
            ));
        }
        validated_addrs.push(SocketAddr::new(ip, port));
    } else {
        let resolved = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| OidcError::DiscoveryFailed(format!("DNS lookup failed: {e}")))?;
        for sock_addr in resolved {
            if is_disallowed_oidc_ip(sock_addr.ip(), allow_loopback, allow_private) {
                return Err(OidcError::DiscoveryFailed(
                    "DNS resolved OIDC host to a blocked private, loopback, or metadata IP"
                        .to_string(),
                ));
            }
            validated_addrs.push(sock_addr);
        }
    }

    let pinned_addr = validated_addrs
        .first()
        .copied()
        .ok_or_else(|| OidcError::DiscoveryFailed("No valid DNS records found".to_string()))?;

    // Build a redirect-free reqwest client pinned to the validated IP to defeat DNS rebinding & 302 SSRF.
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .redirect(reqwest::redirect::Policy::none());
    if host.parse::<IpAddr>().is_err() {
        builder = builder.resolve(&host, pinned_addr);
    }
    let client = builder
        .build()
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;

    let mut resp = client
        .get(&clean_url)
        .send()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(OidcError::DiscoveryFailed(format!(
            "Upstream returned HTTP {}",
            resp.status().as_u16()
        )));
    }
    if let Some(len) = resp.content_length() {
        if len > MAX_OIDC_HTTP_RESPONSE_BYTES as u64 {
            return Err(OidcError::DiscoveryFailed(
                "OIDC response Content-Length exceeded 256 KiB safety limit".to_string(),
            ));
        }
    }
    let mut bytes = Vec::with_capacity(8192);
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| OidcError::DiscoveryFailed(e.to_string()))?
    {
        if bytes.len().saturating_add(chunk.len()) > MAX_OIDC_HTTP_RESPONSE_BYTES {
            return Err(OidcError::DiscoveryFailed(
                "OIDC response body exceeded 256 KiB safety limit".to_string(),
            ));
        }
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice::<T>(&bytes).map_err(|e| OidcError::DiscoveryFailed(e.to_string()))
}

async fn fetch_remote_jwks(
    issuer: &str,
    jwks_uri: &str,
) -> Result<(String, JwksDocument), OidcError> {
    if !jwks_uri.is_empty() {
        if let Ok(doc) = safe_get_json::<JwksDocument>(jwks_uri).await {
            if !doc.keys.is_empty() {
                return Ok((jwks_uri.to_string(), doc));
            }
        }
    }

    // Fallback: auto-discover via /.well-known/openid-configuration with strict OIDC Discovery 1.0 issuer verification
    let well_known = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let disc: OidcDiscoveryDocument = safe_get_json(&well_known).await?;
    if normalize_issuer(&disc.issuer) != normalize_issuer(issuer) {
        return Err(OidcError::DiscoveryFailed(
            "OIDC discovery document issuer mismatch".to_string(),
        ));
    }

    let doc: JwksDocument = safe_get_json(&disc.jwks_uri).await?;
    Ok((disc.jwks_uri, doc))
}

pub fn normalize_issuer(iss: &str) -> String {
    iss.trim().trim_end_matches('/').to_string()
}

/// Validate a subject/claim string against a binding pattern with full backtracking (`SV-AUD-06`).
/// Interior wildcards immediately followed by `:` (`*:`) do not match across `:` hierarchy delimiters,
/// preventing cross-field claim injection while trailing `*` continues to match arbitrary suffixes.
pub fn claim_matches_pattern(value: &str, pattern: &str) -> bool {
    if value.is_empty() || value.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return false;
    }
    if pattern == "*" {
        return true;
    }
    if !pattern.contains('*') {
        return value == pattern;
    }

    fn match_bytes(v: &[u8], p: &[u8]) -> bool {
        if p.is_empty() {
            return v.is_empty();
        }
        if p[0] == b'*' {
            let mut next_p = 1usize;
            while next_p < p.len() && p[next_p] == b'*' {
                next_p += 1;
            }
            if next_p == p.len() {
                return true;
            }
            // If this wildcard is immediately followed by ':', forbid matching across ':'
            let stop_on_colon = p[next_p] == b':';
            for i in 0..=v.len() {
                if stop_on_colon && i > 0 && v[i - 1] == b':' {
                    break;
                }
                if match_bytes(&v[i..], &p[next_p..]) {
                    return true;
                }
            }
            return false;
        }
        if !v.is_empty() && p[0] == v[0] {
            return match_bytes(&v[1..], &p[1..]);
        }
        false
    }

    match_bytes(value.as_bytes(), pattern.as_bytes())
}

/// Validate OIDC binding configuration fields (including `issuer` and `jwks_uri` SSRF checks)
/// prior to SQLCipher persistence.
pub fn validate_oidc_binding_fields_with_jwks(
    name: &str,
    project: &str,
    issuer: &str,
    jwks_uri: &str,
    audience: &str,
    subject_claim: &str,
    subject_pattern: &str,
    allowed_paths: &[String],
    capabilities: &[String],
) -> Result<
    (
        String,
        String,
        String,
        String,
        String,
        String,
        String,
        Vec<String>,
    ),
    &'static str,
> {
    let clean_name = validate_identifier(name)?;
    let clean_project = validate_identifier(project)?;

    let allow_loopback = env_flag_enabled("SV_ALLOW_INSECURE_OIDC_LOOPBACK");
    let allow_private = env_flag_enabled("SV_ALLOW_PRIVATE_OIDC_ENDPOINTS");

    let (clean_issuer, _, _) = parse_and_validate_oidc_url(issuer, allow_loopback, allow_private)?;
    let (clean_jwks_uri, _, _) =
        parse_and_validate_oidc_url(jwks_uri, allow_loopback, allow_private)?;

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
        clean_jwks_uri,
        clean_aud.to_string(),
        clean_claim.to_string(),
        clean_pattern.to_string(),
        clean_paths,
    ))
}

/// Backward-compatible wrapper validating OIDC binding fields with default JWKS URL derived from `issuer`.
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
    let default_jwks = format!(
        "{}/.well-known/jwks.json",
        issuer.trim().trim_end_matches('/')
    );
    let (n, p, iss, _jwks, aud, clm, pat, paths) = validate_oidc_binding_fields_with_jwks(
        name,
        project,
        issuer,
        &default_jwks,
        audience,
        subject_claim,
        subject_pattern,
        allowed_paths,
        capabilities,
    )?;
    Ok((n, p, iss, aud, clm, pat, paths))
}

/// Verify a single JWK against `signing_input` (`header_b64.payload_b64`) and `sig_bytes`,
/// enforcing RFC 7517 `use == "sig"`, `alg`, `kty`, `crv`, and exact EC/OKP coordinate lengths.
pub fn verify_jwk_signature(
    jwk: &JwkKey,
    jwt_alg: &str,
    signing_input: &[u8],
    sig_bytes: &[u8],
) -> Result<(), OidcError> {
    // Reject encryption or non-signature keys (`use: "enc"`).
    if let Some(u) = jwk.key_use.as_deref() {
        if !u.is_empty() && u != "sig" {
            return Err(OidcError::SignatureVerificationFailed);
        }
    }

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
            let (expected_crv, coord_len, alg) = if jwt_alg == "ES256" {
                ("P-256", 32usize, &ECDSA_P256_SHA256_FIXED)
            } else {
                ("P-384", 48usize, &ECDSA_P384_SHA384_FIXED)
            };
            if jwk.crv.as_deref() != Some(expected_crv) {
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
            if x_bytes.len() != coord_len || y_bytes.len() != coord_len {
                return Err(OidcError::SignatureVerificationFailed);
            }

            let mut uncompressed = Vec::with_capacity(1 + 2 * coord_len);
            uncompressed.push(0x04);
            uncompressed.extend_from_slice(&x_bytes);
            uncompressed.extend_from_slice(&y_bytes);

            let pub_key = UnparsedPublicKey::new(alg, &uncompressed);
            pub_key
                .verify(signing_input, sig_bytes)
                .map_err(|_| OidcError::SignatureVerificationFailed)
        }
        "EdDSA" => {
            if jwk.kty != "OKP" || jwk.crv.as_deref() != Some("Ed25519") {
                return Err(OidcError::SignatureVerificationFailed);
            }
            let x_b64 = jwk
                .x
                .as_deref()
                .ok_or(OidcError::SignatureVerificationFailed)?;
            let x_bytes = URL_SAFE_NO_PAD
                .decode(x_b64.trim())
                .map_err(|_| OidcError::InvalidBase64)?;
            if x_bytes.len() != 32 {
                return Err(OidcError::SignatureVerificationFailed);
            }
            let pub_key = UnparsedPublicKey::new(&ED25519, &x_bytes);
            pub_key
                .verify(signing_input, sig_bytes)
                .map_err(|_| OidcError::SignatureVerificationFailed)
        }
        other => Err(OidcError::UnsupportedAlgorithm(other.to_string())),
    }
}

fn verify_against_keyset(
    keys: &[JwkKey],
    jwt_kid: Option<&str>,
    jwt_alg: &str,
    signing_input: &[u8],
    sig_bytes: &[u8],
) -> Result<(), (bool, OidcError)> {
    let mut matched_kid = false;
    for jwk in keys {
        let key_matches = match (jwt_kid, jwk.kid.as_deref()) {
            (Some(h_kid), Some(k_kid)) => h_kid == k_kid,
            // Allow matching an untagged JWK only when it is the sole key in the set
            (Some(_), None) => keys.len() == 1,
            // Prevent `kid`-stripping in JWT header from matching `kid`-tagged keys
            (None, None) => true,
            (None, Some(_)) => false,
        };
        if !key_matches {
            continue;
        }
        matched_kid = true;
        if verify_jwk_signature(jwk, jwt_alg, signing_input, sig_bytes).is_ok() {
            return Ok(());
        }
    }
    Err((matched_kid, OidcError::SignatureVerificationFailed))
}

/// Cryptographically verify an OIDC JWT and resolve it to a least-privilege `ScopedToken`,
/// strictly isolating JWKS trust per binding.
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
    let header: JwtHeader =
        serde_json::from_slice(&header_bytes).map_err(|e| OidcError::InvalidJson(e.to_string()))?;

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
    // SV-AUD-03: Enforce maximum 24h remaining token lifetime even if `iat` is omitted
    if exp.saturating_sub(now_unix) > MAX_OIDC_TOKEN_LIFETIME_SECS + CLOCK_SKEW_LEEWAY_SECS {
        return Err(OidcError::TokenNotYetValid(exp, now_unix));
    }

    if let Some(nbf_val) = claims.get("nbf") {
        let nbf = nbf_val
            .as_i64()
            .ok_or_else(|| OidcError::InvalidJson("nbf claim must be an integer".to_string()))?;
        if now_unix + CLOCK_SKEW_LEEWAY_SECS < nbf {
            return Err(OidcError::TokenNotYetValid(nbf, now_unix));
        }
    }

    if let Some(iat_val) = claims.get("iat") {
        let iat = iat_val
            .as_i64()
            .ok_or_else(|| OidcError::InvalidJson("iat claim must be an integer".to_string()))?;
        if iat > now_unix + CLOCK_SKEW_LEEWAY_SECS
            || exp < iat
            || exp.saturating_sub(iat) > MAX_OIDC_TOKEN_LIFETIME_SECS
        {
            return Err(OidcError::TokenNotYetValid(iat, now_unix));
        }
    }

    let jti_opt = match claims.get("jti") {
        Some(v) => {
            let s = v
                .as_str()
                .map(|s| s.trim())
                .filter(|s| !s.is_empty() && s.len() <= 128)
                .ok_or_else(|| {
                    OidcError::InvalidJson("jti claim must be a 1..=128 char string".to_string())
                })?;
            Some(s.to_string())
        }
        None => None,
    };

    let issuer_bindings: Vec<&OidcBinding> = bindings
        .iter()
        .filter(|b| normalize_issuer(&b.issuer) == norm_iss)
        .collect();
    if issuer_bindings.is_empty() {
        return Err(OidcError::UntrustedIssuer(norm_iss));
    }

    let sig_bytes = URL_SAFE_NO_PAD
        .decode(sig_b64)
        .map_err(|_| OidcError::InvalidBase64)?;
    let signing_input = format!("{header_b64}.{payload_b64}");

    let mut any_claim_matched = false;
    let mut any_keys_available = false;
    let mut any_kid_matched = false;
    let mut any_sig_verified = false;

    for binding in issuer_bindings {
        // Evaluate fast claim predicates BEFORE expensive RSA/ECDSA signature verification (`SV-V2-08`)
        if !jwt_audience_matches(&claims, &binding.audience) {
            continue;
        }
        let Some(claim_val) = claims.get(&binding.subject_claim).and_then(|v| v.as_str()) else {
            continue;
        };
        if !claim_matches_pattern(claim_val, &binding.subject_pattern) {
            continue;
        }
        any_claim_matched = true;

        // Resolve ONLY the keys trusted for this specific binding:
        let binding_keys: Vec<JwkKey> = match binding.inline_jwks_json.as_deref() {
            Some(inline) if !inline.trim().is_empty() => {
                serde_json::from_str::<JwksDocument>(inline)
                    .map(|d| d.keys)
                    .unwrap_or_default()
            }
            _ => cache
                .get_binding_keys(&binding.binding_id)
                .or_else(|| cache.get_issuer_keys(&norm_iss))
                .map(|c| c.keys)
                .unwrap_or_default(),
        };

        if binding_keys.is_empty() {
            continue;
        }
        any_keys_available = true;

        match verify_against_keyset(
            &binding_keys,
            header.kid.as_deref(),
            &header.alg,
            signing_input.as_bytes(),
            &sig_bytes,
        ) {
            Ok(()) => {
                any_kid_matched = true;
                any_sig_verified = true;
            }
            Err((matched_kid, _)) => {
                if matched_kid {
                    any_kid_matched = true;
                }
                continue;
            }
        }

        if let Some(ref jti) = jti_opt {
            cache.check_and_record_jti(&norm_iss, jti, exp, now_unix)?;
        }
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

    if !any_claim_matched {
        return Err(OidcError::NoMatchingBinding(norm_iss));
    }
    if !any_keys_available || !any_kid_matched {
        return Err(OidcError::SigningKeyNotFound(norm_iss, header.kid));
    }
    if !any_sig_verified {
        return Err(OidcError::SignatureVerificationFailed);
    }
    Err(OidcError::NoMatchingBinding(norm_iss))
}

fn jwt_audience_matches(claims: &serde_json::Value, expected_aud: &str) -> bool {
    if expected_aud == "*" {
        return true;
    }
    match claims.get("aud") {
        Some(serde_json::Value::String(s)) => s == expected_aud,
        Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.as_str() == Some(expected_aud)),
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
    fn test_ssrf_url_and_ip_blocking() {
        // Reject cleartext http://, cloud metadata IMDS, loopback, and RFC1918 by default
        assert!(parse_and_validate_oidc_url(
            "http://token.actions.githubusercontent.com",
            false,
            false
        )
        .is_err());
        assert!(parse_and_validate_oidc_url(
            "https://169.254.169.254/latest/meta-data",
            true,
            true
        )
        .is_err());
        assert!(parse_and_validate_oidc_url("https://127.0.0.1:8443/jwks", false, false).is_err());
        assert!(parse_and_validate_oidc_url("https://10.0.0.5/jwks", false, false).is_err());
        assert!(parse_and_validate_oidc_url("https://accounts.google.com", false, false).is_ok());
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
            verify_oidc_jwt_and_resolve(&jwt, std::slice::from_ref(&binding), &cache, now)
                .expect("valid OIDC JWT");
        assert_eq!(resolved.project, "homelab-ai");
        assert!(resolved.is_path_allowed("models/openai_key", "read", now));
        assert!(!resolved.is_path_allowed("billing/stripe_key", "read", now));

        // Stripping `kid` from JWT header MUST be rejected when JWK carries a `kid`
        let stripped_hdr = URL_SAFE_NO_PAD.encode(
            serde_json::to_vec(&serde_json::json!({
                "alg": "EdDSA",
                "typ": "JWT"
            }))
            .unwrap(),
        );
        let stripped_in = format!("{stripped_hdr}.{payload}");
        let stripped_sig = URL_SAFE_NO_PAD.encode(keypair.sign(stripped_in.as_bytes()).as_ref());
        let stripped_jwt = format!("{stripped_in}.{stripped_sig}");
        assert!(verify_oidc_jwt_and_resolve(&stripped_jwt, &[binding], &cache, now).is_err());
    }
}
