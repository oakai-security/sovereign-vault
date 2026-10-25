//! Project and path-scoped Access Control Lists (ACL) with strict path canonicalization
//! and directory-boundary wildcard enforcement.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedToken {
    pub token_id: String,
    pub token_hash_sha512: String,
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
    pub expires_at: Option<i64>,
}

/// Canonicalize and strictly validate a secret path:
/// - Strips a single leading `/` (from Axum wildcard route capture).
/// - Rejects empty paths, paths > 256 bytes, trailing `/`, `//`, `.`, `..`, and characters
///   outside `[a-zA-Z0-9._-]`.
pub fn canonicalize_secret_path(raw: &str) -> Result<String, &'static str> {
    let trimmed = raw.strip_prefix('/').unwrap_or(raw);
    if trimmed.is_empty() || trimmed.len() > 256 {
        return Err("Secret path must be 1..=256 characters");
    }
    if trimmed.starts_with('/') || trimmed.ends_with('/') {
        return Err("Secret path must not contain leading or trailing slashes");
    }

    for segment in trimmed.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err("Invalid traversal or empty segment in secret path");
        }
        if !segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
        {
            return Err("Secret path segments may only contain [a-zA-Z0-9._-]");
        }
    }

    Ok(trimmed.to_string())
}

/// Validate an ACL scope pattern (`"*"`, `"<canonical_path>"`, or `"<canonical_prefix>/*"`).
pub fn validate_scope_pattern(pattern: &str) -> Result<String, &'static str> {
    if pattern == "*" {
        return Ok("*".to_string());
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        let canon = canonicalize_secret_path(prefix)?;
        return Ok(format!("{canon}/*"));
    }
    canonicalize_secret_path(pattern)
}

/// Validate capability names (`read`, `write`, `delete`, `admin`).
pub fn validate_capabilities(caps: &[String]) -> Result<(), &'static str> {
    if caps.is_empty() {
        return Err("At least one capability is required");
    }
    for cap in caps {
        if !matches!(cap.as_str(), "read" | "write" | "delete" | "admin") {
            return Err("Capabilities must be drawn from: read, write, delete, admin");
        }
    }
    Ok(())
}

impl ScopedToken {
    /// Returns whether this token is unexpired and holds `admin` capability.
    pub fn is_admin(&self, now_unix: i64) -> bool {
        if let Some(exp) = self.expires_at {
            if now_unix >= exp {
                return false;
            }
        }
        self.capabilities.iter().any(|c| c == "admin")
    }

    /// Check whether this token is unexpired, holds `required_cap` (or `admin`),
    /// and is permitted to access `canonical_path` along exact directory boundaries.
    pub fn is_path_allowed(
        &self,
        canonical_path: &str,
        required_cap: &str,
        now_unix: i64,
    ) -> bool {
        if let Some(exp) = self.expires_at {
            if now_unix >= exp {
                return false;
            }
        }

        if !self
            .capabilities
            .iter()
            .any(|c| c == required_cap || c == "admin")
        {
            return false;
        }

        for pattern in &self.allowed_paths {
            if pattern == "*" || pattern == canonical_path {
                return true;
            }
            if let Some(dir_prefix) = pattern.strip_suffix("/*") {
                if canonical_path.starts_with(dir_prefix)
                    && canonical_path.as_bytes().get(dir_prefix.len()) == Some(&b'/')
                {
                    return true;
                }
            }
        }
        false
    }
}
