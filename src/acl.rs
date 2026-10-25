//! Project and path-scoped Access Control Lists (ACL).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopedToken {
    pub token_id: String,
    pub token_hash: String,
    pub project: String,
    pub name: String,
    pub allowed_paths: Vec<String>,
    pub capabilities: Vec<String>,
}

impl ScopedToken {
    /// Check whether this token is permitted to access a specific resource path.
    pub fn is_path_allowed(&self, requested_path: &str, required_cap: &str) -> bool {
        if !self.capabilities.iter().any(|c| c == required_cap || c == "admin") {
            return false;
        }

        for pattern in &self.allowed_paths {
            if pattern == "*" || pattern == requested_path {
                return true;
            }
            if pattern.ends_with("/*") {
                let prefix = &pattern[..pattern.len() - 2];
                if requested_path.starts_with(prefix) {
                    return true;
                }
            }
        }
        false
    }
}
