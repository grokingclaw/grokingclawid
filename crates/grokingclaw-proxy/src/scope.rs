//! Scope enforcement engine.
//!
//! Checks whether an outbound request is allowed by the agent's
//! delegation chain. Operates at the domain level for HTTPS (CONNECT)
//! and at the domain + path level for HTTP.

use std::collections::{HashSet, VecDeque};
use url::Url;

/// Scope enforcement configuration for one agent.
#[derive(Debug, Clone)]
pub struct ScopeConfig {
    /// Allowed outbound domains. Empty = allow all.
    pub allowed_domains: HashSet<String>,
    /// Max requests per minute. 0 = unlimited.
    pub max_requests_per_minute: u32,
    /// Sliding window: timestamps of recent requests.
    request_timestamps: VecDeque<std::time::Instant>,
}

/// Result of a scope check.
#[derive(Debug)]
pub enum ScopeDecision {
    /// Request is allowed.
    Allow,
    /// Domain not in allowlist.
    DenyDomain {
        domain: String,
        allowed: Vec<String>,
    },
    /// Rate limit exceeded.
    DenyRateLimit { limit: u32, window_seconds: u64 },
}

impl ScopeConfig {
    /// Create a new scope config.
    pub fn new(allowed_domains: Vec<String>, max_requests_per_minute: u32) -> Self {
        Self {
            allowed_domains: allowed_domains.into_iter().collect(),
            max_requests_per_minute,
            request_timestamps: VecDeque::new(),
        }
    }

    /// Create a permissive scope (allow everything).
    pub fn permissive() -> Self {
        Self {
            allowed_domains: HashSet::new(),
            max_requests_per_minute: 0,
            request_timestamps: VecDeque::new(),
        }
    }

    /// Sliding-window rate limit check. Returns true if request is allowed.
    fn check_rate_limit(&mut self) -> Option<u64> {
        if self.max_requests_per_minute == 0 {
            return None; // Unlimited
        }
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(60);
        // Evict timestamps older than 60s
        while self
            .request_timestamps
            .front()
            .map_or(false, |t| now.duration_since(*t) >= window)
        {
            self.request_timestamps.pop_front();
        }
        if self.request_timestamps.len() as u32 >= self.max_requests_per_minute {
            // Estimate when the oldest will expire
            let oldest = self.request_timestamps.front().unwrap();
            let wait = window.saturating_sub(now.duration_since(*oldest));
            return Some(wait.as_secs().max(1));
        }
        self.request_timestamps.push_back(now);
        None
    }

    /// Check if a request to the given URL is allowed.
    pub fn check_url(&mut self, url: &str) -> ScopeDecision {
        // Sliding-window rate limit check
        if let Some(wait_secs) = self.check_rate_limit() {
            return ScopeDecision::DenyRateLimit {
                limit: self.max_requests_per_minute,
                window_seconds: wait_secs,
            };
        }

        // Domain check
        if self.allowed_domains.is_empty() {
            return ScopeDecision::Allow; // No restrictions
        }

        let domain = extract_domain(url);
        if domain.is_empty() {
            return ScopeDecision::Allow; // Can't parse = allow (localhost, etc.)
        }

        // Check exact match and wildcard subdomain match
        if self.allowed_domains.contains(&domain) {
            return ScopeDecision::Allow;
        }

        // Check if any allowed domain is a parent (e.g., "openai.com" allows "api.openai.com")
        for allowed in &self.allowed_domains {
            if domain.ends_with(&format!(".{}", allowed)) {
                return ScopeDecision::Allow;
            }
        }

        ScopeDecision::DenyDomain {
            domain,
            allowed: self.allowed_domains.iter().cloned().collect(),
        }
    }

    /// Check a CONNECT target (host:port format).
    pub fn check_connect(&mut self, host_port: &str) -> ScopeDecision {
        // CONNECT targets are "host:port"
        let host = host_port.split(':').next().unwrap_or(host_port);

        // Sliding-window rate limit check
        if let Some(wait_secs) = self.check_rate_limit() {
            return ScopeDecision::DenyRateLimit {
                limit: self.max_requests_per_minute,
                window_seconds: wait_secs,
            };
        }

        if self.allowed_domains.is_empty() {
            return ScopeDecision::Allow;
        }

        if self.allowed_domains.contains(host) {
            return ScopeDecision::Allow;
        }

        for allowed in &self.allowed_domains {
            if host.ends_with(&format!(".{}", allowed)) {
                return ScopeDecision::Allow;
            }
        }

        ScopeDecision::DenyDomain {
            domain: host.to_string(),
            allowed: self.allowed_domains.iter().cloned().collect(),
        }
    }
}

/// Extract domain from a URL string.
fn extract_domain(url_str: &str) -> String {
    // Try parsing as URL
    if let Ok(url) = Url::parse(url_str) {
        return url.host_str().unwrap_or("").to_string();
    }
    // Might be just a host:port (CONNECT)
    url_str.split(':').next().unwrap_or("").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_allow_all_when_empty() {
        let mut scope = ScopeConfig::permissive();
        assert!(matches!(
            scope.check_url("https://anything.com/foo"),
            ScopeDecision::Allow
        ));
    }

    #[test]
    fn test_allow_exact_domain() {
        let mut scope = ScopeConfig::new(vec!["api.openai.com".to_string()], 0);
        assert!(matches!(
            scope.check_url("https://api.openai.com/v1/chat"),
            ScopeDecision::Allow
        ));
    }

    #[test]
    fn test_deny_unlisted_domain() {
        let mut scope = ScopeConfig::new(vec!["api.openai.com".to_string()], 0);
        assert!(matches!(
            scope.check_url("https://evil.com/steal"),
            ScopeDecision::DenyDomain { .. }
        ));
    }

    #[test]
    fn test_allow_subdomain() {
        let mut scope = ScopeConfig::new(vec!["openai.com".to_string()], 0);
        assert!(matches!(
            scope.check_url("https://api.openai.com/v1/chat"),
            ScopeDecision::Allow
        ));
    }

    #[test]
    fn test_connect_check() {
        let mut scope = ScopeConfig::new(vec!["github.com".to_string()], 0);
        assert!(matches!(
            scope.check_connect("github.com:443"),
            ScopeDecision::Allow
        ));
        assert!(matches!(
            scope.check_connect("evil.com:443"),
            ScopeDecision::DenyDomain { .. }
        ));
    }

    #[test]
    fn test_rate_limit() {
        let mut scope = ScopeConfig::new(vec![], 2);
        assert!(matches!(
            scope.check_url("https://a.com"),
            ScopeDecision::Allow
        ));
        assert!(matches!(
            scope.check_url("https://b.com"),
            ScopeDecision::Allow
        ));
        assert!(matches!(
            scope.check_url("https://c.com"),
            ScopeDecision::DenyRateLimit { .. }
        ));
    }
}
