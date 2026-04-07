//! OAuth 2.0 token cache and injection for the sidecar proxy.
//!
//! Maps domains to OAuth tokens and injects Bearer tokens into outbound
//! requests. Token refresh is handled via IPC to the daemon process.
//!
//! The proxy is the hot path — this module is designed for minimal latency:
//! - In-memory cache with RwLock for concurrent reads
//! - Proactive refresh before expiry to avoid blocking requests
//! - Wildcard subdomain matching for domain bindings

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// A cached OAuth token for a specific provider/domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedOAuthToken {
    /// The Bearer access token value.
    pub access_token: String,
    /// When this token expires (Unix timestamp in seconds).
    pub expires_at: i64,
    /// OAuth scopes granted.
    pub scopes: Vec<String>,
    /// Provider identifier (e.g., "github", "google").
    pub provider: String,
    /// Registration ID in the daemon's OAuth store.
    pub registration_id: String,
}

impl CachedOAuthToken {
    /// Returns true if the token is expired or will expire within the buffer window.
    pub fn is_expired(&self, buffer_secs: i64) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.expires_at - buffer_secs <= now
    }

    /// Returns true if the token is hard-expired (past expiry, unusable).
    pub fn is_hard_expired(&self) -> bool {
        let now = chrono::Utc::now().timestamp();
        self.expires_at <= now
    }
}

/// Binds a domain pattern to an OAuth provider registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthDomainBinding {
    /// Domain pattern (e.g., "api.github.com", "*.googleapis.com").
    pub domain: String,
    /// The OAuth registration ID in the daemon store.
    pub registration_id: String,
    /// Required scopes for this domain binding.
    pub required_scopes: Vec<String>,
}

/// In-memory OAuth token cache for one proxy instance.
///
/// Loaded from the daemon at proxy startup. Tokens are refreshed on-demand
/// when a request hits an OAuth-bound domain with an expired token.
pub struct OAuthTokenCache {
    /// registration_id → cached token
    tokens: Arc<RwLock<HashMap<String, CachedOAuthToken>>>,
    /// Domain bindings (checked in order; first match wins)
    bindings: RwLock<Vec<OAuthDomainBinding>>,
    /// Agent ID (for IPC refresh requests)
    agent_id: String,
    /// Path to daemon IPC socket (for token refresh)
    daemon_socket: String,
    /// Seconds before expiry to trigger proactive refresh
    refresh_buffer_secs: i64,
}

impl OAuthTokenCache {
    /// Create a new token cache.
    pub fn new(
        agent_id: String,
        daemon_socket: String,
        bindings: Vec<OAuthDomainBinding>,
        initial_tokens: HashMap<String, CachedOAuthToken>,
        refresh_buffer_secs: i64,
    ) -> Self {
        Self {
            tokens: Arc::new(RwLock::new(initial_tokens)),
            bindings: RwLock::new(bindings),
            agent_id,
            daemon_socket,
            refresh_buffer_secs,
        }
    }

    /// Look up a token for the given domain.
    ///
    /// Returns `Some(token)` if a binding exists and a valid token is cached.
    /// If the token is near-expiry, triggers an async refresh in the background
    /// but still returns the current (soon-to-expire) token for this request.
    /// Returns `None` if no binding exists or the token is hard-expired.
    pub async fn get_token(&self, domain: &str) -> Option<CachedOAuthToken> {
        let binding = self.find_binding(domain).await?;
        let registration_id = binding.registration_id.clone();

        let tokens = self.tokens.read().await;
        let token = tokens.get(&registration_id)?.clone();
        drop(tokens);

        if token.is_hard_expired() {
            // Try synchronous refresh — block this request
            match self.refresh_token(&registration_id).await {
                Ok(new_token) => return Some(new_token),
                Err(e) => {
                    tracing::warn!(
                        agent = %self.agent_id,
                        registration = %registration_id,
                        error = %e,
                        "OAuth token refresh failed; token hard-expired"
                    );
                    return None;
                }
            }
        }

        if token.is_expired(self.refresh_buffer_secs) {
            // Proactive background refresh — return current token for now
            let agent_id = self.agent_id.clone();
            let socket = self.daemon_socket.clone();
            let reg_id = registration_id.clone();
            let tokens_ref = Arc::clone(&self.tokens);
            tokio::spawn(async move {
                match refresh_token_via_ipc(&socket, &agent_id, &reg_id).await {
                    Ok(new_token) => {
                        let mut tokens: tokio::sync::RwLockWriteGuard<'_, HashMap<String, CachedOAuthToken>> = tokens_ref.write().await;
                        tokens.insert(reg_id, new_token);
                    }
                    Err(e) => {
                        tracing::warn!(
                            agent = %agent_id,
                            registration = %reg_id,
                            error = %e,
                            "Background OAuth token refresh failed"
                        );
                    }
                }
            });
        }

        Some(token)
    }

    /// Update a token in the cache (called after daemon notifies of refresh).
    pub async fn update_token(&self, registration_id: &str, token: CachedOAuthToken) {
        let mut tokens = self.tokens.write().await;
        tokens.insert(registration_id.to_string(), token);
    }

    /// Remove a token from the cache (revocation).
    pub async fn remove_token(&self, registration_id: &str) {
        let mut tokens = self.tokens.write().await;
        tokens.remove(registration_id);
    }

    /// Add a new domain binding.
    pub async fn add_binding(&self, binding: OAuthDomainBinding) {
        let mut bindings = self.bindings.write().await;
        bindings.push(binding);
    }

    /// Remove all bindings for a registration.
    pub async fn remove_bindings(&self, registration_id: &str) {
        let mut bindings = self.bindings.write().await;
        bindings.retain(|b| b.registration_id != registration_id);
    }

    /// Find the first matching binding for a domain.
    async fn find_binding(&self, domain: &str) -> Option<OAuthDomainBinding> {
        let bindings = self.bindings.read().await;
        for binding in bindings.iter() {
            if domain_matches(&binding.domain, domain) {
                return Some(binding.clone());
            }
        }
        None
    }

    /// Refresh a token via daemon IPC (blocking the current request).
    async fn refresh_token(&self, registration_id: &str) -> anyhow::Result<CachedOAuthToken> {
        let new_token =
            refresh_token_via_ipc(&self.daemon_socket, &self.agent_id, registration_id).await?;
        let mut tokens = self.tokens.write().await;
        tokens.insert(registration_id.to_string(), new_token.clone());
        Ok(new_token)
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

/// Check if a domain matches a binding pattern.
///
/// Supports:
/// - Exact match: "api.github.com" matches "api.github.com"
/// - Wildcard subdomain: "*.googleapis.com" matches "storage.googleapis.com"
pub fn domain_matches(pattern: &str, domain: &str) -> bool {
    if pattern == domain {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Wildcard: *.googleapis.com matches storage.googleapis.com
        // but NOT googleapis.com itself
        if domain.ends_with(suffix) && domain.len() > suffix.len() {
            let prefix = &domain[..domain.len() - suffix.len()];
            // Must have exactly one dot at the boundary
            return prefix.ends_with('.');
        }
    }
    false
}

/// Extract domain from a URL string.
pub fn extract_domain(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}

/// Refresh a token by calling the daemon via Unix socket IPC.
///
/// Sends a JSON-RPC 2.0 request to the daemon's `oauth.refresh` method.
async fn refresh_token_via_ipc(
    socket_path: &str,
    agent_id: &str,
    registration_id: &str,
) -> anyhow::Result<CachedOAuthToken> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixStream;

    let stream = UnixStream::connect(socket_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to daemon socket: {}", e))?;

    let (reader, mut writer) = stream.into_split();

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "oauth.refresh",
        "params": {
            "agent": agent_id,
            "registration_id": registration_id,
        }
    });

    let mut msg = serde_json::to_string(&request)?;
    msg.push('\n');
    writer.write_all(msg.as_bytes()).await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let resp: serde_json::Value = serde_json::from_str(line.trim())?;

    if let Some(error) = resp.get("error") {
        let msg = error
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown error");
        return Err(anyhow::anyhow!("Daemon oauth.refresh failed: {}", msg));
    }

    let result = resp
        .get("result")
        .ok_or_else(|| anyhow::anyhow!("No result in daemon response"))?;

    let token: CachedOAuthToken = serde_json::from_value(result.clone())
        .map_err(|e| anyhow::anyhow!("Failed to parse refreshed token: {}", e))?;

    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_domain_exact_match() {
        assert!(domain_matches("api.github.com", "api.github.com"));
        assert!(!domain_matches("api.github.com", "other.github.com"));
    }

    #[test]
    fn test_domain_wildcard_match() {
        assert!(domain_matches("*.googleapis.com", "storage.googleapis.com"));
        assert!(domain_matches(
            "*.googleapis.com",
            "oauth2.googleapis.com"
        ));
        assert!(!domain_matches("*.googleapis.com", "googleapis.com"));
        assert!(!domain_matches("*.googleapis.com", "evil.com"));
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("http://api.github.com/repos"),
            Some("api.github.com".to_string())
        );
        assert_eq!(
            extract_domain("https://storage.googleapis.com/bucket/obj"),
            Some("storage.googleapis.com".to_string())
        );
        assert_eq!(extract_domain("not-a-url"), None);
    }

    #[test]
    fn test_token_expiry() {
        let future = chrono::Utc::now().timestamp() + 3600;
        let token = CachedOAuthToken {
            access_token: "test".into(),
            expires_at: future,
            scopes: vec![],
            provider: "test".into(),
            registration_id: "test".into(),
        };
        assert!(!token.is_hard_expired());
        assert!(!token.is_expired(60));

        let past = chrono::Utc::now().timestamp() - 10;
        let expired = CachedOAuthToken {
            access_token: "test".into(),
            expires_at: past,
            scopes: vec![],
            provider: "test".into(),
            registration_id: "test".into(),
        };
        assert!(expired.is_hard_expired());
        assert!(expired.is_expired(0));
    }

    #[test]
    fn test_domain_deep_subdomain() {
        assert!(domain_matches(
            "*.googleapis.com",
            "www.storage.googleapis.com"
        ));
    }

    #[tokio::test]
    async fn test_cache_domain_lookup_with_bindings() {
        let bindings = vec![
            OAuthDomainBinding {
                domain: "api.github.com".into(),
                registration_id: "gh-001".into(),
                required_scopes: vec!["repo".into()],
            },
            OAuthDomainBinding {
                domain: "*.googleapis.com".into(),
                registration_id: "gcp-001".into(),
                required_scopes: vec!["cloud-platform".into()],
            },
        ];

        let future_ts = chrono::Utc::now().timestamp() + 3600;
        let mut initial = HashMap::new();
        initial.insert(
            "gh-001".into(),
            CachedOAuthToken {
                access_token: "ghp_abc".into(),
                expires_at: future_ts,
                scopes: vec!["repo".into()],
                provider: "github".into(),
                registration_id: "gh-001".into(),
            },
        );
        initial.insert(
            "gcp-001".into(),
            CachedOAuthToken {
                access_token: "ya29.xyz".into(),
                expires_at: future_ts,
                scopes: vec!["cloud-platform".into()],
                provider: "google".into(),
                registration_id: "gcp-001".into(),
            },
        );

        let cache = OAuthTokenCache::new(
            "test-agent".into(),
            "/tmp/nonexistent.sock".into(),
            bindings,
            initial,
            60,
        );

        // Exact match
        let t = cache.get_token("api.github.com").await;
        assert!(t.is_some());
        assert_eq!(t.unwrap().access_token, "ghp_abc");

        // Wildcard match
        let t = cache.get_token("storage.googleapis.com").await;
        assert!(t.is_some());
        assert_eq!(t.unwrap().access_token, "ya29.xyz");

        // No binding
        let t = cache.get_token("api.openai.com").await;
        assert!(t.is_none());
    }

    #[tokio::test]
    async fn test_cache_update_and_remove() {
        let cache = OAuthTokenCache::new(
            "agent-1".into(),
            "/tmp/test.sock".into(),
            vec![],
            HashMap::new(),
            60,
        );

        let token = CachedOAuthToken {
            access_token: "abc123".into(),
            expires_at: chrono::Utc::now().timestamp() + 3600,
            scopes: vec!["repo".into()],
            provider: "github".into(),
            registration_id: "gh-001".into(),
        };

        cache.update_token("gh-001", token.clone()).await;
        {
            let tokens = cache.tokens.read().await;
            assert!(tokens.contains_key("gh-001"));
        }

        cache.remove_token("gh-001").await;
        {
            let tokens = cache.tokens.read().await;
            assert!(!tokens.contains_key("gh-001"));
        }
    }
}
