//! Encrypted per-agent OAuth token storage.
//!
//! Each agent gets an isolated encrypted store at:
//!   ~/.grokingclaw/agents/<name>/identity/oauth-tokens.enc
//!
//! Encryption: ChaCha20-Poly1305 with key derived from agent's Ed25519 key
//! via HKDF-SHA256 (context: "grokingclaw-oauth-store-v1").
//!
//! The store is loaded into memory, modified, and flushed back to disk.
//! File-level atomicity is ensured by writing to a temp file then renaming.

use anyhow::{Context, Result};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const STORE_VERSION: u32 = 1;
const HKDF_CONTEXT: &[u8] = b"grokingclaw-oauth-store-v1";
const NONCE_LEN: usize = 12;

/// An OAuth provider registration for one agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthRegistration {
    /// Unique registration ID.
    pub id: String,
    /// Human-readable provider name (e.g., "github", "google", "openai").
    pub provider: String,
    /// OAuth client ID.
    pub client_id: String,
    /// OAuth client secret (None for public clients using PKCE).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    /// Authorization endpoint URL.
    pub authorization_url: String,
    /// Token endpoint URL.
    pub token_url: String,
    /// Revocation endpoint URL (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub revocation_url: Option<String>,
    /// Device authorization endpoint (for RFC 8628).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_authorization_url: Option<String>,
    /// Scopes to request.
    pub scopes: Vec<String>,
    /// Which outbound domains use this registration for token injection.
    pub domain_bindings: Vec<String>,
    /// Grant type: "authorization_code", "device_code", "client_credentials".
    pub grant_type: String,
    /// When this registration was created.
    pub created_at: DateTime<Utc>,
    /// Parent registration ID (for delegation tracking).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_registration_id: Option<String>,
    /// Maximum scopes allowed (from delegation chain; None = use scopes field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_scopes: Option<Vec<String>>,
}

/// Stored OAuth tokens for a registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredOAuthTokens {
    /// Registration ID this token belongs to.
    pub registration_id: String,
    /// The access token.
    pub access_token: String,
    /// Refresh token (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    /// When the access token expires.
    pub expires_at: DateTime<Utc>,
    /// Token type (usually "Bearer").
    pub token_type: String,
    /// Granted scopes (may differ from requested).
    pub granted_scopes: Vec<String>,
    /// Last refreshed at.
    pub last_refreshed: DateTime<Utc>,
}

/// The per-agent OAuth store (serialized, encrypted on disk).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OAuthStore {
    pub version: u32,
    pub agent_id: String,
    pub registrations: Vec<OAuthRegistration>,
    pub tokens: Vec<StoredOAuthTokens>,
}

impl OAuthStore {
    /// Create an empty store for an agent.
    pub fn new(agent_id: Uuid) -> Self {
        Self {
            version: STORE_VERSION,
            agent_id: agent_id.to_string(),
            registrations: Vec::new(),
            tokens: Vec::new(),
        }
    }

    /// Load from encrypted file, or create empty if file doesn't exist.
    pub fn load(store_path: &Path, signing_key: &SigningKey) -> Result<Self> {
        if !store_path.exists() {
            // Derive agent ID from key for new store
            let agent_id = Uuid::new_v4(); // caller should provide real ID
            return Ok(Self::new(agent_id));
        }

        let ciphertext = std::fs::read(store_path)
            .with_context(|| format!("Failed to read OAuth store: {}", store_path.display()))?;

        if ciphertext.len() < NONCE_LEN + 1 {
            anyhow::bail!("OAuth store file too small (corrupted?)");
        }

        let nonce_bytes = &ciphertext[..NONCE_LEN];
        let encrypted = &ciphertext[NONCE_LEN..];

        let key = derive_encryption_key(signing_key);
        let cipher = ChaCha20Poly1305::new(&key.into());
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, encrypted)
            .map_err(|_| anyhow::anyhow!("Failed to decrypt OAuth store (wrong key?)"))?;

        let store: OAuthStore = serde_json::from_slice(&plaintext)
            .context("Failed to parse decrypted OAuth store")?;

        Ok(store)
    }

    /// Save to encrypted file (atomic write via temp + rename).
    pub fn save(&self, store_path: &Path, signing_key: &SigningKey) -> Result<()> {
        // Ensure parent dir exists
        if let Some(parent) = store_path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let plaintext = serde_json::to_vec(self).context("Failed to serialize OAuth store")?;

        let key = derive_encryption_key(signing_key);
        let cipher = ChaCha20Poly1305::new(&key.into());

        // Generate random nonce
        let mut nonce_bytes = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to generate nonce: {}", e))?;
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| anyhow::anyhow!("Failed to encrypt OAuth store"))?;

        // Write nonce || ciphertext
        let mut output = Vec::with_capacity(NONCE_LEN + ciphertext.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&ciphertext);

        // Atomic write: temp file + rename
        let tmp_path = store_path.with_extension("enc.tmp");
        std::fs::write(&tmp_path, &output)
            .with_context(|| format!("Failed to write temp file: {}", tmp_path.display()))?;
        std::fs::rename(&tmp_path, store_path)
            .with_context(|| format!("Failed to rename to: {}", store_path.display()))?;

        // Set restrictive permissions (Unix)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(store_path, perms).ok();
        }

        Ok(())
    }

    /// Register a new OAuth provider. Returns error if ID already exists.
    pub fn register_provider(&mut self, reg: OAuthRegistration) -> Result<()> {
        if self.registrations.iter().any(|r| r.id == reg.id) {
            anyhow::bail!("Registration '{}' already exists", reg.id);
        }
        self.registrations.push(reg);
        Ok(())
    }

    /// Store or update tokens for a registration.
    pub fn store_tokens(&mut self, tokens: StoredOAuthTokens) -> Result<()> {
        // Verify registration exists
        if !self.registrations.iter().any(|r| r.id == tokens.registration_id) {
            anyhow::bail!(
                "Registration '{}' not found",
                tokens.registration_id
            );
        }
        // Replace existing or insert new
        self.tokens
            .retain(|t| t.registration_id != tokens.registration_id);
        self.tokens.push(tokens);
        Ok(())
    }

    /// Get tokens for a registration.
    pub fn get_tokens(&self, registration_id: &str) -> Option<&StoredOAuthTokens> {
        self.tokens
            .iter()
            .find(|t| t.registration_id == registration_id)
    }

    /// Get a registration by ID.
    pub fn get_registration(&self, registration_id: &str) -> Option<&OAuthRegistration> {
        self.registrations.iter().find(|r| r.id == registration_id)
    }

    /// Remove a registration and its tokens.
    pub fn remove_registration(&mut self, registration_id: &str) -> Result<()> {
        let existed = self.registrations.iter().any(|r| r.id == registration_id);
        if !existed {
            anyhow::bail!("Registration '{}' not found", registration_id);
        }
        self.registrations.retain(|r| r.id != registration_id);
        self.tokens
            .retain(|t| t.registration_id != registration_id);
        Ok(())
    }

    /// Remove all registrations that are children of a parent (cascade revoke).
    pub fn cascade_remove(&mut self, parent_registration_id: &str) {
        let child_ids: Vec<String> = self
            .registrations
            .iter()
            .filter(|r| r.parent_registration_id.as_deref() == Some(parent_registration_id))
            .map(|r| r.id.clone())
            .collect();

        for child_id in &child_ids {
            // Recurse for grandchildren
            self.cascade_remove(child_id);
        }

        self.registrations
            .retain(|r| r.parent_registration_id.as_deref() != Some(parent_registration_id));
        self.tokens
            .retain(|t| !child_ids.contains(&t.registration_id));
    }

    /// Get all domain bindings (for proxy cache initialization).
    pub fn get_domain_bindings(&self) -> Vec<grokingclaw_proxy::oauth::OAuthDomainBinding> {
        self.registrations
            .iter()
            .flat_map(|reg| {
                reg.domain_bindings.iter().map(move |domain| {
                    grokingclaw_proxy::oauth::OAuthDomainBinding {
                        domain: domain.clone(),
                        registration_id: reg.id.clone(),
                        required_scopes: reg.scopes.clone(),
                    }
                })
            })
            .collect()
    }

    /// Get all cached tokens (for proxy cache initialization).
    pub fn get_cached_tokens(
        &self,
    ) -> std::collections::HashMap<String, grokingclaw_proxy::oauth::CachedOAuthToken> {
        self.tokens
            .iter()
            .filter_map(|t| {
                let reg = self.get_registration(&t.registration_id)?;
                Some((
                    t.registration_id.clone(),
                    grokingclaw_proxy::oauth::CachedOAuthToken {
                        access_token: t.access_token.clone(),
                        expires_at: t.expires_at.timestamp(),
                        scopes: t.granted_scopes.clone(),
                        provider: reg.provider.clone(),
                        registration_id: t.registration_id.clone(),
                    },
                ))
            })
            .collect()
    }

    /// Resolve the store file path for an agent.
    pub fn store_path(agent_dir: &Path) -> PathBuf {
        agent_dir.join("identity").join("oauth-tokens.enc")
    }

    /// Validate that requested scopes are a subset of max_scopes (for delegation).
    pub fn validate_delegation_scopes(
        parent_scopes: &[String],
        requested_scopes: &[String],
    ) -> Result<()> {
        for scope in requested_scopes {
            if !parent_scopes.contains(scope) {
                anyhow::bail!(
                    "Delegation scope '{}' not in parent scopes {:?}",
                    scope,
                    parent_scopes
                );
            }
        }
        Ok(())
    }

    /// Validate that domain bindings are a subset of parent's.
    pub fn validate_delegation_domains(
        parent_domains: &[String],
        requested_domains: &[String],
    ) -> Result<()> {
        for domain in requested_domains {
            if !parent_domains.contains(domain) {
                anyhow::bail!(
                    "Delegation domain '{}' not in parent domains {:?}",
                    domain,
                    parent_domains
                );
            }
        }
        Ok(())
    }
}

/// Derive a 256-bit encryption key from an Ed25519 signing key using HKDF-SHA256.
fn derive_encryption_key(signing_key: &SigningKey) -> [u8; 32] {
    let ikm = signing_key.to_bytes();
    let hk = Hkdf::<Sha256>::new(None, &ikm);
    let mut okm = [0u8; 32];
    hk.expand(HKDF_CONTEXT, &mut okm)
        .expect("HKDF expand should not fail for 32-byte output");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;
    use grokingclawid_core::crypto::generate_keypair;
    use tempfile::TempDir;

    #[test]
    fn test_store_roundtrip() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("oauth-tokens.enc");
        let (signing_key, _) = generate_keypair();
        let agent_id = Uuid::new_v4();

        let mut store = OAuthStore::new(agent_id);

        // Register a provider
        let reg = OAuthRegistration {
            id: "gh-001".into(),
            provider: "github".into(),
            client_id: "test-client".into(),
            client_secret: Some("test-secret".into()),
            authorization_url: "https://github.com/login/oauth/authorize".into(),
            token_url: "https://github.com/login/oauth/access_token".into(),
            revocation_url: None,
            device_authorization_url: None,
            scopes: vec!["repo".into(), "read:org".into()],
            domain_bindings: vec!["api.github.com".into()],
            grant_type: "authorization_code".into(),
            created_at: Utc::now(),
            parent_registration_id: None,
            max_scopes: None,
        };
        store.register_provider(reg).unwrap();

        // Store tokens
        let tokens = StoredOAuthTokens {
            registration_id: "gh-001".into(),
            access_token: "ghp_test123".into(),
            refresh_token: Some("ghr_refresh456".into()),
            expires_at: Utc::now() + chrono::Duration::hours(1),
            token_type: "Bearer".into(),
            granted_scopes: vec!["repo".into()],
            last_refreshed: Utc::now(),
        };
        store.store_tokens(tokens).unwrap();

        // Save encrypted
        store.save(&store_path, &signing_key).unwrap();
        assert!(store_path.exists());

        // Load and verify
        let loaded = OAuthStore::load(&store_path, &signing_key).unwrap();
        assert_eq!(loaded.registrations.len(), 1);
        assert_eq!(loaded.registrations[0].id, "gh-001");
        assert_eq!(loaded.tokens.len(), 1);
        assert_eq!(loaded.tokens[0].access_token, "ghp_test123");
    }

    #[test]
    fn test_wrong_key_fails() {
        let tmp = TempDir::new().unwrap();
        let store_path = tmp.path().join("oauth-tokens.enc");
        let (key1, _) = generate_keypair();
        let (key2, _) = generate_keypair();

        let store = OAuthStore::new(Uuid::new_v4());
        store.save(&store_path, &key1).unwrap();

        // Loading with wrong key should fail
        let result = OAuthStore::load(&store_path, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_cascade_remove() {
        let mut store = OAuthStore::new(Uuid::new_v4());

        // Parent
        store
            .register_provider(OAuthRegistration {
                id: "parent-001".into(),
                provider: "github".into(),
                client_id: "c".into(),
                client_secret: None,
                authorization_url: "https://example.com/auth".into(),
                token_url: "https://example.com/token".into(),
                revocation_url: None,
                device_authorization_url: None,
                scopes: vec!["repo".into()],
                domain_bindings: vec!["api.github.com".into()],
                grant_type: "authorization_code".into(),
                created_at: Utc::now(),
                parent_registration_id: None,
                max_scopes: None,
            })
            .unwrap();

        // Child
        store
            .register_provider(OAuthRegistration {
                id: "child-001".into(),
                provider: "github".into(),
                client_id: "c".into(),
                client_secret: None,
                authorization_url: "https://example.com/auth".into(),
                token_url: "https://example.com/token".into(),
                revocation_url: None,
                device_authorization_url: None,
                scopes: vec!["repo:read".into()],
                domain_bindings: vec!["api.github.com".into()],
                grant_type: "authorization_code".into(),
                created_at: Utc::now(),
                parent_registration_id: Some("parent-001".into()),
                max_scopes: Some(vec!["repo:read".into()]),
            })
            .unwrap();

        assert_eq!(store.registrations.len(), 2);

        // Cascade remove from parent
        store.cascade_remove("parent-001");

        // Child should be removed, parent remains
        assert_eq!(store.registrations.len(), 1);
        assert_eq!(store.registrations[0].id, "parent-001");
    }

    #[test]
    fn test_delegation_scope_validation() {
        let parent = vec!["repo".to_string(), "read:org".to_string()];

        // Valid subset
        assert!(OAuthStore::validate_delegation_scopes(&parent, &["repo".to_string()]).is_ok());

        // Invalid — scope not in parent
        assert!(
            OAuthStore::validate_delegation_scopes(&parent, &["admin:org".to_string()]).is_err()
        );
    }
}
