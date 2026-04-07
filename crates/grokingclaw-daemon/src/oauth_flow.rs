//! OAuth 2.0 authorization flows.
//!
//! Implements the standard OAuth grant types for agent use:
//! - Authorization Code + PKCE (browser-redirect-capable agents)
//! - Device Authorization Grant (RFC 8628 — headless agents)
//! - Client Credentials Grant (M2M, no user involved)
//! - Token Refresh (proactive and on-demand)
//! - RFC 8693 Token Exchange (ClawID identity → OAuth token)

use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{Duration, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::oauth_store::{OAuthRegistration, StoredOAuthTokens};

// ─── PKCE helpers ──────────────────────────────────────────────────────

/// Generate a PKCE code verifier (43–128 URL-safe characters).
pub fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    getrandom::getrandom(&mut bytes).expect("getrandom failed");
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Compute PKCE code challenge from verifier (S256 method).
pub fn compute_code_challenge(verifier: &str) -> String {
    let hash = Sha256::digest(verifier.as_bytes());
    URL_SAFE_NO_PAD.encode(hash)
}

// ─── Authorization Code Flow ───────────────────────────────────────────

/// Parameters for starting an authorization code flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthCodeStart {
    /// The authorization URL the user should visit.
    pub authorization_url: String,
    /// PKCE code verifier (store securely until callback).
    pub code_verifier: String,
    /// CSRF state parameter.
    pub state: String,
    /// Redirect URI to use for the callback.
    pub redirect_uri: String,
}

/// Build the authorization URL for an authorization code flow with PKCE.
pub fn start_auth_code_flow(
    reg: &OAuthRegistration,
    redirect_uri: &str,
) -> Result<AuthCodeStart> {
    let code_verifier = generate_code_verifier();
    let code_challenge = compute_code_challenge(&code_verifier);

    let mut state_bytes = [0u8; 16];
    getrandom::getrandom(&mut state_bytes).expect("getrandom failed");
    let state = URL_SAFE_NO_PAD.encode(state_bytes);

    let scopes = reg.scopes.join(" ");

    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        reg.authorization_url,
        urlencoding::encode(&reg.client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&scopes),
        urlencoding::encode(&state),
        urlencoding::encode(&code_challenge),
    );

    Ok(AuthCodeStart {
        authorization_url: auth_url,
        code_verifier,
        state,
        redirect_uri: redirect_uri.to_string(),
    })
}

/// Exchange an authorization code for tokens.
pub async fn exchange_auth_code(
    reg: &OAuthRegistration,
    code: &str,
    redirect_uri: &str,
    code_verifier: &str,
) -> Result<StoredOAuthTokens> {
    let client = reqwest::Client::new();

    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", &reg.client_id),
        ("code_verifier", code_verifier),
    ];

    // Include client_secret for confidential clients
    let secret_ref;
    if let Some(ref secret) = reg.client_secret {
        secret_ref = secret.clone();
        form.push(("client_secret", &secret_ref));
    }

    let resp = client
        .post(&reg.token_url)
        .form(&form)
        .header("Accept", "application/json")
        .send()
        .await
        .context("Token exchange request failed")?;

    let status = resp.status();
    let body = resp.text().await.context("Failed to read token response")?;

    if !status.is_success() {
        anyhow::bail!("Token exchange failed ({}): {}", status, body);
    }

    parse_token_response(&body, &reg.id)
}

// ─── Device Authorization Grant (RFC 8628) ─────────────────────────────

/// Pending device authorization state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceAuthPending {
    /// The device code (used for polling).
    pub device_code: String,
    /// The user code to display.
    pub user_code: String,
    /// URL the user should visit.
    pub verification_uri: String,
    /// Optional direct URL with code pre-filled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_uri_complete: Option<String>,
    /// Device code expires in seconds.
    pub expires_in: u64,
    /// Polling interval in seconds.
    pub interval: u64,
}

/// Start a device authorization flow.
pub async fn start_device_auth(reg: &OAuthRegistration) -> Result<DeviceAuthPending> {
    let device_url = reg
        .device_authorization_url
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("No device_authorization_url configured for provider"))?;

    let client = reqwest::Client::new();
    let scopes = reg.scopes.join(" ");

    let resp = client
        .post(device_url)
        .form(&[("client_id", &reg.client_id), ("scope", &scopes)])
        .header("Accept", "application/json")
        .send()
        .await
        .context("Device authorization request failed")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        anyhow::bail!("Device authorization failed ({}): {}", status, body);
    }

    let pending: DeviceAuthPending =
        serde_json::from_str(&body).context("Failed to parse device auth response")?;

    Ok(pending)
}

/// Poll for device authorization completion.
/// Returns Ok(Some(tokens)) when authorized, Ok(None) when still pending.
pub async fn poll_device_auth(
    reg: &OAuthRegistration,
    device_code: &str,
) -> Result<Option<StoredOAuthTokens>> {
    let client = reqwest::Client::new();

    let mut form = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:device_code".to_string(),
        ),
        ("device_code", device_code.to_string()),
        ("client_id", reg.client_id.clone()),
    ];

    if let Some(ref secret) = reg.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let resp = client
        .post(&reg.token_url)
        .form(&form)
        .header("Accept", "application/json")
        .send()
        .await
        .context("Device auth poll failed")?;

    let body = resp.text().await?;

    // Check for pending/slow_down errors
    if let Ok(error_resp) = serde_json::from_str::<serde_json::Value>(&body) {
        if let Some(error) = error_resp.get("error").and_then(|e| e.as_str()) {
            match error {
                "authorization_pending" | "slow_down" => return Ok(None),
                "expired_token" => anyhow::bail!("Device code expired"),
                "access_denied" => anyhow::bail!("User denied authorization"),
                _ => {
                    let desc = error_resp
                        .get("error_description")
                        .and_then(|d| d.as_str())
                        .unwrap_or("unknown");
                    anyhow::bail!("Device auth error: {} - {}", error, desc);
                }
            }
        }
    }

    let tokens = parse_token_response(&body, &reg.id)?;
    Ok(Some(tokens))
}

// ─── Client Credentials Grant ──────────────────────────────────────────

/// Perform a client credentials grant (M2M, no user involvement).
pub async fn client_credentials(reg: &OAuthRegistration) -> Result<StoredOAuthTokens> {
    let client = reqwest::Client::new();
    let scopes = reg.scopes.join(" ");

    let secret = reg
        .client_secret
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Client credentials grant requires client_secret"))?;

    let resp = client
        .post(&reg.token_url)
        .basic_auth(&reg.client_id, Some(secret))
        .form(&[
            ("grant_type", "client_credentials"),
            ("scope", &scopes),
        ])
        .header("Accept", "application/json")
        .send()
        .await
        .context("Client credentials request failed")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        anyhow::bail!("Client credentials failed ({}): {}", status, body);
    }

    parse_token_response(&body, &reg.id)
}

// ─── Token Refresh ─────────────────────────────────────────────────────

/// Refresh an access token using a refresh token.
pub async fn refresh_token(
    reg: &OAuthRegistration,
    refresh_token_value: &str,
) -> Result<StoredOAuthTokens> {
    let client = reqwest::Client::new();

    let mut form = vec![
        ("grant_type", "refresh_token".to_string()),
        ("refresh_token", refresh_token_value.to_string()),
        ("client_id", reg.client_id.clone()),
    ];

    if let Some(ref secret) = reg.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let resp = client
        .post(&reg.token_url)
        .form(&form)
        .header("Accept", "application/json")
        .send()
        .await
        .context("Token refresh request failed")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        anyhow::bail!("Token refresh failed ({}): {}", status, body);
    }

    let mut tokens = parse_token_response(&body, &reg.id)?;

    // If the response didn't include a new refresh token, keep the old one
    if tokens.refresh_token.is_none() {
        tokens.refresh_token = Some(refresh_token_value.to_string());
    }

    Ok(tokens)
}

// ─── RFC 8693 Token Exchange (ClawID → OAuth) ──────────────────────────

/// Exchange a ClawID agent identity proof for an OAuth access token.
///
/// The agent signs a nonce with its Ed25519 (+ optionally ML-DSA-65) key(s).
/// The AS validates the signature against the agent's public key and returns
/// a standard OAuth token response.
pub async fn clawid_token_exchange(
    reg: &OAuthRegistration,
    agent_card_json: &str,
    signed_assertion: &str,
    audience: Option<&str>,
) -> Result<StoredOAuthTokens> {
    let client = reqwest::Client::new();
    let scopes = reg.scopes.join(" ");

    let mut form = vec![
        (
            "grant_type",
            "urn:ietf:params:oauth:grant-type:token-exchange".to_string(),
        ),
        ("subject_token", signed_assertion.to_string()),
        (
            "subject_token_type",
            "urn:grokingclaw:agent-identity".to_string(),
        ),
        (
            "requested_token_type",
            "urn:ietf:params:oauth:token-type:access_token".to_string(),
        ),
        ("scope", scopes),
        ("client_id", reg.client_id.clone()),
    ];

    if let Some(aud) = audience {
        form.push(("audience", aud.to_string()));
    }

    // Include agent card as additional context
    form.push(("agent_card", agent_card_json.to_string()));

    if let Some(ref secret) = reg.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let resp = client
        .post(&reg.token_url)
        .form(&form)
        .header("Accept", "application/json")
        .send()
        .await
        .context("Token exchange request failed")?;

    let status = resp.status();
    let body = resp.text().await?;

    if !status.is_success() {
        anyhow::bail!("Token exchange failed ({}): {}", status, body);
    }

    parse_token_response(&body, &reg.id)
}

// ─── Token Revocation ──────────────────────────────────────────────────

/// Revoke a token at the provider's revocation endpoint.
pub async fn revoke_token(
    reg: &OAuthRegistration,
    token: &str,
    token_type_hint: &str,
) -> Result<()> {
    let revocation_url = match &reg.revocation_url {
        Some(url) => url,
        None => return Ok(()), // No revocation endpoint — just delete locally
    };

    let client = reqwest::Client::new();

    let mut form = vec![
        ("token", token.to_string()),
        ("token_type_hint", token_type_hint.to_string()),
        ("client_id", reg.client_id.clone()),
    ];

    if let Some(ref secret) = reg.client_secret {
        form.push(("client_secret", secret.clone()));
    }

    let resp = client
        .post(revocation_url)
        .form(&form)
        .send()
        .await
        .context("Token revocation request failed")?;

    // RFC 7009: revocation endpoint always returns 200, even for invalid tokens
    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        tracing::warn!(
            provider = %reg.provider,
            status = %status,
            "Token revocation returned non-200: {}",
            body
        );
    }

    Ok(())
}

// ─── Response parsing ──────────────────────────────────────────────────

/// Standard OAuth token response fields.
#[derive(Debug, Deserialize)]
struct TokenResponse {
    access_token: String,
    token_type: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    scope: Option<String>,
}

/// Parse a token response into StoredOAuthTokens.
fn parse_token_response(body: &str, registration_id: &str) -> Result<StoredOAuthTokens> {
    let resp: TokenResponse =
        serde_json::from_str(body).context("Failed to parse token response")?;

    let expires_at = match resp.expires_in {
        Some(secs) => Utc::now() + Duration::seconds(secs),
        None => Utc::now() + Duration::hours(1), // default 1h if not specified
    };

    let granted_scopes = resp
        .scope
        .map(|s| s.split_whitespace().map(String::from).collect())
        .unwrap_or_default();

    Ok(StoredOAuthTokens {
        registration_id: registration_id.to_string(),
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        expires_at,
        token_type: resp.token_type.unwrap_or_else(|| "Bearer".to_string()),
        granted_scopes,
        last_refreshed: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pkce_challenge() {
        let verifier = generate_code_verifier();
        assert!(verifier.len() >= 43);

        let challenge = compute_code_challenge(&verifier);
        assert!(!challenge.is_empty());

        // Same verifier → same challenge
        let challenge2 = compute_code_challenge(&verifier);
        assert_eq!(challenge, challenge2);

        // Different verifier → different challenge
        let verifier2 = generate_code_verifier();
        let challenge3 = compute_code_challenge(&verifier2);
        assert_ne!(challenge, challenge3);
    }

    #[test]
    fn test_parse_token_response() {
        let body = r#"{
            "access_token": "gho_abc123",
            "token_type": "bearer",
            "expires_in": 3600,
            "refresh_token": "ghr_xyz789",
            "scope": "repo read:org"
        }"#;

        let tokens = parse_token_response(body, "gh-001").unwrap();
        assert_eq!(tokens.access_token, "gho_abc123");
        assert_eq!(tokens.refresh_token.as_deref(), Some("ghr_xyz789"));
        assert_eq!(tokens.granted_scopes, vec!["repo", "read:org"]);
        assert_eq!(tokens.registration_id, "gh-001");
    }

    #[test]
    fn test_start_auth_code_flow() {
        let reg = OAuthRegistration {
            id: "test".into(),
            provider: "github".into(),
            client_id: "my-app".into(),
            client_secret: None,
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

        let result = start_auth_code_flow(&reg, "http://localhost:8080/callback").unwrap();

        assert!(result.authorization_url.contains("response_type=code"));
        assert!(result.authorization_url.contains("client_id=my-app"));
        assert!(result.authorization_url.contains("code_challenge="));
        assert!(result.authorization_url.contains("code_challenge_method=S256"));
        assert!(!result.code_verifier.is_empty());
        assert!(!result.state.is_empty());
    }
}
