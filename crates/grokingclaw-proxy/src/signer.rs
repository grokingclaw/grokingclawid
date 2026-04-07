//! RFC 9421 request signer for the sidecar proxy.
//!
//! Signs outbound HTTP requests with the agent's Ed25519 key,
//! adding Signature and Signature-Input headers that prove
//! the agent's identity to the receiving service.

use anyhow::{Context, Result};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::SigningKey;
use std::path::Path;

/// Request signer that holds the agent's private key.
///
/// Supports Ed25519-only or hybrid (Ed25519 + ML-DSA-65) signing.
/// When a PQ secret key is present, both a classical `Signature` header
/// and a post-quantum `Signature-PQ` header are emitted.
pub struct RequestSigner {
    signing_key: SigningKey,
    /// Optional ML-DSA-65 secret key bytes for hybrid signing.
    pq_secret_key: Option<Vec<u8>>,
    agent_id: String,
    key_id: String,
}

impl RequestSigner {
    /// Load the agent's signing key from PEM file.
    ///
    /// Attempts hybrid key decoding first (Ed25519 + ML-DSA-65).
    /// Falls back to Ed25519-only if the PEM contains only a classical key.
    pub fn from_pem(pem_path: &Path, agent_id: &str) -> Result<Self> {
        let pem = std::fs::read_to_string(pem_path)
            .with_context(|| format!("Failed to read key: {}", pem_path.display()))?;

        let key_id = format!("clawid-{}", &agent_id[..8.min(agent_id.len())]);

        // Try hybrid key first
        if let Ok((ed_key, pq_secret)) = grokingclawid_core::crypto::decode_hybrid_private_key_pem(&pem) {
            return Ok(Self {
                signing_key: ed_key,
                pq_secret_key: Some(pq_secret),
                agent_id: agent_id.to_string(),
                key_id,
            });
        }

        // Try ML-DSA-65 only (unusual for proxy, but handle gracefully)
        // Fall back to Ed25519-only
        let signing_key = grokingclawid_core::crypto::decode_private_key_pem(&pem)
            .context("Failed to decode agent private key")?;

        Ok(Self {
            signing_key,
            pq_secret_key: None,
            agent_id: agent_id.to_string(),
            key_id,
        })
    }

    /// Sign an HTTP request, returning headers to add.
    ///
    /// Produces a simplified RFC 9421 signature covering:
    /// - @method
    /// - @target-uri (or @authority for CONNECT)
    /// - date
    ///
    /// Returns: Vec<(header_name, header_value)>
    pub fn sign_request(
        &self,
        method: &str,
        uri: &str,
        existing_headers: &[(String, String)],
    ) -> Result<Vec<(String, String)>> {
        let now = chrono::Utc::now();
        let created = now.timestamp();
        let nonce = uuid::Uuid::new_v4().to_string();

        // Build the signature base string
        let sig_base = format!(
            "\"@method\": {}\n\
             \"@target-uri\": {}\n\
             \"@authority\": {}\n\
             \"@signature-params\": (\"@method\" \"@target-uri\" \"@authority\");created={};keyid=\"{}\";nonce=\"{}\";alg=\"ed25519\"",
            method.to_uppercase(),
            uri,
            extract_authority(uri),
            created,
            self.key_id,
            nonce,
        );

        // Sign with Ed25519
        use ed25519_dalek::Signer;
        let signature = self.signing_key.sign(sig_base.as_bytes());
        let sig_b64 = BASE64.encode(signature.to_bytes());

        // Build headers
        let sig_input = format!(
            "sig1=(\"@method\" \"@target-uri\" \"@authority\");created={};keyid=\"{}\";nonce=\"{}\";alg=\"ed25519\"",
            created, self.key_id, nonce,
        );

        let mut headers = vec![
            ("Signature-Input".to_string(), sig_input),
            ("Signature".to_string(), format!("sig1=:{sig_b64}:")),
            ("X-ClawID-Agent".to_string(), self.agent_id.clone()),
        ];

        // Add ML-DSA-65 post-quantum signature if hybrid key is available
        if let Some(ref pq_key) = self.pq_secret_key {
            match grokingclawid_core::crypto::mldsa_sign(pq_key, sig_base.as_bytes()) {
                Ok(pq_sig_b64) => {
                    headers.push(("Signature-PQ".to_string(), format!("sig1=:{pq_sig_b64}:")));
                }
                Err(e) => {
                    tracing::warn!(error = %e, "Failed to generate PQ signature, sending Ed25519 only");
                }
            }
        }

        // Add date if not already present
        let has_date = existing_headers
            .iter()
            .any(|(k, _)| k.to_lowercase() == "date");
        if !has_date {
            headers.push(("Date".to_string(), now.to_rfc2822()));
        }

        Ok(headers)
    }

    /// Get the agent ID.
    pub fn agent_id(&self) -> &str {
        &self.agent_id
    }
}

/// Extract authority (host:port or host) from a URI.
fn extract_authority(uri: &str) -> String {
    if let Ok(url) = url::Url::parse(uri) {
        let host = url.host_str().unwrap_or("");
        match url.port() {
            Some(port) => format!("{}:{}", host, port),
            None => host.to_string(),
        }
    } else {
        // Might be host:port directly (CONNECT)
        uri.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grokingclawid_core::crypto::generate_keypair;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_signer() -> RequestSigner {
        let (signing_key, _) = generate_keypair();
        let pem = grokingclawid_core::crypto::encode_private_key_pem(&signing_key);
        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(pem.as_bytes()).unwrap();

        RequestSigner::from_pem(tmp.path(), "test-agent-123").unwrap()
    }

    #[test]
    fn test_sign_request_produces_headers() {
        let signer = create_test_signer();
        let headers = signer
            .sign_request("GET", "https://api.openai.com/v1/chat/completions", &[])
            .unwrap();

        // Should produce Signature-Input, Signature, X-ClawID-Agent, Date
        assert!(headers.len() >= 3);

        let names: Vec<&str> = headers.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"Signature-Input"));
        assert!(names.contains(&"Signature"));
        assert!(names.contains(&"X-ClawID-Agent"));
    }

    #[test]
    fn test_sign_request_agent_id() {
        let signer = create_test_signer();
        let headers = signer
            .sign_request("POST", "https://example.com", &[])
            .unwrap();
        let agent_header = headers.iter().find(|(k, _)| k == "X-ClawID-Agent").unwrap();
        assert_eq!(agent_header.1, "test-agent-123");
    }
}
