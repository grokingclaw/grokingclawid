//! RFC 9421 HTTP Message Signatures for AI agent authentication.
//!
//! Implements cryptographic signing and verification of HTTP messages
//! per IETF RFC 9421. Supports both Ed25519 (classical) and hybrid
//! Ed25519 + ML-DSA-65 (post-quantum) signing.
//!
//! Also supports WebSocket upgrade request signing — the initial HTTP
//! upgrade handshake is signed, establishing authenticated identity
//! for the entire WebSocket session.
//!
//! ## Usage
//!
//! ```no_run
//! use grokingclawid_core::httpsig::{SignatureParams, sign_request, verify_request};
//! ```
//!
//! ## Compatibility
//! - Visa Trusted Agent Protocol (RFC 9421 based)
//! - Mastercard Verifiable Intent (RFC 9421 based)
//! - OpenBotAuth (RFC 9421 verification service)
//! - Google A2A agent cards (Ed25519-JWS + RFC 9421)

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::Utc;
use ed25519_dalek::{Signer, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::models::HybridSignature;

// ─── Signature Components ───────────────────────────────────────────────

/// HTTP message components that can be included in the signature base.
/// Per RFC 9421 §2.2 — derived components use @ prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Component {
    /// HTTP method (GET, POST, etc.)
    Method,
    /// Target URI (full URL)
    TargetUri,
    /// Authority (host[:port])
    Authority,
    /// Request path
    Path,
    /// Query string (without ?)
    Query,
    /// A regular HTTP header
    Header(String),
}

impl Component {
    /// RFC 9421 canonical identifier string.
    pub fn identifier(&self) -> String {
        match self {
            Component::Method => "\"@method\"".to_string(),
            Component::TargetUri => "\"@target-uri\"".to_string(),
            Component::Authority => "\"@authority\"".to_string(),
            Component::Path => "\"@path\"".to_string(),
            Component::Query => "\"@query\"".to_string(),
            Component::Header(name) => format!("\"{}\"", name.to_lowercase()),
        }
    }
}

/// Parameters for creating an HTTP message signature.
#[derive(Debug, Clone)]
pub struct SignatureParams {
    /// Key identifier — typically a URL to the public key or agent card
    pub keyid: String,
    /// Algorithm identifier
    pub alg: SignatureAlgorithm,
    /// Unix timestamp when signature was created
    pub created: i64,
    /// Optional expiration timestamp
    pub expires: Option<i64>,
    /// Optional nonce for replay protection
    pub nonce: Option<String>,
    /// Signature label (default: "sig1")
    pub label: String,
}

/// Supported signature algorithms.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SignatureAlgorithm {
    /// Ed25519 (classical) — RFC 9421 registered
    #[serde(rename = "ed25519")]
    Ed25519,
    /// Hybrid Ed25519 + ML-DSA-65 (post-quantum)
    /// Custom algorithm identifier for PQ-native agents
    #[serde(rename = "ed25519+ml-dsa-65")]
    Hybrid,
}

impl SignatureAlgorithm {
    pub fn as_str(&self) -> &str {
        match self {
            SignatureAlgorithm::Ed25519 => "ed25519",
            SignatureAlgorithm::Hybrid => "ed25519+ml-dsa-65",
        }
    }
}

impl Default for SignatureParams {
    fn default() -> Self {
        Self {
            keyid: String::new(),
            alg: SignatureAlgorithm::Ed25519,
            created: Utc::now().timestamp(),
            expires: None,
            nonce: None,
            label: "sig1".to_string(),
        }
    }
}

/// An HTTP request representation for signing.
#[derive(Debug, Clone)]
pub struct HttpRequest {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Option<Vec<u8>>,
}

/// A signed HTTP request with Signature and Signature-Input headers.
#[derive(Debug, Clone)]
pub struct SignedRequest {
    /// Original request
    pub request: HttpRequest,
    /// Signature-Input header value
    pub signature_input: String,
    /// Signature header value (Ed25519)
    pub signature: String,
    /// PQ signature header value (ML-DSA-65, if hybrid)
    pub pq_signature: Option<String>,
}

/// Result of signature verification.
#[derive(Debug, Clone)]
pub struct VerificationResult {
    /// Ed25519 signature valid
    pub ed25519_valid: bool,
    /// ML-DSA-65 signature valid (None if not present)
    pub mldsa65_valid: Option<bool>,
    /// Key ID from the signature
    pub keyid: String,
    /// Algorithm used
    pub alg: String,
    /// Creation timestamp
    pub created: i64,
    /// Whether signature has expired
    pub expired: bool,
}

// ─── Signature Base Construction ────────────────────────────────────────

/// Build the RFC 9421 signature base from request components.
///
/// The signature base is the canonical string representation that gets
/// signed. Per RFC 9421 §2.5:
///
/// ```text
/// "@method": GET
/// "@authority": example.com
/// "@path": /api/resource
/// "@signature-params": ("@method" "@authority" "@path");keyid="...";alg="ed25519";created=...
/// ```
pub fn build_signature_base(
    request: &HttpRequest,
    components: &[Component],
    params: &SignatureParams,
) -> Result<String> {
    let mut lines = Vec::new();
    let url = url::Url::parse(&request.url)
        .context("Invalid request URL")?;

    for component in components {
        let value = match component {
            Component::Method => request.method.to_uppercase(),
            Component::TargetUri => request.url.clone(),
            Component::Authority => {
                url.host_str().unwrap_or("").to_string()
                    + &url.port().map(|p| format!(":{}", p)).unwrap_or_default()
            }
            Component::Path => url.path().to_string(),
            Component::Query => {
                url.query().map(|q| format!("?{}", q)).unwrap_or_default()
            }
            Component::Header(name) => {
                let lower_name = name.to_lowercase();
                request.headers.iter()
                    .find(|(k, _)| k.to_lowercase() == lower_name)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            }
        };
        lines.push(format!("{}: {}", component.identifier(), value));
    }

    // Build @signature-params line
    let component_ids: Vec<String> = components.iter()
        .map(|c| c.identifier())
        .collect();
    let mut sig_params = format!("({})", component_ids.join(" "));

    // Append parameters
    sig_params.push_str(&format!(";keyid=\"{}\"", params.keyid));
    sig_params.push_str(&format!(";alg=\"{}\"", params.alg.as_str()));
    sig_params.push_str(&format!(";created={}", params.created));

    if let Some(expires) = params.expires {
        sig_params.push_str(&format!(";expires={}", expires));
    }
    if let Some(ref nonce) = params.nonce {
        sig_params.push_str(&format!(";nonce=\"{}\"", nonce));
    }

    lines.push(format!("\"@signature-params\": {}", sig_params));

    Ok(lines.join("\n"))
}

// ─── Signing ────────────────────────────────────────────────────────────

/// Sign an HTTP request with Ed25519.
///
/// Returns the signed request with `Signature` and `Signature-Input` headers.
pub fn sign_request(
    request: HttpRequest,
    components: &[Component],
    params: &SignatureParams,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<SignedRequest> {
    let sig_base = build_signature_base(&request, components, params)?;

    // Sign the signature base
    let signature = signing_key.sign(sig_base.as_bytes());
    let sig_b64 = BASE64.encode(signature.to_bytes());

    // Build Signature-Input header
    let component_ids: Vec<String> = components.iter()
        .map(|c| c.identifier())
        .collect();
    let mut sig_input = format!("{}=({})", params.label, component_ids.join(" "));
    sig_input.push_str(&format!(";keyid=\"{}\"", params.keyid));
    sig_input.push_str(&format!(";alg=\"{}\"", params.alg.as_str()));
    sig_input.push_str(&format!(";created={}", params.created));
    if let Some(expires) = params.expires {
        sig_input.push_str(&format!(";expires={}", expires));
    }
    if let Some(ref nonce) = params.nonce {
        sig_input.push_str(&format!(";nonce=\"{}\"", nonce));
    }

    // Build Signature header
    let sig_header = format!("{}=:{}:", params.label, sig_b64);

    Ok(SignedRequest {
        request,
        signature_input: sig_input,
        signature: sig_header,
        pq_signature: None,
    })
}

/// Sign an HTTP request with hybrid Ed25519 + ML-DSA-65.
///
/// Produces two signatures over the same signature base:
/// - `Signature` header: Ed25519 (compatible with standard RFC 9421 verifiers)
/// - `Signature-PQ` header: ML-DSA-65 (post-quantum attestation)
///
/// Both signatures cover identical content — quantum-safe from day one.
pub fn sign_request_hybrid(
    request: HttpRequest,
    components: &[Component],
    params: &SignatureParams,
    ed_signing_key: &ed25519_dalek::SigningKey,
    mldsa_secret_key: &[u8],
) -> Result<SignedRequest> {
    let sig_base = build_signature_base(&request, components, params)?;

    // Ed25519 signature (on-wire, RFC 9421 compatible)
    let ed_signature = ed_signing_key.sign(sig_base.as_bytes());
    let ed_sig_b64 = BASE64.encode(ed_signature.to_bytes());

    // ML-DSA-65 signature (PQ attestation, same signature base)
    let pq_sig_b64 = crypto::mldsa_sign(mldsa_secret_key, sig_base.as_bytes())?;

    // Build Signature-Input header
    let component_ids: Vec<String> = components.iter()
        .map(|c| c.identifier())
        .collect();
    let mut sig_input = format!("{}=({})", params.label, component_ids.join(" "));
    sig_input.push_str(&format!(";keyid=\"{}\"", params.keyid));
    sig_input.push_str(&format!(";alg=\"{}\"", params.alg.as_str()));
    sig_input.push_str(&format!(";created={}", params.created));
    if let Some(expires) = params.expires {
        sig_input.push_str(&format!(";expires={}", expires));
    }
    if let Some(ref nonce) = params.nonce {
        sig_input.push_str(&format!(";nonce=\"{}\"", nonce));
    }

    let sig_header = format!("{}=:{}:", params.label, ed_sig_b64);
    let pq_sig_header = format!("{}-pq=:{}:", params.label, pq_sig_b64);

    Ok(SignedRequest {
        request,
        signature_input: sig_input,
        signature: sig_header,
        pq_signature: Some(pq_sig_header),
    })
}

// ─── Verification ───────────────────────────────────────────────────────

/// Parse a Signature-Input header to extract parameters.
pub fn parse_signature_input(input: &str) -> Result<(Vec<Component>, SignatureParams)> {
    // Parse: sig1=("@method" "@authority" "@path");keyid="...";alg="ed25519";created=...
    let input = input.trim();

    // Split label from rest
    let (label, rest) = input.split_once('=')
        .context("Invalid Signature-Input: missing '='")?;

    // Extract component list inside parentheses
    let paren_start = rest.find('(')
        .context("Invalid Signature-Input: missing '('")?;
    let paren_end = rest.find(')')
        .context("Invalid Signature-Input: missing ')'")?;
    let components_str = &rest[paren_start + 1..paren_end];

    let components: Vec<Component> = components_str
        .split_whitespace()
        .map(|s| {
            let s = s.trim_matches('"');
            match s {
                "@method" => Component::Method,
                "@target-uri" => Component::TargetUri,
                "@authority" => Component::Authority,
                "@path" => Component::Path,
                "@query" => Component::Query,
                other => Component::Header(other.to_string()),
            }
        })
        .collect();

    // Parse parameters after the closing paren
    let params_str = &rest[paren_end + 1..];
    let mut params = SignatureParams {
        label: label.to_string(),
        ..Default::default()
    };

    for part in params_str.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some((key, value)) = part.split_once('=') {
            let value = value.trim_matches('"');
            match key {
                "keyid" => params.keyid = value.to_string(),
                "alg" => {
                    params.alg = match value {
                        "ed25519" => SignatureAlgorithm::Ed25519,
                        "ed25519+ml-dsa-65" => SignatureAlgorithm::Hybrid,
                        _ => SignatureAlgorithm::Ed25519,
                    };
                }
                "created" => {
                    params.created = value.parse().unwrap_or(0);
                }
                "expires" => {
                    params.expires = Some(value.parse().unwrap_or(0));
                }
                "nonce" => {
                    params.nonce = Some(value.to_string());
                }
                _ => {}
            }
        }
    }

    Ok((components, params))
}

/// Parse a Signature header to extract the raw signature bytes.
pub fn parse_signature(header: &str) -> Result<(String, Vec<u8>)> {
    // Parse: sig1=:BASE64:
    let (label, rest) = header.split_once('=')
        .context("Invalid Signature header: missing '='")?;
    let sig_b64 = rest.trim_matches(':');
    let sig_bytes = BASE64.decode(sig_b64)
        .context("Invalid Signature header: bad base64")?;
    Ok((label.to_string(), sig_bytes))
}

/// Verify an Ed25519 signature on an HTTP request.
pub fn verify_request(
    request: &HttpRequest,
    signature_input: &str,
    signature: &str,
    ed_public_key_b64: &str,
) -> Result<VerificationResult> {
    let (components, params) = parse_signature_input(signature_input)?;
    let (_, sig_bytes) = parse_signature(signature)?;

    // Reconstruct the signature base
    let sig_base = build_signature_base(request, &components, &params)?;

    // Verify Ed25519
    let pub_bytes = BASE64.decode(ed_public_key_b64)
        .context("Invalid public key base64")?;
    let pub_array: [u8; 32] = pub_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    let verifying_key = VerifyingKey::from_bytes(&pub_array)
        .context("Invalid Ed25519 public key")?;
    let sig_array: [u8; 64] = sig_bytes.try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be 64 bytes"))?;
    let ed_signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    let ed_valid = verifying_key.verify(sig_base.as_bytes(), &ed_signature).is_ok();

    // Check expiration
    let now = Utc::now().timestamp();
    let expired = params.expires.map(|e| now > e).unwrap_or(false);

    Ok(VerificationResult {
        ed25519_valid: ed_valid,
        mldsa65_valid: None,
        keyid: params.keyid.clone(),
        alg: params.alg.as_str().to_string(),
        created: params.created,
        expired,
    })
}

/// Verify a hybrid (Ed25519 + ML-DSA-65) signature on an HTTP request.
pub fn verify_request_hybrid(
    request: &HttpRequest,
    signature_input: &str,
    signature: &str,
    pq_signature: &str,
    ed_public_key_b64: &str,
    mldsa_public_key_b64: &str,
) -> Result<VerificationResult> {
    // First verify Ed25519
    let mut result = verify_request(request, signature_input, signature, ed_public_key_b64)?;

    // Then verify ML-DSA-65
    let (components, params) = parse_signature_input(signature_input)?;
    let sig_base = build_signature_base(request, &components, &params)?;
    let (_, pq_sig_bytes) = parse_signature(pq_signature)?;
    let pq_sig_b64 = BASE64.encode(&pq_sig_bytes);

    let pq_valid = crypto::mldsa_verify(
        mldsa_public_key_b64,
        sig_base.as_bytes(),
        &pq_sig_b64,
    )?;

    result.mldsa65_valid = Some(pq_valid);
    result.alg = "ed25519+ml-dsa-65".to_string();

    Ok(result)
}

// ─── WebSocket Upgrade Signing ──────────────────────────────────────────

/// Create a signed WebSocket upgrade request.
///
/// The initial HTTP upgrade handshake is signed with RFC 9421, establishing
/// cryptographic identity for the entire WebSocket session. The signed
/// components include the upgrade headers so the server knows:
/// 1. WHO is connecting (keyid → agent card)
/// 2. The connection hasn't been tampered with
/// 3. PQ attestation is embedded from the first byte
pub fn sign_ws_upgrade(
    url: &str,
    keyid: &str,
    ed_signing_key: &ed25519_dalek::SigningKey,
    mldsa_secret_key: Option<&[u8]>,
) -> Result<SignedRequest> {
    let parsed_url = url::Url::parse(url).context("Invalid WebSocket URL")?;

    // Build the upgrade request
    let authority = format!(
        "{}{}",
        parsed_url.host_str().unwrap_or(""),
        parsed_url.port().map(|p| format!(":{}", p)).unwrap_or_default()
    );

    let request = HttpRequest {
        method: "GET".to_string(),
        url: url.replace("wss://", "https://").replace("ws://", "http://"),
        headers: vec![
            ("host".to_string(), authority),
            ("upgrade".to_string(), "websocket".to_string()),
            ("connection".to_string(), "Upgrade".to_string()),
            ("sec-websocket-version".to_string(), "13".to_string()),
        ],
        body: None,
    };

    let components = vec![
        Component::Method,
        Component::Authority,
        Component::Path,
        Component::Header("upgrade".to_string()),
        Component::Header("sec-websocket-version".to_string()),
    ];

    let params = SignatureParams {
        keyid: keyid.to_string(),
        alg: if mldsa_secret_key.is_some() {
            SignatureAlgorithm::Hybrid
        } else {
            SignatureAlgorithm::Ed25519
        },
        created: Utc::now().timestamp(),
        expires: Some(Utc::now().timestamp() + 300), // 5 min validity
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        label: "ws-auth".to_string(),
    };

    if let Some(mldsa_sk) = mldsa_secret_key {
        sign_request_hybrid(request, &components, &params, ed_signing_key, mldsa_sk)
    } else {
        sign_request(request, &components, &params, ed_signing_key)
    }
}

/// Format signed headers for inclusion in a WebSocket upgrade request.
///
/// Returns headers as key-value pairs that can be added to the
/// HTTP upgrade request headers.
pub fn signed_headers(signed: &SignedRequest) -> Vec<(String, String)> {
    let mut headers = vec![
        ("Signature-Input".to_string(), signed.signature_input.clone()),
        ("Signature".to_string(), signed.signature.clone()),
    ];
    if let Some(ref pq_sig) = signed.pq_signature {
        headers.push(("Signature-PQ".to_string(), pq_sig.clone()));
    }
    headers
}

// ─── WebSocket Message Signing ──────────────────────────────────────────

/// A signed WebSocket message with inline PQ attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedWsMessage {
    /// The original message payload
    pub payload: String,
    /// Ed25519 signature over the payload (base64)
    pub signature: String,
    /// ML-DSA-65 signature over the payload (base64, if hybrid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
    /// Key ID of the signer
    pub keyid: String,
    /// Unix timestamp
    pub timestamp: i64,
    /// Sequence number for ordering/replay protection
    pub seq: u64,
}

/// Sign an individual WebSocket message.
///
/// For high-security channels where each message needs independent
/// verification (not just the upgrade handshake).
pub fn sign_ws_message(
    payload: &str,
    seq: u64,
    keyid: &str,
    ed_signing_key: &ed25519_dalek::SigningKey,
    mldsa_secret_key: Option<&[u8]>,
) -> Result<SignedWsMessage> {
    let timestamp = Utc::now().timestamp();

    // Sign: payload || seq || timestamp (prevents replay and reordering)
    let sign_data = format!("{}\n{}\n{}", payload, seq, timestamp);

    let ed_sig = crypto::sign(ed_signing_key, sign_data.as_bytes());

    let pq_sig = match mldsa_secret_key {
        Some(sk) => Some(crypto::mldsa_sign(sk, sign_data.as_bytes())?),
        None => None,
    };

    Ok(SignedWsMessage {
        payload: payload.to_string(),
        signature: ed_sig,
        pq_signature: pq_sig,
        keyid: keyid.to_string(),
        timestamp,
        seq,
    })
}

/// Verify a signed WebSocket message.
pub fn verify_ws_message(
    msg: &SignedWsMessage,
    ed_public_key_b64: &str,
    mldsa_public_key_b64: Option<&str>,
) -> Result<bool> {
    let sign_data = format!("{}\n{}\n{}", msg.payload, msg.seq, msg.timestamp);

    // Verify Ed25519
    let ed_valid = crypto::verify(ed_public_key_b64, sign_data.as_bytes(), &msg.signature)?;
    if !ed_valid {
        return Ok(false);
    }

    // Verify ML-DSA-65 if present
    if let (Some(ref pq_sig), Some(pq_pub)) = (&msg.pq_signature, mldsa_public_key_b64) {
        let pq_valid = crypto::mldsa_verify(pq_pub, sign_data.as_bytes(), pq_sig)?;
        if !pq_valid {
            return Ok(false);
        }
    }

    Ok(true)
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{generate_keypair, encode_public_key, generate_hybrid_keypair, encode_mldsa_public_key};

    #[test]
    fn test_sign_verify_ed25519_roundtrip() {
        let (sk, vk) = generate_keypair();
        let pub_b64 = encode_public_key(&vk);

        let request = HttpRequest {
            method: "GET".to_string(),
            url: "https://api.example.com/agents/status".to_string(),
            headers: vec![
                ("host".to_string(), "api.example.com".to_string()),
                ("date".to_string(), "Thu, 26 Mar 2026 00:00:00 GMT".to_string()),
            ],
            body: None,
        };

        let components = vec![
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::Header("date".to_string()),
        ];

        let now = chrono::Utc::now().timestamp();
        let params = SignatureParams {
            keyid: "test-agent-key-1".to_string(),
            alg: SignatureAlgorithm::Ed25519,
            created: now,
            expires: Some(now + 300), // 5 min from now
            nonce: Some("abc123".to_string()),
            label: "sig1".to_string(),
        };

        let signed = sign_request(request, &components, &params, &sk).unwrap();

        // Verify
        let result = verify_request(
            &signed.request,
            &signed.signature_input,
            &signed.signature,
            &pub_b64,
        ).unwrap();

        assert!(result.ed25519_valid);
        assert_eq!(result.keyid, "test-agent-key-1");
        assert_eq!(result.alg, "ed25519");
        assert!(!result.expired);
    }

    #[test]
    fn test_sign_verify_hybrid_roundtrip() {
        let hkp = generate_hybrid_keypair().unwrap();
        let ed_pub = encode_public_key(&hkp.ed25519_verifying);
        let pq_pub = encode_mldsa_public_key(&hkp.mldsa_public);

        let request = HttpRequest {
            method: "POST".to_string(),
            url: "https://api.example.com/agents/transfer".to_string(),
            headers: vec![
                ("host".to_string(), "api.example.com".to_string()),
                ("content-type".to_string(), "application/json".to_string()),
            ],
            body: Some(b"{\"amount\": 1000}".to_vec()),
        };

        let components = vec![
            Component::Method,
            Component::Authority,
            Component::Path,
            Component::Header("content-type".to_string()),
        ];

        let params = SignatureParams {
            keyid: "hybrid-agent-key".to_string(),
            alg: SignatureAlgorithm::Hybrid,
            created: Utc::now().timestamp(),
            expires: Some(Utc::now().timestamp() + 300),
            nonce: None,
            label: "sig1".to_string(),
        };

        let signed = sign_request_hybrid(
            request, &components, &params,
            &hkp.ed25519_signing, &hkp.mldsa_secret,
        ).unwrap();

        assert!(signed.pq_signature.is_some());

        // Verify both signatures
        let result = verify_request_hybrid(
            &signed.request,
            &signed.signature_input,
            &signed.signature,
            signed.pq_signature.as_ref().unwrap(),
            &ed_pub,
            &pq_pub,
        ).unwrap();

        assert!(result.ed25519_valid);
        assert_eq!(result.mldsa65_valid, Some(true));
        assert_eq!(result.alg, "ed25519+ml-dsa-65");
    }

    #[test]
    fn test_tampered_request_fails_verification() {
        let (sk, vk) = generate_keypair();
        let pub_b64 = encode_public_key(&vk);

        let request = HttpRequest {
            method: "GET".to_string(),
            url: "https://api.example.com/secret".to_string(),
            headers: vec![],
            body: None,
        };

        let components = vec![Component::Method, Component::Path];
        let params = SignatureParams {
            keyid: "test".to_string(),
            ..Default::default()
        };

        let signed = sign_request(request, &components, &params, &sk).unwrap();

        // Tamper with the request
        let mut tampered = signed.request.clone();
        tampered.url = "https://api.example.com/admin".to_string();

        let result = verify_request(
            &tampered,
            &signed.signature_input,
            &signed.signature,
            &pub_b64,
        ).unwrap();

        assert!(!result.ed25519_valid);
    }

    #[test]
    fn test_ws_upgrade_signing() {
        let (sk, _vk) = generate_keypair();

        let signed = sign_ws_upgrade(
            "wss://api.testnet.iota.cafe:443/ws",
            "agent-key-1",
            &sk,
            None,
        ).unwrap();

        assert!(signed.signature_input.contains("ws-auth"));
        assert!(signed.signature_input.contains("\"upgrade\""));
        assert!(signed.signature_input.contains("nonce="));
        assert!(signed.pq_signature.is_none());

        let headers = signed_headers(&signed);
        assert_eq!(headers.len(), 2); // Signature-Input + Signature
    }

    #[test]
    fn test_ws_upgrade_signing_hybrid() {
        let hkp = generate_hybrid_keypair().unwrap();

        let signed = sign_ws_upgrade(
            "wss://api.testnet.iota.cafe:443/ws",
            "hybrid-agent",
            &hkp.ed25519_signing,
            Some(&hkp.mldsa_secret),
        ).unwrap();

        assert!(signed.signature_input.contains("ed25519+ml-dsa-65"));
        assert!(signed.pq_signature.is_some());

        let headers = signed_headers(&signed);
        assert_eq!(headers.len(), 3); // Signature-Input + Signature + Signature-PQ
    }

    #[test]
    fn test_ws_message_sign_verify_roundtrip() {
        let (sk, vk) = generate_keypair();
        let pub_b64 = encode_public_key(&vk);

        let signed_msg = sign_ws_message(
            "{\"type\": \"subscribe\", \"filter\": \"all\"}",
            1,
            "agent-key",
            &sk,
            None,
        ).unwrap();

        assert!(verify_ws_message(&signed_msg, &pub_b64, None).unwrap());
    }

    #[test]
    fn test_ws_message_sign_verify_hybrid() {
        let hkp = generate_hybrid_keypair().unwrap();
        let ed_pub = encode_public_key(&hkp.ed25519_verifying);
        let pq_pub = encode_mldsa_public_key(&hkp.mldsa_public);

        let signed_msg = sign_ws_message(
            "{\"type\": \"transfer\", \"amount\": 1000}",
            42,
            "hybrid-agent",
            &hkp.ed25519_signing,
            Some(&hkp.mldsa_secret),
        ).unwrap();

        assert!(signed_msg.pq_signature.is_some());
        assert!(verify_ws_message(&signed_msg, &ed_pub, Some(&pq_pub)).unwrap());
    }

    #[test]
    fn test_ws_message_tampered_fails() {
        let (sk, vk) = generate_keypair();
        let pub_b64 = encode_public_key(&vk);

        let mut signed_msg = sign_ws_message(
            "original payload",
            1,
            "agent-key",
            &sk,
            None,
        ).unwrap();

        // Tamper
        signed_msg.payload = "tampered payload".to_string();

        assert!(!verify_ws_message(&signed_msg, &pub_b64, None).unwrap());
    }

    #[test]
    fn test_ws_message_replay_protection() {
        let (sk, vk) = generate_keypair();
        let pub_b64 = encode_public_key(&vk);

        let signed_msg = sign_ws_message("hello", 1, "key", &sk, None).unwrap();

        // Change sequence number (replay with different seq)
        let mut replayed = signed_msg.clone();
        replayed.seq = 2;

        // Original verifies
        assert!(verify_ws_message(&signed_msg, &pub_b64, None).unwrap());
        // Replayed with wrong seq fails
        assert!(!verify_ws_message(&replayed, &pub_b64, None).unwrap());
    }

    #[test]
    fn test_parse_signature_input_roundtrip() {
        let input = "sig1=(\"@method\" \"@authority\" \"@path\");keyid=\"test-key\";alg=\"ed25519\";created=1711411200;expires=1711411500;nonce=\"xyz\"";
        let (components, params) = parse_signature_input(input).unwrap();

        assert_eq!(components.len(), 3);
        assert_eq!(components[0], Component::Method);
        assert_eq!(components[1], Component::Authority);
        assert_eq!(components[2], Component::Path);
        assert_eq!(params.keyid, "test-key");
        assert_eq!(params.alg, SignatureAlgorithm::Ed25519);
        assert_eq!(params.created, 1711411200);
        assert_eq!(params.expires, Some(1711411500));
        assert_eq!(params.nonce, Some("xyz".to_string()));
    }
}
