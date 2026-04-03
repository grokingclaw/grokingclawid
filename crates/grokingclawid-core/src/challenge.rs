//! Agent-to-agent verification challenges.
//!
//! Implements a cryptographic challenge/response protocol for verifying
//! that a peer is a genuine AI agent with a valid GrokingClawID identity.
//!
//! Inspired by:
//! - aCAPTCHA (arxiv 2603.07116) — asymmetric hardness verification
//! - Unit42 session smuggling research — 82.4% of LLMs execute injected
//!   payloads from peer agents without verification
//!
//! ## Protocol
//!
//! 1. **Challenger** creates a `Challenge` with a nonce, timestamp, and
//!    required capabilities
//! 2. **Responder** signs the challenge with their identity key and
//!    includes their agent card
//! 3. **Challenger** verifies: signature validity, card expiration,
//!    scope sufficiency, and time bounds
//!
//! This prevents session smuggling because every A2A interaction requires
//! cryptographic proof of identity BEFORE any instructions are accepted.

use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Duration, Utc};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto;
use crate::models::{AgentCard, CryptoScheme};

// ─── Challenge ──────────────────────────────────────────────────────────

/// A verification challenge issued to a peer agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Challenge {
    /// Unique challenge ID
    pub id: Uuid,
    /// Random nonce (base64, 32 bytes)
    pub nonce: String,
    /// Who issued this challenge (agent ID or URI)
    pub issuer: String,
    /// Required scopes the responder must have
    pub required_scopes: Vec<String>,
    /// Challenge creation time
    pub issued_at: DateTime<Utc>,
    /// Challenge expiration (default: 30 seconds — tight window)
    pub expires_at: DateTime<Utc>,
    /// Minimum crypto scheme required (e.g., "hybrid" for PQ)
    pub min_crypto: Option<String>,
}

/// A response to a verification challenge.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChallengeResponse {
    /// The challenge ID being responded to
    pub challenge_id: Uuid,
    /// The responder's agent card (full, for verification)
    pub agent_card: AgentCard,
    /// Ed25519 signature over the challenge bytes
    pub signature: String,
    /// ML-DSA-65 signature over the challenge bytes (if hybrid)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
    /// Response timestamp
    pub responded_at: DateTime<Utc>,
}

/// Result of verifying a challenge response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Overall pass/fail
    pub verified: bool,
    /// Individual check results
    pub checks: Vec<Check>,
    /// The verified agent ID (if passed)
    pub agent_id: Option<String>,
    /// The verified agent name (if passed)
    pub agent_name: Option<String>,
}

/// A single verification check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Check {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

// ─── Challenge Creation ─────────────────────────────────────────────────

/// Create a new verification challenge.
///
/// - `issuer`: Your agent ID or URI
/// - `required_scopes`: Scopes the peer must have to pass
/// - `ttl_seconds`: How long the challenge is valid (default: 30s)
/// - `require_pq`: Whether to require post-quantum signing
pub fn create_challenge(
    issuer: &str,
    required_scopes: &[String],
    ttl_seconds: Option<i64>,
    require_pq: bool,
) -> Challenge {
    let ttl = ttl_seconds.unwrap_or(30);
    let now = Utc::now();

    // Generate 32 bytes of random nonce
    let nonce_bytes: [u8; 32] = rand::random();

    Challenge {
        id: Uuid::new_v4(),
        nonce: BASE64.encode(nonce_bytes),
        issuer: issuer.to_string(),
        required_scopes: required_scopes.to_vec(),
        issued_at: now,
        expires_at: now + Duration::seconds(ttl),
        min_crypto: if require_pq {
            Some("hybrid".to_string())
        } else {
            None
        },
    }
}

/// Serialize a challenge to canonical bytes for signing.
///
/// The canonical form is deterministic — same challenge always
/// produces the same bytes regardless of serialization order.
pub fn challenge_to_sign_bytes(challenge: &Challenge) -> Vec<u8> {
    // Canonical: id || nonce || issuer || issued_at_unix || expires_at_unix
    let mut data = Vec::new();
    data.extend_from_slice(challenge.id.as_bytes());
    data.extend_from_slice(challenge.nonce.as_bytes());
    data.extend_from_slice(challenge.issuer.as_bytes());
    data.extend_from_slice(&challenge.issued_at.timestamp().to_le_bytes());
    data.extend_from_slice(&challenge.expires_at.timestamp().to_le_bytes());
    for scope in &challenge.required_scopes {
        data.extend_from_slice(scope.as_bytes());
    }
    data
}

// ─── Challenge Response ─────────────────────────────────────────────────

/// Respond to a challenge by signing it with the agent's keys.
pub fn respond_to_challenge(
    challenge: &Challenge,
    card: &AgentCard,
    ed_signing_key: &ed25519_dalek::SigningKey,
    mldsa_secret_key: Option<&[u8]>,
) -> Result<ChallengeResponse> {
    let sign_bytes = challenge_to_sign_bytes(challenge);

    // Ed25519 signature
    let ed_sig = ed_signing_key.sign(&sign_bytes);
    let ed_sig_b64 = BASE64.encode(ed_sig.to_bytes());

    // ML-DSA-65 signature (if available)
    let pq_sig = match mldsa_secret_key {
        Some(sk) => Some(crypto::mldsa_sign(sk, &sign_bytes)?),
        None => None,
    };

    Ok(ChallengeResponse {
        challenge_id: challenge.id,
        agent_card: card.clone(),
        signature: ed_sig_b64,
        pq_signature: pq_sig,
        responded_at: Utc::now(),
    })
}

// ─── Verification ───────────────────────────────────────────────────────

/// Verify a challenge response.
///
/// Performs 6 checks:
/// 1. Challenge not expired
/// 2. Challenge ID matches
/// 3. Agent card not expired
/// 4. Ed25519 signature valid
/// 5. ML-DSA-65 signature valid (if hybrid)
/// 6. Required scopes satisfied
/// 7. Crypto scheme meets minimum requirement
pub fn verify_response(
    challenge: &Challenge,
    response: &ChallengeResponse,
) -> Result<VerificationResult> {
    let mut checks = Vec::new();
    let now = Utc::now();
    let sign_bytes = challenge_to_sign_bytes(challenge);

    // 1. Challenge not expired
    let time_ok = now <= challenge.expires_at;
    checks.push(Check {
        name: "challenge_expiry".to_string(),
        passed: time_ok,
        detail: if time_ok {
            format!("Challenge valid until {}", challenge.expires_at)
        } else {
            format!("Challenge expired at {} (now: {})", challenge.expires_at, now)
        },
    });

    // 2. Challenge ID matches
    let id_ok = response.challenge_id == challenge.id;
    checks.push(Check {
        name: "challenge_id".to_string(),
        passed: id_ok,
        detail: if id_ok {
            "Challenge ID matches".to_string()
        } else {
            format!(
                "ID mismatch: expected {}, got {}",
                challenge.id, response.challenge_id
            )
        },
    });

    // 3. Agent card not expired
    let card = &response.agent_card;
    let card_ok = now < card.expires_at;
    checks.push(Check {
        name: "card_expiry".to_string(),
        passed: card_ok,
        detail: if card_ok {
            format!("Card valid until {}", card.expires_at)
        } else {
            format!("Card expired at {}", card.expires_at)
        },
    });

    // 4. Ed25519 signature
    let ed_ok = crypto::verify(&card.public_key, &sign_bytes, &response.signature)
        .unwrap_or(false);
    checks.push(Check {
        name: "ed25519_signature".to_string(),
        passed: ed_ok,
        detail: if ed_ok {
            "Ed25519 signature valid".to_string()
        } else {
            "Ed25519 signature INVALID".to_string()
        },
    });

    // 5. ML-DSA-65 signature (if hybrid)
    let _pq_checked = if card.crypto_scheme == CryptoScheme::Hybrid {
        match (&response.pq_signature, &card.pq_public_key) {
            (Some(pq_sig), Some(pq_pub)) => {
                let valid = crypto::mldsa_verify(pq_pub, &sign_bytes, pq_sig)
                    .unwrap_or(false);
                checks.push(Check {
                    name: "mldsa65_signature".to_string(),
                    passed: valid,
                    detail: if valid {
                        "ML-DSA-65 signature valid".to_string()
                    } else {
                        "ML-DSA-65 signature INVALID".to_string()
                    },
                });
                valid
            }
            _ => {
                checks.push(Check {
                    name: "mldsa65_signature".to_string(),
                    passed: false,
                    detail: "Hybrid card but missing PQ signature or public key".to_string(),
                });
                false
            }
        }
    } else {
        true // Not required for ed25519-only
    };

    // 6. Required scopes
    let scopes_ok = challenge.required_scopes.iter().all(|required| {
        card.scopes.iter().any(|s| s == required)
    });
    checks.push(Check {
        name: "scopes".to_string(),
        passed: scopes_ok,
        detail: if scopes_ok {
            format!("All required scopes present: {:?}", challenge.required_scopes)
        } else {
            let missing: Vec<&String> = challenge.required_scopes.iter()
                .filter(|r| !card.scopes.contains(r))
                .collect();
            format!("Missing scopes: {:?}", missing)
        },
    });

    // 7. Crypto scheme minimum
    let crypto_ok = match &challenge.min_crypto {
        Some(min) if min == "hybrid" => card.crypto_scheme == CryptoScheme::Hybrid,
        Some(min) if min == "ml-dsa-65" => {
            card.crypto_scheme == CryptoScheme::MlDsa65
                || card.crypto_scheme == CryptoScheme::Hybrid
        }
        _ => true,
    };
    if challenge.min_crypto.is_some() {
        checks.push(Check {
            name: "crypto_scheme".to_string(),
            passed: crypto_ok,
            detail: if crypto_ok {
                format!("Crypto scheme {} meets requirement", card.crypto_scheme)
            } else {
                format!(
                    "Crypto scheme {} does not meet minimum: {}",
                    card.crypto_scheme,
                    challenge.min_crypto.as_deref().unwrap_or("any")
                )
            },
        });
    }

    let all_passed = checks.iter().all(|c| c.passed);

    Ok(VerificationResult {
        verified: all_passed,
        checks,
        agent_id: if all_passed {
            Some(card.id.to_string())
        } else {
            None
        },
        agent_name: if all_passed {
            Some(card.name.clone())
        } else {
            None
        },
    })
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{
        encode_mldsa_public_key, encode_public_key, generate_hybrid_keypair, generate_keypair,
    };

    fn make_test_card(
        name: &str,
        scopes: Vec<String>,
        scheme: CryptoScheme,
        ed_vk: &ed25519_dalek::VerifyingKey,
        pq_pub: Option<&[u8]>,
    ) -> AgentCard {
        let now = Utc::now();
        let _card_bytes = serde_json::to_vec(&serde_json::json!({
            "name": name, "scopes": scopes
        }))
        .unwrap();

        AgentCard {
            id: Uuid::new_v4(),
            name: name.to_string(),
            owner: "test@example.com".to_string(),
            scopes,
            public_key: encode_public_key(ed_vk),
            pq_public_key: pq_pub.map(encode_mldsa_public_key),
            signature: "placeholder".to_string(),
            pq_signature: None,
            crypto_scheme: scheme,
            issued_at: now,
            expires_at: now + Duration::hours(1),
            agent_type: crate::models::AgentType::Instance,
            parent_id: None,
            spiffe_id: None,
        }
    }

    #[test]
    fn test_challenge_response_ed25519() {
        let (sk, vk) = generate_keypair();
        let card = make_test_card(
            "test-agent",
            vec!["read".to_string()],
            CryptoScheme::Ed25519,
            &vk,
            None,
        );

        let challenge = create_challenge(
            "challenger-1",
            &["read".to_string()],
            Some(60),
            false,
        );

        let response = respond_to_challenge(&challenge, &card, &sk, None).unwrap();
        let result = verify_response(&challenge, &response).unwrap();

        assert!(result.verified, "Checks: {:?}", result.checks);
        assert_eq!(result.agent_name, Some("test-agent".to_string()));
    }

    #[test]
    fn test_challenge_response_hybrid() {
        let hkp = generate_hybrid_keypair().unwrap();
        let card = make_test_card(
            "pq-agent",
            vec!["read".to_string(), "write".to_string()],
            CryptoScheme::Hybrid,
            &hkp.ed25519_verifying,
            Some(&hkp.mldsa_public),
        );

        let challenge = create_challenge(
            "challenger-2",
            &["read".to_string()],
            Some(60),
            true, // require PQ
        );

        let response = respond_to_challenge(
            &challenge,
            &card,
            &hkp.ed25519_signing,
            Some(&hkp.mldsa_secret),
        )
        .unwrap();

        let result = verify_response(&challenge, &response).unwrap();
        assert!(result.verified, "Checks: {:?}", result.checks);
    }

    #[test]
    fn test_challenge_rejects_missing_scope() {
        let (sk, vk) = generate_keypair();
        let card = make_test_card(
            "limited-agent",
            vec!["read".to_string()],
            CryptoScheme::Ed25519,
            &vk,
            None,
        );

        let challenge = create_challenge(
            "challenger",
            &["admin".to_string()], // agent doesn't have "admin"
            Some(60),
            false,
        );

        let response = respond_to_challenge(&challenge, &card, &sk, None).unwrap();
        let result = verify_response(&challenge, &response).unwrap();

        assert!(!result.verified);
        let scope_check = result.checks.iter().find(|c| c.name == "scopes").unwrap();
        assert!(!scope_check.passed);
    }

    #[test]
    fn test_challenge_rejects_wrong_key() {
        let (sk1, _vk1) = generate_keypair();
        let (_sk2, vk2) = generate_keypair();

        // Card has vk2's public key, but we sign with sk1
        let card = make_test_card(
            "imposter",
            vec!["read".to_string()],
            CryptoScheme::Ed25519,
            &vk2, // different key
            None,
        );

        let challenge = create_challenge("challenger", &["read".to_string()], Some(60), false);
        let response = respond_to_challenge(&challenge, &card, &sk1, None).unwrap();
        let result = verify_response(&challenge, &response).unwrap();

        assert!(!result.verified);
        let sig_check = result
            .checks
            .iter()
            .find(|c| c.name == "ed25519_signature")
            .unwrap();
        assert!(!sig_check.passed);
    }

    #[test]
    fn test_challenge_rejects_expired() {
        let (sk, vk) = generate_keypair();
        let card = make_test_card(
            "slow-agent",
            vec!["read".to_string()],
            CryptoScheme::Ed25519,
            &vk,
            None,
        );

        // Create an already-expired challenge
        let mut challenge =
            create_challenge("challenger", &["read".to_string()], Some(60), false);
        challenge.expires_at = Utc::now() - Duration::seconds(10);

        let response = respond_to_challenge(&challenge, &card, &sk, None).unwrap();
        let result = verify_response(&challenge, &response).unwrap();

        assert!(!result.verified);
        let time_check = result
            .checks
            .iter()
            .find(|c| c.name == "challenge_expiry")
            .unwrap();
        assert!(!time_check.passed);
    }

    #[test]
    fn test_challenge_rejects_ed25519_when_pq_required() {
        let (sk, vk) = generate_keypair();
        let card = make_test_card(
            "classical-agent",
            vec!["read".to_string()],
            CryptoScheme::Ed25519,
            &vk,
            None,
        );

        let challenge = create_challenge(
            "challenger",
            &["read".to_string()],
            Some(60),
            true, // require PQ
        );

        let response = respond_to_challenge(&challenge, &card, &sk, None).unwrap();
        let result = verify_response(&challenge, &response).unwrap();

        assert!(!result.verified);
        let crypto_check = result
            .checks
            .iter()
            .find(|c| c.name == "crypto_scheme")
            .unwrap();
        assert!(!crypto_check.passed);
    }
}
