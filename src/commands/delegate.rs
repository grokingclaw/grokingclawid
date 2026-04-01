//! `delegate` subcommand — Create a narrowed delegation token for a sub-agent.
//!
//! Supports Ed25519, ML-DSA-65, and hybrid delegation signing.
//! Delegation enforces two invariants:
//! 1. Scopes can only narrow (delegated scopes must be a subset of parent's).
//! 2. TTL must be shorter than the parent's remaining lifetime.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use std::fs;
use std::path::Path;
use uuid::Uuid;

use crate::audit;
use crate::commands::issue::parse_ttl;
use crate::crypto;
use crate::models::{AgentCard, CryptoScheme, DelegationToken};

/// Execute the `delegate` command.
pub fn execute(
    card_path: &Path,
    key_path: &Path,
    to_name: &str,
    scope: &str,
    ttl: &str,
    output_dir: &Path,
) -> Result<()> {
    // Load parent card
    let card_json = fs::read_to_string(card_path)
        .with_context(|| format!("Failed to read card: {}", card_path.display()))?;
    let parent_card: AgentCard = serde_json::from_str(&card_json)
        .with_context(|| format!("Failed to parse card: {}", card_path.display()))?;

    // Load parent private key(s)
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read key: {}", key_path.display()))?;

    // Parse requested scopes
    let requested_scopes: Vec<String> = scope.split(',').map(|s| s.trim().to_string()).collect();

    // Enforce: delegated scopes must be a subset of parent's scopes
    for s in &requested_scopes {
        if !parent_card.scopes.contains(s) {
            bail!(
                "Cannot delegate scope '{}' — parent only has: [{}]",
                s,
                parent_card.scopes.join(", ")
            );
        }
    }

    // Parse TTL
    let duration = parse_ttl(ttl)?;
    let now = Utc::now();
    let expires_at = now + duration;

    // Enforce: delegation must expire before parent
    if expires_at > parent_card.expires_at {
        bail!(
            "Delegation TTL ({}) would expire after parent ({}). Must be shorter.",
            expires_at.to_rfc3339(),
            parent_card.expires_at.to_rfc3339()
        );
    }

    // Build and sign the delegation token based on parent's crypto scheme
    let id = Uuid::new_v4();

    let (signature, pq_signature, ed_signing_key) = match &parent_card.crypto_scheme {
        CryptoScheme::Ed25519 => {
            let ed_key = crypto::decode_private_key_pem(&key_pem)?;
            // Verify key matches card
            let derived_pub = crypto::encode_public_key(&ed_key.verifying_key());
            if derived_pub != parent_card.public_key {
                bail!("Private key does not match the public key in the agent card");
            }
            let token = build_token(id, parent_card.id, to_name, &requested_scopes, now, expires_at, "", None, &CryptoScheme::Ed25519);
            let payload = token_signing_payload(&token)?;
            let sig = crypto::sign(&ed_key, payload.as_bytes());
            (sig, None, ed_key)
        }
        CryptoScheme::MlDsa65 | CryptoScheme::Hybrid => {
            let (ed_key, mldsa_key) = crypto::decode_hybrid_private_key_pem(&key_pem)?;
            // Verify Ed25519 key matches
            let derived_pub = crypto::encode_public_key(&ed_key.verifying_key());
            if derived_pub != parent_card.public_key {
                bail!("Private key does not match the public key in the agent card");
            }
            let token = build_token(id, parent_card.id, to_name, &requested_scopes, now, expires_at, "", None, &parent_card.crypto_scheme);
            let payload = token_signing_payload(&token)?;
            let ed_sig = crypto::sign(&ed_key, payload.as_bytes());
            let pq_sig = crypto::mldsa_sign(&mldsa_key, payload.as_bytes())?;
            (ed_sig, Some(pq_sig), ed_key)
        }
    };

    let token = DelegationToken {
        id,
        parent_id: parent_card.id,
        agent_name: to_name.to_string(),
        scopes: requested_scopes,
        issued_at: now,
        expires_at,
        signature,
        pq_signature,
        crypto_scheme: parent_card.crypto_scheme.clone(),
    };

    // Write output
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

    let token_path = output_dir.join("delegation-token.json");
    let token_json =
        serde_json::to_string_pretty(&token).context("Failed to serialize delegation token")?;
    fs::write(&token_path, &token_json)
        .with_context(|| format!("Failed to write {}", token_path.display()))?;

    // Record in audit log
    let conn = audit::open_db()?;
    let target_desc = format!("delegate:{}", to_name);
    audit::record_entry(&conn, &parent_card.id, "delegate", &target_desc, &ed_signing_key)?;

    // Print summary
    println!("✅ Delegation token created successfully!");
    println!();
    println!("  Token ID:  {}", token.id);
    println!("  Parent ID: {}", token.parent_id);
    println!("  Agent:     {}", token.agent_name);
    println!("  Crypto:    {}", token.crypto_scheme);
    println!("  Scopes:    {}", token.scopes.join(", "));
    println!("  Issued:    {}", token.issued_at.to_rfc3339());
    println!("  Expires:   {}", token.expires_at.to_rfc3339());
    println!();
    println!("  Token:     {}", token_path.display());

    Ok(())
}

/// Build a DelegationToken with placeholder signatures.
#[allow(clippy::too_many_arguments)]
fn build_token(
    id: Uuid,
    parent_id: Uuid,
    agent_name: &str,
    scopes: &[String],
    issued_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    signature: &str,
    pq_signature: Option<&str>,
    crypto_scheme: &CryptoScheme,
) -> DelegationToken {
    DelegationToken {
        id,
        parent_id,
        agent_name: agent_name.to_string(),
        scopes: scopes.to_vec(),
        issued_at,
        expires_at,
        signature: signature.to_string(),
        pq_signature: pq_signature.map(|s| s.to_string()),
        crypto_scheme: crypto_scheme.clone(),
    }
}

/// Create the canonical signing payload for a delegation token.
fn token_signing_payload(token: &DelegationToken) -> Result<String> {
    let mut tok = token.clone();
    tok.signature = String::new();
    tok.pq_signature = None;
    serde_json::to_string(&tok).context("Failed to serialize token for signing")
}
