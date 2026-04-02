//! `verify` subcommand — Validate an agent card's signature and expiration.
//!
//! Supports Ed25519, ML-DSA-65, and hybrid verification.

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs;
use std::path::Path;

use crate::commands::issue::card_signing_payload;
use grokingclawid_core::crypto;
use grokingclawid_core::models::{AgentCard, CryptoScheme};

/// Execute the `verify` command.
pub fn execute(card_path: &Path) -> Result<()> {
    let card_json = fs::read_to_string(card_path)
        .with_context(|| format!("Failed to read card: {}", card_path.display()))?;
    let card: AgentCard = serde_json::from_str(&card_json)
        .with_context(|| format!("Failed to parse card: {}", card_path.display()))?;

    println!("Agent Identity Card");
    println!("═══════════════════════════════════════");
    println!("  ID:        {}", card.id);
    println!("  Name:      {}", card.name);
    println!("  Owner:     {}", card.owner);
    println!("  Type:      {}", card.agent_type);
    println!("  Crypto:    {}", card.crypto_scheme);
    println!("  Scopes:    {}", card.scopes.join(", "));
    println!("  Issued:    {}", card.issued_at.to_rfc3339());
    println!("  Expires:   {}", card.expires_at.to_rfc3339());
    if let Some(ref sid) = card.spiffe_id {
        println!("  SPIFFE ID: {}", sid);
    }
    if let Some(ref pid) = card.parent_id {
        println!("  Parent ID: {}", pid);
    }
    println!("═══════════════════════════════════════");

    // Verify signature(s) based on crypto scheme
    let payload = card_signing_payload(&card)?;

    let (ed_valid, pq_valid) = match &card.crypto_scheme {
        CryptoScheme::Ed25519 => {
            let ed_ok = crypto::verify(&card.public_key, payload.as_bytes(), &card.signature)?;
            (ed_ok, None)
        }
        CryptoScheme::MlDsa65 => {
            let pq_pub = card.pq_public_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("ML-DSA-65 card missing pq_public_key"))?;
            let pq_sig = card.pq_signature.as_ref()
                .ok_or_else(|| anyhow::anyhow!("ML-DSA-65 card missing pq_signature"))?;
            let pq_ok = crypto::mldsa_verify(pq_pub, payload.as_bytes(), pq_sig)?;
            // Also check Ed25519 if present
            let ed_ok = crypto::verify(&card.public_key, payload.as_bytes(), &card.signature)?;
            (ed_ok, Some(pq_ok))
        }
        CryptoScheme::Hybrid => {
            let ed_ok = crypto::verify(&card.public_key, payload.as_bytes(), &card.signature)?;
            let pq_pub = card.pq_public_key.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Hybrid card missing pq_public_key"))?;
            let pq_sig = card.pq_signature.as_ref()
                .ok_or_else(|| anyhow::anyhow!("Hybrid card missing pq_signature"))?;
            let pq_ok = crypto::mldsa_verify(pq_pub, payload.as_bytes(), pq_sig)?;
            (ed_ok, Some(pq_ok))
        }
    };

    // Check expiration
    let now = Utc::now();
    let not_expired = now < card.expires_at;
    let not_before = now >= card.issued_at;

    println!();
    println!("  Ed25519:   {}", if ed_valid { "✅ VALID" } else { "❌ INVALID" });
    if let Some(pq) = pq_valid {
        println!("  ML-DSA-65: {}", if pq { "✅ VALID" } else { "❌ INVALID" });
    }
    println!("  Expired:   {}", if not_expired { "✅ No" } else { "❌ Yes" });
    println!("  Time OK:   {}", if not_before { "✅ Yes" } else { "⚠️  Not yet valid" });
    println!();

    let all_sigs_valid = ed_valid && pq_valid.unwrap_or(true);
    if all_sigs_valid && not_expired && not_before {
        println!("  ══ RESULT: ✅ VALID ══");
    } else {
        println!("  ══ RESULT: ❌ INVALID ══");
        std::process::exit(1);
    }

    Ok(())
}
