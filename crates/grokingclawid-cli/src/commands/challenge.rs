//! `challenge`, `respond`, and `verify-response` subcommands.
//!
//! Implements the agent-to-agent verification handshake:
//! 1. Challenger issues a time-bounded challenge
//! 2. Responder signs it with their identity key
//! 3. Challenger verifies signature, scopes, expiry, and crypto scheme

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use grokingclawid_core::challenge::{self, ChallengeResponse};
use grokingclawid_core::crypto;
use grokingclawid_core::models::{AgentCard, CryptoScheme};

/// Execute `challenge` — create a verification challenge for a peer.
pub fn execute_challenge(
    card_path: &Path,
    require_scope: &str,
    ttl: i64,
    require_pq: bool,
    output: &Path,
) -> Result<()> {
    let card = load_card(card_path)?;
    let scopes: Vec<String> = require_scope
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let challenge = challenge::create_challenge(
        &format!("urn:uuid:{}", card.id),
        &scopes,
        Some(ttl),
        require_pq,
    );

    let json = serde_json::to_string_pretty(&challenge).context("Failed to serialize challenge")?;
    fs::write(output, &json)
        .with_context(|| format!("Failed to write challenge: {}", output.display()))?;

    println!("🔐 Agent Verification Challenge");
    println!("═══════════════════════════════════════");
    println!("  Challenger:  {} ({})", card.name, card.id);
    println!("  Challenge:   {}", challenge.id);
    println!("  Nonce:       {}...", &challenge.nonce[..16]);
    println!("  Required:    {:?}", scopes);
    println!("  TTL:         {}s", ttl);
    println!("  Expires:     {}", challenge.expires_at);
    if require_pq {
        println!("  PQ Required: 🛡️  YES (hybrid Ed25519+ML-DSA-65)");
    }
    println!("═══════════════════════════════════════");
    println!();
    println!("  Saved to: {}", output.display());
    println!("  Send this to the peer agent.");
    println!("  They must respond within {} seconds.", ttl);

    Ok(())
}

/// Execute `respond` — sign a challenge with our identity.
pub fn execute_respond(
    challenge_path: &Path,
    card_path: &Path,
    key_path: &Path,
    output: &Path,
) -> Result<()> {
    let challenge_json = fs::read_to_string(challenge_path)
        .with_context(|| format!("Failed to read challenge: {}", challenge_path.display()))?;
    let challenge: challenge::Challenge =
        serde_json::from_str(&challenge_json).context("Failed to parse challenge JSON")?;

    let card = load_card(card_path)?;
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read key: {}", key_path.display()))?;

    // Check if challenge is already expired
    let now = chrono::Utc::now();
    if now > challenge.expires_at {
        anyhow::bail!(
            "Challenge has expired (expired at {}, now {}). Request a new one.",
            challenge.expires_at,
            now
        );
    }

    // Load keys based on crypto scheme
    let (ed_key, mldsa_sk) = match &card.crypto_scheme {
        CryptoScheme::Ed25519 => {
            let ed = crypto::decode_private_key_pem(&key_pem)?;
            (ed, None)
        }
        CryptoScheme::MlDsa65 => {
            anyhow::bail!(
                "ML-DSA-65 only identity cannot respond to challenges. \
                 Ed25519 is required for the base signature. Use --crypto hybrid."
            );
        }
        CryptoScheme::Hybrid => {
            let (ed, mldsa) = crypto::decode_hybrid_private_key_pem(&key_pem)?;
            (ed, Some(mldsa))
        }
    };

    let response =
        challenge::respond_to_challenge(&challenge, &card, &ed_key, mldsa_sk.as_deref())?;

    let json = serde_json::to_string_pretty(&response).context("Failed to serialize response")?;
    fs::write(output, &json)
        .with_context(|| format!("Failed to write response: {}", output.display()))?;

    println!("✍️  Challenge Response");
    println!("═══════════════════════════════════════");
    println!("  Agent:       {} ({})", card.name, card.id);
    println!("  Challenge:   {}", challenge.id);
    println!("  Challenger:  {}", challenge.issuer);
    println!("  Crypto:      {}", card.crypto_scheme);
    if mldsa_sk.is_some() {
        println!("  PQ Sig:      🛡️  ML-DSA-65 included");
    }
    println!("  Responded:   {}", response.responded_at);
    println!("═══════════════════════════════════════");
    println!();
    println!("  Saved to: {}", output.display());
    println!("  Send this back to the challenger.");

    Ok(())
}

/// Execute `verify-response` — verify a peer's challenge response.
pub fn execute_verify_response(challenge_path: &Path, response_path: &Path) -> Result<()> {
    let challenge_json = fs::read_to_string(challenge_path)
        .with_context(|| format!("Failed to read challenge: {}", challenge_path.display()))?;
    let challenge: challenge::Challenge =
        serde_json::from_str(&challenge_json).context("Failed to parse challenge JSON")?;

    let response_json = fs::read_to_string(response_path)
        .with_context(|| format!("Failed to read response: {}", response_path.display()))?;
    let response: ChallengeResponse =
        serde_json::from_str(&response_json).context("Failed to parse response JSON")?;

    println!("🔍 Verifying Challenge Response");
    println!("═══════════════════════════════════════");
    println!("  Challenger:  {}", challenge.issuer);
    println!(
        "  Responder:   {} ({})",
        response.agent_card.name, response.agent_card.id
    );
    println!("  Challenge:   {}", challenge.id);
    println!("  Crypto:      {}", response.agent_card.crypto_scheme);
    println!("═══════════════════════════════════════");
    println!();

    let result = challenge::verify_response(&challenge, &response)?;

    for check in &result.checks {
        let icon = if check.passed { "✅" } else { "❌" };
        println!("  {} {}: {}", icon, check.name, check.detail);
    }

    println!();
    if result.verified {
        println!("  ═══════════════════════════════════");
        println!("  ✅ AGENT VERIFIED");
        println!(
            "  Agent: {} ({})",
            result.agent_name.as_deref().unwrap_or("?"),
            result.agent_id.as_deref().unwrap_or("?")
        );
        println!("  ═══════════════════════════════════");
        println!();
        println!("  This agent has proven:");
        println!("  • They hold the private key matching their card");
        println!("  • Their card is not expired");
        println!("  • They have the required scopes");
        if response.pq_signature.is_some() {
            println!("  • Post-quantum ML-DSA-65 attestation is valid");
        }
        println!();
        println!("  Safe to accept instructions from this agent.");
    } else {
        println!("  ═══════════════════════════════════");
        println!("  ❌ VERIFICATION FAILED");
        println!("  ═══════════════════════════════════");
        println!();
        println!("  ⚠️  DO NOT accept instructions from this agent.");
        println!("  (Unit42: 82.4% of LLMs execute unverified peer payloads)");
        std::process::exit(1);
    }

    Ok(())
}

fn load_card(card_path: &Path) -> Result<AgentCard> {
    let card_json = fs::read_to_string(card_path)
        .with_context(|| format!("Failed to read card: {}", card_path.display()))?;
    serde_json::from_str(&card_json)
        .with_context(|| format!("Failed to parse card: {}", card_path.display()))
}
