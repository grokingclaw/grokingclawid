//! `revoke` subcommand — Mark an agent card as revoked.
//!
//! Adds the card to the revocation registry, signed by the card's own key.
//! After revocation, `verify` will reject the card.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use grokingclawid_core::audit;
use grokingclawid_core::crypto;
use grokingclawid_core::models::{AgentCard, CryptoScheme};
use grokingclawid_core::revocation;

/// Execute the `revoke` command.
pub fn execute(
    agent_card_path: &Path,
    key_path: &Path,
    reason: &str,
) -> Result<()> {
    // Load agent card
    let card_json = fs::read_to_string(agent_card_path)
        .with_context(|| format!("Failed to read agent card: {}", agent_card_path.display()))?;
    let card: AgentCard = serde_json::from_str(&card_json)
        .context("Failed to parse agent card JSON")?;

    // Load private key
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read key: {}", key_path.display()))?;

    let ed_key = match &card.crypto_scheme {
        CryptoScheme::Ed25519 => crypto::decode_private_key_pem(&key_pem)?,
        CryptoScheme::MlDsa65 | CryptoScheme::Hybrid => {
            let (ed, _) = crypto::decode_hybrid_private_key_pem(&key_pem)?;
            ed
        }
    };

    // Revoke in registry
    let revoke_conn = revocation::open_db()?;
    let entry = revocation::revoke(
        &revoke_conn,
        &card.id,
        &card.name,
        reason,
        "self",
        &ed_key,
    )?;

    // Record in audit log
    let audit_conn = audit::open_db()?;
    audit::record_entry(
        &audit_conn,
        &card.id,
        "revoke",
        &format!("reason={}", reason),
        &ed_key,
    )?;

    println!("🚫 Agent card revoked!");
    println!();
    println!("  ID:        {}", entry.agent_id);
    println!("  Name:      {}", entry.agent_name);
    println!("  Reason:    {}", entry.reason);
    println!("  Revoked:   {}", entry.revoked_at.to_rfc3339());
    println!();
    println!("  The agent card at {} is no longer valid.", agent_card_path.display());
    println!("  Any `verify` check will now reject this card.");

    Ok(())
}

/// Execute the `revocation-list` command — show all revoked cards.
pub fn execute_list() -> Result<()> {
    let conn = revocation::open_db()?;
    let entries = revocation::list_revocations(&conn)?;

    if entries.is_empty() {
        println!("No revoked agent cards.");
        return Ok(());
    }

    println!("Revoked agent cards ({}):\n", entries.len());
    for entry in &entries {
        println!("  {} ({})", entry.agent_name, entry.agent_id);
        println!("    Reason:  {}", entry.reason);
        println!("    By:      {}", entry.revoked_by);
        println!("    At:      {}", entry.revoked_at.to_rfc3339());
        println!();
    }

    Ok(())
}
