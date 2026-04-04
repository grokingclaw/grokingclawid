//! `rotate` subcommand — Generate new keys for an existing agent card.
//!
//! Creates a new keypair, re-signs the card with the new keys, archives
//! the old key, and records the rotation in the audit log.
//!
//! The card ID, name, owner, scopes, and type are preserved.
//! A new expiry is set based on the provided TTL.

use anyhow::{Context, Result};
use chrono::Utc;
use grokingclawid_core::audit;
use grokingclawid_core::crypto;
use grokingclawid_core::models::{AgentCard, CryptoScheme};
use std::fs;
use std::path::Path;

use crate::commands::issue::{card_signing_payload, parse_ttl};

/// Execute the `rotate` command.
pub fn execute(
    agent_card_path: &Path,
    key_path: &Path,
    ttl: &str,
    output_dir: &Path,
) -> Result<()> {
    // Load existing card
    let card_json = fs::read_to_string(agent_card_path)
        .with_context(|| format!("Failed to read agent card: {}", agent_card_path.display()))?;
    let old_card: AgentCard =
        serde_json::from_str(&card_json).context("Failed to parse agent card JSON")?;

    // Load old private key (to prove ownership + audit)
    let old_key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read key: {}", key_path.display()))?;
    let old_ed_key = match &old_card.crypto_scheme {
        CryptoScheme::Ed25519 => crypto::decode_private_key_pem(&old_key_pem)?,
        CryptoScheme::MlDsa65 | CryptoScheme::Hybrid => {
            let (ed, _) = crypto::decode_hybrid_private_key_pem(&old_key_pem)?;
            ed
        }
    };

    // Verify the old key matches the card's public key
    let old_pub_b64 = crypto::encode_public_key(&old_ed_key.verifying_key());
    if old_pub_b64 != old_card.public_key {
        anyhow::bail!("Key file does not match the agent card's public key. Rotation denied.");
    }

    let duration = parse_ttl(ttl)?;
    let now = Utc::now();

    // Generate new keys based on scheme
    let (public_key, pq_public_key, signature, pq_signature, new_key_pem) = match &old_card
        .crypto_scheme
    {
        CryptoScheme::Ed25519 => {
            let (sk, vk) = crypto::generate_keypair();
            let pub_b64 = crypto::encode_public_key(&vk);

            let card = build_rotated_card(&old_card, &pub_b64, None, "", None, now, duration);
            let payload = card_signing_payload(&card)?;
            let sig = crypto::sign(&sk, payload.as_bytes());
            let pem = crypto::encode_private_key_pem(&sk);

            (pub_b64, None, sig, None, pem)
        }
        CryptoScheme::MlDsa65 => {
            let mldsa_kp = crypto::generate_mldsa_keypair()?;
            let pq_pub_b64 = crypto::encode_mldsa_public_key(&mldsa_kp.public_key_bytes);
            let (ed_sk, ed_vk) = crypto::generate_keypair();
            let ed_pub_b64 = crypto::encode_public_key(&ed_vk);

            let card = build_rotated_card(
                &old_card,
                &ed_pub_b64,
                Some(&pq_pub_b64),
                "",
                None,
                now,
                duration,
            );
            let payload = card_signing_payload(&card)?;
            let pq_sig = crypto::mldsa_sign(&mldsa_kp.secret_key_bytes, payload.as_bytes())?;
            let ed_sig = crypto::sign(&ed_sk, payload.as_bytes());
            let pem = crypto::encode_hybrid_private_key_pem(&ed_sk, &mldsa_kp.secret_key_bytes);

            (ed_pub_b64, Some(pq_pub_b64), ed_sig, Some(pq_sig), pem)
        }
        CryptoScheme::Hybrid => {
            let hkp = crypto::generate_hybrid_keypair()?;
            let ed_pub_b64 = crypto::encode_public_key(&hkp.ed25519_verifying);
            let pq_pub_b64 = crypto::encode_mldsa_public_key(&hkp.mldsa_public);

            let card = build_rotated_card(
                &old_card,
                &ed_pub_b64,
                Some(&pq_pub_b64),
                "",
                None,
                now,
                duration,
            );
            let payload = card_signing_payload(&card)?;
            let hsig =
                crypto::hybrid_sign(&hkp.ed25519_signing, &hkp.mldsa_secret, payload.as_bytes())?;
            let pem =
                crypto::encode_hybrid_private_key_pem(&hkp.ed25519_signing, &hkp.mldsa_secret);

            (
                ed_pub_b64,
                Some(pq_pub_b64),
                hsig.ed25519,
                Some(hsig.mldsa65),
                pem,
            )
        }
    };

    // Build rotated card — same ID, name, owner, scopes, type — new keys + expiry
    let new_card = AgentCard {
        id: old_card.id,
        name: old_card.name.clone(),
        owner: old_card.owner.clone(),
        scopes: old_card.scopes.clone(),
        public_key,
        pq_public_key,
        signature,
        pq_signature,
        crypto_scheme: old_card.crypto_scheme.clone(),
        issued_at: now,
        expires_at: now + duration,
        agent_type: old_card.agent_type.clone(),
        parent_id: old_card.parent_id,
        spiffe_id: old_card.spiffe_id.clone(),
    };

    // Archive old key
    fs::create_dir_all(output_dir).with_context(|| {
        format!(
            "Failed to create output directory: {}",
            output_dir.display()
        )
    })?;

    let archive_name = format!("agent-key.pem.{}", now.format("%Y%m%d-%H%M%S"));
    let archive_path = output_dir.join(&archive_name);
    fs::copy(key_path, &archive_path)
        .with_context(|| format!("Failed to archive old key to {}", archive_path.display()))?;

    // Write new card and key
    let card_out = output_dir.join("agent-card.json");
    let card_json = serde_json::to_string_pretty(&new_card)
        .context("Failed to serialize rotated agent card")?;
    fs::write(&card_out, &card_json)
        .with_context(|| format!("Failed to write {}", card_out.display()))?;

    let key_out = output_dir.join("agent-key.pem");
    fs::write(&key_out, &new_key_pem)
        .with_context(|| format!("Failed to write {}", key_out.display()))?;

    // Restrict key file permissions to owner-only (0o600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_out, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("Failed to set permissions on {}", key_out.display()))?;
    }

    // Record rotation in audit log using OLD key (proves the rotation was authorized)
    let conn = audit::open_db()?;
    audit::record_entry(
        &conn,
        &old_card.id,
        "rotate",
        &format!(
            "old_key={}... new_key={}...",
            &old_pub_b64[..16],
            &new_card.public_key[..16]
        ),
        &old_ed_key,
    )?;

    println!("🔄 Key rotation complete!");
    println!();
    println!("  ID:          {}", new_card.id);
    println!("  Name:        {}", new_card.name);
    println!("  Crypto:      {}", new_card.crypto_scheme);
    println!("  New expiry:  {}", new_card.expires_at.to_rfc3339());
    println!("  Old key:     {}...", &old_pub_b64[..16]);
    println!("  New key:     {}...", &new_card.public_key[..16]);
    println!();
    println!("  Card:        {}", card_out.display());
    println!("  Key:         {}", key_out.display());
    println!("  Archived:    {}", archive_path.display());
    println!();
    println!(
        "  ⚠️  Old key archived to {}. Delete it after confirming the new key works.",
        archive_name
    );

    Ok(())
}

/// Build a rotated card preserving identity fields but with new crypto.
fn build_rotated_card(
    old: &AgentCard,
    public_key: &str,
    pq_public_key: Option<&str>,
    signature: &str,
    pq_signature: Option<&str>,
    now: chrono::DateTime<Utc>,
    duration: chrono::Duration,
) -> AgentCard {
    AgentCard {
        id: old.id,
        name: old.name.clone(),
        owner: old.owner.clone(),
        scopes: old.scopes.clone(),
        public_key: public_key.to_string(),
        pq_public_key: pq_public_key.map(|s| s.to_string()),
        signature: signature.to_string(),
        pq_signature: pq_signature.map(|s| s.to_string()),
        crypto_scheme: old.crypto_scheme.clone(),
        issued_at: now,
        expires_at: now + duration,
        agent_type: old.agent_type.clone(),
        parent_id: old.parent_id,
        spiffe_id: old.spiffe_id.clone(),
    }
}
