//! `issue` subcommand — Generate a new agent identity card.
//!
//! Supports three crypto schemes:
//! - ed25519: Classical Ed25519 only
//! - ml-dsa-65: Post-quantum ML-DSA-65 only
//! - hybrid: Ed25519 + ML-DSA-65 (both signatures, both must validate)

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use std::fs;
use std::path::Path;
use uuid::Uuid;

use grokingclawid_core::audit;
use grokingclawid_core::crypto;
use grokingclawid_core::models::{AgentCard, AgentType, CryptoScheme};

/// Parse a human-readable TTL string like "24h", "30m", "7d" into a chrono::Duration.
pub fn parse_ttl(ttl: &str) -> Result<Duration> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        return Err(anyhow::anyhow!("TTL cannot be empty"));
    }

    let (num_str, unit) = ttl.split_at(ttl.len() - 1);
    let num: i64 = num_str
        .parse()
        .with_context(|| format!("Invalid TTL number: '{}'", num_str))?;

    match unit {
        "m" => Ok(Duration::minutes(num)),
        "h" => Ok(Duration::hours(num)),
        "d" => Ok(Duration::days(num)),
        _ => Err(anyhow::anyhow!(
            "Unknown TTL unit: '{}'. Use 'm' (minutes), 'h' (hours), or 'd' (days)",
            unit
        )),
    }
}

/// Execute the `issue` command.
pub fn execute(
    name: &str,
    owner: &str,
    scope: &str,
    ttl: &str,
    agent_type: &str,
    crypto_scheme: &str,
    trust_domain: Option<&str>,
    output_dir: &Path,
) -> Result<()> {
    let scopes: Vec<String> = scope.split(',').map(|s| s.trim().to_string()).collect();
    let duration = parse_ttl(ttl)?;
    let atype: AgentType = agent_type.parse()?;
    let scheme: CryptoScheme = crypto_scheme.parse()?;

    let now = Utc::now();
    let id = Uuid::new_v4();

    // Generate SPIFFE ID if trust domain is provided
    let spiffe_id = trust_domain
        .map(|td| AgentCard::generate_spiffe_id(td, name, &atype));

    // Generate keys and sign based on scheme
    let (public_key, pq_public_key, signature, pq_signature, key_pem) = match &scheme {
        CryptoScheme::Ed25519 => {
            let (sk, vk) = crypto::generate_keypair();
            let pub_b64 = crypto::encode_public_key(&vk);

            // Build card for signing
            let card = build_card(id, name, owner, &scopes, &pub_b64, None, "", None, &scheme, now, duration, &atype, None, &spiffe_id);
            let payload = card_signing_payload(&card)?;
            let sig = crypto::sign(&sk, payload.as_bytes());
            let pem = crypto::encode_private_key_pem(&sk);

            (pub_b64, None, sig, None, pem)
        }
        CryptoScheme::MlDsa65 => {
            let mldsa_kp = crypto::generate_mldsa_keypair()?;
            let pq_pub_b64 = crypto::encode_mldsa_public_key(&mldsa_kp.public_key_bytes);
            // Use a dummy Ed25519 key for the public_key field (backward compat)
            let (ed_sk, ed_vk) = crypto::generate_keypair();
            let ed_pub_b64 = crypto::encode_public_key(&ed_vk);

            let card = build_card(id, name, owner, &scopes, &ed_pub_b64, Some(&pq_pub_b64), "", None, &scheme, now, duration, &atype, None, &spiffe_id);
            let payload = card_signing_payload(&card)?;
            let pq_sig = crypto::mldsa_sign(&mldsa_kp.secret_key_bytes, payload.as_bytes())?;
            // Sign with ed25519 too for the signature field
            let ed_sig = crypto::sign(&ed_sk, payload.as_bytes());
            let pem = crypto::encode_hybrid_private_key_pem(&ed_sk, &mldsa_kp.secret_key_bytes);

            (ed_pub_b64, Some(pq_pub_b64), ed_sig, Some(pq_sig), pem)
        }
        CryptoScheme::Hybrid => {
            let hkp = crypto::generate_hybrid_keypair()?;
            let ed_pub_b64 = crypto::encode_public_key(&hkp.ed25519_verifying);
            let pq_pub_b64 = crypto::encode_mldsa_public_key(&hkp.mldsa_public);

            let card = build_card(id, name, owner, &scopes, &ed_pub_b64, Some(&pq_pub_b64), "", None, &scheme, now, duration, &atype, None, &spiffe_id);
            let payload = card_signing_payload(&card)?;
            let hsig = crypto::hybrid_sign(&hkp.ed25519_signing, &hkp.mldsa_secret, payload.as_bytes())?;
            let pem = crypto::encode_hybrid_private_key_pem(&hkp.ed25519_signing, &hkp.mldsa_secret);

            (ed_pub_b64, Some(pq_pub_b64), hsig.ed25519, Some(hsig.mldsa65), pem)
        }
    };

    // Build final card with signatures
    let card = AgentCard {
        id,
        name: name.to_string(),
        owner: owner.to_string(),
        scopes,
        public_key,
        pq_public_key,
        signature,
        pq_signature,
        crypto_scheme: scheme.clone(),
        issued_at: now,
        expires_at: now + duration,
        agent_type: atype,
        parent_id: None,
        spiffe_id,
    };

    // Write output files
    fs::create_dir_all(output_dir)
        .with_context(|| format!("Failed to create output directory: {}", output_dir.display()))?;

    let card_path = output_dir.join("agent-card.json");
    let card_json =
        serde_json::to_string_pretty(&card).context("Failed to serialize agent card")?;
    fs::write(&card_path, &card_json)
        .with_context(|| format!("Failed to write {}", card_path.display()))?;

    let key_path = output_dir.join("agent-key.pem");
    fs::write(&key_path, &key_pem)
        .with_context(|| format!("Failed to write {}", key_path.display()))?;

    // Record in audit log using Ed25519 key (always available)
    let ed_key = match &scheme {
        CryptoScheme::Ed25519 => crypto::decode_private_key_pem(&key_pem)?,
        CryptoScheme::MlDsa65 | CryptoScheme::Hybrid => {
            let (ed, _) = crypto::decode_hybrid_private_key_pem(&key_pem)?;
            ed
        }
    };
    let conn = audit::open_db()?;
    audit::record_entry(&conn, &id, "issue", &card.name, &ed_key)?;

    // Print summary
    println!("✅ Agent identity issued successfully!");
    println!();
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
    println!("  Ed25519:   {}...", &card.public_key[..16]);
    if let Some(ref pq) = card.pq_public_key {
        println!("  ML-DSA-65: {}...", &pq[..16]);
    }
    println!();
    println!("  Card:      {}", card_path.display());
    println!("  Key:       {}", key_path.display());
    println!();
    println!("  ⚠️  Keep agent-key.pem secure. It cannot be recovered.");

    Ok(())
}

/// Helper: build an AgentCard (with empty/placeholder signatures for payload generation).
#[allow(clippy::too_many_arguments)]
fn build_card(
    id: Uuid,
    name: &str,
    owner: &str,
    scopes: &[String],
    public_key: &str,
    pq_public_key: Option<&str>,
    signature: &str,
    pq_signature: Option<&str>,
    crypto_scheme: &CryptoScheme,
    now: chrono::DateTime<Utc>,
    duration: Duration,
    agent_type: &AgentType,
    parent_id: Option<Uuid>,
    spiffe_id: &Option<String>,
) -> AgentCard {
    AgentCard {
        id,
        name: name.to_string(),
        owner: owner.to_string(),
        scopes: scopes.to_vec(),
        public_key: public_key.to_string(),
        pq_public_key: pq_public_key.map(|s| s.to_string()),
        signature: signature.to_string(),
        pq_signature: pq_signature.map(|s| s.to_string()),
        crypto_scheme: crypto_scheme.clone(),
        issued_at: now,
        expires_at: now + duration,
        agent_type: agent_type.clone(),
        parent_id,
        spiffe_id: spiffe_id.clone(),
    }
}

/// Create the canonical signing payload for an agent card.
/// Signature fields are zeroed for deterministic signing.
pub fn card_signing_payload(card: &AgentCard) -> Result<String> {
    let mut card_for_signing = card.clone();
    card_for_signing.signature = String::new();
    card_for_signing.pq_signature = None;
    serde_json::to_string(&card_for_signing).context("Failed to serialize card for signing")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_ttl() {
        assert_eq!(parse_ttl("24h").unwrap(), Duration::hours(24));
        assert_eq!(parse_ttl("30m").unwrap(), Duration::minutes(30));
        assert_eq!(parse_ttl("7d").unwrap(), Duration::days(7));
        assert!(parse_ttl("abc").is_err());
        assert!(parse_ttl("").is_err());
    }
}
