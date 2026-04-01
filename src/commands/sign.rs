//! `sign` and `verify-sig` subcommands — RFC 9421 HTTP message signatures.
//!
//! Signs or verifies HTTP requests using the agent's cryptographic keys.
//! Supports Ed25519 (classical) and hybrid Ed25519 + ML-DSA-65 (PQ).

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::crypto;
use crate::httpsig::{
    self, Component, HttpRequest, SignatureAlgorithm, SignatureParams,
};
use crate::models::{AgentCard, CryptoScheme};

/// Execute `sign` — create RFC 9421 signature for an HTTP request.
pub fn execute_sign(
    method: &str,
    url: &str,
    card_path: &Path,
    key_path: &Path,
    headers: &[String],
    format: &str,
) -> Result<()> {
    let card = load_card(card_path)?;
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read key: {}", key_path.display()))?;

    // Parse headers
    let parsed_headers: Vec<(String, String)> = headers
        .iter()
        .filter_map(|h| {
            h.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    let request = HttpRequest {
        method: method.to_uppercase(),
        url: url.to_string(),
        headers: parsed_headers.clone(),
        body: None,
    };

    // Build components: always sign method + authority + path, plus any provided headers
    let mut components = vec![
        Component::Method,
        Component::Authority,
        Component::Path,
    ];
    for (name, _) in &parsed_headers {
        components.push(Component::Header(name.to_lowercase()));
    }

    let is_hybrid = card.crypto_scheme == CryptoScheme::Hybrid;
    let keyid = format!("urn:uuid:{}", card.id);

    let params = SignatureParams {
        keyid: keyid.clone(),
        alg: if is_hybrid {
            SignatureAlgorithm::Hybrid
        } else {
            SignatureAlgorithm::Ed25519
        },
        created: chrono::Utc::now().timestamp(),
        expires: Some(chrono::Utc::now().timestamp() + 300),
        nonce: Some(uuid::Uuid::new_v4().to_string()),
        label: "sig1".to_string(),
    };

    let signed = if is_hybrid {
        let (ed_key, mldsa_sk) = crypto::decode_hybrid_private_key_pem(&key_pem)?;
        httpsig::sign_request_hybrid(request, &components, &params, &ed_key, &mldsa_sk)?
    } else {
        let ed_key = crypto::decode_private_key_pem(&key_pem)?;
        httpsig::sign_request(request, &components, &params, &ed_key)?
    };

    match format {
        "curl" => {
            // Output as a curl command
            println!("curl -X {} \\", method.to_uppercase());
            println!("  '{}' \\", url);
            for (name, value) in &parsed_headers {
                println!("  -H '{}: {}' \\", name, value);
            }
            println!("  -H 'Signature-Input: {}' \\", signed.signature_input);
            println!("  -H 'Signature: {}'", signed.signature);
            if let Some(ref pq) = signed.pq_signature {
                println!("  -H 'Signature-PQ: {}'", pq);
            }
        }
        _ => {
            // Output as headers
            println!("🔏 RFC 9421 Signed Request");
            println!("═══════════════════════════════════════");
            println!("  Agent:   {}", card.name);
            println!("  KeyID:   {}", keyid);
            println!("  Crypto:  {}", card.crypto_scheme);
            println!("  Method:  {} {}", method.to_uppercase(), url);
            println!("═══════════════════════════════════════");
            println!();
            println!("Signature-Input: {}", signed.signature_input);
            println!();
            println!("Signature: {}", signed.signature);
            if let Some(ref pq) = signed.pq_signature {
                println!();
                println!("Signature-PQ: {}", pq);
            }
            println!();
            if is_hybrid {
                println!("  🛡️  POST-QUANTUM: Both Ed25519 + ML-DSA-65 signatures");
                println!("     cover the same signature base. Compatible with");
                println!("     standard RFC 9421 verifiers (Ed25519) AND future");
                println!("     PQ-aware verifiers (ML-DSA-65).");
            }
        }
    }

    Ok(())
}

/// Execute `verify-sig` — verify an RFC 9421 signed HTTP request.
pub fn execute_verify(
    method: &str,
    url: &str,
    signature_input: &str,
    signature: &str,
    pq_signature: Option<&str>,
    card_path: &Path,
    headers: &[String],
) -> Result<()> {
    let card = load_card(card_path)?;

    let parsed_headers: Vec<(String, String)> = headers
        .iter()
        .filter_map(|h| {
            h.split_once(':').map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        })
        .collect();

    let request = HttpRequest {
        method: method.to_uppercase(),
        url: url.to_string(),
        headers: parsed_headers,
        body: None,
    };

    println!("🔍 Verifying RFC 9421 Signature");
    println!("═══════════════════════════════════════");

    let result = if let Some(pq_sig) = pq_signature {
        let pq_pub = card.pq_public_key.as_ref()
            .ok_or_else(|| anyhow::anyhow!("Card has no PQ public key for hybrid verification"))?;
        httpsig::verify_request_hybrid(
            &request,
            signature_input,
            signature,
            pq_sig,
            &card.public_key,
            pq_pub,
        )?
    } else {
        httpsig::verify_request(
            &request,
            signature_input,
            signature,
            &card.public_key,
        )?
    };

    let ed_status = if result.ed25519_valid { "✅ VALID" } else { "❌ INVALID" };
    println!("  Ed25519:   {}", ed_status);

    if let Some(pq_valid) = result.mldsa65_valid {
        let pq_status = if pq_valid { "✅ VALID" } else { "❌ INVALID" };
        println!("  ML-DSA-65: {}", pq_status);
    }

    println!("  KeyID:     {}", result.keyid);
    println!("  Algorithm: {}", result.alg);
    println!("  Created:   {}", result.created);
    if result.expired {
        println!("  ⚠️  Signature has EXPIRED");
    }

    let overall = result.ed25519_valid
        && result.mldsa65_valid.unwrap_or(true)
        && !result.expired;

    println!();
    if overall {
        println!("  RESULT: ✅ SIGNATURE VALID");
    } else {
        println!("  RESULT: ❌ SIGNATURE INVALID");
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
