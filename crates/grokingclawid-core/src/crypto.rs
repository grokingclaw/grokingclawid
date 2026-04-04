//! Cryptographic utilities for GrokingClawID.
//!
//! Provides:
//! - Ed25519 key generation, signing, verification (classical)
//! - ML-DSA-65 key generation, signing, verification (post-quantum, FIPS 204)
//! - Hybrid Ed25519 + ML-DSA-65 signing/verification (both must validate)
//! - SHA-256 hashing for audit chain

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use fips204::ml_dsa_65;
use fips204::traits::{SerDes, Signer as PqSigner, Verifier as PqVerifier};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

use crate::models::HybridSignature;

// ─── Ed25519 (classical) ───────────────────────────────────────────────

/// Generate a fresh Ed25519 signing keypair.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign a message with an Ed25519 signing key.
/// Returns the signature as a base64-encoded string.
pub fn sign(signing_key: &SigningKey, message: &[u8]) -> String {
    let signature = signing_key.sign(message);
    BASE64.encode(signature.to_bytes())
}

/// Verify an Ed25519 signature.
/// Returns Ok(true) if valid, Ok(false) if signature doesn't match.
pub fn verify(public_key_b64: &str, message: &[u8], signature_b64: &str) -> Result<bool> {
    let pub_bytes = BASE64
        .decode(public_key_b64)
        .context("Failed to decode public key from base64")?;
    let sig_bytes = BASE64
        .decode(signature_b64)
        .context("Failed to decode signature from base64")?;

    let pub_key_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be exactly 32 bytes"))?;
    let sig_array: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Signature must be exactly 64 bytes"))?;

    let verifying_key =
        VerifyingKey::from_bytes(&pub_key_array).context("Invalid public key bytes")?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_array);

    Ok(verifying_key.verify(message, &signature).is_ok())
}

/// Encode an Ed25519 public key as base64.
pub fn encode_public_key(key: &VerifyingKey) -> String {
    BASE64.encode(key.as_bytes())
}

/// Encode an Ed25519 signing key as PEM-like format.
pub fn encode_private_key_pem(key: &SigningKey) -> String {
    let b64 = BASE64.encode(key.to_bytes());
    format!(
        "-----BEGIN ED25519 PRIVATE KEY-----\n{}\n-----END ED25519 PRIVATE KEY-----\n",
        b64
    )
}

/// Decode an Ed25519 signing key from PEM-like format.
pub fn decode_private_key_pem(pem: &str) -> Result<SigningKey> {
    let b64 = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let bytes = BASE64
        .decode(b64.trim())
        .context("Failed to decode private key from base64")?;
    let key_array: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Private key seed must be exactly 32 bytes"))?;
    Ok(SigningKey::from_bytes(&key_array))
}

// ─── ML-DSA-65 (post-quantum, FIPS 204) ────────────────────────────────

/// ML-DSA-65 key pair container.
/// Secret key is ~4032 bytes, public key is ~1952 bytes.
pub struct MlDsaKeyPair {
    pub public_key_bytes: Vec<u8>,
    pub secret_key_bytes: Vec<u8>,
}

/// Generate an ML-DSA-65 key pair.
pub fn generate_mldsa_keypair() -> Result<MlDsaKeyPair> {
    let mut rng = OsRng;
    let (pk, sk) = ml_dsa_65::try_keygen_with_rng(&mut rng)
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 keygen failed: {:?}", e))?;
    Ok(MlDsaKeyPair {
        public_key_bytes: pk.into_bytes().to_vec(),
        secret_key_bytes: sk.into_bytes().to_vec(),
    })
}

/// Sign a message with ML-DSA-65.
/// Returns signature as base64-encoded string.
pub fn mldsa_sign(secret_key_bytes: &[u8], message: &[u8]) -> Result<String> {
    let sk_array: &[u8] = secret_key_bytes;
    let sk = ml_dsa_65::PrivateKey::try_from_bytes(
        sk_array
            .try_into()
            .map_err(|_| anyhow::anyhow!("ML-DSA-65 secret key has wrong length"))?,
    )
    .map_err(|e| anyhow::anyhow!("Failed to decode ML-DSA-65 secret key: {:?}", e))?;
    let sig = sk
        .try_sign(message, &[])
        .map_err(|e| anyhow::anyhow!("ML-DSA-65 signing failed: {:?}", e))?;
    Ok(BASE64.encode(sig))
}

/// Verify an ML-DSA-65 signature.
/// Returns Ok(true) if valid, Ok(false) if invalid.
pub fn mldsa_verify(public_key_b64: &str, message: &[u8], signature_b64: &str) -> Result<bool> {
    let pk_bytes = BASE64
        .decode(public_key_b64)
        .context("Failed to decode ML-DSA public key from base64")?;
    let sig_bytes = BASE64
        .decode(signature_b64)
        .context("Failed to decode ML-DSA signature from base64")?;

    let pk =
        ml_dsa_65::PublicKey::try_from_bytes(pk_bytes.as_slice().try_into().map_err(|_| {
            anyhow::anyhow!("ML-DSA-65 public key has wrong length (expected 1952 bytes)")
        })?)
        .map_err(|e| anyhow::anyhow!("Invalid ML-DSA-65 public key: {:?}", e))?;

    let sig_array: &[u8] = sig_bytes.as_slice();
    Ok(pk.verify(
        message,
        sig_array
            .try_into()
            .map_err(|_| anyhow::anyhow!("ML-DSA-65 signature has wrong length"))?,
        &[],
    ))
}

/// Encode ML-DSA-65 public key as base64.
pub fn encode_mldsa_public_key(key_bytes: &[u8]) -> String {
    BASE64.encode(key_bytes)
}

/// Encode ML-DSA-65 secret key in PEM-like format.
pub fn encode_mldsa_private_key_pem(key_bytes: &[u8]) -> String {
    let b64 = BASE64.encode(key_bytes);
    // Split into 64-char lines for readability
    let lines: Vec<&str> = b64
        .as_bytes()
        .chunks(64)
        .map(|chunk| std::str::from_utf8(chunk).unwrap_or(""))
        .collect();
    format!(
        "-----BEGIN ML-DSA-65 PRIVATE KEY-----\n{}\n-----END ML-DSA-65 PRIVATE KEY-----\n",
        lines.join("\n")
    )
}

/// Decode ML-DSA-65 secret key from PEM-like format.
pub fn decode_mldsa_private_key_pem(pem: &str) -> Result<Vec<u8>> {
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    BASE64
        .decode(b64.trim())
        .context("Failed to decode ML-DSA-65 private key from base64")
}

// ─── Hybrid Ed25519 + ML-DSA-65 ────────────────────────────────────────

/// Container for hybrid key material.
pub struct HybridKeyPair {
    pub ed25519_signing: SigningKey,
    pub ed25519_verifying: VerifyingKey,
    pub mldsa_public: Vec<u8>,
    pub mldsa_secret: Vec<u8>,
}

/// Generate a hybrid Ed25519 + ML-DSA-65 key pair.
pub fn generate_hybrid_keypair() -> Result<HybridKeyPair> {
    let (ed_sk, ed_vk) = generate_keypair();
    let mldsa = generate_mldsa_keypair()?;
    Ok(HybridKeyPair {
        ed25519_signing: ed_sk,
        ed25519_verifying: ed_vk,
        mldsa_public: mldsa.public_key_bytes,
        mldsa_secret: mldsa.secret_key_bytes,
    })
}

/// Create a hybrid signature (both Ed25519 and ML-DSA-65).
pub fn hybrid_sign(
    ed_signing_key: &SigningKey,
    mldsa_secret_key: &[u8],
    message: &[u8],
) -> Result<HybridSignature> {
    let ed25519_sig = sign(ed_signing_key, message);
    let mldsa_sig = mldsa_sign(mldsa_secret_key, message)?;
    Ok(HybridSignature {
        ed25519: ed25519_sig,
        mldsa65: mldsa_sig,
    })
}

/// Verify a hybrid signature — BOTH signatures must be valid.
#[allow(dead_code)]
pub fn hybrid_verify(
    ed_public_key_b64: &str,
    mldsa_public_key_b64: &str,
    message: &[u8],
    sig: &HybridSignature,
) -> Result<bool> {
    let ed_ok = verify(ed_public_key_b64, message, &sig.ed25519)?;
    if !ed_ok {
        return Ok(false);
    }
    let pq_ok = mldsa_verify(mldsa_public_key_b64, message, &sig.mldsa65)?;
    Ok(pq_ok)
}

/// Encode hybrid private keys into a combined PEM file.
pub fn encode_hybrid_private_key_pem(ed_key: &SigningKey, mldsa_secret: &[u8]) -> String {
    let ed_section = encode_private_key_pem(ed_key);
    let mldsa_section = encode_mldsa_private_key_pem(mldsa_secret);
    format!("{}\n{}", ed_section, mldsa_section)
}

/// Decode hybrid private keys from a combined PEM file.
/// Expects both an Ed25519 and ML-DSA-65 section.
pub fn decode_hybrid_private_key_pem(pem: &str) -> Result<(SigningKey, Vec<u8>)> {
    // Split into sections
    let ed_start = pem
        .find("-----BEGIN ED25519 PRIVATE KEY-----")
        .context("Missing Ed25519 section in hybrid PEM")?;
    let ed_end = pem
        .find("-----END ED25519 PRIVATE KEY-----")
        .context("Missing Ed25519 end marker")?
        + "-----END ED25519 PRIVATE KEY-----".len();
    let ed_section = &pem[ed_start..ed_end];

    let mldsa_start = pem
        .find("-----BEGIN ML-DSA-65 PRIVATE KEY-----")
        .context("Missing ML-DSA-65 section in hybrid PEM")?;
    let mldsa_end = pem
        .find("-----END ML-DSA-65 PRIVATE KEY-----")
        .context("Missing ML-DSA-65 end marker")?
        + "-----END ML-DSA-65 PRIVATE KEY-----".len();
    let mldsa_section = &pem[mldsa_start..mldsa_end];

    let ed_key = decode_private_key_pem(ed_section)?;
    let mldsa_key = decode_mldsa_private_key_pem(mldsa_section)?;

    Ok((ed_key, mldsa_key))
}

// ─── Hashing ────────────────────────────────────────────────────────────

/// Compute SHA-256 hash of the given data, returned as a hex string.
pub fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// Compute the audit chain hash for an entry.
///
/// Uses `\x00` field separators to prevent collision attacks where
/// different field boundaries produce the same concatenated string
/// (e.g., agent_id="ab"+action="cd" vs agent_id="abc"+action="d").
pub fn compute_chain_hash(
    prev_hash: &str,
    agent_id: &str,
    action: &str,
    target: &str,
    timestamp: i64,
) -> String {
    let input = format!(
        "{}\x00{}\x00{}\x00{}\x00{}",
        prev_hash, agent_id, action, target, timestamp
    );
    sha256_hex(input.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let (signing_key, verifying_key) = generate_keypair();
        let message = b"hello world";
        let sig = sign(&signing_key, message);
        let pub_b64 = encode_public_key(&verifying_key);
        assert!(verify(&pub_b64, message, &sig).unwrap());
    }

    #[test]
    fn test_ed25519_verify_wrong_message() {
        let (signing_key, verifying_key) = generate_keypair();
        let sig = sign(&signing_key, b"hello");
        let pub_b64 = encode_public_key(&verifying_key);
        assert!(!verify(&pub_b64, b"world", &sig).unwrap());
    }

    #[test]
    fn test_ed25519_pem_roundtrip() {
        let (signing_key, _) = generate_keypair();
        let pem = encode_private_key_pem(&signing_key);
        let recovered = decode_private_key_pem(&pem).unwrap();
        assert_eq!(signing_key.to_bytes(), recovered.to_bytes());
    }

    #[test]
    fn test_mldsa_sign_verify_roundtrip() {
        let kp = generate_mldsa_keypair().unwrap();
        let message = b"post-quantum test message";
        let sig = mldsa_sign(&kp.secret_key_bytes, message).unwrap();
        let pub_b64 = encode_mldsa_public_key(&kp.public_key_bytes);
        assert!(mldsa_verify(&pub_b64, message, &sig).unwrap());
    }

    #[test]
    fn test_mldsa_verify_wrong_message() {
        let kp = generate_mldsa_keypair().unwrap();
        let sig = mldsa_sign(&kp.secret_key_bytes, b"hello").unwrap();
        let pub_b64 = encode_mldsa_public_key(&kp.public_key_bytes);
        assert!(!mldsa_verify(&pub_b64, b"wrong message", &sig).unwrap());
    }

    #[test]
    fn test_mldsa_pem_roundtrip() {
        let kp = generate_mldsa_keypair().unwrap();
        let pem = encode_mldsa_private_key_pem(&kp.secret_key_bytes);
        let recovered = decode_mldsa_private_key_pem(&pem).unwrap();
        assert_eq!(kp.secret_key_bytes, recovered);
    }

    #[test]
    fn test_hybrid_sign_verify() {
        let hkp = generate_hybrid_keypair().unwrap();
        let message = b"hybrid signature test";
        let sig = hybrid_sign(&hkp.ed25519_signing, &hkp.mldsa_secret, message).unwrap();
        let ed_pub = encode_public_key(&hkp.ed25519_verifying);
        let pq_pub = encode_mldsa_public_key(&hkp.mldsa_public);
        assert!(hybrid_verify(&ed_pub, &pq_pub, message, &sig).unwrap());
    }

    #[test]
    fn test_hybrid_verify_fails_wrong_message() {
        let hkp = generate_hybrid_keypair().unwrap();
        let sig = hybrid_sign(&hkp.ed25519_signing, &hkp.mldsa_secret, b"correct").unwrap();
        let ed_pub = encode_public_key(&hkp.ed25519_verifying);
        let pq_pub = encode_mldsa_public_key(&hkp.mldsa_public);
        assert!(!hybrid_verify(&ed_pub, &pq_pub, b"wrong", &sig).unwrap());
    }

    #[test]
    fn test_hybrid_pem_roundtrip() {
        let hkp = generate_hybrid_keypair().unwrap();
        let pem = encode_hybrid_private_key_pem(&hkp.ed25519_signing, &hkp.mldsa_secret);
        let (ed_recovered, mldsa_recovered) = decode_hybrid_private_key_pem(&pem).unwrap();
        assert_eq!(hkp.ed25519_signing.to_bytes(), ed_recovered.to_bytes());
        assert_eq!(hkp.mldsa_secret, mldsa_recovered);
    }

    #[test]
    fn test_chain_hash_deterministic() {
        let h1 = compute_chain_hash("genesis", "abc", "issue", "test", 1000);
        let h2 = compute_chain_hash("genesis", "abc", "issue", "test", 1000);
        assert_eq!(h1, h2);
        let h3 = compute_chain_hash("genesis", "abc", "issue", "test", 1001);
        assert_ne!(h1, h3);
    }
}
