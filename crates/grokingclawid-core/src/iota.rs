//! IOTA Rebased testnet integration.
//!
//! Provides lightweight JSON-RPC client for IOTA testnet operations:
//! - Address derivation from Ed25519 keys (BLAKE2b-256)
//! - Balance queries
//! - Faucet requests
//! - IOTA transfers between agent wallets
//!
//! Uses direct HTTP + JSON-RPC instead of the full iota-sdk to keep
//! the binary small (<5MB).

#[cfg(feature = "wallet")]
use anyhow::{Context, Result};
#[cfg(feature = "wallet")]
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
#[cfg(feature = "wallet")]
use blake2::{digest::VariableOutput, Blake2bVar};
#[cfg(feature = "wallet")]
use ed25519_dalek::Signer;
#[cfg(feature = "wallet")]
use serde::{Deserialize, Serialize};

/// IOTA network endpoints.
pub const TESTNET_RPC: &str = "https://api.testnet.iota.cafe";
pub const TESTNET_FAUCET: &str = "https://faucet.testnet.iota.cafe/gas";
#[allow(dead_code)]
pub const DEVNET_RPC: &str = "https://api.devnet.iota.cafe";
#[allow(dead_code)]
pub const DEVNET_FAUCET: &str = "https://faucet.devnet.iota.cafe/gas";

/// Derive an IOTA address from an Ed25519 public key.
///
/// IOTA Rebased (Ed25519 default scheme, flag 0x00):
///   address = BLAKE2b-256(pubkey_bytes)  (no flag prefix for 0x00)
///
/// Returns "0x" + hex-encoded 32-byte hash.
#[cfg(feature = "wallet")]
pub fn derive_iota_address(public_key_bytes: &[u8; 32]) -> String {
    use std::io::Write;
    // IOTA Rebased: Ed25519 address = BLAKE2b-256(flag || pubkey)
    // Flag byte 0x00 = Ed25519 scheme identifier, prepended before hashing.
    let mut hasher = Blake2bVar::new(32).expect("32 bytes is a valid Blake2b output size");
    hasher.write_all(&[0x00]).expect("write Ed25519 flag byte");
    hasher.write_all(public_key_bytes).expect("write to hasher");
    let mut hash = [0u8; 32];
    hasher
        .finalize_variable(&mut hash)
        .expect("finalize Blake2b");
    format!("0x{}", hex::encode(hash))
}

/// Intent scope for transaction signing.
/// IntentScope::TransactionData = 0
/// IntentVersion::V0 = 0
/// AppId::Iota = 0
#[cfg(feature = "wallet")]
const INTENT_PREFIX: [u8; 3] = [0, 0, 0];

/// A post-quantum attestation over a transaction.
/// The ML-DSA-65 signature covers the same BLAKE2b-256 digest
/// that the Ed25519 on-chain signature covers, so the PQ attestation
/// binds to the exact same transaction bytes.
#[cfg(feature = "wallet")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqTransactionAttestation {
    /// BLAKE2b-256 digest of (intent || tx_bytes) — same as what Ed25519 signs.
    pub tx_digest: String,
    /// Base64-encoded ML-DSA-65 signature over the digest.
    pub mldsa65_signature: String,
    /// Base64-encoded ML-DSA-65 public key that produced the signature.
    pub mldsa65_public_key: String,
    /// ISO 8601 timestamp of when the attestation was created.
    pub attested_at: String,
}

/// Compute the BLAKE2b-256 transaction digest that IOTA signs.
///
/// This is the canonical digest for both Ed25519 (on-chain) and
/// ML-DSA-65 (PQ attestation) signatures.
#[cfg(feature = "wallet")]
pub fn compute_tx_digest(tx_bytes: &[u8]) -> [u8; 32] {
    use std::io::Write;
    let mut hasher = Blake2bVar::new(32).expect("32 bytes is a valid Blake2b output size");
    hasher.write_all(&INTENT_PREFIX).expect("write intent");
    hasher.write_all(tx_bytes).expect("write tx_bytes");
    let mut digest = [0u8; 32];
    hasher
        .finalize_variable(&mut digest)
        .expect("finalize Blake2b");
    digest
}

/// Sign IOTA transaction bytes with Ed25519.
///
/// IOTA signature format: flag(0x00) || ed25519_signature(64 bytes) || pubkey(32 bytes)
/// The message signed is: BLAKE2b-256(intent_prefix || tx_bytes)
#[cfg(feature = "wallet")]
pub fn sign_transaction(signing_key: &ed25519_dalek::SigningKey, tx_bytes: &[u8]) -> String {
    let digest = compute_tx_digest(tx_bytes);

    // Sign the digest
    let signature = signing_key.sign(&digest);

    // Encode: flag(0x00) || sig(64) || pubkey(32) = 97 bytes total
    let mut sig_bytes = Vec::with_capacity(97);
    sig_bytes.push(0x00); // Ed25519 flag
    sig_bytes.extend_from_slice(&signature.to_bytes());
    sig_bytes.extend_from_slice(signing_key.verifying_key().as_bytes());

    BASE64.encode(&sig_bytes)
}

/// Create a post-quantum attestation over the same transaction digest.
///
/// This doesn't go on-chain (IOTA doesn't support ML-DSA-65 yet), but it:
/// 1. Creates a quantum-resistant proof of authorization
/// 2. Gets stored in the local audit log
/// 3. Can be verified independently even after Ed25519 is broken
#[cfg(feature = "wallet")]
pub fn create_pq_attestation(
    mldsa_secret_key: &[u8],
    mldsa_public_key: &[u8],
    tx_bytes: &[u8],
) -> Result<PqTransactionAttestation> {
    let digest = compute_tx_digest(tx_bytes);
    let mldsa_sig = crate::crypto::mldsa_sign(mldsa_secret_key, &digest)?;

    Ok(PqTransactionAttestation {
        tx_digest: hex::encode(digest),
        mldsa65_signature: mldsa_sig,
        mldsa65_public_key: BASE64.encode(mldsa_public_key),
        attested_at: chrono::Utc::now().to_rfc3339(),
    })
}

/// Verify a post-quantum attestation against transaction bytes.
#[cfg(feature = "wallet")]
pub fn verify_pq_attestation(
    attestation: &PqTransactionAttestation,
    tx_bytes: &[u8],
) -> Result<bool> {
    // Recompute digest and verify it matches
    let digest = compute_tx_digest(tx_bytes);
    let expected_digest = hex::encode(digest);
    if attestation.tx_digest != expected_digest {
        return Ok(false);
    }
    // Verify ML-DSA-65 signature over the digest
    crate::crypto::mldsa_verify(
        &attestation.mldsa65_public_key,
        &digest,
        &attestation.mldsa65_signature,
    )
}

// ─── RPC types ──────────────────────────────────────────────────────────

#[cfg(feature = "wallet")]
#[derive(Serialize)]
struct RpcRequest<T: Serialize> {
    jsonrpc: String,
    id: u64,
    method: String,
    params: T,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize, Debug)]
struct RpcResponse<T> {
    #[allow(dead_code)]
    jsonrpc: String,
    #[allow(dead_code)]
    id: u64,
    result: Option<T>,
    error: Option<RpcError>,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize, Debug)]
struct RpcError {
    #[allow(dead_code)]
    code: i64,
    message: String,
}

#[cfg(feature = "wallet")]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BalanceResponse {
    pub total_balance: String,
    #[allow(dead_code)]
    pub coin_type: String,
    pub coin_object_count: u64,
}

/// Response from unsafe_transferIota.
#[cfg(feature = "wallet")]
#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct TransferResponse {
    pub tx_bytes: String,
    pub gas: Vec<serde_json::Value>,
}

/// Response from iota_executeTransactionBlock.
#[cfg(feature = "wallet")]
#[derive(Deserialize, Debug)]
pub struct ExecuteResponse {
    pub digest: String,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
struct FaucetRequest {
    #[serde(rename = "FixedAmountRequest")]
    fixed_amount_request: FixedAmountRequest,
}

#[cfg(feature = "wallet")]
#[derive(Serialize)]
struct FixedAmountRequest {
    recipient: String,
}

// ─── Client ─────────────────────────────────────────────────────────────

#[cfg(feature = "wallet")]
pub struct IotaClient {
    rpc_url: String,
    faucet_url: String,
    http: reqwest::Client,
}

#[cfg(feature = "wallet")]
impl IotaClient {
    /// Create a new client with a custom RPC endpoint.
    ///
    /// Faucet defaults to testnet. Use `testnet()` or `devnet()` for preset configs.
    pub fn new(rpc_url: &str) -> Self {
        Self {
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            faucet_url: TESTNET_FAUCET.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Create a new client for IOTA testnet.
    pub fn testnet() -> Self {
        Self {
            rpc_url: TESTNET_RPC.to_string(),
            faucet_url: TESTNET_FAUCET.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Create a new client for IOTA devnet.
    #[allow(dead_code)]
    pub fn devnet() -> Self {
        Self {
            rpc_url: DEVNET_RPC.to_string(),
            faucet_url: DEVNET_FAUCET.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Get the balance for an IOTA address.
    pub async fn get_balance(&self, address: &str) -> Result<BalanceResponse> {
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "iotax_getBalance".to_string(),
            params: vec![address],
        };

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to IOTA RPC")?;
        let body: RpcResponse<BalanceResponse> = resp
            .json()
            .await
            .context("Failed to parse balance response")?;

        if let Some(err) = body.error {
            anyhow::bail!("RPC error: {}", err.message);
        }
        body.result
            .ok_or_else(|| anyhow::anyhow!("No balance result returned"))
    }

    /// Request test tokens from the faucet.
    pub async fn request_faucet(&self, address: &str) -> Result<String> {
        let req = FaucetRequest {
            fixed_amount_request: FixedAmountRequest {
                recipient: address.to_string(),
            },
        };

        let resp = self
            .http
            .post(&self.faucet_url)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to IOTA faucet")?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .context("Failed to read faucet response")?;

        if !status.is_success() {
            anyhow::bail!("Faucet request failed ({}): {}", status, body);
        }
        Ok(body)
    }

    /// Get all coins owned by an address.
    pub async fn get_coins(&self, address: &str) -> Result<serde_json::Value> {
        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "iotax_getCoins".to_string(),
            params: serde_json::json!([address]),
        };

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to IOTA RPC")?;
        let body: RpcResponse<serde_json::Value> = resp
            .json()
            .await
            .context("Failed to parse coins response")?;

        if let Some(err) = body.error {
            anyhow::bail!("RPC error: {}", err.message);
        }
        body.result
            .ok_or_else(|| anyhow::anyhow!("No coins result returned"))
    }

    /// Build an unsigned IOTA transfer transaction.
    ///
    /// Uses `unsafe_transferIota` which handles coin selection and
    /// transaction building on the server side.
    pub async fn build_transfer(
        &self,
        sender: &str,
        recipient: &str,
        amount: u64,
        gas_budget: u64,
    ) -> Result<Vec<u8>> {
        // First get the coin object to use
        let coins = self.get_coins(sender).await?;
        let coin_id = coins
            .get("data")
            .and_then(|d| d.as_array())
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("coinObjectId"))
            .and_then(|id| id.as_str())
            .ok_or_else(|| {
                anyhow::anyhow!("No coin objects found. Request tokens from faucet first.")
            })?;

        let params = serde_json::json!([
            sender,                 // signer
            coin_id,                // iota_object_id (coin to use for gas + transfer)
            gas_budget.to_string(), // gas_budget (string)
            recipient,              // recipient
            amount.to_string()      // amount (string)
        ]);

        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "unsafe_transferIota".to_string(),
            params,
        };

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to IOTA RPC")?;
        let body: RpcResponse<TransferResponse> = resp
            .json()
            .await
            .context("Failed to parse transfer response")?;

        if let Some(err) = body.error {
            anyhow::bail!("Transfer build failed: {}", err.message);
        }

        let tx = body
            .result
            .ok_or_else(|| anyhow::anyhow!("No transfer result"))?;
        let tx_bytes = BASE64
            .decode(&tx.tx_bytes)
            .context("Failed to decode transaction bytes")?;

        Ok(tx_bytes)
    }

    /// Execute a signed transaction.
    pub async fn execute_transaction(
        &self,
        tx_bytes: &[u8],
        signature: &str,
    ) -> Result<ExecuteResponse> {
        let tx_b64 = BASE64.encode(tx_bytes);
        let params = serde_json::json!([
            tx_b64,
            [signature],
            { "showEffects": true },
            "WaitForLocalExecution"
        ]);

        let req = RpcRequest {
            jsonrpc: "2.0".to_string(),
            id: 1,
            method: "iota_executeTransactionBlock".to_string(),
            params,
        };

        let resp = self
            .http
            .post(&self.rpc_url)
            .json(&req)
            .send()
            .await
            .context("Failed to connect to IOTA RPC")?;
        let body: RpcResponse<ExecuteResponse> = resp
            .json()
            .await
            .context("Failed to parse execution response")?;

        if let Some(err) = body.error {
            anyhow::bail!("Transaction execution failed: {}", err.message);
        }
        body.result
            .ok_or_else(|| anyhow::anyhow!("No execution result"))
    }

    /// Transfer IOTA: build, sign, and execute in one call (Ed25519 only).
    pub async fn transfer_iota(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        sender: &str,
        recipient: &str,
        amount: u64,
        gas_budget: u64,
    ) -> Result<String> {
        // 1. Build unsigned transaction
        let tx_bytes = self
            .build_transfer(sender, recipient, amount, gas_budget)
            .await?;

        // 2. Sign
        let signature = sign_transaction(signing_key, &tx_bytes);

        // 3. Execute
        let result = self.execute_transaction(&tx_bytes, &signature).await?;

        Ok(result.digest)
    }

    /// Transfer IOTA with post-quantum attestation (hybrid signing).
    ///
    /// 1. Builds the unsigned transaction
    /// 2. Signs with Ed25519 (for on-chain submission)
    /// 3. Creates ML-DSA-65 attestation (for PQ audit trail)
    /// 4. Executes on-chain
    /// 5. Returns digest + PQ attestation
    pub async fn transfer_iota_pq(
        &self,
        ed_signing_key: &ed25519_dalek::SigningKey,
        mldsa_secret_key: &[u8],
        mldsa_public_key: &[u8],
        sender: &str,
        recipient: &str,
        amount: u64,
        gas_budget: u64,
    ) -> Result<(String, PqTransactionAttestation)> {
        // 1. Build unsigned transaction
        let tx_bytes = self
            .build_transfer(sender, recipient, amount, gas_budget)
            .await?;

        // 2. Ed25519 sign for on-chain
        let ed_signature = sign_transaction(ed_signing_key, &tx_bytes);

        // 3. ML-DSA-65 attestation for PQ audit trail
        let pq_attestation = create_pq_attestation(mldsa_secret_key, mldsa_public_key, &tx_bytes)?;

        // 4. Execute on-chain
        let result = self.execute_transaction(&tx_bytes, &ed_signature).await?;

        Ok((result.digest, pq_attestation))
    }
}
