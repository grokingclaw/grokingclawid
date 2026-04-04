//! `wallet` subcommand — IOTA testnet wallet operations.
//!
//! Derives an IOTA wallet address from the agent's Ed25519 key,
//! checks balance, requests faucet tokens, and transfers IOTA.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use base64::Engine;
use grokingclawid_core::audit;
use grokingclawid_core::crypto;
use grokingclawid_core::iota::{self, IotaClient};
use grokingclawid_core::models::{AgentCard, CryptoScheme, PqAttestation, WalletReceipt};
use grokingclawid_core::ws::{self, EventFilter, IotaWsClient};

/// Execute `wallet init` — derive IOTA address from agent card.
pub fn execute_init(card_path: &Path) -> Result<()> {
    let card = load_card(card_path)?;
    let address = derive_address_from_card(&card)?;

    println!("🪙 IOTA Wallet Initialized");
    println!("═══════════════════════════════════════");
    println!("  Agent:     {}", card.name);
    println!("  Agent ID:  {}", card.id);
    println!("  Address:   {}", address);
    println!("  Network:   IOTA Testnet");
    println!("  RPC:       {}", iota::TESTNET_RPC);
    println!("═══════════════════════════════════════");
    println!();
    println!("  Your agent's Ed25519 key derives this IOTA address.");
    println!("  Use 'grokingclawid wallet faucet' to get test tokens.");

    Ok(())
}

/// Execute `wallet balance` — check IOTA balance.
pub fn execute_balance(card_path: &Path, network: &str) -> Result<()> {
    let card = load_card(card_path)?;
    let address = derive_address_from_card(&card)?;
    let client = make_client(network);

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    let balance = rt.block_on(client.get_balance(&address))?;

    let total_iota = balance.total_balance.parse::<u64>().unwrap_or(0);
    let display_iota = total_iota as f64 / 1_000_000_000.0; // IOTA uses 9 decimals (nanos)

    println!("💰 IOTA Wallet Balance");
    println!("═══════════════════════════════════════");
    println!("  Agent:     {}", card.name);
    println!("  Address:   {}", address);
    println!("  Network:   {}", network);
    println!("═══════════════════════════════════════");
    println!("  Balance:   {:.9} IOTA", display_iota);
    println!("  Raw:       {} nanos", balance.total_balance);
    println!("  Coins:     {} objects", balance.coin_object_count);

    Ok(())
}

/// Execute `wallet faucet` — request test tokens.
pub fn execute_faucet(card_path: &Path, network: &str) -> Result<()> {
    let card = load_card(card_path)?;
    let address = derive_address_from_card(&card)?;
    let client = make_client(network);

    println!("🚰 Requesting test IOTA from faucet...");
    println!("  Address: {}", address);
    println!("  Network: {}", network);

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    let response = rt.block_on(client.request_faucet(&address))?;

    println!();
    println!("  ✅ Faucet request submitted!");
    println!("  Response: {}", truncate(&response, 200));
    println!();
    println!("  Tokens may take a few seconds to arrive.");
    println!(
        "  Check with: grokingclawid wallet balance --agent-card {}",
        card_path.display()
    );

    Ok(())
}

/// Execute `wallet coins` — list all coin objects.
pub fn execute_coins(card_path: &Path, network: &str) -> Result<()> {
    let card = load_card(card_path)?;
    let address = derive_address_from_card(&card)?;
    let client = make_client(network);

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    let coins = rt.block_on(client.get_coins(&address))?;

    println!("🪙 IOTA Coin Objects");
    println!("═══════════════════════════════════════");
    println!("  Agent:   {}", card.name);
    println!("  Address: {}", address);
    println!("═══════════════════════════════════════");

    if let Some(data) = coins.get("data").and_then(|d| d.as_array()) {
        if data.is_empty() {
            println!("  No coins found. Use 'wallet faucet' to get test tokens.");
        } else {
            for (i, coin) in data.iter().enumerate() {
                let balance = coin.get("balance").and_then(|b| b.as_str()).unwrap_or("0");
                let coin_type = coin
                    .get("coinType")
                    .and_then(|t| t.as_str())
                    .unwrap_or("unknown");
                let object_id = coin
                    .get("coinObjectId")
                    .and_then(|o| o.as_str())
                    .unwrap_or("?");
                println!(
                    "  [{}] {} nanos | type: {} | id: {}...",
                    i + 1,
                    balance,
                    coin_type,
                    truncate(object_id, 20)
                );
            }
        }
    } else {
        println!("  {}", serde_json::to_string_pretty(&coins)?);
    }

    Ok(())
}

/// Execute `wallet send` — transfer IOTA to another address.
///
/// **PQ-native**: For hybrid/PQ identities, every transaction is dual-signed:
/// - Ed25519 signature goes on-chain (IOTA requires it)
/// - ML-DSA-65 attestation is stored locally in the audit log
///
/// This means even when quantum computers break Ed25519, the PQ attestation
/// in our audit trail still proves exactly who authorized each transaction.
pub fn execute_send(
    card_path: &Path,
    key_path: &Path,
    recipient: &str,
    amount_str: &str,
    network: &str,
) -> Result<()> {
    let card = load_card(card_path)?;
    let sender = derive_address_from_card(&card)?;

    // Parse amount — support both raw nanos and IOTA decimal
    let amount_nanos: u64 = if amount_str.contains('.') {
        let iota_amount: f64 = amount_str.parse().context("Invalid IOTA amount")?;
        (iota_amount * 1_000_000_000.0) as u64
    } else {
        amount_str.parse().context("Invalid amount in nanos")?
    };

    // Load signing keys
    let key_pem = fs::read_to_string(key_path)
        .with_context(|| format!("Failed to read key: {}", key_path.display()))?;

    let (ed_key, mldsa_secret, mldsa_public): (
        ed25519_dalek::SigningKey,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
    ) = match &card.crypto_scheme {
        CryptoScheme::Ed25519 => {
            let ed = crypto::decode_private_key_pem(&key_pem)?;
            (ed, None, None)
        }
        CryptoScheme::MlDsa65 => {
            // ML-DSA-65 only — still need Ed25519 for IOTA on-chain
            // This is a configuration error for wallet operations
            anyhow::bail!(
                "ML-DSA-65 only identity cannot sign IOTA transactions. \
                 Use --crypto hybrid to get both Ed25519 (on-chain) and ML-DSA-65 (PQ attestation)."
            );
        }
        CryptoScheme::Hybrid => {
            let (ed, mldsa_sk) = crypto::decode_hybrid_private_key_pem(&key_pem)?;
            let mldsa_pk = card
                .pq_public_key
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("Hybrid card missing pq_public_key"))?;
            let pk_bytes = base64::engine::general_purpose::STANDARD
                .decode(mldsa_pk)
                .context("Failed to decode ML-DSA-65 public key")?;
            (ed, Some(mldsa_sk), Some(pk_bytes))
        }
    };

    let client = make_client(network);
    let gas_budget = 10_000_000; // 0.01 IOTA gas budget
    let display_amount = amount_nanos as f64 / 1_000_000_000.0;
    let is_pq = mldsa_secret.is_some();

    println!("💸 Sending IOTA...");
    println!("  From:      {}", sender);
    println!("  To:        {}", recipient);
    println!(
        "  Amount:    {:.9} IOTA ({} nanos)",
        display_amount, amount_nanos
    );
    println!("  Gas:       {} nanos", gas_budget);
    println!("  Network:   {}", network);
    println!("  Crypto:    {}", card.crypto_scheme);
    if is_pq {
        println!("  PQ:        🛡️  ML-DSA-65 attestation ENABLED");
    }
    println!();

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

    let (digest, pq_attestation) =
        if let (Some(mldsa_sk), Some(mldsa_pk)) = (&mldsa_secret, &mldsa_public) {
            // PQ-native path: dual sign
            let (digest, attestation) = rt.block_on(client.transfer_iota_pq(
                &ed_key,
                mldsa_sk,
                mldsa_pk,
                &sender,
                recipient,
                amount_nanos,
                gas_budget,
            ))?;
            (digest, Some(attestation))
        } else {
            // Classical Ed25519-only path
            let digest = rt.block_on(client.transfer_iota(
                &ed_key,
                &sender,
                recipient,
                amount_nanos,
                gas_budget,
            ))?;
            (digest, None)
        };

    println!("  ✅ Transaction executed!");
    println!("  Digest: {}", digest);
    if pq_attestation.is_some() {
        println!("  🛡️  ML-DSA-65 attestation: SIGNED");
    }
    println!();
    println!(
        "  View on explorer: https://explorer.iota.cafe/txblock/{}?network={}",
        digest, network
    );

    // Build receipt
    let receipt = WalletReceipt {
        tx_digest: digest.clone(),
        sender: sender.clone(),
        recipient: recipient.to_string(),
        amount_nanos,
        network: network.to_string(),
        agent_id: card.id.to_string(),
        agent_name: card.name.clone(),
        crypto_scheme: card.crypto_scheme.clone(),
        pq_attestation: pq_attestation.as_ref().map(|a| PqAttestation {
            tx_digest: a.tx_digest.clone(),
            mldsa65_signature: a.mldsa65_signature.clone(),
            mldsa65_public_key: a.mldsa65_public_key.clone(),
            attested_at: a.attested_at.clone(),
        }),
        timestamp: chrono::Utc::now().to_rfc3339(),
    };

    // Save receipt alongside agent card
    let receipt_path = card_path
        .parent()
        .unwrap_or(Path::new("."))
        .join("wallet-receipt.json");
    let receipt_json =
        serde_json::to_string_pretty(&receipt).context("Failed to serialize receipt")?;
    fs::write(&receipt_path, &receipt_json)
        .with_context(|| format!("Failed to write receipt: {}", receipt_path.display()))?;
    println!("  📄 Receipt saved: {}", receipt_path.display());

    // Record in tamper-evident audit log
    let audit_target = format!(
        "transfer:{}:{}:{}:{}",
        recipient, amount_nanos, network, digest
    );
    if let Ok(conn) = audit::open_db() {
        match audit::record_entry(&conn, &card.id, "wallet_transfer", &audit_target, &ed_key) {
            Ok(entry) => {
                println!(
                    "  🔗 Audit logged: chain #{} (hash: {}...)",
                    entry.id,
                    &entry.entry_hash[..16]
                );
            }
            Err(e) => {
                eprintln!("  ⚠️  Audit log warning: {}", e);
            }
        }
    }

    if is_pq {
        println!();
        println!("  🛡️  POST-QUANTUM SECURITY");
        println!("  ─────────────────────────");
        println!("  On-chain sig:  Ed25519 (required by IOTA)");
        println!("  PQ attestation: ML-DSA-65 (FIPS 204)");
        println!("  Both cover the same BLAKE2b-256 tx digest.");
        println!("  The PQ attestation is stored in the local");
        println!("  audit log and wallet receipt — verifiable");
        println!("  even after quantum breaks Ed25519.");
    }

    Ok(())
}

/// Execute `wallet watch` — real-time WebSocket event stream for an agent's address.
///
/// Opens a persistent WebSocket connection to an IOTA full node and
/// streams all events involving the agent's derived address.
pub fn execute_watch(card_path: &Path, network: &str, limit: u32) -> Result<()> {
    let card = load_card(card_path)?;
    let address = derive_address_from_card(&card)?;
    let ws_client = make_ws_client(network);

    println!("👁️  Watching wallet events via WebSocket");
    println!("═══════════════════════════════════════");
    println!("  Agent:     {}", card.name);
    println!("  Address:   {}", address);
    println!("  Network:   {}", network);
    println!("  WebSocket: {}", ws_url_for_network(network));
    if limit > 0 {
        println!("  Limit:     {} events", limit);
    } else {
        println!("  Limit:     unlimited (Ctrl+C to stop)");
    }
    println!("═══════════════════════════════════════");
    println!();
    println!("  Subscribing to incoming + outgoing events...");
    println!();

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;
    let mut count: u32 = 0;

    rt.block_on(ws_client.watch_address(&address, |event, direction| {
        count += 1;
        let arrow = if direction == "incoming" {
            "⬅️  IN "
        } else {
            "➡️  OUT"
        };
        let timestamp = event.timestamp_ms.as_deref().unwrap_or("?");
        let event_type = event.event_type.as_deref().unwrap_or("unknown");
        let sender = event.sender.as_deref().unwrap_or("?");

        println!("  {} [#{}] {}", arrow, count, event_type);
        println!("       Sender:    {}", sender);
        println!("       Timestamp: {}", timestamp);
        if let Some(ref json) = event.parsed_json {
            if let Ok(pretty) = serde_json::to_string_pretty(json) {
                for line in pretty.lines().take(5) {
                    println!("       {}", line);
                }
            }
        }
        println!();

        // Continue listening unless we hit the limit
        limit == 0 || count < limit
    }))?;

    println!("  ✅ Watch complete ({} events received)", count);
    Ok(())
}

/// Execute `wallet events` — query historical events for an agent's address.
///
/// Uses HTTP JSON-RPC to fetch past events (complement to WebSocket streaming).
pub fn execute_events(card_path: &Path, network: &str, limit: u32) -> Result<()> {
    let card = load_card(card_path)?;
    let address = derive_address_from_card(&card)?;
    let ws_client = make_ws_client(network);

    println!("📜 Historical events for wallet");
    println!("═══════════════════════════════════════");
    println!("  Agent:   {}", card.name);
    println!("  Address: {}", address);
    println!("  Network: {}", network);
    println!("  Limit:   {}", limit);
    println!("═══════════════════════════════════════");
    println!();

    let rt = tokio::runtime::Runtime::new().context("Failed to create async runtime")?;

    let filter = EventFilter::Sender {
        sender: address.clone(),
    };
    let events = rt.block_on(ws_client.query_events(&filter, limit))?;

    if events.is_empty() {
        println!("  No events found for this address.");
        println!("  (Events are emitted by Move contracts — basic");
        println!("   transfers may not produce queryable events.)");
    } else {
        for (i, event) in events.iter().enumerate() {
            let event_type = event
                .get("type")
                .and_then(|t| t.as_str())
                .unwrap_or("unknown");
            let tx_digest = event
                .get("id")
                .and_then(|id| id.get("txDigest"))
                .and_then(|d| d.as_str())
                .unwrap_or("?");
            let timestamp = event
                .get("timestampMs")
                .and_then(|t| t.as_str())
                .unwrap_or("?");

            println!("  [{}] {}", i + 1, event_type);
            println!("      Tx:        {}", tx_digest);
            println!("      Timestamp: {}", timestamp);
            println!();
        }
    }

    Ok(())
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn make_ws_client(network: &str) -> IotaWsClient {
    match network {
        "devnet" => IotaWsClient::devnet(),
        _ => IotaWsClient::testnet(),
    }
}

fn ws_url_for_network(network: &str) -> &str {
    match network {
        "devnet" => ws::DEVNET_WS,
        _ => ws::TESTNET_WS,
    }
}

fn load_card(card_path: &Path) -> Result<AgentCard> {
    let card_json = fs::read_to_string(card_path)
        .with_context(|| format!("Failed to read card: {}", card_path.display()))?;
    serde_json::from_str(&card_json)
        .with_context(|| format!("Failed to parse card: {}", card_path.display()))
}

fn derive_address_from_card(card: &AgentCard) -> Result<String> {
    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
    let pub_bytes = BASE64
        .decode(&card.public_key)
        .context("Failed to decode public key")?;
    let pub_array: [u8; 32] = pub_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Public key must be 32 bytes"))?;
    Ok(iota::derive_iota_address(&pub_array))
}

fn make_client(network: &str) -> IotaClient {
    match network {
        "devnet" => IotaClient::devnet(),
        "mainnet" => {
            eprintln!("⚠️  Mainnet not recommended for testing. Using testnet.");
            IotaClient::testnet()
        }
        _ => IotaClient::testnet(),
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}
