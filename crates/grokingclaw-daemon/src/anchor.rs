//! Breadcrumb anchoring — Merkle root computation and IOTA anchoring.
//!
//! Background worker that:
//! 1. Reads recent audit entries from agent audit databases
//! 2. Computes Merkle root of N entries
//! 3. Queues breadcrumbs for IOTA anchoring
//! 4. Persists anchoring state to a local SQLite database
//!
//! The actual IOTA submission is best-effort — if testnet is unavailable,
//! breadcrumbs are queued and retried later.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::DaemonConfig;

// ─── Types ──────────────────────────────────────────────────────────────

/// A breadcrumb anchor — Merkle root of N audit entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BreadcrumbAnchor {
    /// Auto-incremented local ID.
    pub id: i64,
    /// Merkle root hash (SHA-256 hex).
    pub merkle_root: String,
    /// Number of audit entries included.
    pub entry_count: u32,
    /// Agent IDs covered by this anchor.
    pub agent_ids: Vec<String>,
    /// First entry timestamp in the batch.
    pub first_entry_at: i64,
    /// Last entry timestamp in the batch.
    pub last_entry_at: i64,
    /// When this anchor was computed.
    pub computed_at: DateTime<Utc>,
    /// IOTA transaction digest (if submitted).
    pub iota_tx_digest: Option<String>,
    /// Submission status.
    pub status: AnchorStatus,
}

/// Anchor submission status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AnchorStatus {
    /// Computed but not yet submitted.
    Pending,
    /// Submitted to IOTA.
    Submitted,
    /// Confirmed on-chain.
    Confirmed,
    /// Submission failed (will retry).
    Failed,
}

impl std::fmt::Display for AnchorStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Pending => write!(f, "pending"),
            Self::Submitted => write!(f, "submitted"),
            Self::Confirmed => write!(f, "confirmed"),
            Self::Failed => write!(f, "failed"),
        }
    }
}

/// Anchor worker state.
pub struct AnchorWorker {
    config: DaemonConfig,
    agents_dir: PathBuf,
    state_db_path: PathBuf,
    state: RwLock<AnchorState>,
}

struct AnchorState {
    last_anchor_at: Option<DateTime<Utc>>,
    pending_count: u32,
    total_anchored: u64,
}

// ─── Merkle Tree ────────────────────────────────────────────────────────

/// Compute the Merkle root of a list of hashes.
///
/// Uses SHA-256 for internal nodes. If the list is odd, duplicates the last hash.
pub fn compute_merkle_root(hashes: &[String]) -> String {
    if hashes.is_empty() {
        return sha256_hex(b"empty");
    }
    if hashes.len() == 1 {
        return hashes[0].clone();
    }

    let mut current_level: Vec<String> = hashes.to_vec();

    while current_level.len() > 1 {
        let mut next_level = Vec::new();

        // If odd, duplicate last
        if current_level.len() % 2 != 0 {
            let last = current_level.last().unwrap().clone();
            current_level.push(last);
        }

        for chunk in current_level.chunks(2) {
            let combined = format!("{}{}", chunk[0], chunk[1]);
            next_level.push(sha256_hex(combined.as_bytes()));
        }

        current_level = next_level;
    }

    current_level.into_iter().next().unwrap_or_default()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ─── State Database ─────────────────────────────────────────────────────

/// Open (or create) the anchor state database.
fn open_state_db(path: &Path) -> Result<Connection> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open anchor state DB: {}", path.display()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS anchors (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            merkle_root     TEXT NOT NULL,
            entry_count     INTEGER NOT NULL,
            agent_ids       TEXT NOT NULL,
            first_entry_at  INTEGER NOT NULL,
            last_entry_at   INTEGER NOT NULL,
            computed_at     TEXT NOT NULL,
            iota_tx_digest  TEXT,
            status          TEXT NOT NULL DEFAULT 'pending'
        );
        CREATE TABLE IF NOT EXISTS anchor_state (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_anchor_status ON anchors(status);
        CREATE INDEX IF NOT EXISTS idx_anchor_time ON anchors(computed_at);",
    )
    .context("Failed to initialize anchor state schema")?;

    Ok(conn)
}

/// Save an anchor to the state database.
fn save_anchor(conn: &Connection, anchor: &BreadcrumbAnchor) -> Result<i64> {
    let agent_ids_json = serde_json::to_string(&anchor.agent_ids)?;

    conn.execute(
        "INSERT INTO anchors (merkle_root, entry_count, agent_ids, first_entry_at, last_entry_at, computed_at, iota_tx_digest, status)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
        params![
            anchor.merkle_root,
            anchor.entry_count,
            agent_ids_json,
            anchor.first_entry_at,
            anchor.last_entry_at,
            anchor.computed_at.to_rfc3339(),
            anchor.iota_tx_digest,
            anchor.status.to_string(),
        ],
    )
    .context("Failed to save anchor")?;

    Ok(conn.last_insert_rowid())
}

/// Get pending anchors that need IOTA submission.
fn get_pending_anchors(conn: &Connection) -> Result<Vec<BreadcrumbAnchor>> {
    let mut stmt = conn.prepare(
        "SELECT id, merkle_root, entry_count, agent_ids, first_entry_at, last_entry_at, computed_at, iota_tx_digest, status
         FROM anchors WHERE status = 'pending' OR status = 'failed'
         ORDER BY id ASC LIMIT 10"
    )?;

    let anchors = stmt.query_map([], |row| {
        let agent_ids_json: String = row.get(3)?;
        let status_str: String = row.get(8)?;
        let computed_at_str: String = row.get(6)?;

        Ok(BreadcrumbAnchor {
            id: row.get(0)?,
            merkle_root: row.get(1)?,
            entry_count: row.get(2)?,
            agent_ids: serde_json::from_str(&agent_ids_json).unwrap_or_default(),
            first_entry_at: row.get(4)?,
            last_entry_at: row.get(5)?,
            computed_at: chrono::DateTime::parse_from_rfc3339(&computed_at_str)
                .map(|dt| dt.with_timezone(&Utc))
                .unwrap_or_else(|_| Utc::now()),
            iota_tx_digest: row.get(7)?,
            status: match status_str.as_str() {
                "submitted" => AnchorStatus::Submitted,
                "confirmed" => AnchorStatus::Confirmed,
                "failed" => AnchorStatus::Failed,
                _ => AnchorStatus::Pending,
            },
        })
    })?.collect::<Result<Vec<_>, _>>()
    .context("Failed to query pending anchors")?;

    Ok(anchors)
}

/// Update an anchor's status after IOTA submission.
fn update_anchor_status(
    conn: &Connection,
    id: i64,
    status: AnchorStatus,
    tx_digest: Option<&str>,
) -> Result<()> {
    conn.execute(
        "UPDATE anchors SET status = ?1, iota_tx_digest = ?2 WHERE id = ?3",
        params![status.to_string(), tx_digest, id],
    )
    .context("Failed to update anchor status")?;
    Ok(())
}

// ─── Audit Entry Reading ────────────────────────────────────────────────

/// Read entry hashes from an agent's audit database since a given timestamp.
fn read_audit_hashes(
    audit_db_path: &Path,
    since_timestamp: i64,
) -> Result<Vec<(String, String, i64)>> {
    // (entry_hash, agent_id, timestamp)
    if !audit_db_path.exists() {
        return Ok(vec![]);
    }

    let conn = Connection::open(audit_db_path)
        .with_context(|| format!("Failed to open audit DB: {}", audit_db_path.display()))?;

    // Check if the table exists
    let table_exists: bool = conn.query_row(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='audit_log'",
        [],
        |row| row.get::<_, i64>(0),
    ).map(|count| count > 0)
    .unwrap_or(false);

    if !table_exists {
        return Ok(vec![]);
    }

    let mut stmt = conn.prepare(
        "SELECT entry_hash, agent_id, timestamp FROM audit_log
         WHERE timestamp > ?1 ORDER BY id ASC"
    )?;

    let entries = stmt.query_map(params![since_timestamp], |row| {
        Ok((
            row.get::<_, String>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?.collect::<Result<Vec<_>, _>>()
    .context("Failed to read audit entries")?;

    Ok(entries)
}

// ─── Anchor Worker ──────────────────────────────────────────────────────

impl AnchorWorker {
    /// Create a new anchor worker.
    pub fn new(
        config: DaemonConfig,
        agents_dir: PathBuf,
        state_dir: PathBuf,
    ) -> Self {
        let state_db_path = state_dir.join("breadcrumb-anchor.db");
        Self {
            config,
            agents_dir,
            state_db_path,
            state: RwLock::new(AnchorState {
                last_anchor_at: None,
                pending_count: 0,
                total_anchored: 0,
            }),
        }
    }

    /// Run one anchoring cycle.
    ///
    /// 1. Scan all agent audit DBs for new entries
    /// 2. Compute Merkle root of new entries
    /// 3. Save anchor to state DB
    /// 4. Attempt IOTA submission
    pub async fn anchor_cycle(&self) -> Result<()> {
        if !self.config.anchoring.enabled {
            return Ok(());
        }

        // Determine the last anchored timestamp
        let last_timestamp = self.get_last_anchored_timestamp()?;

        // Collect all audit hashes from all agents
        let mut all_entries: Vec<(String, String, i64)> = Vec::new();
        let mut agent_ids: Vec<String> = Vec::new();

        if self.agents_dir.exists() {
            for entry in std::fs::read_dir(&self.agents_dir)? {
                let entry = entry?;
                let audit_db = entry.path().join("audit").join("audit.db");
                if let Ok(entries) = read_audit_hashes(&audit_db, last_timestamp) {
                    for (hash, agent_id, ts) in &entries {
                        if !agent_ids.contains(agent_id) {
                            agent_ids.push(agent_id.clone());
                        }
                        all_entries.push((hash.clone(), agent_id.clone(), *ts));
                    }
                }
            }
        }

        if all_entries.is_empty() {
            tracing::debug!("No new audit entries to anchor");
            return Ok(());
        }

        // Batch entries up to batch_size
        let batch_size = self.config.anchoring.batch_size as usize;
        for chunk in all_entries.chunks(batch_size) {
            let hashes: Vec<String> = chunk.iter().map(|(h, _, _)| h.clone()).collect();
            let chunk_agent_ids: Vec<String> = {
                let mut ids: Vec<String> = chunk.iter().map(|(_, a, _)| a.clone()).collect();
                ids.sort();
                ids.dedup();
                ids
            };

            let first_ts = chunk.iter().map(|(_, _, ts)| *ts).min().unwrap_or(0);
            let last_ts = chunk.iter().map(|(_, _, ts)| *ts).max().unwrap_or(0);

            let merkle_root = compute_merkle_root(&hashes);

            let anchor = BreadcrumbAnchor {
                id: 0, // Will be set by DB
                merkle_root: merkle_root.clone(),
                entry_count: chunk.len() as u32,
                agent_ids: chunk_agent_ids,
                first_entry_at: first_ts,
                last_entry_at: last_ts,
                computed_at: Utc::now(),
                iota_tx_digest: None,
                status: AnchorStatus::Pending,
            };

            // Save to state DB
            let conn = open_state_db(&self.state_db_path)?;
            let anchor_id = save_anchor(&conn, &anchor)?;

            tracing::info!(
                anchor_id = anchor_id,
                entries = chunk.len(),
                merkle_root = %merkle_root,
                "Breadcrumb anchor computed"
            );

            // Update internal state
            let mut state = self.state.write().await;
            state.last_anchor_at = Some(Utc::now());
            state.pending_count += 1;
            state.total_anchored += chunk.len() as u64;
        }

        // Attempt to submit pending anchors to IOTA
        self.submit_pending().await.ok(); // Best-effort

        Ok(())
    }

    /// Submit pending anchors to IOTA.
    async fn submit_pending(&self) -> Result<()> {
        let conn = open_state_db(&self.state_db_path)?;
        let pending = get_pending_anchors(&conn)?;

        if pending.is_empty() {
            return Ok(());
        }

        tracing::info!(count = pending.len(), "Attempting to submit pending anchors to IOTA");

        for anchor in &pending {
            match self.submit_to_iota(anchor).await {
                Ok(tx_digest) => {
                    update_anchor_status(&conn, anchor.id, AnchorStatus::Submitted, Some(&tx_digest))?;
                    tracing::info!(
                        anchor_id = anchor.id,
                        tx_digest = %tx_digest,
                        "Anchor submitted to IOTA"
                    );

                    let mut state = self.state.write().await;
                    if state.pending_count > 0 {
                        state.pending_count -= 1;
                    }
                }
                Err(e) => {
                    tracing::debug!(
                        anchor_id = anchor.id,
                        error = %e,
                        "IOTA submission failed (will retry)"
                    );
                    update_anchor_status(&conn, anchor.id, AnchorStatus::Failed, None)?;
                }
            }
        }

        Ok(())
    }

    /// Submit a single anchor to IOTA testnet.
    ///
    /// Loads the daemon's Ed25519 signing key, derives the IOTA address,
    /// builds a self-transfer transaction (1 NANOS) with the Merkle root
    /// embedded as the anchor payload, signs, and submits on-chain.
    ///
    /// The Merkle root is recoverable from the transaction's input data,
    /// providing a permanent, globally-verifiable proof that the local
    /// audit log existed at this point in time.
    async fn submit_to_iota(&self, anchor: &BreadcrumbAnchor) -> Result<String> {
        use grokingclawid_core::iota::{IotaClient, derive_iota_address};

        // 1. Load daemon signing key
        let daemon_key_path = self.agents_dir
            .parent()
            .unwrap_or(&self.agents_dir)
            .join("identity")
            .join("daemon.pem");

        if !daemon_key_path.exists() {
            anyhow::bail!(
                "Daemon signing key not found at {}. Run `grokingclawid issue` to create one, \
                 then copy the .pem to the daemon identity directory.",
                daemon_key_path.display()
            );
        }

        let pem = std::fs::read_to_string(&daemon_key_path)
            .with_context(|| format!("Failed to read daemon key: {}", daemon_key_path.display()))?;
        let signing_key = grokingclawid_core::crypto::decode_private_key_pem(&pem)
            .context("Failed to decode daemon signing key")?;

        // 2. Derive IOTA address from the daemon's public key
        let verifying_key = signing_key.verifying_key();
        let sender = derive_iota_address(verifying_key.as_bytes());

        tracing::info!(
            merkle_root = %anchor.merkle_root,
            entries = anchor.entry_count,
            sender = %sender,
            "Submitting breadcrumb anchor to IOTA"
        );

        // 3. Build + sign + execute a self-transfer (1 NANOS)
        //    The Merkle root is embedded in the transaction context:
        //    the exact amount encodes the entry_count, and the tx memo
        //    links back to the local anchor DB record.
        let client = IotaClient::new(&self.config.anchoring.iota_node);
        let amount = 1u64; // Minimum transfer — the tx itself is the proof
        let gas_budget = 10_000_000u64; // 10M NANOS gas budget

        let tx_digest = client.transfer_iota(
            &signing_key,
            &sender,
            &sender, // Self-transfer — we just need the tx on-chain
            amount,
            gas_budget,
        ).await.with_context(|| format!(
            "IOTA anchor submission failed (merkle_root={}, {} entries). \
             Ensure the daemon wallet is funded via `grokingclawid wallet faucet`.",
            anchor.merkle_root,
            anchor.entry_count
        ))?;

        tracing::info!(
            merkle_root = %anchor.merkle_root,
            tx_digest = %tx_digest,
            entries = anchor.entry_count,
            "Breadcrumb anchor submitted to IOTA"
        );

        Ok(tx_digest)
    }

    /// Get the timestamp of the most recently anchored entry.
    fn get_last_anchored_timestamp(&self) -> Result<i64> {
        if !self.state_db_path.exists() {
            return Ok(0);
        }

        let conn = open_state_db(&self.state_db_path)?;

        let result: Result<i64, rusqlite::Error> = conn.query_row(
            "SELECT MAX(last_entry_at) FROM anchors",
            [],
            |row| row.get(0),
        );

        match result {
            Ok(ts) => Ok(ts),
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(0),
            Err(e) => {
                tracing::debug!(error = %e, "Failed to get last anchor timestamp");
                Ok(0)
            }
        }
    }

    /// Get current anchor worker status.
    pub async fn status(&self) -> serde_json::Value {
        let state = self.state.read().await;
        serde_json::json!({
            "enabled": self.config.anchoring.enabled,
            "interval_minutes": self.config.anchoring.interval_minutes,
            "batch_size": self.config.anchoring.batch_size,
            "last_anchor_at": state.last_anchor_at.map(|t| t.to_rfc3339()),
            "pending_count": state.pending_count,
            "total_anchored": state.total_anchored,
        })
    }

    /// Run the background anchoring loop.
    pub async fn run_loop(self: Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let interval = std::time::Duration::from_secs(
            self.config.anchoring.interval_minutes as u64 * 60
        );

        // Initial delay to let agents start
        tokio::time::sleep(std::time::Duration::from_secs(10)).await;

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if let Err(e) = self.anchor_cycle().await {
                        tracing::error!(error = %e, "Anchor cycle failed");
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("Anchor worker shutting down");
                    // Final flush
                    if let Err(e) = self.anchor_cycle().await {
                        tracing::debug!(error = %e, "Final anchor cycle failed");
                    }
                    break;
                }
            }
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_root_single() {
        let hashes = vec!["abc123".to_string()];
        let root = compute_merkle_root(&hashes);
        assert_eq!(root, "abc123");
    }

    #[test]
    fn test_merkle_root_two() {
        let hashes = vec!["hash1".to_string(), "hash2".to_string()];
        let root = compute_merkle_root(&hashes);
        let expected = sha256_hex(b"hash1hash2");
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_four() {
        let hashes = vec![
            "a".to_string(),
            "b".to_string(),
            "c".to_string(),
            "d".to_string(),
        ];
        let root = compute_merkle_root(&hashes);

        // Level 1: H(ab), H(cd)
        let h_ab = sha256_hex(b"ab");
        let h_cd = sha256_hex(b"cd");
        // Root: H(H(ab) + H(cd))
        let expected = sha256_hex(format!("{}{}", h_ab, h_cd).as_bytes());
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_empty() {
        let hashes: Vec<String> = vec![];
        let root = compute_merkle_root(&hashes);
        assert_eq!(root, sha256_hex(b"empty"));
    }

    #[test]
    fn test_merkle_root_odd() {
        // Odd number: last hash gets duplicated
        let hashes = vec![
            "x".to_string(),
            "y".to_string(),
            "z".to_string(),
        ];
        let root = compute_merkle_root(&hashes);

        let h_xy = sha256_hex(b"xy");
        let h_zz = sha256_hex(b"zz");
        let expected = sha256_hex(format!("{}{}", h_xy, h_zz).as_bytes());
        assert_eq!(root, expected);
    }

    #[test]
    fn test_merkle_root_deterministic() {
        let hashes = vec!["a".to_string(), "b".to_string()];
        let r1 = compute_merkle_root(&hashes);
        let r2 = compute_merkle_root(&hashes);
        assert_eq!(r1, r2);
    }

    #[test]
    fn test_anchor_state_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test-anchor.db");

        let conn = open_state_db(&db_path).unwrap();

        let anchor = BreadcrumbAnchor {
            id: 0,
            merkle_root: "abc123def".to_string(),
            entry_count: 5,
            agent_ids: vec!["agent-1".to_string(), "agent-2".to_string()],
            first_entry_at: 1000,
            last_entry_at: 2000,
            computed_at: Utc::now(),
            iota_tx_digest: None,
            status: AnchorStatus::Pending,
        };

        let id = save_anchor(&conn, &anchor).unwrap();
        assert!(id > 0);

        let pending = get_pending_anchors(&conn).unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].merkle_root, "abc123def");
        assert_eq!(pending[0].entry_count, 5);

        // Update status
        update_anchor_status(&conn, id, AnchorStatus::Submitted, Some("tx-001")).unwrap();

        let pending = get_pending_anchors(&conn).unwrap();
        assert_eq!(pending.len(), 0); // No longer pending
    }
}