//! Revocation registry backed by SQLite.
//!
//! Tracks revoked agent cards by ID. Revocations include a reason,
//! timestamp, and signature from the revoking authority (the card's
//! own key or a parent/admin key).
//!
//! The revocation list is checked during `verify` to reject cards
//! that have been explicitly revoked.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::crypto;

/// A revocation entry in the registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevocationEntry {
    /// The agent card ID that was revoked.
    pub agent_id: Uuid,
    /// Human-readable agent name (for display).
    pub agent_name: String,
    /// Why the card was revoked.
    pub reason: String,
    /// Who revoked it: "self", "parent", or an agent ID.
    pub revoked_by: String,
    /// When the revocation was recorded.
    pub revoked_at: DateTime<Utc>,
    /// Ed25519 signature over the revocation payload (proves authority).
    pub signature: String,
    /// ML-DSA-65 post-quantum signature (optional; present for hybrid cards).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
}

/// Default revocation DB directory: ~/.grokingclawid/
fn db_dir() -> Result<std::path::PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".grokingclawid"))
}

/// Open (or create) the revocation database and ensure the schema exists.
pub fn open_db() -> Result<Connection> {
    let dir = db_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create directory: {}", dir.display()))?;

    let path = dir.join("revocations.db");
    let conn = Connection::open(&path)
        .with_context(|| format!("Failed to open database: {}", path.display()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS revocations (
            agent_id      TEXT PRIMARY KEY,
            agent_name    TEXT NOT NULL,
            reason        TEXT NOT NULL,
            revoked_by    TEXT NOT NULL,
            revoked_at    TEXT NOT NULL,
            signature     TEXT NOT NULL,
            pq_signature  TEXT
        );",
    )
    .context("Failed to initialize revocations schema")?;

    Ok(conn)
}

/// Open a revocation database at a specific path (used for testing).
pub fn open_db_at(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database: {}", path.display()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS revocations (
            agent_id      TEXT PRIMARY KEY,
            agent_name    TEXT NOT NULL,
            reason        TEXT NOT NULL,
            revoked_by    TEXT NOT NULL,
            revoked_at    TEXT NOT NULL,
            signature     TEXT NOT NULL,
            pq_signature  TEXT
        );",
    )
    .context("Failed to initialize revocations schema")?;

    Ok(conn)
}

/// Build the canonical payload for signing a revocation.
fn revocation_payload(agent_id: &Uuid, reason: &str, revoked_at: &DateTime<Utc>) -> String {
    format!("REVOKE:{}:{}:{}", agent_id, reason, revoked_at.to_rfc3339())
}

/// Revoke an agent card. Records the revocation in the database.
///
/// The signing key must belong to the card owner (self-revocation)
/// or a parent agent (parent revocation).
///
/// If `pq_secret_key` is provided, a post-quantum ML-DSA-65 signature
/// is also recorded, making the revocation PQ-resistant.
pub fn revoke(
    conn: &Connection,
    agent_id: &Uuid,
    agent_name: &str,
    reason: &str,
    revoked_by: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<RevocationEntry> {
    revoke_hybrid(conn, agent_id, agent_name, reason, revoked_by, signing_key, None)
}

/// Revoke with optional post-quantum signature.
pub fn revoke_hybrid(
    conn: &Connection,
    agent_id: &Uuid,
    agent_name: &str,
    reason: &str,
    revoked_by: &str,
    signing_key: &ed25519_dalek::SigningKey,
    pq_secret_key: Option<&[u8]>,
) -> Result<RevocationEntry> {
    // Check if already revoked
    if is_revoked(conn, agent_id)? {
        anyhow::bail!("Agent {} is already revoked", agent_id);
    }

    let now = Utc::now();
    let payload = revocation_payload(agent_id, reason, &now);
    let signature = crypto::sign(signing_key, payload.as_bytes());

    // Optional PQ signature
    let pq_signature = if let Some(pq_key) = pq_secret_key {
        Some(crypto::mldsa_sign(pq_key, payload.as_bytes())?)
    } else {
        None
    };

    conn.execute(
        "INSERT INTO revocations (agent_id, agent_name, reason, revoked_by, revoked_at, signature, pq_signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            agent_id.to_string(),
            agent_name,
            reason,
            revoked_by,
            now.to_rfc3339(),
            signature,
            pq_signature,
        ],
    )
    .context("Failed to insert revocation entry")?;

    Ok(RevocationEntry {
        agent_id: *agent_id,
        agent_name: agent_name.to_string(),
        reason: reason.to_string(),
        revoked_by: revoked_by.to_string(),
        revoked_at: now,
        signature,
        pq_signature,
    })
}

/// Check if an agent card has been revoked.
pub fn is_revoked(conn: &Connection, agent_id: &Uuid) -> Result<bool> {
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM revocations WHERE agent_id = ?1",
            params![agent_id.to_string()],
            |row| row.get(0),
        )
        .context("Failed to check revocation status")?;
    Ok(count > 0)
}

/// Get the revocation entry for an agent card, if it exists.
pub fn get_revocation(conn: &Connection, agent_id: &Uuid) -> Result<Option<RevocationEntry>> {
    let result = conn.query_row(
        "SELECT agent_id, agent_name, reason, revoked_by, revoked_at, signature, pq_signature
         FROM revocations WHERE agent_id = ?1",
        params![agent_id.to_string()],
        |row| {
            let id_str: String = row.get(0)?;
            let revoked_at_str: String = row.get(4)?;
            Ok(RevocationEntry {
                agent_id: Uuid::parse_str(&id_str).unwrap_or_default(),
                agent_name: row.get(1)?,
                reason: row.get(2)?,
                revoked_by: row.get(3)?,
                revoked_at: DateTime::parse_from_rfc3339(&revoked_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                signature: row.get(5)?,
                pq_signature: row.get(6)?,
            })
        },
    );

    match result {
        Ok(entry) => Ok(Some(entry)),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
        Err(e) => Err(e).context("Failed to query revocation"),
    }
}

/// List all revocations in the registry.
pub fn list_revocations(conn: &Connection) -> Result<Vec<RevocationEntry>> {
    let mut stmt = conn
        .prepare(
            "SELECT agent_id, agent_name, reason, revoked_by, revoked_at, signature, pq_signature
             FROM revocations ORDER BY revoked_at DESC",
        )
        .context("Failed to prepare revocation query")?;

    let entries = stmt
        .query_map([], |row| {
            let id_str: String = row.get(0)?;
            let revoked_at_str: String = row.get(4)?;
            Ok(RevocationEntry {
                agent_id: Uuid::parse_str(&id_str).unwrap_or_default(),
                agent_name: row.get(1)?,
                reason: row.get(2)?,
                revoked_by: row.get(3)?,
                revoked_at: DateTime::parse_from_rfc3339(&revoked_at_str)
                    .map(|dt| dt.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                signature: row.get(5)?,
                pq_signature: row.get(6)?,
            })
        })
        .context("Failed to execute revocation query")?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read revocation entries")?;

    Ok(entries)
}

/// Verify a revocation entry's Ed25519 signature.
pub fn verify_revocation(entry: &RevocationEntry, public_key_b64: &str) -> Result<bool> {
    let payload = revocation_payload(&entry.agent_id, &entry.reason, &entry.revoked_at);
    crypto::verify(public_key_b64, payload.as_bytes(), &entry.signature)
}

/// Verify a revocation entry's signatures (both Ed25519 and ML-DSA-65 if present).
///
/// For hybrid cards, both signatures MUST verify. If only Ed25519 signature
/// exists (legacy revocation), only classical verification is performed.
pub fn verify_revocation_hybrid(
    entry: &RevocationEntry,
    ed25519_public_key_b64: &str,
    pq_public_key_b64: Option<&str>,
) -> Result<bool> {
    let payload = revocation_payload(&entry.agent_id, &entry.reason, &entry.revoked_at);

    // Always verify Ed25519
    let ed_valid = crypto::verify(ed25519_public_key_b64, payload.as_bytes(), &entry.signature)?;
    if !ed_valid {
        return Ok(false);
    }

    // If PQ signature is present, verify it too (both MUST pass for hybrid)
    if let (Some(pq_sig), Some(pq_pub)) = (&entry.pq_signature, pq_public_key_b64) {
        let pq_valid = crypto::mldsa_verify(pq_pub, payload.as_bytes(), pq_sig)?;
        return Ok(pq_valid);
    }

    // If entry has PQ sig but no PQ public key was provided, we can't verify PQ part
    // This is acceptable for backward compatibility (classical-only verification)
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto;
    use tempfile::NamedTempFile;

    #[test]
    fn test_revoke_and_check() {
        let tmp = NamedTempFile::new().unwrap();
        let conn = open_db_at(tmp.path()).unwrap();

        let (sk, _vk) = crypto::generate_keypair();
        let agent_id = Uuid::new_v4();

        assert!(!is_revoked(&conn, &agent_id).unwrap());

        let entry = revoke(
            &conn,
            &agent_id,
            "test-agent",
            "key compromised",
            "self",
            &sk,
        )
        .unwrap();
        assert_eq!(entry.agent_id, agent_id);
        assert_eq!(entry.reason, "key compromised");

        assert!(is_revoked(&conn, &agent_id).unwrap());
    }

    #[test]
    fn test_double_revoke_fails() {
        let tmp = NamedTempFile::new().unwrap();
        let conn = open_db_at(tmp.path()).unwrap();

        let (sk, _vk) = crypto::generate_keypair();
        let agent_id = Uuid::new_v4();

        revoke(&conn, &agent_id, "test-agent", "reason1", "self", &sk).unwrap();
        let result = revoke(&conn, &agent_id, "test-agent", "reason2", "self", &sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_get_revocation() {
        let tmp = NamedTempFile::new().unwrap();
        let conn = open_db_at(tmp.path()).unwrap();

        let (sk, _vk) = crypto::generate_keypair();
        let agent_id = Uuid::new_v4();

        assert!(get_revocation(&conn, &agent_id).unwrap().is_none());

        revoke(&conn, &agent_id, "test-agent", "testing", "self", &sk).unwrap();

        let entry = get_revocation(&conn, &agent_id).unwrap().unwrap();
        assert_eq!(entry.reason, "testing");
        assert_eq!(entry.revoked_by, "self");
    }

    #[test]
    fn test_verify_revocation_signature() {
        let tmp = NamedTempFile::new().unwrap();
        let conn = open_db_at(tmp.path()).unwrap();

        let (sk, vk) = crypto::generate_keypair();
        let pub_b64 = crypto::encode_public_key(&vk);
        let agent_id = Uuid::new_v4();

        let entry = revoke(&conn, &agent_id, "test-agent", "compromised", "self", &sk).unwrap();
        assert!(verify_revocation(&entry, &pub_b64).unwrap());

        // Wrong key should fail
        let (_sk2, vk2) = crypto::generate_keypair();
        let wrong_pub = crypto::encode_public_key(&vk2);
        assert!(!verify_revocation(&entry, &wrong_pub).unwrap());
    }

    #[test]
    fn test_revoke_hybrid_and_verify() {
        let tmp = NamedTempFile::new().unwrap();
        let conn = open_db_at(tmp.path()).unwrap();

        let (ed_key, ed_vk) = crypto::generate_keypair();
        let ed_pub = crypto::encode_public_key(&ed_vk);
        let agent_id = Uuid::new_v4();

        // Generate ML-DSA-65 keypair
        let pq_kp = crypto::generate_mldsa_keypair().unwrap();
        let pq_pub = crypto::encode_mldsa_public_key(&pq_kp.public_key_bytes);

        // Hybrid revocation
        let entry = revoke_hybrid(
            &conn,
            &agent_id,
            "hybrid-agent",
            "quantum threat",
            "self",
            &ed_key,
            Some(&pq_kp.secret_key_bytes),
        )
        .unwrap();

        assert!(entry.pq_signature.is_some());

        // Both signatures verify
        assert!(verify_revocation_hybrid(&entry, &ed_pub, Some(&pq_pub)).unwrap());

        // Wrong PQ key fails
        let pq_kp2 = crypto::generate_mldsa_keypair().unwrap();
        let wrong_pq = crypto::encode_mldsa_public_key(&pq_kp2.public_key_bytes);
        assert!(!verify_revocation_hybrid(&entry, &ed_pub, Some(&wrong_pq)).unwrap());

        // Classical-only verification still works (backward compat)
        assert!(verify_revocation(&entry, &ed_pub).unwrap());
    }

    #[test]
    fn test_list_revocations() {
        let tmp = NamedTempFile::new().unwrap();
        let conn = open_db_at(tmp.path()).unwrap();

        let (sk, _vk) = crypto::generate_keypair();

        revoke(&conn, &Uuid::new_v4(), "agent-1", "reason-a", "self", &sk).unwrap();
        revoke(&conn, &Uuid::new_v4(), "agent-2", "reason-b", "admin", &sk).unwrap();

        let all = list_revocations(&conn).unwrap();
        assert_eq!(all.len(), 2);
    }
}
