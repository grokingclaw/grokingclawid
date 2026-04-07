//! Audit log backed by SQLite with a tamper-evident hash chain.
//!
//! Each entry's hash incorporates the previous entry's hash, forming a chain
//! that makes retroactive modification detectable.

use anyhow::{Context, Result};
use chrono::{Duration, Utc};
use rusqlite::{params, Connection};
use std::path::PathBuf;
use uuid::Uuid;

use crate::crypto;
use crate::models::AuditEntry;

/// Default database directory: ~/.grokingclawid/
fn db_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".grokingclawid"))
}

/// Default database path: ~/.grokingclawid/audit.db
#[allow(dead_code)]
pub fn db_path() -> Result<PathBuf> {
    Ok(db_dir()?.join("audit.db"))
}

/// Open (or create) the audit database and ensure the schema exists.
pub fn open_db() -> Result<Connection> {
    let dir = db_dir()?;
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create directory: {}", dir.display()))?;

    let path = dir.join("audit.db");
    let conn = Connection::open(&path)
        .with_context(|| format!("Failed to open database: {}", path.display()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id   TEXT NOT NULL,
            action     TEXT NOT NULL,
            target     TEXT NOT NULL,
            timestamp  INTEGER NOT NULL,
            prev_hash  TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            signature  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
        CREATE INDEX IF NOT EXISTS idx_audit_time  ON audit_log(timestamp);",
    )
    .context("Failed to initialize audit_log schema")?;

    Ok(conn)
}

/// Open a database at a specific path (used for testing).
#[allow(dead_code)]
pub fn open_db_at(path: &std::path::Path) -> Result<Connection> {
    let conn = Connection::open(path)
        .with_context(|| format!("Failed to open database: {}", path.display()))?;

    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS audit_log (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_id   TEXT NOT NULL,
            action     TEXT NOT NULL,
            target     TEXT NOT NULL,
            timestamp  INTEGER NOT NULL,
            prev_hash  TEXT NOT NULL,
            entry_hash TEXT NOT NULL,
            signature  TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_audit_agent ON audit_log(agent_id);
        CREATE INDEX IF NOT EXISTS idx_audit_time  ON audit_log(timestamp);",
    )
    .context("Failed to initialize audit_log schema")?;

    Ok(conn)
}

/// Get the hash of the last entry in the chain (or "genesis" if empty).
fn get_last_hash(conn: &Connection) -> Result<String> {
    let result: Result<String, rusqlite::Error> = conn.query_row(
        "SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1",
        [],
        |row| row.get(0),
    );
    match result {
        Ok(hash) => Ok(hash),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok("genesis".to_string()),
        Err(e) => Err(e).context("Failed to query last audit hash"),
    }
}

/// Record a new audit entry, extending the hash chain.
///
/// The entry is signed with the provided signing key to prove provenance.
pub fn record_entry(
    conn: &Connection,
    agent_id: &Uuid,
    action: &str,
    target: &str,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<AuditEntry> {
    let prev_hash = get_last_hash(conn)?;
    let timestamp = Utc::now().timestamp();
    let agent_str = agent_id.to_string();

    // Compute the chain hash
    let entry_hash = crypto::compute_chain_hash(&prev_hash, &agent_str, action, target, timestamp);

    // Sign the entry hash
    let signature = crypto::sign(signing_key, entry_hash.as_bytes());

    conn.execute(
        "INSERT INTO audit_log (agent_id, action, target, timestamp, prev_hash, entry_hash, signature)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![agent_str, action, target, timestamp, prev_hash, entry_hash, signature],
    )
    .context("Failed to insert audit entry")?;

    let id = conn.last_insert_rowid();

    Ok(AuditEntry {
        id,
        agent_id: *agent_id,
        action: action.to_string(),
        target: target.to_string(),
        timestamp,
        prev_hash,
        entry_hash,
        signature,
    })
}

/// Query audit entries with optional filters.
///
/// - `agent_id`: filter to a specific agent
/// - `last_duration`: only entries within this time window
pub fn query_entries(
    conn: &Connection,
    agent_id: Option<&str>,
    last_duration: Option<Duration>,
) -> Result<Vec<AuditEntry>> {
    // Build query with typed parameters to avoid string-based binding issues.
    // We use Box<dyn ToSql> to hold heterogeneous param types (String and i64).
    let mut conditions: Vec<String> = Vec::new();
    let mut bind_values: Vec<Box<dyn rusqlite::types::ToSql>> = Vec::new();

    if let Some(aid) = agent_id {
        conditions.push(format!("agent_id = ?{}", bind_values.len() + 1));
        bind_values.push(Box::new(aid.to_string()));
    }

    if let Some(dur) = last_duration {
        let cutoff: i64 = Utc::now().timestamp() - dur.num_seconds();
        conditions.push(format!("timestamp >= ?{}", bind_values.len() + 1));
        bind_values.push(Box::new(cutoff));
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", conditions.join(" AND "))
    };

    let sql = format!(
        "SELECT id, agent_id, action, target, timestamp, prev_hash, entry_hash, signature FROM audit_log{} ORDER BY id ASC",
        where_clause
    );

    let mut stmt = conn
        .prepare(&sql)
        .context("Failed to prepare audit query")?;

    let params: Vec<&dyn rusqlite::types::ToSql> = bind_values
        .iter()
        .map(|v| v.as_ref() as &dyn rusqlite::types::ToSql)
        .collect();

    let entries = stmt
        .query_map(params.as_slice(), |row| {
            let agent_str: String = row.get(1)?;
            Ok(AuditEntry {
                id: row.get(0)?,
                agent_id: Uuid::parse_str(&agent_str).unwrap_or_default(),
                action: row.get(2)?,
                target: row.get(3)?,
                timestamp: row.get(4)?,
                prev_hash: row.get(5)?,
                entry_hash: row.get(6)?,
                signature: row.get(7)?,
            })
        })
        .context("Failed to execute audit query")?
        .collect::<Result<Vec<_>, _>>()
        .context("Failed to read audit entries")?;

    Ok(entries)
}
