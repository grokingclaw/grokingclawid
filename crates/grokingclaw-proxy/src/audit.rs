//! Proxy audit logger.
//!
//! Logs every proxied request to the agent's hash-chained SQLite audit log.
//! Uses the core crate's audit functions (open_db_at, record_entry) directly.

use anyhow::{Context, Result};
use ed25519_dalek::SigningKey;
use rusqlite::Connection;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Audit entry for a proxied request.
#[derive(Debug, Clone)]
pub struct ProxyAuditEntry {
    pub method: String,
    pub url: String,
    pub status_code: Option<u16>,
    pub scope_decision: String,
    pub request_size_bytes: u64,
    pub response_size_bytes: u64,
    pub duration_ms: u64,
    pub signed: bool,
    /// Whether an OAuth Bearer token was injected into this request.
    pub oauth_injected: bool,
}

/// Thread-safe audit logger wrapping a rusqlite Connection + signing key.
pub struct ProxyAuditLogger {
    conn: Arc<Mutex<Connection>>,
    agent_id: Uuid,
    signing_key: Arc<SigningKey>,
}

impl ProxyAuditLogger {
    /// Open or create an audit log for an agent.
    pub fn new(db_path: &Path, agent_id: Uuid, signing_key: Arc<SigningKey>) -> Result<Self> {
        let conn = grokingclawid_core::audit::open_db_at(db_path)
            .with_context(|| format!("Failed to open audit DB: {}", db_path.display()))?;
        Ok(Self {
            conn: Arc::new(Mutex::new(conn)),
            agent_id,
            signing_key,
        })
    }

    /// Log a proxied request.
    pub async fn log_request(&self, entry: &ProxyAuditEntry) -> Result<()> {
        let oauth_tag = if entry.oauth_injected { " oauth=injected" } else { "" };
        let action = format!(
            "PROXY {} {} [{}] status={} req:{}B resp:{}B {}ms{}",
            entry.method,
            entry.url,
            entry.scope_decision,
            entry
                .status_code
                .map(|c| c.to_string())
                .unwrap_or_else(|| "-".into()),
            entry.request_size_bytes,
            entry.response_size_bytes,
            entry.duration_ms,
            oauth_tag,
        );

        let target = entry.url.clone();
        let conn = self.conn.lock().await;
        grokingclawid_core::audit::record_entry(
            &conn,
            &self.agent_id,
            &action,
            &target,
            &self.signing_key,
        )
        .context("Failed to record audit entry")?;

        tracing::debug!(
            agent = %self.agent_id,
            method = %entry.method,
            url = %entry.url,
            decision = %entry.scope_decision,
            "Audit logged"
        );

        Ok(())
    }

    /// Log a scope denial (request blocked).
    pub async fn log_denial(&self, method: &str, url: &str, reason: &str) -> Result<()> {
        let action = format!("PROXY_DENIED {} {} reason={}", method, url, reason);
        let conn = self.conn.lock().await;
        grokingclawid_core::audit::record_entry(
            &conn,
            &self.agent_id,
            &action,
            url,
            &self.signing_key,
        )
        .context("Failed to record denial entry")?;

        tracing::warn!(
            agent = %self.agent_id,
            method = %method,
            url = %url,
            reason = %reason,
            "Request DENIED by scope"
        );

        Ok(())
    }
}
