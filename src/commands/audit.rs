//! `audit` subcommand — Query and display the tamper-evident audit log.

use anyhow::Result;
use chrono::DateTime;

use crate::audit as audit_db;
use crate::commands::issue::parse_ttl;

/// Execute the `audit` command.
///
/// Queries the audit log with optional filters and prints a formatted table.
pub fn execute(agent_id: Option<&str>, last: Option<&str>) -> Result<()> {
    let conn = audit_db::open_db()?;

    let duration = match last {
        Some(ttl) => Some(parse_ttl(ttl)?),
        None => None,
    };

    let entries = audit_db::query_entries(&conn, agent_id, duration)?;

    if entries.is_empty() {
        println!("No audit entries found.");
        return Ok(());
    }

    // Print header
    println!(
        "{:<5} {:<36} {:<12} {:<24} {:<20} {:<16}",
        "ID", "Agent ID", "Action", "Target", "Timestamp", "Hash (first 16)"
    );
    println!("{}", "─".repeat(120));

    // Print entries
    for entry in &entries {
        let time_str = DateTime::from_timestamp(entry.timestamp, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| entry.timestamp.to_string());

        let hash_short = if entry.entry_hash.len() >= 16 {
            &entry.entry_hash[..16]
        } else {
            &entry.entry_hash
        };

        println!(
            "{:<5} {:<36} {:<12} {:<24} {:<20} {}…",
            entry.id,
            entry.agent_id,
            entry.action,
            truncate(&entry.target, 24),
            time_str,
            hash_short,
        );
    }

    println!();
    println!("Total: {} entries", entries.len());

    Ok(())
}

/// Truncate a string to max_len, appending "…" if truncated.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len - 1])
    }
}
