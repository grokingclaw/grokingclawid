//! `export` subcommand — Export agent card to A2A (Agent-to-Agent) format.
//!
//! Reads a GrokingClawID agent card and produces an A2A-compatible
//! agent card JSON for agent discovery and interoperability.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

use crate::models::AgentCard;

/// Execute the `export` command.
pub fn execute(card_path: &Path, base_url: &str, output: Option<&Path>) -> Result<()> {
    // Read and parse the card
    let card_json = fs::read_to_string(card_path)
        .with_context(|| format!("Failed to read card: {}", card_path.display()))?;
    let card: AgentCard = serde_json::from_str(&card_json)
        .with_context(|| format!("Failed to parse card: {}", card_path.display()))?;

    // Convert to A2A format
    let a2a_card = card.to_a2a(base_url);
    let a2a_json = serde_json::to_string_pretty(&a2a_card)
        .context("Failed to serialize A2A agent card")?;

    // Write output
    let out_path = output
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| {
            card_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("a2a-agent-card.json")
        });

    fs::write(&out_path, &a2a_json)
        .with_context(|| format!("Failed to write {}", out_path.display()))?;

    println!("✅ A2A agent card exported successfully!");
    println!();
    println!("  Agent:     {}", a2a_card.name);
    println!("  URL:       {}", a2a_card.url);
    println!("  Provider:  {}", a2a_card.provider.organization);
    println!("  Skills:    {}", a2a_card.skills.len());
    println!("  Crypto:    {}", a2a_card.authentication.crypto_scheme);
    println!();
    println!("  Output:    {}", out_path.display());

    Ok(())
}
