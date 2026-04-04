//! `license` subcommand — Show, activate, and deactivate license.

use anyhow::Result;

use grokingclawid_core::license;

/// Execute the `license` command (show current license status).
pub fn execute_show() -> Result<()> {
    let state = license::load_license();

    println!("🦀 GrokingClawID License");
    println!();
    println!("  Tier:          {}", state.tier);

    if let Some(ref email) = state.licensee_email {
        println!("  Licensee:      {}", email);
    }
    if let Some(ref issued) = state.issued_at {
        println!("  Issued:        {}", issued.to_rfc3339());
    }

    println!();
    println!("  Limits:");
    match state.limits.max_agents {
        Some(max) => println!("    Agents:      {}", max),
        None => println!("    Agents:      unlimited"),
    }
    match state.limits.max_proxy_agents {
        Some(max) => println!("    Proxy:       {}", max),
        None => println!("    Proxy:       unlimited"),
    }
    match state.limits.max_mesh_nodes {
        Some(0) => println!("    Mesh nodes:  disabled"),
        Some(max) => println!("    Mesh nodes:  {}", max),
        None => println!("    Mesh nodes:  unlimited"),
    }

    if !state.limits.features.is_empty() {
        println!();
        println!("  Features:");
        for feature in &state.limits.features {
            println!("    ✅ {}", feature);
        }
    }

    // Show agent usage
    let agents_dir = license::license_file_path()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("agents")))
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let agent_count = license::count_agents(&agents_dir);
    println!();
    match state.limits.max_agents {
        Some(max) => println!("  Usage:         {}/{} agents", agent_count, max),
        None => println!("  Usage:         {} agents (unlimited)", agent_count),
    }

    if state.tier == license::LicenseTier::Free {
        println!();
        println!("  Upgrade at https://grokingclaw.com for more agents and features.");
    }

    Ok(())
}

/// Execute the `license activate <key>` command.
pub fn execute_activate(key: &str) -> Result<()> {
    let state = license::activate_license(key)?;

    println!("✅ License activated!");
    println!();
    println!("  Tier:     {}", state.tier);
    if let Some(ref email) = state.licensee_email {
        println!("  Licensee: {}", email);
    }
    match state.limits.max_agents {
        Some(max) => println!("  Agents:   up to {}", max),
        None => println!("  Agents:   unlimited"),
    }

    if !state.limits.features.is_empty() {
        println!(
            "  Features: {}",
            state
                .limits
                .features
                .iter()
                .map(|f| f.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
    }

    Ok(())
}

/// Execute the `license deactivate` command.
pub fn execute_deactivate() -> Result<()> {
    license::deactivate_license()?;

    println!("✅ License deactivated. Reverted to Free tier.");
    println!();
    println!("  You can still use the CLI (issue, verify, sign, etc.) without limits.");
    println!("  Daemon features are limited to 5 agents.");

    Ok(())
}
