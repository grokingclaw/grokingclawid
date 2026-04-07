//! `oauth` subcommand — OAuth 2.0 bridge management.
//!
//! Register OAuth providers, start authorization flows, check token status,
//! and revoke tokens. All operations are dispatched to the daemon via IPC.

use anyhow::{Context, Result};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// Default daemon socket path.
fn default_socket_path() -> String {
    let home = dirs::home_dir().unwrap_or_default();
    home.join(".grokingclaw").join("daemon.sock").to_string_lossy().to_string()
}

/// Send a JSON-RPC 2.0 request to the daemon and return the result.
async fn ipc_call(method: &str, params: Value) -> Result<Value> {
    let socket_path = default_socket_path();
    let stream = UnixStream::connect(&socket_path)
        .await
        .with_context(|| format!("Cannot connect to daemon at {}. Is it running?", socket_path))?;

    let (reader, mut writer) = stream.into_split();

    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });

    let mut msg = serde_json::to_string(&request)?;
    msg.push('\n');
    writer.write_all(msg.as_bytes()).await?;

    let mut reader = BufReader::new(reader);
    let mut line = String::new();
    reader.read_line(&mut line).await?;

    let resp: Value = serde_json::from_str(line.trim())?;

    if let Some(error) = resp.get("error") {
        let msg = error.get("message").and_then(|m| m.as_str()).unwrap_or("unknown");
        anyhow::bail!("{}", msg);
    }

    Ok(resp.get("result").cloned().unwrap_or(Value::Null))
}

/// `oauth register` — register an OAuth provider for an agent.
pub fn execute_register(
    agent: &str,
    provider: &str,
    client_id: &str,
    client_secret: Option<&str>,
    authorization_url: Option<&str>,
    token_url: &str,
    scopes: &str,
    domains: &str,
    grant_type: &str,
) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(ipc_call("oauth.register", serde_json::json!({
        "agent": agent,
        "provider": provider,
        "client_id": client_id,
        "client_secret": client_secret,
        "authorization_url": authorization_url.unwrap_or(""),
        "token_url": token_url,
        "scopes": scopes.split_whitespace().collect::<Vec<_>>(),
        "domain_bindings": domains.split(',').map(str::trim).collect::<Vec<_>>(),
        "grant_type": grant_type,
    })))?;

    let reg_id = result.get("registration_id").and_then(|v| v.as_str()).unwrap_or("?");
    println!("✅ OAuth provider registered");
    println!("   Registration ID: {}", reg_id);
    println!("   Provider:        {}", provider);
    println!("   Domains:         {}", domains);
    println!("   Grant type:      {}", grant_type);

    Ok(())
}

/// `oauth authorize` — start an authorization flow.
pub fn execute_authorize(agent: &str, registration_id: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(ipc_call("oauth.authorize", serde_json::json!({
        "agent": agent,
        "registration_id": registration_id,
    })))?;

    // Device code flow
    if let Some(user_code) = result.get("user_code").and_then(|v| v.as_str()) {
        let uri = result.get("verification_uri").and_then(|v| v.as_str()).unwrap_or("?");
        println!("🔑 Device Authorization");
        println!("═══════════════════════════════════════");
        println!("  Code:  {}", user_code);
        println!("  URL:   {}", uri);
        println!("═══════════════════════════════════════");
        println!();
        println!("  Open the URL above and enter the code.");
        if let Some(complete_uri) = result.get("verification_uri_complete").and_then(|v| v.as_str()) {
            println!("  Or visit: {}", complete_uri);
        }
        return Ok(());
    }

    // Auth code flow
    if let Some(auth_url) = result.get("authorization_url").and_then(|v| v.as_str()) {
        println!("🔗 Authorization Code Flow");
        println!("═══════════════════════════════════════");
        println!("  Visit: {}", auth_url);
        println!("═══════════════════════════════════════");
        return Ok(());
    }

    // Client credentials (already completed)
    if result.get("status").and_then(|v| v.as_str()) == Some("tokens_acquired") {
        println!("✅ Tokens acquired (client credentials grant)");
        return Ok(());
    }

    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

/// `oauth status` — check token status.
pub fn execute_status(agent: &str, registration_id: Option<&str>) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let mut params = serde_json::json!({ "agent": agent });
    if let Some(reg_id) = registration_id {
        params["registration_id"] = serde_json::json!(reg_id);
    }
    let result = rt.block_on(ipc_call("oauth.status", params))?;

    if let Some(regs) = result.get("registrations").and_then(|v| v.as_array()) {
        println!("🔐 OAuth Registrations for '{}'", agent);
        println!("═══════════════════════════════════════");
        for reg in regs {
            let id = reg.get("id").and_then(|v| v.as_str()).unwrap_or("?");
            let provider = reg.get("provider").and_then(|v| v.as_str()).unwrap_or("?");
            let status = reg.get("token_status").and_then(|v| v.as_str()).unwrap_or("?");
            let icon = match status {
                "valid" => "🟢",
                "expired" => "🟡",
                _ => "🔴",
            };
            println!("  {} {} [{}] — {}", icon, provider, id, status);
        }
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}

/// `oauth revoke` — revoke tokens for a registration.
pub fn execute_revoke(agent: &str, registration_id: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(ipc_call("oauth.revoke", serde_json::json!({
        "agent": agent,
        "registration_id": registration_id,
    })))?;

    println!("🗑️  OAuth registration '{}' revoked", registration_id);
    if let Some(revoked) = result.get("revoked").and_then(|v| v.as_str()) {
        println!("   Revoked: {}", revoked);
    }

    Ok(())
}

/// `oauth exchange` — RFC 8693 ClawID→OAuth token exchange.
pub fn execute_exchange(agent: &str, registration_id: &str) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    let result = rt.block_on(ipc_call("oauth.exchange", serde_json::json!({
        "agent": agent,
        "registration_id": registration_id,
    })))?;

    if result.get("ok").and_then(|v| v.as_bool()) == Some(true) {
        println!("✅ Token exchange successful — ClawID identity → OAuth token");
    } else {
        println!("{}", serde_json::to_string_pretty(&result)?);
    }

    Ok(())
}
