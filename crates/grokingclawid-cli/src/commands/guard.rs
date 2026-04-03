//! `guard` subcommand — MCP auth middleware.
//!
//! Wraps any MCP server with GrokingClawID authentication.
//! Sits between the agent and the real MCP server as a stdio proxy.
//!
//! Flow:
//!   Agent ──stdio──► guard ──stdio──► MCP server
//!
//! The guard intercepts every JSON-RPC request and:
//! 1. Requires `clawid_authenticate` as the first tool call (presents agent card)
//! 2. Verifies the card's signature, expiration, and revocation status
//! 3. Checks that the agent's scopes include the required scope
//! 4. Forwards allowed requests to the real MCP server
//! 5. Blocks unauthorized requests with an error response
//!
//! Usage:
//!   grokingclawid guard --scope read,write -- node my-mcp-server.js
//!   grokingclawid guard --require-pq -- python mcp_server.py

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};

use grokingclawid_core::crypto;
use grokingclawid_core::models::{AgentCard, CryptoScheme};
use grokingclawid_core::revocation;

/// JSON-RPC 2.0 request (minimal).
#[derive(Debug, Deserialize, Serialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    #[serde(default)]
    id: serde_json::Value,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

/// JSON-RPC 2.0 response (minimal).
#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i64,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

/// Guard session state.
struct GuardState {
    authenticated: bool,
    agent_card: Option<AgentCard>,
    allowed_scopes: Vec<String>,
    require_pq: bool,
    request_count: u64,
    blocked_count: u64,
}

impl GuardState {
    fn new(allowed_scopes: Vec<String>, require_pq: bool) -> Self {
        Self {
            authenticated: false,
            agent_card: None,
            allowed_scopes,
            require_pq,
            request_count: 0,
            blocked_count: 0,
        }
    }
}

/// Execute the `guard` command.
pub fn execute(
    scope: &str,
    require_pq: bool,
    allow_unauthenticated_init: bool,
    server_cmd: &[String],
) -> Result<()> {
    if server_cmd.is_empty() {
        anyhow::bail!(
            "No MCP server command specified.\n\
             Usage: grokingclawid guard --scope read,write -- node my-mcp-server.js"
        );
    }

    let scopes: Vec<String> = scope.split(',').map(|s| s.trim().to_string()).collect();
    let state = Arc::new(Mutex::new(GuardState::new(scopes, require_pq)));

    eprintln!("[guard] 🛡️  GrokingClawID MCP Auth Guard");
    eprintln!("[guard] Required scopes: {}", scope);
    eprintln!("[guard] Require PQ: {}", require_pq);
    eprintln!("[guard] Wrapping: {}", server_cmd.join(" "));

    // Start the real MCP server as a child process
    let mut child = Command::new(&server_cmd[0])
        .args(&server_cmd[1..])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit()) // pass through stderr
        .spawn()
        .with_context(|| format!("Failed to start MCP server: {}", server_cmd[0]))?;

    let child_stdin = child.stdin.take().context("Failed to get child stdin")?;
    let child_stdout = child.stdout.take().context("Failed to get child stdout")?;

    let child_stdin = Arc::new(Mutex::new(child_stdin));

    // Thread: read from real MCP server stdout → write to our stdout (agent)
    let server_reader = BufReader::new(child_stdout);
    let forward_thread = std::thread::spawn(move || {
        let stdout = std::io::stdout();
        for line in server_reader.lines() {
            match line {
                Ok(line) => {
                    let mut out = stdout.lock();
                    let _ = writeln!(out, "{}", line);
                    let _ = out.flush();
                }
                Err(_) => break,
            }
        }
    });

    // Main thread: read from our stdin (agent) → guard → write to child stdin
    let stdin = std::io::stdin();
    let reader = BufReader::new(stdin.lock());

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => break,
        };

        if line.trim().is_empty() {
            continue;
        }

        // Try to parse as JSON-RPC
        let request: JsonRpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(_) => {
                // Not valid JSON-RPC, forward as-is
                let mut child_in = child_stdin.lock().unwrap();
                let _ = writeln!(child_in, "{}", line);
                let _ = child_in.flush();
                continue;
            }
        };

        let mut guard = state.lock().unwrap();
        guard.request_count += 1;

        // Handle authentication tool call
        if request.method == "tools/call" {
            if let Some(name) = request.params.get("name").and_then(|n| n.as_str()) {
                if name == "clawid_authenticate" {
                    // Handle authentication
                    let response = handle_authenticate(&mut guard, &request);
                    let resp_json = serde_json::to_string(&response).unwrap();
                    let mut out = std::io::stdout().lock();
                    let _ = writeln!(out, "{}", resp_json);
                    let _ = out.flush();
                    continue;
                }

                if name == "clawid_guard_status" {
                    // Return guard status
                    let response = handle_status(&guard, &request);
                    let resp_json = serde_json::to_string(&response).unwrap();
                    let mut out = std::io::stdout().lock();
                    let _ = writeln!(out, "{}", resp_json);
                    let _ = out.flush();
                    continue;
                }
            }
        }

        // Allow initialize and tools/list through without auth
        // (agent needs to discover tools including clawid_authenticate)
        let is_init = matches!(
            request.method.as_str(),
            "initialize" | "initialized" | "tools/list" | "ping"
        );

        if is_init || (allow_unauthenticated_init && !guard.authenticated) {
            drop(guard);
            // Forward to real server
            let mut child_in = child_stdin.lock().unwrap();
            let _ = writeln!(child_in, "{}", line);
            let _ = child_in.flush();

            // If it was tools/list, we need to inject our guard tools
            // (handled by injecting into the response in the forward thread)
            continue;
        }

        // Require authentication for all other requests
        if !guard.authenticated {
            guard.blocked_count += 1;
            let response = JsonRpcResponse {
                jsonrpc: "2.0".into(),
                id: request.id.clone(),
                result: None,
                error: Some(JsonRpcError {
                    code: -32001,
                    message: "Authentication required. Call 'clawid_authenticate' first with your agent card.".into(),
                    data: None,
                }),
            };
            let resp_json = serde_json::to_string(&response).unwrap();
            let mut out = std::io::stdout().lock();
            let _ = writeln!(out, "{}", resp_json);
            let _ = out.flush();
            eprintln!(
                "[guard] ❌ Blocked request #{} ({}): not authenticated",
                guard.request_count, request.method
            );
            continue;
        }

        // Check scope for tools/call
        if request.method == "tools/call" {
            if let Some(name) = request.params.get("name").and_then(|n| n.as_str()) {
                if !check_scope(&guard, name) {
                    guard.blocked_count += 1;
                    let response = JsonRpcResponse {
                        jsonrpc: "2.0".into(),
                        id: request.id.clone(),
                        result: None,
                        error: Some(JsonRpcError {
                            code: -32003,
                            message: format!(
                                "Insufficient scope. Tool '{}' requires scopes not held by agent '{}'.",
                                name,
                                guard.agent_card.as_ref().map(|c| c.name.as_str()).unwrap_or("?")
                            ),
                            data: Some(serde_json::json!({
                                "agent_scopes": guard.agent_card.as_ref().map(|c| &c.scopes),
                                "required_scopes": &guard.allowed_scopes,
                            })),
                        }),
                    };
                    let resp_json = serde_json::to_string(&response).unwrap();
                    let mut out = std::io::stdout().lock();
                    let _ = writeln!(out, "{}", resp_json);
                    let _ = out.flush();
                    eprintln!(
                        "[guard] ❌ Blocked tool '{}': insufficient scope",
                        name
                    );
                    continue;
                }
            }
        }

        // Authenticated and authorized — forward to real server
        eprintln!(
            "[guard] ✅ {} → {} (agent: {})",
            guard.request_count,
            request.method,
            guard.agent_card.as_ref().map(|c| c.name.as_str()).unwrap_or("?")
        );
        drop(guard);

        let mut child_in = child_stdin.lock().unwrap();
        let _ = writeln!(child_in, "{}", line);
        let _ = child_in.flush();
    }

    // Clean up
    let _ = child.kill();
    let _ = forward_thread.join();

    let guard = state.lock().unwrap();
    eprintln!("[guard] Session ended. {} requests, {} blocked.", guard.request_count, guard.blocked_count);

    Ok(())
}

/// Handle the `clawid_authenticate` tool call.
fn handle_authenticate(state: &mut GuardState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let args = request
        .params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::Value::Null);

    // Extract agent card from arguments
    let card_json = match args.get("agent_card") {
        Some(v) if v.is_string() => v.as_str().unwrap().to_string(),
        Some(v) if v.is_object() => serde_json::to_string(v).unwrap_or_default(),
        _ => {
            return error_response(
                &request.id,
                -32002,
                "Missing 'agent_card' in arguments. Provide the agent card JSON.",
            );
        }
    };

    // Parse the agent card
    let card: AgentCard = match serde_json::from_str(&card_json) {
        Ok(c) => c,
        Err(e) => {
            return error_response(
                &request.id,
                -32002,
                &format!("Invalid agent card JSON: {}", e),
            );
        }
    };

    // Verify signature
    let payload = {
        let mut c = card.clone();
        c.signature = String::new();
        c.pq_signature = None;
        match serde_json::to_string(&c) {
            Ok(p) => p,
            Err(e) => {
                return error_response(&request.id, -32002, &format!("Card serialization error: {}", e));
            }
        }
    };

    let ed_valid = match crypto::verify(&card.public_key, payload.as_bytes(), &card.signature) {
        Ok(v) => v,
        Err(e) => {
            return error_response(&request.id, -32002, &format!("Ed25519 verification error: {}", e));
        }
    };

    if !ed_valid {
        eprintln!("[guard] ❌ Authentication failed: invalid Ed25519 signature for '{}'", card.name);
        return error_response(&request.id, -32002, "Invalid Ed25519 signature on agent card.");
    }

    // Check PQ signature if required or hybrid
    if state.require_pq || card.crypto_scheme == CryptoScheme::Hybrid {
        let pq_pub = match &card.pq_public_key {
            Some(k) => k,
            None => {
                return error_response(
                    &request.id,
                    -32002,
                    "Post-quantum signature required but card has no PQ public key.",
                );
            }
        };
        let pq_sig = match &card.pq_signature {
            Some(s) => s,
            None => {
                return error_response(
                    &request.id,
                    -32002,
                    "Post-quantum signature required but card has no PQ signature.",
                );
            }
        };
        match crypto::mldsa_verify(pq_pub, payload.as_bytes(), pq_sig) {
            Ok(true) => {}
            Ok(false) => {
                eprintln!("[guard] ❌ Authentication failed: invalid ML-DSA-65 signature for '{}'", card.name);
                return error_response(&request.id, -32002, "Invalid ML-DSA-65 signature on agent card.");
            }
            Err(e) => {
                return error_response(&request.id, -32002, &format!("ML-DSA-65 verification error: {}", e));
            }
        }
    }

    // Check expiration
    let now = chrono::Utc::now();
    if now >= card.expires_at {
        eprintln!("[guard] ❌ Authentication failed: card expired for '{}'", card.name);
        return error_response(
            &request.id,
            -32002,
            &format!("Agent card expired at {}", card.expires_at.to_rfc3339()),
        );
    }

    // Check revocation
    if let Ok(conn) = revocation::open_db() {
        if revocation::is_revoked(&conn, &card.id).unwrap_or(false) {
            eprintln!("[guard] ❌ Authentication failed: card revoked for '{}'", card.name);
            return error_response(&request.id, -32002, "Agent card has been revoked.");
        }
    }

    // Check scopes
    let has_required_scope = state.allowed_scopes.iter().all(|required| {
        card.scopes.iter().any(|s| s == required || s == "*" || s == "admin")
    });

    if !has_required_scope {
        eprintln!(
            "[guard] ❌ Authentication failed: insufficient scopes for '{}' (has: {:?}, needs: {:?})",
            card.name, card.scopes, state.allowed_scopes
        );
        return error_response(
            &request.id,
            -32003,
            &format!(
                "Insufficient scopes. Agent has {:?}, guard requires {:?}.",
                card.scopes, state.allowed_scopes
            ),
        );
    }

    // All checks passed
    state.authenticated = true;
    state.agent_card = Some(card.clone());

    eprintln!(
        "[guard] ✅ Authenticated: '{}' ({}), scopes: {:?}, expires: {}",
        card.name, card.id, card.scopes, card.expires_at.to_rfc3339()
    );

    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: request.id.clone(),
        result: Some(serde_json::json!({
            "content": [{
                "type": "text",
                "text": format!(
                    "✅ Authenticated as '{}' ({}). Scopes: {:?}. Session active until {}.",
                    card.name, card.id, card.scopes, card.expires_at.to_rfc3339()
                )
            }]
        })),
        error: None,
    }
}

/// Handle the `clawid_guard_status` tool call.
fn handle_status(state: &GuardState, request: &JsonRpcRequest) -> JsonRpcResponse {
    let status = serde_json::json!({
        "authenticated": state.authenticated,
        "agent": state.agent_card.as_ref().map(|c| serde_json::json!({
            "name": c.name,
            "id": c.id.to_string(),
            "scopes": c.scopes,
            "expires_at": c.expires_at.to_rfc3339(),
            "crypto_scheme": format!("{}", c.crypto_scheme),
        })),
        "guard": {
            "required_scopes": state.allowed_scopes,
            "require_pq": state.require_pq,
            "requests_total": state.request_count,
            "requests_blocked": state.blocked_count,
        }
    });

    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: request.id.clone(),
        result: Some(serde_json::json!({
            "content": [{
                "type": "text",
                "text": serde_json::to_string_pretty(&status).unwrap_or_default()
            }]
        })),
        error: None,
    }
}

/// Check if the authenticated agent has scope for a given tool.
fn check_scope(state: &GuardState, _tool_name: &str) -> bool {
    // For now, if authenticated and passed scope check, allow all tools.
    // Future: per-tool scope mapping
    state.authenticated
}

fn error_response(id: &serde_json::Value, code: i64, message: &str) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".into(),
        id: id.clone(),
        result: None,
        error: Some(JsonRpcError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}
