//! IPC server — Unix domain socket with JSON-RPC 2.0 protocol.
//!
//! The CLI (`grokingclaw`) communicates with the daemon via this socket.
//! Protocol: newline-delimited JSON-RPC 2.0.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};

use crate::birth::BirthParams;
use crate::daemon::DaemonState;
use crate::mesh::MeshState;

/// JSON-RPC 2.0 Request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
    #[allow(dead_code)]
    pub jsonrpc: String,
    pub id: Option<Value>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
}

/// JSON-RPC 2.0 Response.
#[derive(Debug, Serialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
pub struct JsonRpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

impl JsonRpcResponse {
    pub fn success(id: Option<Value>, result: Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<Value>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message, data: None }),
        }
    }
}

/// Start the IPC server listening on a Unix socket.
pub async fn start_ipc_server(
    socket_path: &Path,
    state: Arc<DaemonState>,
) -> Result<()> {
    // Remove stale socket file
    if socket_path.exists() {
        std::fs::remove_file(socket_path)
            .with_context(|| format!("Failed to remove stale socket: {}", socket_path.display()))?;
    }

    // Ensure parent directory exists
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)
        .with_context(|| format!("Failed to bind socket: {}", socket_path.display()))?;

    tracing::info!(path = %socket_path.display(), "IPC server listening");

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, state).await {
                        tracing::error!(error = %e, "IPC connection error");
                    }
                });
            }
            Err(e) => {
                tracing::error!(error = %e, "Failed to accept IPC connection");
            }
        }
    }
}

/// Handle a single IPC connection (may send multiple requests).
async fn handle_connection(stream: UnixStream, state: Arc<DaemonState>) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let bytes = reader.read_line(&mut line).await?;
        if bytes == 0 {
            break; // EOF
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let response = match serde_json::from_str::<JsonRpcRequest>(trimmed) {
            Ok(request) => dispatch(&state, request).await,
            Err(e) => JsonRpcResponse::error(
                None,
                -32700,
                format!("Parse error: {}", e),
            ),
        };

        let mut response_json = serde_json::to_string(&response)?;
        response_json.push('\n');
        writer.write_all(response_json.as_bytes()).await?;
        writer.flush().await?;
    }

    Ok(())
}

/// Dispatch a JSON-RPC request to the appropriate handler.
async fn dispatch(state: &DaemonState, request: JsonRpcRequest) -> JsonRpcResponse {
    let id = request.id.clone();

    match request.method.as_str() {
        // ─── Daemon ────────────────────────────────────────────────
        "status" => {
            let agents = state.supervisor.list_agents().await;

            // Get mesh status
            let mesh_status = if let Some(ref mesh) = state.mesh {
                let status = mesh.status().await;
                match status {
                    MeshState::Connected { mesh_ip, peers, connected_at } => serde_json::json!({
                        "state": "connected",
                        "mesh_ip": mesh_ip,
                        "peer_count": peers.len(),
                        "connected_at": connected_at.to_rfc3339(),
                    }),
                    MeshState::Connecting => serde_json::json!({"state": "connecting"}),
                    MeshState::Disconnected => serde_json::json!({"state": "disconnected"}),
                }
            } else {
                serde_json::json!({"state": "disabled"})
            };

            // Get anchor status
            let anchor_status = {
                let aw = state.anchor_worker.read().await;
                if let Some(ref worker) = *aw {
                    worker.status().await
                } else {
                    serde_json::json!({"enabled": false})
                }
            };

            let info = serde_json::json!({
                "daemon": "running",
                "version": env!("CARGO_PKG_VERSION"),
                "agents_count": agents.len(),
                "agents": agents,
                "uptime_seconds": state.started_at.elapsed().as_secs(),
                "mesh": mesh_status,
                "anchor": anchor_status,
            });
            JsonRpcResponse::success(id, info)
        }

        "shutdown" => {
            tracing::info!("Shutdown requested via IPC");
            state.request_shutdown();
            JsonRpcResponse::success(id, serde_json::json!({"status": "shutting_down"}))
        }

        // ─── Agents ────────────────────────────────────────────────
        "agents.list" => {
            let agents = state.supervisor.list_agents().await;
            JsonRpcResponse::success(id, serde_json::to_value(agents).unwrap_or_default())
        }

        "agents.get" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.get_agent(name).await {
                Some(info) => JsonRpcResponse::success(id, serde_json::to_value(info).unwrap_or_default()),
                None => JsonRpcResponse::error(id, -32001, format!("Agent '{}' not found", name)),
            }
        }

        "birth" => {
            let params = match BirthParams::from_json(&request.params) {
                Ok(p) => p,
                Err(e) => return JsonRpcResponse::error(id, -32602, format!("Invalid birth params: {:#}", e)),
            };

            match state.birth_agent(params).await {
                Ok(result) => {
                    let mut value = serde_json::to_value(&result.agent_info).unwrap_or_default();
                    if let Value::Object(ref mut map) = value {
                        map.insert("birth_mode".to_string(), serde_json::json!(result.birth_mode));
                        if let Some(cert) = &result.certificate {
                            map.insert("certificate_id".to_string(), serde_json::json!(cert.certificate_id));
                        }
                    }
                    JsonRpcResponse::success(id, value)
                }
                Err(e) => JsonRpcResponse::error(id, -32000, format!("Birth failed: {:#}", e)),
            }
        }

        "agents.start" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.start_agent(name).await {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "started", "agent": name})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("{:#}", e)),
            }
        }

        "agents.stop" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.stop_agent(name).await {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "stopped", "agent": name})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("{:#}", e)),
            }
        }

        "agents.delete" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.delete_agent(name).await {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "deleted", "agent": name})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("{:#}", e)),
            }
        }

        "agents.logs" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let lines = request.params.get("lines")
                .and_then(|v| v.as_u64())
                .unwrap_or(50) as usize;
            match state.read_agent_logs(name, lines).await {
                Ok(logs) => JsonRpcResponse::success(id, serde_json::json!({"logs": logs})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("{:#}", e)),
            }
        }

        // ─── Mesh ──────────────────────────────────────────────────
        "mesh.status" => {
            if let Some(ref mesh) = state.mesh {
                let status = mesh.status().await;
                let value = match status {
                    MeshState::Connected { mesh_ip, peers, connected_at } => serde_json::json!({
                        "state": "connected",
                        "mesh_ip": mesh_ip,
                        "peer_count": peers.len(),
                        "connected_at": connected_at.to_rfc3339(),
                    }),
                    MeshState::Connecting => serde_json::json!({"state": "connecting"}),
                    MeshState::Disconnected => serde_json::json!({"state": "disconnected"}),
                };
                JsonRpcResponse::success(id, value)
            } else {
                JsonRpcResponse::success(id, serde_json::json!({
                    "state": "disabled",
                    "message": "Mesh networking is not enabled. Set [mesh] enabled = true in daemon.toml"
                }))
            }
        }

        "mesh.connect" => {
            if let Some(ref mesh) = state.mesh {
                match mesh.connect().await {
                    Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "connected"})),
                    Err(e) => JsonRpcResponse::error(id, -32000, format!("Mesh connection failed: {:#}", e)),
                }
            } else {
                JsonRpcResponse::error(id, -32000, "Mesh networking is not enabled".to_string())
            }
        }

        "mesh.disconnect" => {
            if let Some(ref mesh) = state.mesh {
                match mesh.disconnect().await {
                    Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "disconnected"})),
                    Err(e) => JsonRpcResponse::error(id, -32000, format!("Mesh disconnect failed: {:#}", e)),
                }
            } else {
                JsonRpcResponse::error(id, -32000, "Mesh networking is not enabled".to_string())
            }
        }

        "mesh.peers" => {
            if let Some(ref mesh) = state.mesh {
                match mesh.list_peers().await {
                    Ok(peers) => JsonRpcResponse::success(id, serde_json::json!({"peers": peers})),
                    Err(e) => JsonRpcResponse::error(id, -32000, format!("Failed to list peers: {:#}", e)),
                }
            } else {
                JsonRpcResponse::success(id, serde_json::json!({"peers": []}))
            }
        }

        "mesh.ping" => {
            let did = request.params.get("did")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if did.is_empty() {
                return JsonRpcResponse::error(id, -32602, "Missing 'did' parameter".to_string());
            }
            if let Some(ref mesh) = state.mesh {
                match mesh.ping(did).await {
                    Ok(result) => JsonRpcResponse::success(id, serde_json::to_value(result).unwrap_or_default()),
                    Err(e) => JsonRpcResponse::error(id, -32000, format!("Ping failed: {:#}", e)),
                }
            } else {
                JsonRpcResponse::error(id, -32000, "Mesh networking is not enabled".to_string())
            }
        }

        // ─── Templates ─────────────────────────────────────────────
        "templates.list" => {
            match state.templates.list_local() {
                Ok(templates) => {
                    let summaries: Vec<serde_json::Value> = templates.iter().map(|t| {
                        serde_json::json!({
                            "name": t.name,
                            "version": t.version,
                            "description": t.description,
                            "has_manifest": t.has_manifest,
                        })
                    }).collect();
                    JsonRpcResponse::success(id, serde_json::json!({"templates": summaries}))
                }
                Err(e) => JsonRpcResponse::error(id, -32000, format!("Failed to list templates: {:#}", e)),
            }
        }

        "templates.inspect" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            if name.is_empty() {
                return JsonRpcResponse::error(id, -32602, "Missing 'name' parameter".to_string());
            }
            match state.templates.get_template(name) {
                Ok(Some(manifest)) => {
                    JsonRpcResponse::success(id, serde_json::to_value(manifest).unwrap_or_default())
                }
                Ok(None) => JsonRpcResponse::error(id, -32001, format!("Template '{}' not found", name)),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("Failed to inspect template: {:#}", e)),
            }
        }

        "templates.install" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("").to_string();
            let version = request.params.get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("latest").to_string();
            if name.is_empty() {
                return JsonRpcResponse::error(id, -32602, "Missing 'name' parameter".to_string());
            }
            match state.templates.install_template(&name, &version).await {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "installed", "template": name, "version": version})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("Install failed: {:#}", e)),
            }
        }

        "templates.create" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("").to_string();
            let source = request.params.get("source")
                .and_then(|v| v.as_str())
                .unwrap_or("").to_string();
            if name.is_empty() || source.is_empty() {
                return JsonRpcResponse::error(id, -32602, "Missing 'name' or 'source' parameter".to_string());
            }
            match state.templates.create_from_local(&name, &std::path::PathBuf::from(&source)) {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "created", "template": name})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("Create failed: {:#}", e)),
            }
        }

        // ─── Audit ─────────────────────────────────────────────────
        "audit.query" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let last = request.params.get("last")
                .and_then(|v| v.as_u64())
                .unwrap_or(20);
            let verify = request.params.get("verify")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            if name.is_empty() {
                return JsonRpcResponse::error(id, -32602, "Missing 'name' parameter".to_string());
            }
            match state.query_audit(name, last, verify).await {
                Ok(result) => JsonRpcResponse::success(id, result),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("Audit query failed: {:#}", e)),
            }
        }

        // ─── Updates ───────────────────────────────────────────────
        "update.check" => {
            let uc = state.update_checker.read().await;
            if let Some(ref checker) = *uc {
                match checker.check().await {
                    Ok(result) => JsonRpcResponse::success(id, serde_json::to_value(result).unwrap_or_default()),
                    Err(e) => JsonRpcResponse::error(id, -32000, format!("Update check failed: {:#}", e)),
                }
            } else {
                JsonRpcResponse::success(id, serde_json::json!({"available_updates": [], "message": "Update checker not initialized"}))
            }
        }

        "update.apply" => {
            let uc = state.update_checker.read().await;
            if let Some(ref checker) = *uc {
                match checker.apply_template_updates().await {
                    Ok(applied) => JsonRpcResponse::success(id, serde_json::json!({
                        "applied": applied,
                        "count": applied.len(),
                    })),
                    Err(e) => JsonRpcResponse::error(id, -32000, format!("Update apply failed: {:#}", e)),
                }
            } else {
                JsonRpcResponse::error(id, -32000, "Update checker not initialized".to_string())
            }
        }

        "update.status" => {
            let uc = state.update_checker.read().await;
            if let Some(ref checker) = *uc {
                let updates = checker.get_status().await;
                JsonRpcResponse::success(id, serde_json::json!({"available_updates": updates}))
            } else {
                JsonRpcResponse::success(id, serde_json::json!({"available_updates": []}))
            }
        }

        // ─── Unknown ───────────────────────────────────────────────
        _ => JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", request.method),
        ),
    }
}
