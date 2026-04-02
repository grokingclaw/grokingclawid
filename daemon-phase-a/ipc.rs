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

use crate::daemon::DaemonState;

/// JSON-RPC 2.0 Request.
#[derive(Debug, Deserialize)]
pub struct JsonRpcRequest {
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
        // Daemon status
        "status" => {
            let agents = state.supervisor.list_agents().await;
            let info = serde_json::json!({
                "daemon": "running",
                "version": env!("CARGO_PKG_VERSION"),
                "agents_count": agents.len(),
                "agents": agents,
                "uptime_seconds": state.started_at.elapsed().as_secs(),
            });
            JsonRpcResponse::success(id, info)
        }

        // List agents
        "agents.list" => {
            let agents = state.supervisor.list_agents().await;
            JsonRpcResponse::success(id, serde_json::to_value(agents).unwrap_or_default())
        }

        // Get single agent
        "agents.get" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.get_agent(name).await {
                Some(info) => JsonRpcResponse::success(id, serde_json::to_value(info).unwrap_or_default()),
                None => JsonRpcResponse::error(id, -32001, format!("Agent '{}' not found", name)),
            }
        }

        // Birth (local, Phase A — no Naja/Morpheus)
        "birth" => {
            let template = request.params.get("template")
                .and_then(|v| v.as_str())
                .unwrap_or("").to_string();
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("").to_string();

            if template.is_empty() || name.is_empty() {
                return JsonRpcResponse::error(id, -32602, "Missing 'template' or 'name' parameter".to_string());
            }

            match state.birth_local(&template, &name, &request.params).await {
                Ok(info) => JsonRpcResponse::success(id, serde_json::to_value(info).unwrap_or_default()),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("Birth failed: {:#}", e)),
            }
        }

        // Start agent
        "agents.start" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.start_agent(name).await {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "started", "agent": name})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("{:#}", e)),
            }
        }

        // Stop agent
        "agents.stop" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.stop_agent(name).await {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "stopped", "agent": name})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("{:#}", e)),
            }
        }

        // Delete agent
        "agents.delete" => {
            let name = request.params.get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            match state.supervisor.delete_agent(name).await {
                Ok(()) => JsonRpcResponse::success(id, serde_json::json!({"status": "deleted", "agent": name})),
                Err(e) => JsonRpcResponse::error(id, -32000, format!("{:#}", e)),
            }
        }

        // Agent logs
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

        // Shutdown daemon
        "shutdown" => {
            tracing::info!("Shutdown requested via IPC");
            state.request_shutdown();
            JsonRpcResponse::success(id, serde_json::json!({"status": "shutting_down"}))
        }

        // Unknown method
        _ => JsonRpcResponse::error(
            id,
            -32601,
            format!("Method not found: {}", request.method),
        ),
    }
}
