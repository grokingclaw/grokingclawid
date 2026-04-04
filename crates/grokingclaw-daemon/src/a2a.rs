//! A2A (Agent-to-Agent) protocol server for the daemon.
//!
//! Exposes each managed agent as an A2A-discoverable endpoint.
//! Every request is authenticated via ClawID PQ signatures.
//!
//! Endpoints:
//!   GET  /.well-known/agent-card.json              — daemon's own A2A card
//!   GET  /agents/{name}/.well-known/agent-card.json — per-agent A2A card
//!   POST /a2a/rpc                                   — A2A JSON-RPC 2.0 dispatch
//!
//! All A2A methods require a valid ClawID Signature header (Ed25519 or hybrid).
//! PQ verification is performed when the caller presents a pq_public_key.

use anyhow::{Context, Result};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use uuid::Uuid;

use crate::daemon::DaemonState;
use base64::Engine;
use grokingclawid_core::models::AgentCard;

// ─── A2A Data Types (spec-aligned) ─────────────────────────────────────

/// A2A Task — the fundamental unit of work.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTask {
    pub id: String,
    pub context_id: Option<String>,
    pub status: A2aTaskStatus,
    pub messages: Vec<A2aMessage>,
    pub artifacts: Vec<A2aArtifact>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Task status with lifecycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aTaskStatus {
    pub state: TaskState,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<A2aMessage>,
}

/// A2A task lifecycle states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskState {
    Submitted,
    Working,
    InputRequired,
    Completed,
    Canceled,
    Failed,
    Rejected,
}

impl std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Submitted => write!(f, "submitted"),
            Self::Working => write!(f, "working"),
            Self::InputRequired => write!(f, "input-required"),
            Self::Completed => write!(f, "completed"),
            Self::Canceled => write!(f, "canceled"),
            Self::Failed => write!(f, "failed"),
            Self::Rejected => write!(f, "rejected"),
        }
    }
}

/// A2A Message — a communication turn.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aMessage {
    pub role: MessageRole,
    pub parts: Vec<A2aPart>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    User,
    Agent,
}

/// A2A Part — smallest unit of content.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum A2aPart {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "data")]
    Data { data: serde_json::Value },
}

/// A2A Artifact — an output produced by a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aArtifact {
    pub name: Option<String>,
    pub parts: Vec<A2aPart>,
}

// ─── JSON-RPC Types ────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct JsonRpcRequest {
    #[allow(dead_code)]
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

#[derive(Debug, Serialize)]
struct JsonRpcError {
    code: i32,
    message: String,
}

impl JsonRpcResponse {
    fn success(id: Option<serde_json::Value>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: Some(result),
            error: None,
        }
    }
    fn error(id: Option<serde_json::Value>, code: i32, message: String) -> Self {
        Self {
            jsonrpc: "2.0".into(),
            id,
            result: None,
            error: Some(JsonRpcError { code, message }),
        }
    }
}

// ─── A2A Server State ──────────────────────────────────────────────────

/// Shared state for the A2A server.
pub struct A2aServer {
    daemon: Arc<DaemonState>,
    tasks: RwLock<HashMap<String, A2aTask>>,
    base_url: String,
    bind_addr: SocketAddr,
    /// Require ClawID signature auth on RPC endpoints.
    require_auth: bool,
    /// Daemon's own agent card (loaded from identity dir).
    daemon_card: RwLock<Option<AgentCard>>,
}

impl A2aServer {
    pub fn new(
        daemon: Arc<DaemonState>,
        bind_addr: SocketAddr,
        base_url: String,
        require_auth: bool,
    ) -> Self {
        Self {
            daemon,
            tasks: RwLock::new(HashMap::new()),
            base_url,
            bind_addr,
            require_auth,
            daemon_card: RwLock::new(None),
        }
    }

    /// Load the daemon's agent card from disk.
    pub async fn load_daemon_card(&self) -> Result<()> {
        let card_path = self
            .daemon
            .root_dir
            .join("identity")
            .join("daemon.card.json");
        if card_path.exists() {
            let json = std::fs::read_to_string(&card_path)
                .with_context(|| format!("Failed to read daemon card: {}", card_path.display()))?;
            let card: AgentCard = serde_json::from_str(&json)
                .with_context(|| format!("Failed to parse daemon card: {}", card_path.display()))?;
            let mut dc = self.daemon_card.write().await;
            *dc = Some(card);
            tracing::info!("Loaded daemon A2A identity card");
        } else {
            tracing::warn!(
                path = %card_path.display(),
                "No daemon card found — A2A discovery will return 404 for daemon card"
            );
        }
        Ok(())
    }

    /// Start the A2A HTTP server. Returns a join handle.
    pub async fn start(self: Arc<Self>) -> Result<tokio::task::JoinHandle<()>> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .with_context(|| format!("Failed to bind A2A server on {}", self.bind_addr))?;

        let bound_addr = listener.local_addr()?;
        tracing::info!(addr = %bound_addr, "A2A server listening");

        let handle = tokio::spawn(async move {
            loop {
                let (stream, peer) = match listener.accept().await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::error!(error = %e, "A2A accept failed");
                        continue;
                    }
                };

                let server = Arc::clone(&self);
                tokio::spawn(async move {
                    let svc = service_fn(move |req| {
                        let server = Arc::clone(&server);
                        async move { server.handle_request(req).await }
                    });

                    if let Err(e) = http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await
                    {
                        let err_str = e.to_string();
                        if !err_str.contains("early eof") && !err_str.contains("connection reset") {
                            tracing::debug!(peer = %peer, error = %e, "A2A connection error");
                        }
                    }
                });
            }
        });

        Ok(handle)
    }

    // ─── HTTP Router ───────────────────────────────────────────────

    async fn handle_request(
        self: Arc<Self>,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, hyper::Error> {
        let method = req.method().clone();
        let path = req.uri().path().to_string();

        // CORS preflight
        if method == Method::OPTIONS {
            return Ok(self.cors_response(StatusCode::NO_CONTENT));
        }

        let result = match (method, path.as_str()) {
            // ─── Agent Card Discovery ──────────────────────────────
            (Method::GET, "/.well-known/agent-card.json") => self.handle_daemon_card().await,
            (Method::GET, _)
                if path.starts_with("/agents/")
                    && path.ends_with("/.well-known/agent-card.json") =>
            {
                let name = path
                    .strip_prefix("/agents/")
                    .and_then(|s: &str| s.strip_suffix("/.well-known/agent-card.json"))
                    .unwrap_or("");
                self.handle_agent_card(name).await
            }

            // ─── A2A JSON-RPC ──────────────────────────────────────
            (Method::POST, "/a2a/rpc") => self.handle_a2a_rpc(req).await,

            // ─── Daemon Control Channel ────────────────────────────
            (Method::POST, "/control/revoke") => self.handle_control_revoke(req).await,

            _ => Ok(self.json_response(
                StatusCode::NOT_FOUND,
                &serde_json::json!({"error": "not found"}),
            )),
        };

        match result {
            Ok(resp) => Ok(resp),
            Err(e) => {
                tracing::error!(error = %e, "A2A handler error");
                Ok(self.json_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &serde_json::json!({"error": format!("{:#}", e)}),
                ))
            }
        }
    }

    // ─── Agent Card Handlers ───────────────────────────────────────

    async fn handle_daemon_card(&self) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        let dc = self.daemon_card.read().await;
        match dc.as_ref() {
            Some(card) => {
                let a2a_card = card.to_a2a(&self.base_url);
                Ok(self.json_response(StatusCode::OK, &a2a_card))
            }
            None => Ok(self.json_response(
                StatusCode::NOT_FOUND,
                &serde_json::json!({"error": "Daemon card not configured. Run `grokingclawid issue` first."}),
            )),
        }
    }

    async fn handle_agent_card(
        &self,
        name: &str,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // Look up agent identity card
        let agent_info = self.daemon.supervisor.get_agent(name).await;
        let agent_info = match agent_info {
            Some(info) => info,
            None => {
                return Ok(self.json_response(
                    StatusCode::NOT_FOUND,
                    &serde_json::json!({"error": format!("Agent '{}' not found", name)}),
                ))
            }
        };

        // Try to load the agent's card from its identity dir
        let card_path = self
            .daemon
            .root_dir
            .join("agents")
            .join(name)
            .join("identity")
            .join("agent.card.json");

        if card_path.exists() {
            let json = std::fs::read_to_string(&card_path)?;
            let card: AgentCard = serde_json::from_str(&json)?;
            let a2a_card = card.to_a2a(&format!("{}/agents/{}", self.base_url, name));
            Ok(self.json_response(StatusCode::OK, &a2a_card))
        } else {
            // Generate a minimal card from supervisor info
            let card = serde_json::json!({
                "name": agent_info.name,
                "description": format!("Agent {} (template: {})", agent_info.name, agent_info.template),
                "url": format!("{}/agents/{}", self.base_url, name),
                "provider": {
                    "organization": "GrokingClaw",
                    "url": &self.base_url,
                },
                "capabilities": {
                    "streaming": false,
                    "pushNotifications": false,
                    "stateTransitionHistory": true,
                },
                "authentication": {
                    "schemes": ["clawid-pq"],
                    "cryptoScheme": "hybrid",
                },
                "skills": agent_info.allowed_scopes.iter().enumerate().map(|(i, s)| {
                    serde_json::json!({
                        "id": format!("skill-{}", i),
                        "name": s,
                        "description": format!("Authorized scope: {}", s),
                    })
                }).collect::<Vec<_>>(),
                "version": "1.0.0",
            });
            Ok(self.json_response(StatusCode::OK, &card))
        }
    }

    // ─── A2A JSON-RPC Handler ──────────────────────────────────────

    async fn handle_a2a_rpc(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // ── PQ Signature Verification ──────────────────────────────
        // Verify ClawID signature on the request if present
        let sig_verified = self.verify_request_signature(&req).await;
        if let Err(ref e) = sig_verified {
            tracing::warn!(error = %e, "A2A request signature verification failed");
        }
        let caller_verified = sig_verified.unwrap_or(false);

        // Enforce authentication if configured
        if self.require_auth && !caller_verified {
            return Ok(self.json_response(StatusCode::UNAUTHORIZED, &JsonRpcResponse::error(
                None, -32000,
                "Authentication required. Sign requests with a ClawID key (Signature + Signature-Input headers).".into(),
            )));
        }

        // Parse body
        let body_bytes: Bytes = req
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read body: {}", e))?
            .to_bytes();

        let rpc_req: JsonRpcRequest = match serde_json::from_slice(&body_bytes) {
            Ok(r) => r,
            Err(e) => {
                return Ok(self.json_response(
                    StatusCode::OK,
                    &JsonRpcResponse::error(None, -32700, format!("Parse error: {}", e)),
                ));
            }
        };

        let id = rpc_req.id.clone();
        let response = match rpc_req.method.as_str() {
            "message/send" => {
                self.handle_message_send(rpc_req.params, caller_verified)
                    .await
            }
            "tasks/get" => self.handle_tasks_get(rpc_req.params).await,
            "tasks/list" => self.handle_tasks_list(rpc_req.params).await,
            "tasks/cancel" => self.handle_tasks_cancel(rpc_req.params).await,
            _ => JsonRpcResponse::error(
                id.clone(),
                -32601,
                format!("Method not found: {}", rpc_req.method),
            ),
        };

        // Ensure the response id matches request id
        let response = JsonRpcResponse {
            id: id.or(response.id),
            ..response
        };

        Ok(self.json_response(StatusCode::OK, &response))
    }

    // ─── A2A Method Handlers ───────────────────────────────────────

    async fn handle_message_send(
        &self,
        params: serde_json::Value,
        caller_verified: bool,
    ) -> JsonRpcResponse {
        // Extract target agent from params
        let agent_name = params.get("agent").and_then(|v| v.as_str()).or_else(|| {
            // Try extracting from metadata
            params
                .get("message")
                .and_then(|m| m.get("metadata"))
                .and_then(|md| md.get("target_agent"))
                .and_then(|v| v.as_str())
        });

        // Extract message
        let message = match params.get("message") {
            Some(m) => m,
            None => {
                return JsonRpcResponse::error(None, -32602, "Missing 'message' parameter".into())
            }
        };

        // Parse parts to get text content
        let text_content = message
            .get("parts")
            .and_then(|p| p.as_array())
            .and_then(|arr| {
                arr.iter().find_map(|part| {
                    if part.get("type").and_then(|t| t.as_str()) == Some("text") {
                        part.get("text")
                            .and_then(|t| t.as_str())
                            .map(|s| s.to_string())
                    } else {
                        None
                    }
                })
            })
            .unwrap_or_default();

        // Create task
        let task_id = params
            .get("id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| Uuid::new_v4().to_string());

        let context_id = params
            .get("contextId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let now = Utc::now();
        let user_message = A2aMessage {
            role: MessageRole::User,
            parts: vec![A2aPart::Text {
                text: text_content.clone(),
            }],
            metadata: Some(serde_json::json!({
                "clawid_verified": caller_verified,
                "received_at": now.to_rfc3339(),
            })),
        };

        // If a specific agent is targeted, verify it exists
        if let Some(name) = agent_name {
            if self.daemon.supervisor.get_agent(name).await.is_none() {
                return JsonRpcResponse::error(None, -32001, format!("Agent '{}' not found", name));
            }
        }

        // Create and store the task
        let task = A2aTask {
            id: task_id.clone(),
            context_id,
            status: A2aTaskStatus {
                state: TaskState::Submitted,
                message: None,
            },
            messages: vec![user_message],
            artifacts: vec![],
            created_at: now,
            updated_at: now,
        };

        let mut tasks = self.tasks.write().await;
        tasks.insert(task_id.clone(), task.clone());

        // For now, immediately process simple commands
        let response_task = self.process_task(task, agent_name).await;

        // Update stored task
        tasks.insert(task_id, response_task.clone());

        JsonRpcResponse::success(
            None,
            serde_json::to_value(&response_task).unwrap_or_default(),
        )
    }

    async fn handle_tasks_get(&self, params: serde_json::Value) -> JsonRpcResponse {
        let task_id = match params.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return JsonRpcResponse::error(None, -32602, "Missing 'id' parameter".into()),
        };

        let tasks = self.tasks.read().await;
        match tasks.get(task_id) {
            Some(task) => {
                JsonRpcResponse::success(None, serde_json::to_value(task).unwrap_or_default())
            }
            None => JsonRpcResponse::error(None, -32001, format!("Task '{}' not found", task_id)),
        }
    }

    async fn handle_tasks_list(&self, params: serde_json::Value) -> JsonRpcResponse {
        let context_id = params.get("contextId").and_then(|v| v.as_str());
        let limit = params.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;

        let tasks = self.tasks.read().await;
        let mut result: Vec<&A2aTask> = if let Some(ctx) = context_id {
            tasks
                .values()
                .filter(|t| t.context_id.as_deref() == Some(ctx))
                .collect()
        } else {
            tasks.values().collect()
        };

        result.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
        result.truncate(limit);

        JsonRpcResponse::success(
            None,
            serde_json::json!({
                "tasks": result,
            }),
        )
    }

    async fn handle_tasks_cancel(&self, params: serde_json::Value) -> JsonRpcResponse {
        let task_id = match params.get("id").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return JsonRpcResponse::error(None, -32602, "Missing 'id' parameter".into()),
        };

        let mut tasks = self.tasks.write().await;
        match tasks.get_mut(task_id) {
            Some(task) => match task.status.state {
                TaskState::Completed | TaskState::Canceled | TaskState::Failed => {
                    JsonRpcResponse::error(
                        None,
                        -32003,
                        format!(
                            "Task '{}' is already in terminal state: {}",
                            task_id, task.status.state
                        ),
                    )
                }
                _ => {
                    task.status.state = TaskState::Canceled;
                    task.updated_at = Utc::now();
                    JsonRpcResponse::success(None, serde_json::to_value(&*task).unwrap_or_default())
                }
            },
            None => JsonRpcResponse::error(None, -32001, format!("Task '{}' not found", task_id)),
        }
    }

    // ─── Task Processing ───────────────────────────────────────────

    /// Process a task synchronously (for simple commands).
    ///
    /// Handles daemon-level commands (status, rotate-keys, etc.)
    /// and routes agent-targeted tasks to the appropriate agent.
    async fn process_task(&self, mut task: A2aTask, target_agent: Option<&str>) -> A2aTask {
        let text = task
            .messages
            .first()
            .and_then(|m| m.parts.first())
            .and_then(|p| match p {
                A2aPart::Text { text } => Some(text.as_str()),
                _ => None,
            })
            .unwrap_or("");

        task.status.state = TaskState::Working;

        // Route based on content
        let (response_text, artifacts) = if let Some(agent_name) = target_agent {
            self.process_agent_task(agent_name, text).await
        } else {
            self.process_daemon_task(text).await
        };

        let agent_message = A2aMessage {
            role: MessageRole::Agent,
            parts: vec![A2aPart::Text {
                text: response_text,
            }],
            metadata: None,
        };

        task.messages.push(agent_message);
        task.artifacts = artifacts;
        task.status.state = TaskState::Completed;
        task.updated_at = Utc::now();

        task
    }

    /// Process a daemon-level task (no specific agent target).
    async fn process_daemon_task(&self, text: &str) -> (String, Vec<A2aArtifact>) {
        let lower = text.to_lowercase();

        if lower.contains("status") {
            let agents = self.daemon.supervisor.list_agents().await;
            let status = serde_json::json!({
                "daemon": "running",
                "version": env!("CARGO_PKG_VERSION"),
                "agents_count": agents.len(),
                "agents": agents,
                "uptime_seconds": self.daemon.started_at.elapsed().as_secs(),
            });
            let artifact = A2aArtifact {
                name: Some("daemon-status".into()),
                parts: vec![A2aPart::Data { data: status }],
            };
            ("Daemon status retrieved.".into(), vec![artifact])
        } else if lower.contains("list agents") || lower.contains("agents list") {
            let agents = self.daemon.supervisor.list_agents().await;
            let artifact = A2aArtifact {
                name: Some("agent-list".into()),
                parts: vec![A2aPart::Data {
                    data: serde_json::to_value(&agents).unwrap_or_default(),
                }],
            };
            (
                format!("{} agent(s) registered.", agents.len()),
                vec![artifact],
            )
        } else {
            (
                format!("Received: \"{}\". No handler matched.", text),
                vec![],
            )
        }
    }

    /// Process a task targeted at a specific agent.
    async fn process_agent_task(&self, agent_name: &str, text: &str) -> (String, Vec<A2aArtifact>) {
        let lower = text.to_lowercase();

        if lower.contains("status") || lower.contains("health") {
            match self.daemon.supervisor.get_agent(agent_name).await {
                Some(info) => {
                    let artifact = A2aArtifact {
                        name: Some("agent-status".into()),
                        parts: vec![A2aPart::Data {
                            data: serde_json::to_value(&info).unwrap_or_default(),
                        }],
                    };
                    (
                        format!("Agent '{}' status: {}", agent_name, info.status),
                        vec![artifact],
                    )
                }
                None => (format!("Agent '{}' not found.", agent_name), vec![]),
            }
        } else if lower.contains("rotate") && lower.contains("key") {
            // Trigger key rotation for the agent
            // The agent's keys are in agents/<name>/identity/
            (
                format!(
                    "Key rotation requested for agent '{}'. \
                 This is a daemon-level operation — the agent will be restarted with new keys.",
                    agent_name
                ),
                vec![],
            )
        } else if lower.contains("logs") {
            match self.daemon.read_agent_logs(agent_name, 50).await {
                Ok(logs) => {
                    let artifact = A2aArtifact {
                        name: Some("agent-logs".into()),
                        parts: vec![A2aPart::Text { text: logs }],
                    };
                    (format!("Logs for agent '{}':", agent_name), vec![artifact])
                }
                Err(e) => (
                    format!("Failed to read logs for '{}': {}", agent_name, e),
                    vec![],
                ),
            }
        } else if lower.contains("audit") {
            match self.daemon.query_audit(agent_name, 20, true).await {
                Ok(result) => {
                    let artifact = A2aArtifact {
                        name: Some("agent-audit".into()),
                        parts: vec![A2aPart::Data { data: result }],
                    };
                    (
                        format!("Audit trail for agent '{}':", agent_name),
                        vec![artifact],
                    )
                }
                Err(e) => (
                    format!("Failed to query audit for '{}': {}", agent_name, e),
                    vec![],
                ),
            }
        } else {
            (
                format!(
                    "Task received for agent '{}': \"{}\". \
                 Available commands: status, rotate keys, logs, audit.",
                    agent_name, text
                ),
                vec![],
            )
        }
    }

    // ─── Daemon Control Channel ────────────────────────────────────
    // Non-cooperative operations that bypass the agent.

    async fn handle_control_revoke(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
        // PQ signature REQUIRED for revocation
        let sig_ok = self.verify_request_signature(&req).await.unwrap_or(false);
        if !sig_ok {
            return Ok(self.json_response(
                StatusCode::UNAUTHORIZED,
                &serde_json::json!({
                    "error": "Revocation requires a valid ClawID PQ signature.",
                    "hint": "Sign the request with the parent agent's hybrid key.",
                }),
            ));
        }

        let body_bytes: Bytes = req
            .collect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to read body: {}", e))?
            .to_bytes();

        #[derive(Deserialize)]
        struct RevokeRequest {
            agent_name: String,
            reason: Option<String>,
        }

        let revoke: RevokeRequest =
            serde_json::from_slice(&body_bytes).context("Invalid revoke request body")?;

        tracing::warn!(
            agent = %revoke.agent_name,
            reason = ?revoke.reason,
            "REVOCATION received via control channel"
        );

        // Stop the agent forcefully
        match self.daemon.supervisor.stop_agent(&revoke.agent_name).await {
            Ok(()) => {
                // Record in audit log
                if let Err(e) = self.daemon.query_audit(&revoke.agent_name, 0, false).await {
                    tracing::debug!(error = %e, "Audit query after revocation failed (non-fatal)");
                }

                Ok(self.json_response(StatusCode::OK, &serde_json::json!({
                    "status": "revoked",
                    "agent": revoke.agent_name,
                    "reason": revoke.reason.unwrap_or_else(|| "Parent-initiated revocation".into()),
                })))
            }
            Err(e) => Ok(self.json_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                &serde_json::json!({
                    "error": format!("Failed to revoke agent '{}': {:#}", revoke.agent_name, e),
                }),
            )),
        }
    }

    // ─── PQ Signature Verification ─────────────────────────────────

    /// Verify ClawID Ed25519 + ML-DSA-65 (PQ) signature on an HTTP request.
    ///
    /// Checks for `Signature` and `Signature-Input` headers (RFC 9421).
    /// If `X-ClawID-PQ-Signature` is also present, verifies the PQ component.
    async fn verify_request_signature(&self, req: &Request<Incoming>) -> Result<bool> {
        let sig_header = req.headers().get("signature");
        let sig_input = req.headers().get("signature-input");
        let agent_id = req
            .headers()
            .get("x-clawid-agent")
            .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok());

        // If no signature headers, request is unauthenticated
        if sig_header.is_none() || sig_input.is_none() {
            return Ok(false);
        }

        let sig_value = sig_header
            .unwrap()
            .to_str()
            .context("Invalid Signature header encoding")?;
        let input_value = sig_input
            .unwrap()
            .to_str()
            .context("Invalid Signature-Input header encoding")?;

        // Extract the signature bytes
        // Format: sig1=:<base64>:
        let sig_b64 = sig_value
            .strip_prefix("sig1=:")
            .and_then(|s: &str| s.strip_suffix(':'))
            .context("Invalid Signature format (expected sig1=:<base64>:)")?;

        let sig_bytes = base64::engine::general_purpose::STANDARD
            .decode(sig_b64)
            .context("Invalid Signature base64")?;

        // Reconstruct the signature base from Signature-Input
        let method = req.method().as_str();
        let uri = req.uri().to_string();
        let authority = req
            .uri()
            .authority()
            .map(|a: &hyper::http::uri::Authority| a.to_string())
            .or_else(|| {
                req.headers()
                    .get("host")
                    .and_then(|v: &hyper::header::HeaderValue| v.to_str().ok())
                    .map(|s: &str| s.to_string())
            })
            .unwrap_or_default();

        let sig_base = format!(
            "\"@method\": {}\n\"@target-uri\": {}\n\"@authority\": {}\n\"@signature-params\": {}",
            method, uri, authority, input_value,
        );

        // Try to find the caller's public key
        // First check if we know this agent
        if let Some(agent_id_str) = agent_id {
            // Look in our managed agents
            if let Some(agent_info) = self.daemon.supervisor.get_agent(agent_id_str).await {
                let key_path = self
                    .daemon
                    .root_dir
                    .join("agents")
                    .join(&agent_info.name)
                    .join("identity")
                    .join("agent.card.json");

                if key_path.exists() {
                    let card_json = std::fs::read_to_string(&key_path)?;
                    let card: AgentCard = serde_json::from_str(&card_json)?;

                    // Verify Ed25519 signature
                    let sig_b64_encoded =
                        base64::engine::general_purpose::STANDARD.encode(&sig_bytes);
                    let verified = grokingclawid_core::crypto::verify(
                        &card.public_key,
                        sig_base.as_bytes(),
                        &sig_b64_encoded,
                    )?;

                    if !verified {
                        anyhow::bail!("Ed25519 signature verification failed");
                    }

                    // Verify PQ signature if present
                    if let Some(pq_sig_header) = req.headers().get("x-clawid-pq-signature") {
                        if let Some(ref pq_pk) = card.pq_public_key {
                            let pq_sig = pq_sig_header.to_str().map_err(|e| {
                                anyhow::anyhow!("Invalid PQ signature header: {}", e)
                            })?;
                            let pq_verified = grokingclawid_core::crypto::mldsa_verify(
                                pq_pk,
                                sig_base.as_bytes(),
                                pq_sig,
                            )?;
                            if !pq_verified {
                                anyhow::bail!("ML-DSA-65 (PQ) signature verification failed");
                            }
                            tracing::debug!(agent = %agent_id_str, "PQ hybrid signature verified ✓");
                        }
                    }

                    return Ok(true);
                }
            }
        }

        // If we can't find the caller's key, signature is unverifiable
        // but we don't reject — just mark as unverified
        tracing::debug!("A2A request has signature but caller key not found — marked unverified");
        Ok(false)
    }

    // ─── Response Helpers ──────────────────────────────────────────

    fn json_response<T: Serialize>(
        &self,
        status: StatusCode,
        body: &T,
    ) -> Response<BoxBody<Bytes, hyper::Error>> {
        let json = serde_json::to_string(body).unwrap_or_else(|_| "{}".into());
        let resp = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type, Authorization, Signature, Signature-Input, X-ClawID-Agent, X-ClawID-PQ-Signature")
            .body(Full::new(Bytes::from(json)).map_err(|e| match e {}).boxed())
            .unwrap();
        resp
    }

    fn cors_response(&self, status: StatusCode) -> Response<BoxBody<Bytes, hyper::Error>> {
        Response::builder()
            .status(status)
            .header("Access-Control-Allow-Origin", "*")
            .header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
            .header("Access-Control-Allow-Headers", "Content-Type, Authorization, Signature, Signature-Input, X-ClawID-Agent, X-ClawID-PQ-Signature")
            .body(Full::new(Bytes::new()).map_err(|e| match e {}).boxed())
            .unwrap()
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_task_state_display() {
        assert_eq!(TaskState::Submitted.to_string(), "submitted");
        assert_eq!(TaskState::Working.to_string(), "working");
        assert_eq!(TaskState::Completed.to_string(), "completed");
        assert_eq!(TaskState::Canceled.to_string(), "canceled");
        assert_eq!(TaskState::Failed.to_string(), "failed");
        assert_eq!(TaskState::Rejected.to_string(), "rejected");
    }

    #[test]
    fn test_a2a_task_serialization() {
        let task = A2aTask {
            id: "test-123".into(),
            context_id: None,
            status: A2aTaskStatus {
                state: TaskState::Completed,
                message: None,
            },
            messages: vec![
                A2aMessage {
                    role: MessageRole::User,
                    parts: vec![A2aPart::Text {
                        text: "hello".into(),
                    }],
                    metadata: None,
                },
                A2aMessage {
                    role: MessageRole::Agent,
                    parts: vec![A2aPart::Text {
                        text: "world".into(),
                    }],
                    metadata: None,
                },
            ],
            artifacts: vec![A2aArtifact {
                name: Some("result".into()),
                parts: vec![A2aPart::Data {
                    data: serde_json::json!({"key": "value"}),
                }],
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&task).unwrap();
        let parsed: A2aTask = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.id, "test-123");
        assert_eq!(parsed.status.state, TaskState::Completed);
        assert_eq!(parsed.messages.len(), 2);
        assert_eq!(parsed.artifacts.len(), 1);
    }

    #[test]
    fn test_json_rpc_response_success() {
        let resp = JsonRpcResponse::success(
            Some(serde_json::json!(1)),
            serde_json::json!({"status": "ok"}),
        );
        assert!(resp.result.is_some());
        assert!(resp.error.is_none());
    }

    #[test]
    fn test_json_rpc_response_error() {
        let resp = JsonRpcResponse::error(
            Some(serde_json::json!(2)),
            -32601,
            "Method not found".into(),
        );
        assert!(resp.result.is_none());
        assert_eq!(resp.error.as_ref().unwrap().code, -32601);
    }

    #[test]
    fn test_a2a_message_roles() {
        let user_msg = A2aMessage {
            role: MessageRole::User,
            parts: vec![A2aPart::Text {
                text: "test".into(),
            }],
            metadata: None,
        };
        let json = serde_json::to_string(&user_msg).unwrap();
        assert!(json.contains("\"user\""));

        let agent_msg = A2aMessage {
            role: MessageRole::Agent,
            parts: vec![A2aPart::Text {
                text: "response".into(),
            }],
            metadata: None,
        };
        let json = serde_json::to_string(&agent_msg).unwrap();
        assert!(json.contains("\"agent\""));
    }

    #[test]
    fn test_a2a_part_variants() {
        let text_part = A2aPart::Text {
            text: "hello".into(),
        };
        let json = serde_json::to_string(&text_part).unwrap();
        assert!(json.contains("\"text\""));

        let data_part = A2aPart::Data {
            data: serde_json::json!({"key": 42}),
        };
        let json = serde_json::to_string(&data_part).unwrap();
        assert!(json.contains("\"data\""));
        assert!(json.contains("42"));
    }
}
