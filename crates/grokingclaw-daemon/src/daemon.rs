//! Core daemon logic — state management, main loop, birth integration.
//!
//! The daemon manages agent lifecycles, handles IPC requests,
//! and runs health checks on a timer.

use anyhow::{Context, Result};
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;

use crate::anchor::AnchorWorker;
use crate::birth::{self, BirthParams, BirthResult};
use crate::config::DaemonConfig;
use crate::mesh::MeshClient;
use crate::supervisor::Supervisor;
use crate::templates::TemplateRegistry;
use crate::updates::UpdateChecker;
use grokingclawid_core::license;

/// Shared daemon state accessible from IPC handlers and the main loop.
pub struct DaemonState {
    pub config: DaemonConfig,
    pub supervisor: Supervisor,
    pub started_at: Instant,
    pub root_dir: PathBuf,
    pub templates: Arc<TemplateRegistry>,
    pub mesh: Option<Arc<MeshClient>>,
    pub anchor_worker: RwLock<Option<Arc<AnchorWorker>>>,
    pub update_checker: RwLock<Option<Arc<UpdateChecker>>>,
    shutdown: AtomicBool,
}

impl DaemonState {
    pub fn new(
        config: DaemonConfig,
        root_dir: PathBuf,
        templates: Arc<TemplateRegistry>,
        mesh: Option<Arc<MeshClient>>,
    ) -> Self {
        let agents_dir = root_dir.join("agents");
        Self {
            config,
            supervisor: Supervisor::new(agents_dir),
            started_at: Instant::now(),
            root_dir,
            templates,
            mesh,
            anchor_worker: RwLock::new(None),
            update_checker: RwLock::new(None),
            shutdown: AtomicBool::new(false),
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn should_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Birth a new agent using the birth protocol.
    ///
    /// Delegates to birth::birth_agent which handles mesh vs local birth.
    /// Enforces license limits before allowing agent creation.
    pub async fn birth_agent(&self, params: BirthParams) -> Result<BirthResult> {
        // Check if agent already exists
        if self.supervisor.get_agent(&params.name).await.is_some() {
            anyhow::bail!("Agent '{}' already exists", params.name);
        }

        // ── License enforcement ──────────────────────────────────────
        let lic = license::load_license();
        let current_agents = self.supervisor.list_agents().await.len() as u32;
        license::check_limit("agents", current_agents, &lic)?;

        // Check agent limit from daemon config too
        let current_count = self.supervisor.list_agents().await.len();
        if current_count >= self.config.resources.max_agents as usize {
            anyhow::bail!(
                "Agent limit reached ({}/{}). Increase max_agents in daemon.toml.",
                current_count,
                self.config.resources.max_agents
            );
        }

        // Perform birth (mesh or local)
        let mesh_ref = self.mesh.as_deref();
        let result = birth::birth_agent(
            &self.config,
            &self.root_dir,
            mesh_ref,
            &self.templates,
            params,
        )
        .await?;

        // Register agent with supervisor (loads agent.toml that was created during birth)
        let agent_dir = self.root_dir.join("agents").join(&result.agent_info.name);
        let config_path = agent_dir.join("agent.toml");
        if config_path.exists() {
            let content = std::fs::read_to_string(&config_path)?;
            let agent_config: crate::supervisor::AgentConfig = toml::from_str(&content)
                .context("Failed to parse agent config created by birth")?;
            self.supervisor.register(agent_config).await?;
        }

        Ok(result)
    }

    /// Read the last N lines of an agent's logs.
    pub async fn read_agent_logs(&self, name: &str, lines: usize) -> Result<String> {
        let log_path = self
            .root_dir
            .join("agents")
            .join(name)
            .join("logs")
            .join("stdout.log");
        if !log_path.exists() {
            return Ok(String::new());
        }

        let content = std::fs::read_to_string(&log_path)?;
        let all_lines: Vec<&str> = content.lines().collect();
        let start = if all_lines.len() > lines {
            all_lines.len() - lines
        } else {
            0
        };
        Ok(all_lines[start..].join("\n"))
    }

    /// Query audit entries for an agent.
    pub async fn query_audit(&self, agent_name: &str, last: u64, verify: bool) -> Result<Value> {
        let audit_db_path = self
            .root_dir
            .join("agents")
            .join(agent_name)
            .join("audit")
            .join("audit.db");

        if !audit_db_path.exists() {
            return Ok(serde_json::json!({
                "entries": [],
                "message": "No audit database found for this agent"
            }));
        }

        let conn = grokingclawid_core::audit::open_db_at(&audit_db_path)?;

        // Query entries for this agent
        let agent_info = self.supervisor.get_agent(agent_name).await;
        let agent_id_str = agent_info.as_ref().map(|a| a.agent_id.to_string());

        let entries =
            grokingclawid_core::audit::query_entries(&conn, agent_id_str.as_deref(), None)?;

        // Take last N entries
        let start = if entries.len() > last as usize {
            entries.len() - last as usize
        } else {
            0
        };
        let recent = &entries[start..];

        let mut result = serde_json::json!({
            "entries": recent,
            "total": entries.len(),
        });

        // Verify chain if requested
        if verify {
            let valid = verify_chain(&entries);
            result["chain_valid"] = serde_json::json!(valid);
        }

        Ok(result)
    }

    // ─── OAuth 2.0 Bridge Methods ──────────────────────────────────────

    /// Helper: load an agent's OAuth store (encrypted).
    fn load_oauth_store(&self, agent_name: &str) -> Result<(crate::oauth_store::OAuthStore, std::path::PathBuf, ed25519_dalek::SigningKey)> {
        let agent_dir = self.root_dir.join("agents").join(agent_name);
        let key_path = agent_dir.join("identity").join("agent.pem");
        if !key_path.exists() {
            anyhow::bail!("Agent '{}' identity not found", agent_name);
        }
        let pem = std::fs::read_to_string(&key_path)
            .with_context(|| format!("Failed to read key: {}", key_path.display()))?;
        let signing_key = grokingclawid_core::crypto::decode_private_key_pem(&pem)?;
        let store_path = crate::oauth_store::OAuthStore::store_path(&agent_dir);
        let store = crate::oauth_store::OAuthStore::load(&store_path, &signing_key)?;
        Ok((store, store_path, signing_key))
    }

    /// Helper: save an agent's OAuth store.
    fn save_oauth_store(&self, store: &crate::oauth_store::OAuthStore, store_path: &std::path::Path, signing_key: &ed25519_dalek::SigningKey) -> Result<()> {
        store.save(store_path, signing_key)
    }

    /// Register an OAuth provider for an agent.
    pub async fn oauth_register(&self, agent_name: &str, params: &serde_json::Value) -> Result<serde_json::Value> {
        let (mut store, store_path, signing_key) = self.load_oauth_store(agent_name)?;

        let reg = crate::oauth_store::OAuthRegistration {
            id: params.get("registration_id").and_then(|v| v.as_str())
                .unwrap_or(&uuid::Uuid::new_v4().to_string()).to_string(),
            provider: params.get("provider").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            client_id: params.get("client_id").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            client_secret: params.get("client_secret").and_then(|v| v.as_str()).map(String::from),
            authorization_url: params.get("authorization_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            token_url: params.get("token_url").and_then(|v| v.as_str()).unwrap_or("").to_string(),
            revocation_url: params.get("revocation_url").and_then(|v| v.as_str()).map(String::from),
            device_authorization_url: params.get("device_authorization_url").and_then(|v| v.as_str()).map(String::from),
            scopes: params.get("scopes").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            domain_bindings: params.get("domain_bindings").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect())
                .unwrap_or_default(),
            grant_type: params.get("grant_type").and_then(|v| v.as_str()).unwrap_or("authorization_code").to_string(),
            created_at: chrono::Utc::now(),
            parent_registration_id: params.get("parent_registration_id").and_then(|v| v.as_str()).map(String::from),
            max_scopes: params.get("max_scopes").and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|s| s.as_str().map(String::from)).collect()),
        };

        let reg_id = reg.id.clone();
        store.register_provider(reg)?;
        self.save_oauth_store(&store, &store_path, &signing_key)?;

        Ok(serde_json::json!({ "ok": true, "registration_id": reg_id }))
    }

    /// Start an OAuth authorization flow for an agent.
    pub async fn oauth_authorize(&self, agent_name: &str, registration_id: &str) -> Result<serde_json::Value> {
        let (store, _, _) = self.load_oauth_store(agent_name)?;
        let reg = store.get_registration(registration_id)
            .ok_or_else(|| anyhow::anyhow!("Registration '{}' not found", registration_id))?;

        match reg.grant_type.as_str() {
            "device_code" => {
                let pending = crate::oauth_flow::start_device_auth(reg).await?;
                Ok(serde_json::to_value(pending)?)
            }
            "client_credentials" => {
                let tokens = crate::oauth_flow::client_credentials(reg).await?;
                let (mut store, store_path, signing_key) = self.load_oauth_store(agent_name)?;
                store.store_tokens(tokens)?;
                self.save_oauth_store(&store, &store_path, &signing_key)?;
                Ok(serde_json::json!({ "ok": true, "status": "tokens_acquired" }))
            }
            "authorization_code" => {
                let redirect_uri = format!("http://localhost:{}/oauth/callback", self.config.oauth.callback_port);
                let start = crate::oauth_flow::start_auth_code_flow(reg, &redirect_uri)?;
                Ok(serde_json::to_value(start)?)
            }
            other => anyhow::bail!("Unsupported grant type: {}", other),
        }
    }

    /// Complete an authorization code exchange.
    pub async fn oauth_callback(&self, agent_name: &str, registration_id: &str, code: &str, code_verifier: &str, redirect_uri: &str) -> Result<serde_json::Value> {
        let (mut store, store_path, signing_key) = self.load_oauth_store(agent_name)?;
        let reg = store.get_registration(registration_id)
            .ok_or_else(|| anyhow::anyhow!("Registration '{}' not found", registration_id))?
            .clone();

        let tokens = crate::oauth_flow::exchange_auth_code(&reg, code, redirect_uri, code_verifier).await?;
        store.store_tokens(tokens)?;
        self.save_oauth_store(&store, &store_path, &signing_key)?;

        Ok(serde_json::json!({ "ok": true, "status": "tokens_stored" }))
    }

    /// Refresh an OAuth token for an agent.
    pub async fn oauth_refresh(&self, agent_name: &str, registration_id: &str) -> Result<serde_json::Value> {
        let (mut store, store_path, signing_key) = self.load_oauth_store(agent_name)?;
        let reg = store.get_registration(registration_id)
            .ok_or_else(|| anyhow::anyhow!("Registration '{}' not found", registration_id))?
            .clone();
        let existing = store.get_tokens(registration_id)
            .ok_or_else(|| anyhow::anyhow!("No tokens found for registration '{}'", registration_id))?;
        let refresh_token_value = existing.refresh_token.clone()
            .ok_or_else(|| anyhow::anyhow!("No refresh token available for '{}'", registration_id))?;

        let new_tokens = crate::oauth_flow::refresh_token(&reg, &refresh_token_value).await?;

        // Return the cached token format for the proxy
        let cached = grokingclaw_proxy::oauth::CachedOAuthToken {
            access_token: new_tokens.access_token.clone(),
            expires_at: new_tokens.expires_at.timestamp(),
            scopes: new_tokens.granted_scopes.clone(),
            provider: reg.provider.clone(),
            registration_id: registration_id.to_string(),
        };

        store.store_tokens(new_tokens)?;
        self.save_oauth_store(&store, &store_path, &signing_key)?;

        Ok(serde_json::to_value(cached)?)
    }

    /// Revoke OAuth tokens and remove registration.
    pub async fn oauth_revoke(&self, agent_name: &str, registration_id: &str) -> Result<serde_json::Value> {
        let (mut store, store_path, signing_key) = self.load_oauth_store(agent_name)?;
        let reg = store.get_registration(registration_id)
            .ok_or_else(|| anyhow::anyhow!("Registration '{}' not found", registration_id))?
            .clone();

        // Revoke at provider if endpoint available
        if let Some(tokens) = store.get_tokens(registration_id) {
            // Try revoking refresh token first, then access token
            if let Some(ref rt) = tokens.refresh_token {
                let _ = crate::oauth_flow::revoke_token(&reg, rt, "refresh_token").await;
            }
            let _ = crate::oauth_flow::revoke_token(&reg, &tokens.access_token, "access_token").await;
        }

        // Cascade remove child delegations
        store.cascade_remove(registration_id);
        // Remove the registration itself
        store.remove_registration(registration_id)?;
        self.save_oauth_store(&store, &store_path, &signing_key)?;

        Ok(serde_json::json!({ "ok": true, "revoked": registration_id }))
    }

    /// List all OAuth registrations for an agent.
    pub async fn oauth_list(&self, agent_name: &str) -> Result<serde_json::Value> {
        let (store, _, _) = self.load_oauth_store(agent_name)?;
        let regs: Vec<serde_json::Value> = store.registrations.iter().map(|r| {
            let has_tokens = store.get_tokens(&r.id).is_some();
            let token_status = store.get_tokens(&r.id).map(|t| {
                if t.expires_at < chrono::Utc::now() { "expired" } else { "valid" }
            }).unwrap_or("missing");
            serde_json::json!({
                "id": r.id,
                "provider": r.provider,
                "grant_type": r.grant_type,
                "scopes": r.scopes,
                "domain_bindings": r.domain_bindings,
                "has_tokens": has_tokens,
                "token_status": token_status,
            })
        }).collect();

        Ok(serde_json::json!({ "registrations": regs }))
    }

    /// Get OAuth token status for an agent.
    pub async fn oauth_status(&self, agent_name: &str, registration_id: Option<&str>) -> Result<serde_json::Value> {
        let (store, _, _) = self.load_oauth_store(agent_name)?;

        if let Some(reg_id) = registration_id {
            let reg = store.get_registration(reg_id)
                .ok_or_else(|| anyhow::anyhow!("Registration '{}' not found", reg_id))?;
            let tokens = store.get_tokens(reg_id);
            let status = match tokens {
                Some(t) if t.expires_at > chrono::Utc::now() => "valid",
                Some(_) => "expired",
                None => "missing",
            };
            Ok(serde_json::json!({
                "registration_id": reg_id,
                "provider": reg.provider,
                "status": status,
                "expires_at": tokens.map(|t| t.expires_at.to_rfc3339()),
            }))
        } else {
            self.oauth_list(agent_name).await
        }
    }

    /// RFC 8693 token exchange: ClawID identity → OAuth token.
    pub async fn oauth_exchange(&self, agent_name: &str, registration_id: &str) -> Result<serde_json::Value> {
        let (mut store, store_path, signing_key) = self.load_oauth_store(agent_name)?;
        let reg = store.get_registration(registration_id)
            .ok_or_else(|| anyhow::anyhow!("Registration '{}' not found", registration_id))?
            .clone();

        // Load agent card for the assertion
        let agent_dir = self.root_dir.join("agents").join(agent_name);
        let card_path = agent_dir.join("identity").join("agent-card.json");
        let card_json = std::fs::read_to_string(&card_path)
            .context("Failed to read agent card")?;

        // Create signed assertion (sign the card JSON with agent's key)
        let signed_assertion = grokingclawid_core::crypto::sign(&signing_key, card_json.as_bytes());

        let tokens = crate::oauth_flow::clawid_token_exchange(&reg, &card_json, &signed_assertion, None).await?;
        store.store_tokens(tokens)?;
        self.save_oauth_store(&store, &store_path, &signing_key)?;

        Ok(serde_json::json!({ "ok": true, "status": "token_exchanged" }))
    }
}

/// Verify the audit hash chain integrity.
fn verify_chain(entries: &[grokingclawid_core::models::AuditEntry]) -> bool {
    if entries.is_empty() {
        return true;
    }

    // Check first entry has "genesis" as prev_hash
    if entries[0].prev_hash != "genesis" {
        return false;
    }

    // Check each entry's hash chains correctly
    for i in 1..entries.len() {
        if entries[i].prev_hash != entries[i - 1].entry_hash {
            return false;
        }

        // Verify the hash itself
        let expected = grokingclawid_core::crypto::compute_chain_hash(
            &entries[i].prev_hash,
            &entries[i].agent_id.to_string(),
            &entries[i].action,
            &entries[i].target,
            entries[i].timestamp,
        );

        if entries[i].entry_hash != expected {
            return false;
        }
    }

    true
}

/// Write PID file.
pub fn write_pid_file(path: &std::path::Path) -> Result<()> {
    let pid = std::process::id();
    std::fs::write(path, pid.to_string())
        .with_context(|| format!("Failed to write PID file: {}", path.display()))?;
    Ok(())
}

/// Remove PID file.
pub fn remove_pid_file(path: &std::path::Path) {
    let _ = std::fs::remove_file(path);
}

/// Check if daemon is already running by checking PID file.
pub fn check_already_running(path: &std::path::Path) -> Result<Option<u32>> {
    if !path.exists() {
        return Ok(None);
    }

    let pid_str = std::fs::read_to_string(path)?;
    let pid: u32 = pid_str.trim().parse().context("Invalid PID in file")?;

    // Check if process is alive (signal 0 = existence check)
    #[cfg(unix)]
    {
        // SAFETY: libc::kill with signal 0 is a standard POSIX process existence check.
        // Returns 0 if process exists and we have permission, or -1 with errno.
        let ret = unsafe { libc::kill(pid as i32, 0) };
        if ret == 0 {
            return Ok(Some(pid));
        }
        // EPERM means process exists but we lack permission — still alive
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EPERM {
            return Ok(Some(pid));
        }
        // ESRCH or other error — process is gone
    }

    // Stale PID file
    let _ = std::fs::remove_file(path);
    Ok(None)
}
