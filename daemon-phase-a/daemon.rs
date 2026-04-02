//! Core daemon logic — state management, main loop, local birth.
//!
//! The daemon manages agent lifecycles, handles IPC requests,
//! and runs health checks on a timer.

use anyhow::{Context, Result};
use chrono::Utc;
use serde_json::Value;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;
use uuid::Uuid;

use crate::config::{daemon_root, DaemonConfig};
use crate::supervisor::{AgentConfig, AgentInfo, ModelConfig, ResourceConfig, RestartConfig, Supervisor};

/// Shared daemon state accessible from IPC handlers and the main loop.
pub struct DaemonState {
    pub config: DaemonConfig,
    pub supervisor: Supervisor,
    pub started_at: Instant,
    pub root_dir: PathBuf,
    shutdown: AtomicBool,
}

impl DaemonState {
    pub fn new(config: DaemonConfig, root_dir: PathBuf) -> Self {
        let agents_dir = root_dir.join("agents");
        Self {
            config,
            supervisor: Supervisor::new(agents_dir),
            started_at: Instant::now(),
            root_dir,
            shutdown: AtomicBool::new(false),
        }
    }

    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    pub fn should_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Local birth — Phase A version (no Naja/Morpheus, issues identity locally).
    ///
    /// In Phase C, this will be replaced by the full birth protocol
    /// that communicates with Naja and Morpheus over the mesh.
    pub async fn birth_local(
        &self,
        template: &str,
        name: &str,
        params: &Value,
    ) -> Result<AgentInfo> {
        // Check if agent already exists
        if self.supervisor.get_agent(name).await.is_some() {
            anyhow::bail!("Agent '{}' already exists", name);
        }

        // Check agent limit
        let current_count = self.supervisor.list_agents().await.len();
        if current_count >= self.config.resources.max_agents as usize {
            anyhow::bail!(
                "Agent limit reached ({}/{}). Increase max_agents in daemon.toml.",
                current_count,
                self.config.resources.max_agents
            );
        }

        // Parse scope from params
        let allowed_domains: Vec<String> = params.get("scope")
            .and_then(|s| s.get("allowed_domains"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        let allowed_scopes: Vec<String> = params.get("scope")
            .and_then(|s| s.get("allowed_scopes"))
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_else(|| vec!["*".to_string()]);

        let ttl_seconds: i64 = params.get("scope")
            .and_then(|s| s.get("ttl_seconds"))
            .and_then(|v| v.as_i64())
            .unwrap_or(30 * 24 * 3600); // 30 days default

        // Parse model from params
        let model = params.get("model")
            .and_then(|v| serde_json::from_value::<ModelConfig>(v.clone()).ok())
            .unwrap_or_default();

        // Parse resources from params
        let resources = params.get("resources")
            .and_then(|v| serde_json::from_value::<ResourceConfig>(v.clone()).ok())
            .unwrap_or_default();

        let agent_id = Uuid::new_v4();
        let now = Utc::now();
        let expires_at = now + chrono::Duration::seconds(ttl_seconds);

        let config = AgentConfig {
            name: name.to_string(),
            template: template.to_string(),
            template_version: "local".to_string(),
            agent_id,
            did: None, // Phase C: will be did:iota:...
            created_at: now,
            allowed_domains,
            allowed_scopes,
            expires_at: Some(expires_at),
            model,
            resources,
            restart: RestartConfig::default(),
        };

        // Register agent (creates directory structure + agent.toml)
        self.supervisor.register(config).await?;

        // Install template (Phase A: create a basic run.sh)
        self.install_template(template, name).await?;

        // Issue local identity (Phase A: just generate a keypair + card)
        self.issue_local_identity(name, agent_id).await?;

        tracing::info!(
            agent = %name,
            template = %template,
            agent_id = %agent_id,
            "Agent birthed (local mode)"
        );

        // Return agent info
        self.supervisor.get_agent(name).await
            .context("Agent was registered but not found (internal error)")
    }

    /// Install a template's files for an agent.
    /// Phase A: checks templates/ dir for the template, or creates a stub.
    async fn install_template(&self, template: &str, agent_name: &str) -> Result<()> {
        let template_dir = self.root_dir.join("templates").join(template);
        let agent_dir = self.root_dir.join("agents").join(agent_name);

        if template_dir.exists() {
            // Copy template files
            let install_script = template_dir.join("install.sh");
            let run_script = template_dir.join("run.sh");
            let health_script = template_dir.join("health.sh");

            if install_script.exists() {
                std::fs::copy(&install_script, agent_dir.join("install.sh"))?;
            }
            if run_script.exists() {
                std::fs::copy(&run_script, agent_dir.join("run.sh"))?;
            }
            if health_script.exists() {
                std::fs::copy(&health_script, agent_dir.join("health.sh"))?;
            }

            // Run install script if present
            if install_script.exists() {
                tracing::info!(agent = %agent_name, "Running template install script");
                let output = tokio::process::Command::new("bash")
                    .arg(agent_dir.join("install.sh"))
                    .current_dir(agent_dir.join("data"))
                    .output()
                    .await
                    .context("Failed to run install.sh")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    anyhow::bail!("Template install failed: {}", stderr);
                }
            }
        } else {
            // Create a stub run.sh for testing
            tracing::warn!(
                template = %template,
                "Template not found, creating stub run.sh"
            );
            let stub = format!(
                "#!/bin/bash\n\
                 # Stub agent for template '{}'\n\
                 # Replace with actual agent code\n\
                 echo \"Agent $CLAWID_AGENT_NAME started (template: {})\"\n\
                 echo \"Agent ID: $CLAWID_AGENT_ID\"\n\
                 echo \"Data dir: $CLAWID_DATA_DIR\"\n\
                 \n\
                 # Keep alive (replace with actual agent loop)\n\
                 while true; do\n\
                 \tsleep 30\n\
                 \techo \"[$(date)] Agent $CLAWID_AGENT_NAME heartbeat\"\n\
                 done\n",
                template, template
            );
            let run_path = agent_dir.join("run.sh");
            std::fs::write(&run_path, &stub)?;

            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&run_path, std::fs::Permissions::from_mode(0o755))?;
            }
        }

        Ok(())
    }

    /// Issue a local identity (Phase A — no Naja/Morpheus).
    /// Generates keypair, creates agent card, writes to agent's identity dir.
    async fn issue_local_identity(&self, agent_name: &str, agent_id: Uuid) -> Result<()> {
        let identity_dir = self.root_dir.join("agents").join(agent_name).join("identity");

        // Generate Ed25519 keypair using the core crypto module
        // Phase A: just create the key files — the card will be a simplified version
        let (signing_key, verifying_key) = grokingclawid_core::crypto::generate_keypair();

        // Write private key
        let pem = grokingclawid_core::crypto::encode_private_key_pem(&signing_key);
        std::fs::write(identity_dir.join("agent.pem"), &pem)?;

        // Write public key as a simple JSON card (Phase A simplified)
        let pub_key_b64 = grokingclawid_core::crypto::encode_public_key(&verifying_key);
        let card = serde_json::json!({
            "id": agent_id,
            "name": agent_name,
            "public_key": pub_key_b64,
            "crypto_scheme": "ed25519",
            "issued_at": Utc::now().to_rfc3339(),
            "issuer": "local",
            "note": "Phase A local identity — will be replaced by Naja-issued card in Phase C"
        });
        std::fs::write(
            identity_dir.join("agent.card.json"),
            serde_json::to_string_pretty(&card)?,
        )?;

        tracing::info!(agent = %agent_name, "Local identity issued");
        Ok(())
    }

    /// Read the last N lines of an agent's logs.
    pub async fn read_agent_logs(&self, name: &str, lines: usize) -> Result<String> {
        let log_path = self.root_dir.join("agents").join(name).join("logs").join("stdout.log");
        if !log_path.exists() {
            return Ok(String::new());
        }

        let content = std::fs::read_to_string(&log_path)?;
        let all_lines: Vec<&str> = content.lines().collect();
        let start = if all_lines.len() > lines { all_lines.len() - lines } else { 0 };
        Ok(all_lines[start..].join("\n"))
    }
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
    let pid: u32 = pid_str.trim().parse()
        .context("Invalid PID in file")?;

    // Check if process is alive
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let alive = unsafe { libc::kill(pid as i32, 0) == 0 };
        if alive {
            return Ok(Some(pid));
        }
    }

    // Stale PID file
    let _ = std::fs::remove_file(path);
    Ok(None)
}
