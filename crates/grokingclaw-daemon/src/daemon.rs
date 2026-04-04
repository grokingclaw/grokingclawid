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
