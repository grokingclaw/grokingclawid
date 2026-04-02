//! Agent process supervisor.
//!
//! Manages agent lifecycle: spawn, monitor, restart, stop, kill.
//! Each agent runs as an isolated child process with its own
//! working directory and environment.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::process::{Child, Command};
use tokio::sync::RwLock;
use uuid::Uuid;

/// Agent lifecycle state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    /// Being created (template install, identity issuance).
    Creating,
    /// Process is starting up.
    Starting,
    /// Running and healthy.
    Running,
    /// Cleanly stopped by user or scope expiry.
    Stopped,
    /// Crashed and exceeded restart limit.
    Crashed,
    /// Revoked by guardian or parent.
    Revoked,
}

impl std::fmt::Display for AgentStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Creating => write!(f, "creating"),
            Self::Starting => write!(f, "starting"),
            Self::Running => write!(f, "running"),
            Self::Stopped => write!(f, "stopped"),
            Self::Crashed => write!(f, "crashed"),
            Self::Revoked => write!(f, "revoked"),
        }
    }
}

/// Per-agent configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentConfig {
    /// Human-readable name.
    pub name: String,
    /// Template used to create this agent.
    pub template: String,
    /// Template version.
    pub template_version: String,
    /// Agent's unique ID.
    pub agent_id: Uuid,
    /// Agent's DID (if issued).
    pub did: Option<String>,
    /// When this agent was born.
    pub created_at: DateTime<Utc>,
    /// Allowed outbound domains (for proxy scope enforcement).
    pub allowed_domains: Vec<String>,
    /// Allowed capability scopes.
    pub allowed_scopes: Vec<String>,
    /// When the delegation expires.
    pub expires_at: Option<DateTime<Utc>>,
    /// LLM model configuration.
    pub model: ModelConfig,
    /// Resource limits.
    pub resources: ResourceConfig,
    /// Restart policy.
    pub restart: RestartConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelConfig {
    pub provider: String,
    pub endpoint: String,
    pub model: String,
}

impl Default for ModelConfig {
    fn default() -> Self {
        Self {
            provider: "ollama".to_string(),
            endpoint: "http://localhost:11434".to_string(),
            model: "qwen3.5".to_string(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceConfig {
    pub memory_mb: u64,
    pub cpu_percent: u32,
    pub max_disk_gb: u64,
    pub max_requests_per_minute: u32,
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            memory_mb: 2048,
            cpu_percent: 50,
            max_disk_gb: 10,
            max_requests_per_minute: 60,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartConfig {
    pub max_restarts: u32,
    pub restart_window_seconds: u64,
    pub restart_on_success: bool,
}

impl Default for RestartConfig {
    fn default() -> Self {
        Self {
            max_restarts: 3,
            restart_window_seconds: 300,
            restart_on_success: false,
        }
    }
}

/// Runtime state for a running agent.
struct AgentProcess {
    config: AgentConfig,
    status: AgentStatus,
    child: Option<Child>,
    pid: Option<u32>,
    restart_count: u32,
    restart_timestamps: Vec<DateTime<Utc>>,
    started_at: Option<DateTime<Utc>>,
}

/// The process supervisor — manages all agent processes.
pub struct Supervisor {
    agents: RwLock<HashMap<String, AgentProcess>>,
    agents_dir: PathBuf,
}

/// Snapshot of agent state for IPC responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub name: String,
    pub agent_id: Uuid,
    pub did: Option<String>,
    pub template: String,
    pub status: AgentStatus,
    pub pid: Option<u32>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub restart_count: u32,
    pub allowed_scopes: Vec<String>,
}

impl Supervisor {
    /// Create a new supervisor rooted at the given agents directory.
    pub fn new(agents_dir: PathBuf) -> Self {
        Self {
            agents: RwLock::new(HashMap::new()),
            agents_dir,
        }
    }

    /// Initialize: scan agents_dir for existing agent.toml files,
    /// load their configs, set status to Stopped.
    pub async fn init(&self) -> Result<()> {
        if !self.agents_dir.exists() {
            std::fs::create_dir_all(&self.agents_dir)
                .context("Failed to create agents directory")?;
            return Ok(());
        }

        let mut agents = self.agents.write().await;
        let entries = std::fs::read_dir(&self.agents_dir)
            .context("Failed to read agents directory")?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                let config_path = path.join("agent.toml");
                if config_path.exists() {
                    let content = std::fs::read_to_string(&config_path)?;
                    let config: AgentConfig = toml::from_str(&content)
                        .with_context(|| format!("Failed to parse {}", config_path.display()))?;
                    let name = config.name.clone();
                    agents.insert(name, AgentProcess {
                        config,
                        status: AgentStatus::Stopped,
                        child: None,
                        pid: None,
                        restart_count: 0,
                        restart_timestamps: Vec::new(),
                        started_at: None,
                    });
                }
            }
        }

        tracing::info!("Loaded {} existing agents", agents.len());
        Ok(())
    }

    /// Register a newly birthed agent (doesn't start it yet).
    pub async fn register(&self, config: AgentConfig) -> Result<()> {
        let name = config.name.clone();
        let agent_dir = self.agents_dir.join(&name);

        // Create directory structure
        std::fs::create_dir_all(agent_dir.join("identity"))?;
        std::fs::create_dir_all(agent_dir.join("audit"))?;
        std::fs::create_dir_all(agent_dir.join("data"))?;
        std::fs::create_dir_all(agent_dir.join("logs"))?;
        std::fs::create_dir_all(agent_dir.join("breadcrumbs"))?;

        // Write agent.toml
        let toml_str = toml::to_string_pretty(&config)
            .context("Failed to serialize agent config")?;
        std::fs::write(agent_dir.join("agent.toml"), &toml_str)?;

        let mut agents = self.agents.write().await;
        agents.insert(name.clone(), AgentProcess {
            config,
            status: AgentStatus::Creating,
            child: None,
            pid: None,
            restart_count: 0,
            restart_timestamps: Vec::new(),
            started_at: None,
        });

        tracing::info!(agent = %name, "Agent registered");
        Ok(())
    }

    /// Start an agent process.
    pub async fn start_agent(&self, name: &str) -> Result<()> {
        let agent_dir = self.agents_dir.join(name);
        let run_script = agent_dir.join("run.sh");

        if !run_script.exists() {
            anyhow::bail!("No run.sh found for agent '{}'. Template may not be installed.", name);
        }

        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(name)
            .context(format!("Agent '{}' not found", name))?;

        if agent.status == AgentStatus::Running {
            anyhow::bail!("Agent '{}' is already running", name);
        }

        // Set up environment
        let data_dir = agent_dir.join("data");
        let audit_db = agent_dir.join("audit").join("audit.db");
        let stdout_log = agent_dir.join("logs").join("stdout.log");
        let stderr_log = agent_dir.join("logs").join("stderr.log");

        let stdout_file = std::fs::File::create(&stdout_log)
            .context("Failed to create stdout log")?;
        let stderr_file = std::fs::File::create(&stderr_log)
            .context("Failed to create stderr log")?;

        let child = Command::new("bash")
            .arg(&run_script)
            .current_dir(&data_dir)
            .env("CLAWID_AGENT_ID", agent.config.agent_id.to_string())
            .env("CLAWID_AGENT_NAME", &agent.config.name)
            .env("CLAWID_DATA_DIR", &data_dir)
            .env("CLAWID_AUDIT_DB", &audit_db)
            .env("CLAWID_AGENT_DID", agent.config.did.as_deref().unwrap_or(""))
            // Proxy env vars will be set in Phase B
            .stdout(Stdio::from(stdout_file.try_clone()?))
            .stderr(Stdio::from(stderr_file.try_clone()?))
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("Failed to spawn agent '{}'", name))?;

        let pid = child.id();
        agent.child = Some(child);
        agent.pid = pid;
        agent.status = AgentStatus::Running;
        agent.started_at = Some(Utc::now());

        tracing::info!(agent = %name, pid = ?pid, "Agent started");
        Ok(())
    }

    /// Stop an agent gracefully (SIGTERM, then SIGKILL after 10s).
    pub async fn stop_agent(&self, name: &str) -> Result<()> {
        let mut agents = self.agents.write().await;
        let agent = agents.get_mut(name)
            .context(format!("Agent '{}' not found", name))?;

        if let Some(ref mut child) = agent.child {
            // Send SIGTERM first
            tracing::info!(agent = %name, "Sending SIGTERM");
            let _ = child.kill().await;
            agent.child = None;
        }

        agent.status = AgentStatus::Stopped;
        agent.pid = None;
        tracing::info!(agent = %name, "Agent stopped");
        Ok(())
    }

    /// Check if any running agents have exited, handle restart policy.
    pub async fn check_health(&self) -> Result<()> {
        let mut agents = self.agents.write().await;

        let agent_names: Vec<String> = agents.keys().cloned().collect();

        for name in agent_names {
            let agent = match agents.get_mut(&name) {
                Some(a) => a,
                None => continue,
            };

            if agent.status != AgentStatus::Running {
                continue;
            }

            // Check if child process has exited
            if let Some(ref mut child) = agent.child {
                match child.try_wait() {
                    Ok(Some(exit_status)) => {
                        if exit_status.success() && !agent.config.restart.restart_on_success {
                            tracing::info!(agent = %name, "Agent exited cleanly");
                            agent.status = AgentStatus::Stopped;
                            agent.child = None;
                            agent.pid = None;
                        } else {
                            // Crashed or restart-on-success
                            tracing::warn!(
                                agent = %name,
                                exit_code = ?exit_status.code(),
                                "Agent exited unexpectedly"
                            );

                            // Check restart budget
                            let now = Utc::now();
                            let window = chrono::Duration::seconds(
                                agent.config.restart.restart_window_seconds as i64
                            );
                            agent.restart_timestamps.retain(|t| now - *t < window);

                            if agent.restart_timestamps.len() < agent.config.restart.max_restarts as usize {
                                agent.restart_timestamps.push(now);
                                agent.restart_count += 1;
                                agent.child = None;
                                agent.pid = None;
                                agent.status = AgentStatus::Starting;
                                tracing::info!(
                                    agent = %name,
                                    restart = agent.restart_count,
                                    "Restarting agent"
                                );
                                // Will be restarted by the daemon main loop
                            } else {
                                tracing::error!(
                                    agent = %name,
                                    "Restart limit exceeded ({} in {}s), marking CRASHED",
                                    agent.config.restart.max_restarts,
                                    agent.config.restart.restart_window_seconds
                                );
                                agent.status = AgentStatus::Crashed;
                                agent.child = None;
                                agent.pid = None;
                            }
                        }
                    }
                    Ok(None) => {
                        // Still running, good
                    }
                    Err(e) => {
                        tracing::error!(agent = %name, error = %e, "Failed to check agent status");
                    }
                }
            }

            // Check scope expiration
            if let Some(expires_at) = agent.config.expires_at {
                if Utc::now() > expires_at {
                    tracing::warn!(agent = %name, "Delegation expired, stopping agent");
                    if let Some(ref mut child) = agent.child {
                        let _ = child.kill().await;
                    }
                    agent.status = AgentStatus::Stopped;
                    agent.child = None;
                    agent.pid = None;
                }
            }
        }

        Ok(())
    }

    /// Get all agents that need to be (re)started.
    pub async fn agents_needing_start(&self) -> Vec<String> {
        let agents = self.agents.read().await;
        agents.iter()
            .filter(|(_, a)| a.status == AgentStatus::Starting)
            .map(|(name, _)| name.clone())
            .collect()
    }

    /// List all agents with their current state.
    pub async fn list_agents(&self) -> Vec<AgentInfo> {
        let agents = self.agents.read().await;
        agents.values().map(|a| AgentInfo {
            name: a.config.name.clone(),
            agent_id: a.config.agent_id,
            did: a.config.did.clone(),
            template: a.config.template.clone(),
            status: a.status,
            pid: a.pid,
            created_at: a.config.created_at,
            started_at: a.started_at,
            restart_count: a.restart_count,
            allowed_scopes: a.config.allowed_scopes.clone(),
        }).collect()
    }

    /// Get a single agent's info.
    pub async fn get_agent(&self, name: &str) -> Option<AgentInfo> {
        let agents = self.agents.read().await;
        agents.get(name).map(|a| AgentInfo {
            name: a.config.name.clone(),
            agent_id: a.config.agent_id,
            did: a.config.did.clone(),
            template: a.config.template.clone(),
            status: a.status,
            pid: a.pid,
            created_at: a.config.created_at,
            started_at: a.started_at,
            restart_count: a.restart_count,
            allowed_scopes: a.config.allowed_scopes.clone(),
        })
    }

    /// Delete an agent (stop + remove all data).
    pub async fn delete_agent(&self, name: &str) -> Result<()> {
        self.stop_agent(name).await.ok(); // ignore errors if not running

        let agent_dir = self.agents_dir.join(name);
        if agent_dir.exists() {
            std::fs::remove_dir_all(&agent_dir)
                .with_context(|| format!("Failed to delete agent directory: {}", agent_dir.display()))?;
        }

        let mut agents = self.agents.write().await;
        agents.remove(name);

        tracing::info!(agent = %name, "Agent deleted");
        Ok(())
    }

    /// Stop all agents (for daemon shutdown).
    pub async fn stop_all(&self) -> Result<()> {
        let names: Vec<String> = {
            let agents = self.agents.read().await;
            agents.keys().cloned().collect()
        };

        for name in names {
            if let Err(e) = self.stop_agent(&name).await {
                tracing::error!(agent = %name, error = %e, "Failed to stop agent during shutdown");
            }
        }
        Ok(())
    }
}
