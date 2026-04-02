//! Daemon configuration.
//!
//! Reads from ~/.grokingclaw/daemon.toml or uses sensible defaults.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Root directory for all daemon state.
pub fn daemon_root() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".grokingclaw"))
}

/// Full daemon configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    #[serde(default)]
    pub daemon: DaemonSection,
    #[serde(default)]
    pub resources: ResourcesSection,
    #[serde(default)]
    pub mesh: MeshSection,
    #[serde(default)]
    pub anchoring: AnchoringSection,
    #[serde(default)]
    pub updates: UpdatesSection,
    #[serde(default)]
    pub registry: RegistrySection,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonSection {
    /// Path to the Unix socket for CLI communication.
    #[serde(default = "default_socket_path")]
    pub listen: String,
    /// Log level.
    #[serde(default = "default_log_level")]
    pub log_level: String,
    /// PID file path.
    #[serde(default = "default_pid_path")]
    pub pid_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcesSection {
    /// Maximum concurrent agents on this daemon.
    #[serde(default = "default_max_agents")]
    pub max_agents: u32,
    /// Default per-agent memory limit in MB.
    #[serde(default = "default_memory_mb")]
    pub default_memory_mb: u64,
    /// Default per-agent CPU percent limit.
    #[serde(default = "default_cpu_percent")]
    pub default_cpu_percent: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchoringSection {
    /// Enable breadcrumb anchoring to IOTA.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Anchor interval in minutes.
    #[serde(default = "default_anchor_interval")]
    pub interval_minutes: u32,
    /// IOTA JSON-RPC endpoint.
    #[serde(default = "default_iota_node")]
    pub iota_node: String,
    /// Max audit entries per Merkle root.
    #[serde(default = "default_batch_size")]
    pub batch_size: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdatesSection {
    /// Check interval in minutes.
    #[serde(default = "default_update_interval")]
    pub check_interval_minutes: u32,
    /// Auto-update daemon binary.
    #[serde(default)]
    pub auto_update_daemon: bool,
    /// Auto-update templates.
    #[serde(default = "default_true")]
    pub auto_update_templates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshSection {
    /// Enable mesh networking.
    #[serde(default)]
    pub enabled: bool,
    /// Coordination server URL.
    #[serde(default = "default_coordination_server")]
    pub coordination_server: String,
    /// Auto-connect on daemon start.
    #[serde(default)]
    pub auto_connect: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistrySection {
    /// Remote template registry URL.
    #[serde(default)]
    pub url: Option<String>,
}

// Default value functions
fn default_socket_path() -> String {
    "~/.grokingclaw/daemon.sock".to_string()
}
fn default_log_level() -> String {
    "info".to_string()
}
fn default_pid_path() -> String {
    "~/.grokingclaw/daemon.pid".to_string()
}
fn default_max_agents() -> u32 {
    10
}
fn default_memory_mb() -> u64 {
    2048
}
fn default_cpu_percent() -> u32 {
    50
}
fn default_true() -> bool {
    true
}
fn default_anchor_interval() -> u32 {
    5
}
fn default_iota_node() -> String {
    "https://api.iota-rebased.org".to_string()
}
fn default_batch_size() -> u32 {
    100
}
fn default_update_interval() -> u32 {
    30
}
fn default_coordination_server() -> String {
    "https://mesh.grokingclaw.com".to_string()
}

impl Default for DaemonSection {
    fn default() -> Self {
        Self {
            listen: default_socket_path(),
            log_level: default_log_level(),
            pid_file: default_pid_path(),
        }
    }
}

impl Default for ResourcesSection {
    fn default() -> Self {
        Self {
            max_agents: default_max_agents(),
            default_memory_mb: default_memory_mb(),
            default_cpu_percent: default_cpu_percent(),
        }
    }
}

impl Default for AnchoringSection {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_minutes: default_anchor_interval(),
            iota_node: default_iota_node(),
            batch_size: default_batch_size(),
        }
    }
}

impl Default for UpdatesSection {
    fn default() -> Self {
        Self {
            check_interval_minutes: default_update_interval(),
            auto_update_daemon: false,
            auto_update_templates: true,
        }
    }
}

impl Default for MeshSection {
    fn default() -> Self {
        Self {
            enabled: false,
            coordination_server: default_coordination_server(),
            auto_connect: false,
        }
    }
}

impl Default for RegistrySection {
    fn default() -> Self {
        Self {
            url: None,
        }
    }
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            daemon: DaemonSection::default(),
            resources: ResourcesSection::default(),
            mesh: MeshSection::default(),
            anchoring: AnchoringSection::default(),
            updates: UpdatesSection::default(),
            registry: RegistrySection::default(),
        }
    }
}

impl DaemonConfig {
    /// Load config from file, falling back to defaults.
    pub fn load(path: &Path) -> Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read config: {}", path.display()))?;
            let config: DaemonConfig = toml::from_str(&content)
                .with_context(|| format!("Failed to parse config: {}", path.display()))?;
            Ok(config)
        } else {
            Ok(Self::default())
        }
    }

    /// Resolve the socket path (expand ~).
    pub fn socket_path(&self) -> Result<PathBuf> {
        expand_tilde(&self.daemon.listen)
    }

    /// Resolve the PID file path (expand ~).
    pub fn pid_path(&self) -> Result<PathBuf> {
        expand_tilde(&self.daemon.pid_file)
    }
}

/// Expand ~ to home directory.
fn expand_tilde(path: &str) -> Result<PathBuf> {
    if path.starts_with("~/") {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(&path[2..]))
    } else {
        Ok(PathBuf::from(path))
    }
}
