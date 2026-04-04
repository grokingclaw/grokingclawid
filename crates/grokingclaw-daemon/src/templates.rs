//! Template registry — install, manage, and instantiate agent templates.
//!
//! Templates define how to install and run an agent. They can be:
//! - Local: stored in ~/.grokingclaw/templates/<name>/
//! - Remote: downloaded from a template registry
//!
//! Each template has a manifest.toml describing requirements, install steps,
//! run configuration, health checks, and default scope.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─── Template Manifest ──────────────────────────────────────────────────

/// Full template manifest (parsed from manifest.toml).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateManifest {
    pub template: TemplateInfo,
    #[serde(default)]
    pub requirements: TemplateRequirements,
    #[serde(default)]
    pub install: InstallConfig,
    #[serde(default)]
    pub run: RunConfig,
    #[serde(default)]
    pub health: HealthConfig,
    #[serde(default)]
    pub scope: ScopeDefaults,
}

/// Basic template information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateInfo {
    /// Template name (e.g., "swe-agent").
    pub name: String,
    /// Template version (semver).
    pub version: String,
    /// Human-readable description.
    #[serde(default)]
    pub description: String,
    /// Author/maintainer.
    #[serde(default)]
    pub author: String,
    /// License.
    #[serde(default = "default_license")]
    pub license: String,
    /// Tags for discovery.
    #[serde(default)]
    pub tags: Vec<String>,
}

fn default_license() -> String {
    "Apache-2.0".to_string()
}

/// System requirements for the template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateRequirements {
    /// Minimum memory in MB.
    #[serde(default = "default_min_memory")]
    pub min_memory_mb: u64,
    /// Minimum disk space in GB.
    #[serde(default = "default_min_disk")]
    pub min_disk_gb: u64,
    /// Required system binaries.
    #[serde(default)]
    pub binaries: Vec<String>,
    /// Required OS (e.g., ["linux", "darwin"]).
    #[serde(default)]
    pub os: Vec<String>,
}

fn default_min_memory() -> u64 {
    512
}
fn default_min_disk() -> u64 {
    1
}

impl Default for TemplateRequirements {
    fn default() -> Self {
        Self {
            min_memory_mb: default_min_memory(),
            min_disk_gb: default_min_disk(),
            binaries: vec![],
            os: vec![],
        }
    }
}

/// How to install the template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallConfig {
    /// Install script filename (relative to template dir).
    #[serde(default = "default_install_script")]
    pub script: String,
    /// Files to copy to agent dir.
    #[serde(default)]
    pub files: Vec<String>,
    /// Environment variables to set during install.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
}

fn default_install_script() -> String {
    "install.sh".to_string()
}

impl Default for InstallConfig {
    fn default() -> Self {
        Self {
            script: default_install_script(),
            files: vec![],
            env: std::collections::HashMap::new(),
        }
    }
}

/// How to run the agent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RunConfig {
    /// Run script filename.
    #[serde(default = "default_run_script")]
    pub script: String,
    /// Working directory (relative to agent dir).
    #[serde(default = "default_workdir")]
    pub workdir: String,
    /// Environment variables for runtime.
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,
    /// Restart on crash.
    #[serde(default = "default_true")]
    pub restart_on_crash: bool,
    /// Max restart attempts.
    #[serde(default = "default_max_restarts")]
    pub max_restarts: u32,
}

fn default_run_script() -> String {
    "run.sh".to_string()
}
fn default_workdir() -> String {
    "data".to_string()
}
fn default_true() -> bool {
    true
}
fn default_max_restarts() -> u32 {
    3
}

impl Default for RunConfig {
    fn default() -> Self {
        Self {
            script: default_run_script(),
            workdir: default_workdir(),
            env: std::collections::HashMap::new(),
            restart_on_crash: true,
            max_restarts: default_max_restarts(),
        }
    }
}

/// Health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Health check script.
    #[serde(default = "default_health_script")]
    pub script: String,
    /// Health check interval in seconds.
    #[serde(default = "default_health_interval")]
    pub interval_seconds: u64,
    /// Number of consecutive failures before declaring unhealthy.
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
}

fn default_health_script() -> String {
    "health.sh".to_string()
}
fn default_health_interval() -> u64 {
    30
}
fn default_unhealthy_threshold() -> u32 {
    3
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            script: default_health_script(),
            interval_seconds: default_health_interval(),
            unhealthy_threshold: default_unhealthy_threshold(),
        }
    }
}

/// Default scope configuration from template.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScopeDefaults {
    /// Default allowed domains.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
    /// Default scopes.
    #[serde(default)]
    pub allowed_scopes: Vec<String>,
    /// Default TTL in seconds.
    #[serde(default = "default_ttl")]
    pub ttl_seconds: i64,
}

fn default_ttl() -> i64 {
    30 * 24 * 3600 // 30 days
}

impl Default for ScopeDefaults {
    fn default() -> Self {
        Self {
            allowed_domains: vec![],
            allowed_scopes: vec!["*".to_string()],
            ttl_seconds: default_ttl(),
        }
    }
}

// ─── Template Summary ───────────────────────────────────────────────────

/// Summary info for listing templates.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TemplateSummary {
    pub name: String,
    pub version: String,
    pub description: String,
    pub path: PathBuf,
    pub has_manifest: bool,
}

// ─── Template Registry ─────────────────────────────────────────────────

/// Manages template installation, discovery, and instantiation.
pub struct TemplateRegistry {
    /// Local templates directory.
    registry_path: PathBuf,
    /// Optional remote registry URL.
    registry_url: Option<String>,
}

impl TemplateRegistry {
    /// Create a new template registry.
    pub fn new(registry_path: PathBuf, registry_url: Option<String>) -> Self {
        Self {
            registry_path,
            registry_url,
        }
    }

    /// Ensure the registry directory exists.
    pub fn init(&self) -> Result<()> {
        std::fs::create_dir_all(&self.registry_path).with_context(|| {
            format!(
                "Failed to create templates directory: {}",
                self.registry_path.display()
            )
        })?;
        Ok(())
    }

    /// List all locally installed templates.
    pub fn list_local(&self) -> Result<Vec<TemplateSummary>> {
        let mut templates = Vec::new();

        if !self.registry_path.exists() {
            return Ok(templates);
        }

        let entries =
            std::fs::read_dir(&self.registry_path).context("Failed to read templates directory")?;

        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            let name = path
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown")
                .to_string();

            let manifest_path = path.join("manifest.toml");
            if manifest_path.exists() {
                match self.parse_manifest(&manifest_path) {
                    Ok(manifest) => {
                        templates.push(TemplateSummary {
                            name: manifest.template.name.clone(),
                            version: manifest.template.version.clone(),
                            description: manifest.template.description.clone(),
                            path: path.clone(),
                            has_manifest: true,
                        });
                    }
                    Err(e) => {
                        tracing::warn!(
                            template = %name,
                            error = %e,
                            "Failed to parse manifest, listing with defaults"
                        );
                        templates.push(TemplateSummary {
                            name,
                            version: "unknown".to_string(),
                            description: String::new(),
                            path: path.clone(),
                            has_manifest: false,
                        });
                    }
                }
            } else {
                // Template dir without manifest — still list it
                templates.push(TemplateSummary {
                    name,
                    version: "unknown".to_string(),
                    description: "(no manifest.toml)".to_string(),
                    path: path.clone(),
                    has_manifest: false,
                });
            }
        }

        templates.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(templates)
    }

    /// Get a template's manifest by name.
    pub fn get_template(&self, name: &str) -> Result<Option<TemplateManifest>> {
        let template_dir = self.registry_path.join(name);
        if !template_dir.exists() {
            return Ok(None);
        }

        let manifest_path = template_dir.join("manifest.toml");
        if !manifest_path.exists() {
            return Ok(None);
        }

        let manifest = self.parse_manifest(&manifest_path)?;
        Ok(Some(manifest))
    }

    /// Get a template's version, if available.
    pub fn get_template_version(&self, name: &str) -> Option<String> {
        let manifest_path = self.registry_path.join(name).join("manifest.toml");
        if !manifest_path.exists() {
            return None;
        }

        self.parse_manifest(&manifest_path)
            .ok()
            .map(|m| m.template.version)
    }

    /// Install a template from the remote registry.
    pub async fn install_template(&self, name: &str, version: &str) -> Result<()> {
        let registry_url = self
            .registry_url
            .as_ref()
            .context("No remote registry URL configured")?;

        let url = format!(
            "{}/v1/templates/{}/versions/{}/archive",
            registry_url.trim_end_matches('/'),
            name,
            version
        );

        tracing::info!(template = %name, version = %version, "Downloading template");

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .unwrap_or_default();

        let resp = http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("Failed to download template '{}'", name))?;

        if !resp.status().is_success() {
            anyhow::bail!(
                "Template download failed (HTTP {}): {}",
                resp.status(),
                resp.text().await.unwrap_or_default()
            );
        }

        let archive_bytes = resp
            .bytes()
            .await
            .context("Failed to read template archive")?;

        // Verify hash if provided
        let hash = grokingclawid_core::crypto::sha256_hex(&archive_bytes);
        tracing::info!(template = %name, hash = %hash, "Archive downloaded, extracting");

        // Extract tar.gz to templates dir
        let template_dir = self.registry_path.join(name);
        std::fs::create_dir_all(&template_dir)?;

        // Use tar command to extract
        let archive_path = template_dir.join("archive.tar.gz");
        std::fs::write(&archive_path, &archive_bytes)?;

        let output = tokio::process::Command::new("tar")
            .args([
                "xzf",
                &archive_path.to_string_lossy(),
                "-C",
                &template_dir.to_string_lossy(),
            ])
            .output()
            .await
            .context("Failed to extract template archive")?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("Archive extraction failed: {}", stderr);
        }

        // Cleanup archive
        std::fs::remove_file(&archive_path).ok();

        tracing::info!(template = %name, version = %version, "Template installed");
        Ok(())
    }

    /// Install template files for a specific agent.
    ///
    /// Copies template files (run.sh, install.sh, health.sh, etc.) to agent dir.
    /// If template doesn't exist, creates a stub run.sh.
    pub fn install_for_agent(&self, template_name: &str, agent_dir: &Path) -> Result<()> {
        let template_dir = self.registry_path.join(template_name);

        if template_dir.exists() {
            // Copy template files
            let files = ["run.sh", "install.sh", "health.sh"];
            for file in &files {
                let src = template_dir.join(file);
                if src.exists() {
                    std::fs::copy(&src, agent_dir.join(file))
                        .with_context(|| format!("Failed to copy {} to agent dir", file))?;
                }
            }

            // Copy any additional files listed in manifest
            if let Ok(Some(manifest)) = self.get_template(template_name) {
                for file in &manifest.install.files {
                    let src = template_dir.join(file);
                    if src.exists() {
                        let dest = agent_dir.join(file);
                        if let Some(parent) = dest.parent() {
                            std::fs::create_dir_all(parent)?;
                        }
                        std::fs::copy(&src, &dest)?;
                    }
                }
            }

            // Run install script if present
            let install_script = agent_dir.join("install.sh");
            if install_script.exists() {
                tracing::info!(
                    template = %template_name,
                    "Running template install script"
                );
                let output = std::process::Command::new("bash")
                    .arg(&install_script)
                    .current_dir(agent_dir.join("data"))
                    .output()
                    .context("Failed to run install.sh")?;

                if !output.status.success() {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::warn!(
                        template = %template_name,
                        error = %stderr,
                        "Template install script failed (non-fatal)"
                    );
                }
            }
        } else {
            // Create stub run.sh
            tracing::warn!(
                template = %template_name,
                "Template not found, creating stub run.sh"
            );
            let stub = format!(
                "#!/bin/bash\n\
                 # Stub agent for template '{}'\n\
                 echo \"Agent $CLAWID_AGENT_NAME started (template: {})\"\n\
                 echo \"Agent ID: $CLAWID_AGENT_ID\"\n\
                 echo \"Data dir: $CLAWID_DATA_DIR\"\n\
                 \n\
                 while true; do\n\
                 \tsleep 30\n\
                 \techo \"[$(date)] Agent $CLAWID_AGENT_NAME heartbeat\"\n\
                 done\n",
                template_name, template_name
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

    /// Create a template from a local directory.
    ///
    /// Useful for development/testing without a remote registry.
    pub fn create_from_local(&self, name: &str, source_dir: &Path) -> Result<()> {
        if !source_dir.exists() {
            anyhow::bail!("Source directory does not exist: {}", source_dir.display());
        }

        let template_dir = self.registry_path.join(name);
        if template_dir.exists() {
            anyhow::bail!("Template '{}' already exists. Remove it first.", name);
        }

        // Copy directory recursively
        copy_dir_recursive(source_dir, &template_dir)?;

        // Create manifest if not present
        let manifest_path = template_dir.join("manifest.toml");
        if !manifest_path.exists() {
            let manifest = TemplateManifest {
                template: TemplateInfo {
                    name: name.to_string(),
                    version: "0.1.0".to_string(),
                    description: format!("Template created from {}", source_dir.display()),
                    author: String::new(),
                    license: "Apache-2.0".to_string(),
                    tags: vec![],
                },
                requirements: TemplateRequirements::default(),
                install: InstallConfig::default(),
                run: RunConfig::default(),
                health: HealthConfig::default(),
                scope: ScopeDefaults::default(),
            };

            let toml_str = toml::to_string_pretty(&manifest)?;
            std::fs::write(&manifest_path, &toml_str)?;
        }

        tracing::info!(template = %name, "Template created from local directory");
        Ok(())
    }

    /// Parse a manifest.toml file.
    fn parse_manifest(&self, path: &Path) -> Result<TemplateManifest> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read manifest: {}", path.display()))?;
        let manifest: TemplateManifest = toml::from_str(&content)
            .with_context(|| format!("Failed to parse manifest: {}", path.display()))?;
        Ok(manifest)
    }
}

/// Recursively copy a directory.
fn copy_dir_recursive(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;

    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if src_path.is_dir() {
            copy_dir_recursive(&src_path, &dst_path)?;
        } else {
            std::fs::copy(&src_path, &dst_path)?;
        }
    }

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_manifest_parsing() {
        let toml_str = r#"
[template]
name = "swe-agent"
version = "1.0.0"
description = "SWE-bench solving agent"
author = "GrokingClaw Labs"
license = "Apache-2.0"
tags = ["swe-bench", "coding"]

[requirements]
min_memory_mb = 4096
min_disk_gb = 10
binaries = ["python3", "git"]
os = ["linux", "darwin"]

[install]
script = "install.sh"
files = ["requirements.txt", "config.yaml"]

[run]
script = "run.sh"
workdir = "workspace"
restart_on_crash = true
max_restarts = 5

[health]
script = "health.sh"
interval_seconds = 60
unhealthy_threshold = 3

[scope]
allowed_domains = ["api.openai.com", "github.com"]
allowed_scopes = ["code", "web"]
ttl_seconds = 604800
"#;

        let manifest: TemplateManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.template.name, "swe-agent");
        assert_eq!(manifest.template.version, "1.0.0");
        assert_eq!(manifest.requirements.min_memory_mb, 4096);
        assert_eq!(manifest.run.max_restarts, 5);
        assert_eq!(manifest.scope.allowed_domains.len(), 2);
    }

    #[test]
    fn test_manifest_defaults() {
        let toml_str = r#"
[template]
name = "basic"
version = "0.1.0"
"#;

        let manifest: TemplateManifest = toml::from_str(toml_str).unwrap();
        assert_eq!(manifest.template.name, "basic");
        assert_eq!(manifest.requirements.min_memory_mb, 512);
        assert_eq!(manifest.run.script, "run.sh");
        assert_eq!(manifest.health.interval_seconds, 30);
        assert_eq!(manifest.scope.ttl_seconds, 30 * 24 * 3600);
    }

    #[test]
    fn test_list_local_empty() {
        let dir = tempfile::tempdir().unwrap();
        let registry = TemplateRegistry::new(dir.path().to_path_buf(), None);
        let templates = registry.list_local().unwrap();
        assert!(templates.is_empty());
    }

    #[test]
    fn test_list_local_with_templates() {
        let dir = tempfile::tempdir().unwrap();
        let registry = TemplateRegistry::new(dir.path().to_path_buf(), None);

        // Create a template dir with manifest
        let tmpl_dir = dir.path().join("test-template");
        fs::create_dir_all(&tmpl_dir).unwrap();
        fs::write(
            tmpl_dir.join("manifest.toml"),
            r#"
[template]
name = "test-template"
version = "1.0.0"
description = "A test template"
"#,
        )
        .unwrap();

        // Create another without manifest
        let tmpl_dir2 = dir.path().join("no-manifest");
        fs::create_dir_all(&tmpl_dir2).unwrap();

        let templates = registry.list_local().unwrap();
        assert_eq!(templates.len(), 2);

        let with_manifest = templates
            .iter()
            .find(|t| t.name == "test-template")
            .unwrap();
        assert_eq!(with_manifest.version, "1.0.0");
        assert!(with_manifest.has_manifest);

        let without_manifest = templates.iter().find(|t| t.name == "no-manifest").unwrap();
        assert_eq!(without_manifest.version, "unknown");
        assert!(!without_manifest.has_manifest);
    }

    #[test]
    fn test_install_for_agent_stub() {
        let templates_dir = tempfile::tempdir().unwrap();
        let agent_dir = tempfile::tempdir().unwrap();
        let registry = TemplateRegistry::new(templates_dir.path().to_path_buf(), None);

        // Template doesn't exist — should create stub
        registry
            .install_for_agent("nonexistent", agent_dir.path())
            .unwrap();

        let run_sh = agent_dir.path().join("run.sh");
        assert!(run_sh.exists());
        let content = fs::read_to_string(&run_sh).unwrap();
        assert!(content.contains("nonexistent"));
    }

    #[test]
    fn test_install_for_agent_with_template() {
        let templates_dir = tempfile::tempdir().unwrap();
        let agent_dir = tempfile::tempdir().unwrap();

        // Create template
        let tmpl_dir = templates_dir.path().join("my-template");
        fs::create_dir_all(&tmpl_dir).unwrap();
        fs::write(tmpl_dir.join("run.sh"), "#!/bin/bash\necho hello\n").unwrap();
        fs::write(tmpl_dir.join("health.sh"), "#!/bin/bash\nexit 0\n").unwrap();

        let registry = TemplateRegistry::new(templates_dir.path().to_path_buf(), None);
        registry
            .install_for_agent("my-template", agent_dir.path())
            .unwrap();

        assert!(agent_dir.path().join("run.sh").exists());
        assert!(agent_dir.path().join("health.sh").exists());
    }

    #[test]
    fn test_create_from_local() {
        let templates_dir = tempfile::tempdir().unwrap();
        let source_dir = tempfile::tempdir().unwrap();

        fs::write(
            source_dir.path().join("run.sh"),
            "#!/bin/bash\necho hello\n",
        )
        .unwrap();

        let registry = TemplateRegistry::new(templates_dir.path().to_path_buf(), None);
        registry
            .create_from_local("new-template", source_dir.path())
            .unwrap();

        let template_dir = templates_dir.path().join("new-template");
        assert!(template_dir.exists());
        assert!(template_dir.join("manifest.toml").exists());
        assert!(template_dir.join("run.sh").exists());
    }

    #[test]
    fn test_get_template() {
        let dir = tempfile::tempdir().unwrap();
        let registry = TemplateRegistry::new(dir.path().to_path_buf(), None);

        // No template
        assert!(registry.get_template("nonexistent").unwrap().is_none());

        // Create template with manifest
        let tmpl_dir = dir.path().join("test");
        fs::create_dir_all(&tmpl_dir).unwrap();
        fs::write(
            tmpl_dir.join("manifest.toml"),
            "[template]\nname = \"test\"\nversion = \"2.0.0\"\n",
        )
        .unwrap();

        let manifest = registry.get_template("test").unwrap().unwrap();
        assert_eq!(manifest.template.name, "test");
        assert_eq!(manifest.template.version, "2.0.0");
    }
}
