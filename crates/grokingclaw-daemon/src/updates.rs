//! Update checker — template and daemon update management.
//!
//! Periodically checks the remote registry for:
//! - Template updates (compare installed vs latest version)
//! - Daemon binary updates (compare current vs latest version)
//!
//! Can auto-apply minor template patches if configured.

use anyhow::Result;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::DaemonConfig;
use crate::templates::TemplateRegistry;

// ─── Types ──────────────────────────────────────────────────────────────

/// An available update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateInfo {
    pub kind: UpdateKind,
    pub name: String,
    pub current_version: String,
    pub latest_version: String,
    pub is_major: bool,
    pub changelog_url: Option<String>,
    pub checked_at: DateTime<Utc>,
}

/// Type of update.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UpdateKind {
    Template,
    Daemon,
}

/// Result of an update check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateCheckResult {
    pub available_updates: Vec<UpdateInfo>,
    pub checked_at: DateTime<Utc>,
    pub next_check_at: DateTime<Utc>,
}

/// Remote version info response.
#[derive(Debug, Deserialize)]
struct VersionResponse {
    version: String,
    #[serde(default)]
    changelog_url: Option<String>,
}

// ─── Update Checker ─────────────────────────────────────────────────────

/// Background update checker.
pub struct UpdateChecker {
    config: DaemonConfig,
    templates: Arc<TemplateRegistry>,
    registry_url: Option<String>,
    state: RwLock<UpdateState>,
}

struct UpdateState {
    last_check: Option<DateTime<Utc>>,
    available_updates: Vec<UpdateInfo>,
}

impl UpdateChecker {
    /// Create a new update checker.
    pub fn new(
        config: DaemonConfig,
        templates: Arc<TemplateRegistry>,
        registry_url: Option<String>,
    ) -> Self {
        Self {
            config,
            templates,
            registry_url,
            state: RwLock::new(UpdateState {
                last_check: None,
                available_updates: Vec::new(),
            }),
        }
    }

    /// Run a single update check cycle.
    pub async fn check(&self) -> Result<UpdateCheckResult> {
        let mut updates = Vec::new();

        // Check daemon version
        if let Ok(Some(daemon_update)) = self.check_daemon_update().await {
            updates.push(daemon_update);
        }

        // Check template versions
        if let Ok(template_updates) = self.check_template_updates().await {
            updates.extend(template_updates);
        }

        let now = Utc::now();
        let interval = chrono::Duration::minutes(self.config.updates.check_interval_minutes as i64);
        let next_check = now + interval;

        let result = UpdateCheckResult {
            available_updates: updates.clone(),
            checked_at: now,
            next_check_at: next_check,
        };

        // Update state
        let mut state = self.state.write().await;
        state.last_check = Some(now);
        state.available_updates = updates;

        Ok(result)
    }

    /// Get the most recent update check results.
    pub async fn get_status(&self) -> Vec<UpdateInfo> {
        self.state.read().await.available_updates.clone()
    }

    /// Check if a daemon update is available.
    async fn check_daemon_update(&self) -> Result<Option<UpdateInfo>> {
        let registry_url = match &self.registry_url {
            Some(url) => url,
            None => return Ok(None),
        };

        let url = format!("{}/v1/daemon/latest", registry_url.trim_end_matches('/'));

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        let resp = match http.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to check daemon updates (network)");
                return Ok(None);
            }
        };

        if !resp.status().is_success() {
            return Ok(None);
        }

        let version_info: VersionResponse = match resp.json().await {
            Ok(v) => v,
            Err(e) => {
                tracing::debug!(error = %e, "Failed to parse daemon version response");
                return Ok(None);
            }
        };

        let current = env!("CARGO_PKG_VERSION");
        if version_info.version != current {
            let is_major = is_major_update(current, &version_info.version);
            Ok(Some(UpdateInfo {
                kind: UpdateKind::Daemon,
                name: "grokingclaw".to_string(),
                current_version: current.to_string(),
                latest_version: version_info.version,
                is_major,
                changelog_url: version_info.changelog_url,
                checked_at: Utc::now(),
            }))
        } else {
            Ok(None)
        }
    }

    /// Check for template updates.
    async fn check_template_updates(&self) -> Result<Vec<UpdateInfo>> {
        let registry_url = match &self.registry_url {
            Some(url) => url.clone(),
            None => return Ok(vec![]),
        };

        let local_templates = self.templates.list_local()?;
        let mut updates = Vec::new();

        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .build()
            .unwrap_or_default();

        for template in &local_templates {
            if template.version == "unknown" {
                continue; // Can't check versions without current version
            }

            let url = format!(
                "{}/v1/templates/{}/latest",
                registry_url.trim_end_matches('/'),
                template.name
            );

            let resp = match http.get(&url).send().await {
                Ok(r) if r.status().is_success() => r,
                _ => continue,
            };

            let version_info: VersionResponse = match resp.json().await {
                Ok(v) => v,
                Err(_) => continue,
            };

            if version_info.version != template.version {
                let is_major = is_major_update(&template.version, &version_info.version);
                updates.push(UpdateInfo {
                    kind: UpdateKind::Template,
                    name: template.name.clone(),
                    current_version: template.version.clone(),
                    latest_version: version_info.version,
                    is_major,
                    changelog_url: version_info.changelog_url,
                    checked_at: Utc::now(),
                });
            }
        }

        Ok(updates)
    }

    /// Apply available template updates (minor/patch only).
    pub async fn apply_template_updates(&self) -> Result<Vec<String>> {
        let state = self.state.read().await;
        let template_updates: Vec<&UpdateInfo> = state
            .available_updates
            .iter()
            .filter(|u| matches!(u.kind, UpdateKind::Template) && !u.is_major)
            .collect();

        if template_updates.is_empty() {
            return Ok(vec![]);
        }

        let mut applied = Vec::new();

        for update in template_updates {
            match self
                .templates
                .install_template(&update.name, &update.latest_version)
                .await
            {
                Ok(()) => {
                    tracing::info!(
                        template = %update.name,
                        from = %update.current_version,
                        to = %update.latest_version,
                        "Template updated"
                    );
                    applied.push(format!(
                        "{}: {} → {}",
                        update.name, update.current_version, update.latest_version
                    ));
                }
                Err(e) => {
                    tracing::error!(
                        template = %update.name,
                        error = %e,
                        "Failed to apply template update"
                    );
                }
            }
        }

        Ok(applied)
    }

    /// Run the background update check loop.
    pub async fn run_loop(self: Arc<Self>, mut shutdown: tokio::sync::watch::Receiver<bool>) {
        let interval =
            std::time::Duration::from_secs(self.config.updates.check_interval_minutes as u64 * 60);

        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    match self.check().await {
                        Ok(result) => {
                            let count = result.available_updates.len();
                            if count > 0 {
                                tracing::info!(
                                    count = count,
                                    "Update check: {} updates available",
                                    count
                                );

                                // Auto-apply template patches if configured
                                if self.config.updates.auto_update_templates {
                                    if let Ok(applied) = self.apply_template_updates().await {
                                        for a in &applied {
                                            tracing::info!("Auto-applied update: {}", a);
                                        }
                                    }
                                }
                            } else {
                                tracing::debug!("Update check: everything up to date");
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "Update check failed (will retry)");
                        }
                    }
                }
                _ = shutdown.changed() => {
                    tracing::info!("Update checker shutting down");
                    break;
                }
            }
        }
    }
}

/// Check if version B is a major update from version A.
/// Simple semver major version comparison.
fn is_major_update(current: &str, latest: &str) -> bool {
    let current_major = current
        .split('.')
        .next()
        .and_then(|v| v.parse::<u32>().ok());
    let latest_major = latest.split('.').next().and_then(|v| v.parse::<u32>().ok());

    match (current_major, latest_major) {
        (Some(c), Some(l)) => l > c,
        _ => false,
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_major_update() {
        assert!(is_major_update("0.1.0", "1.0.0"));
        assert!(is_major_update("1.5.2", "2.0.0"));
        assert!(!is_major_update("1.0.0", "1.1.0"));
        assert!(!is_major_update("1.0.0", "1.0.1"));
        assert!(!is_major_update("2.0.0", "2.5.3"));
    }

    #[test]
    fn test_update_info_serialization() {
        let info = UpdateInfo {
            kind: UpdateKind::Template,
            name: "swe-agent".to_string(),
            current_version: "1.0.0".to_string(),
            latest_version: "1.1.0".to_string(),
            is_major: false,
            changelog_url: Some("https://example.com/changelog".to_string()),
            checked_at: Utc::now(),
        };

        let json = serde_json::to_string(&info).unwrap();
        let parsed: UpdateInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.name, "swe-agent");
        assert_eq!(parsed.latest_version, "1.1.0");
        assert!(!parsed.is_major);
    }
}
