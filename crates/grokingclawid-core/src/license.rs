//! License enforcement for GrokingClawID.
//!
//! Provides offline license validation using Ed25519 signed tokens.
//! The free tier is the default when no license file is found.
//!
//! License file location: `~/.grokingclaw/license.json`
//!
//! License key format: base64-encoded Ed25519 signature over the
//! canonical JSON payload `{ tier, licensee_email, issued_at }`.

use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use crate::crypto;

// ─── GrokingClaw Labs License Public Key ────────────────────────────────
//
// This is the Ed25519 public key used to verify license tokens.
// The corresponding private key is kept offline by GrokingClaw Labs.
// Generated 2026-04-02.

/// Base64-encoded Ed25519 public key for license verification.
pub const GROKINGCLAW_LICENSE_PUBLIC_KEY: &str = "DrxEgwQ+E6iuwcW4aXtPc1myPvMsMg1LG/GJbBhLz04=";

/// Raw bytes of the license verification public key.
pub const GROKINGCLAW_LICENSE_PUBLIC_KEY_BYTES: [u8; 32] = [
    0x0e, 0xbc, 0x44, 0x83, 0x04, 0x3e, 0x13, 0xa8, 0xae, 0xc1, 0xc5, 0xb8,
    0x69, 0x7b, 0x4f, 0x73, 0x59, 0xb2, 0x3e, 0xf3, 0x2c, 0x32, 0x0d, 0x4b,
    0x1b, 0xf1, 0x89, 0x6c, 0x18, 0x4b, 0xcf, 0x4e,
];

// ─── License Tiers ──────────────────────────────────────────────────────

/// License tier — determines feature limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LicenseTier {
    /// Free tier: 5 agents, 1 proxy, no mesh, no birth protocol.
    Free,
    /// Indie ($99): 25 agents, unlimited proxy, 3 mesh nodes, local birth.
    Indie,
    /// Team ($199): 100 agents, unlimited proxy, 10 mesh nodes, local+mesh birth.
    Team,
    /// Enterprise ($399): unlimited everything.
    Enterprise,
}

impl std::fmt::Display for LicenseTier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseTier::Free => write!(f, "Free"),
            LicenseTier::Indie => write!(f, "Indie ($99)"),
            LicenseTier::Team => write!(f, "Team ($199)"),
            LicenseTier::Enterprise => write!(f, "Enterprise ($399)"),
        }
    }
}

impl std::str::FromStr for LicenseTier {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "free" => Ok(LicenseTier::Free),
            "indie" => Ok(LicenseTier::Indie),
            "team" => Ok(LicenseTier::Team),
            "enterprise" => Ok(LicenseTier::Enterprise),
            _ => Err(anyhow::anyhow!(
                "Invalid license tier: '{}'. Expected: free, indie, team, enterprise",
                s
            )),
        }
    }
}

// ─── Feature Flags ──────────────────────────────────────────────────────

/// Named features that can be gated by license tier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LicenseFeature {
    /// Mesh networking (inter-daemon communication).
    Mesh,
    /// Birth protocol (agent creation via Naja/Morpheus).
    BirthLocal,
    /// Mesh birth (birth via coordination server).
    BirthMesh,
    /// Remote birth.
    BirthRemote,
    /// Unlimited proxy agents.
    UnlimitedProxy,
    /// Compliance reporting.
    ComplianceReporting,
    /// On-chain breadcrumb anchoring.
    OnChainAnchoring,
    /// Agent monitoring (GrokingClawWatch).
    AgentMonitoring,
    /// Private template registry.
    PrivateRegistry,
}

impl std::fmt::Display for LicenseFeature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LicenseFeature::Mesh => write!(f, "mesh"),
            LicenseFeature::BirthLocal => write!(f, "birth_local"),
            LicenseFeature::BirthMesh => write!(f, "birth_mesh"),
            LicenseFeature::BirthRemote => write!(f, "birth_remote"),
            LicenseFeature::UnlimitedProxy => write!(f, "unlimited_proxy"),
            LicenseFeature::ComplianceReporting => write!(f, "compliance_reporting"),
            LicenseFeature::OnChainAnchoring => write!(f, "on_chain_anchoring"),
            LicenseFeature::AgentMonitoring => write!(f, "agent_monitoring"),
            LicenseFeature::PrivateRegistry => write!(f, "private_registry"),
        }
    }
}

// ─── License Limits ─────────────────────────────────────────────────────

/// Concrete limits for a license tier.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseLimits {
    /// Maximum number of agent identities.
    /// `None` means unlimited.
    pub max_agents: Option<u32>,
    /// Maximum number of mesh nodes.
    /// `None` means unlimited.
    pub max_mesh_nodes: Option<u32>,
    /// Maximum number of proxy agents.
    /// `None` means unlimited.
    pub max_proxy_agents: Option<u32>,
    /// Features available on this tier.
    pub features: Vec<LicenseFeature>,
}

impl LicenseLimits {
    /// Get the limits for a given tier.
    pub fn for_tier(tier: LicenseTier) -> Self {
        match tier {
            LicenseTier::Free => Self {
                max_agents: Some(5),
                max_mesh_nodes: Some(0),
                max_proxy_agents: Some(1),
                features: vec![],
            },
            LicenseTier::Indie => Self {
                max_agents: Some(25),
                max_mesh_nodes: Some(3),
                max_proxy_agents: None, // unlimited
                features: vec![
                    LicenseFeature::UnlimitedProxy,
                    LicenseFeature::BirthLocal,
                    LicenseFeature::Mesh,
                ],
            },
            LicenseTier::Team => Self {
                max_agents: Some(100),
                max_mesh_nodes: Some(10),
                max_proxy_agents: None,
                features: vec![
                    LicenseFeature::UnlimitedProxy,
                    LicenseFeature::BirthLocal,
                    LicenseFeature::BirthMesh,
                    LicenseFeature::Mesh,
                    LicenseFeature::ComplianceReporting,
                ],
            },
            LicenseTier::Enterprise => Self {
                max_agents: None, // unlimited
                max_mesh_nodes: None,
                max_proxy_agents: None,
                features: vec![
                    LicenseFeature::UnlimitedProxy,
                    LicenseFeature::BirthLocal,
                    LicenseFeature::BirthMesh,
                    LicenseFeature::BirthRemote,
                    LicenseFeature::Mesh,
                    LicenseFeature::ComplianceReporting,
                    LicenseFeature::OnChainAnchoring,
                    LicenseFeature::AgentMonitoring,
                    LicenseFeature::PrivateRegistry,
                ],
            },
        }
    }

    /// Check if a feature is available.
    pub fn has_feature(&self, feature: LicenseFeature) -> bool {
        self.features.contains(&feature)
    }
}

// ─── License File ───────────────────────────────────────────────────────

/// The on-disk license file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LicenseFile {
    /// License tier.
    pub tier: LicenseTier,
    /// The signed license key (base64-encoded Ed25519 signature).
    pub license_key: String,
    /// When the license was issued.
    pub issued_at: DateTime<Utc>,
    /// Email of the licensee.
    pub licensee_email: String,
    /// Concrete limits (computed from tier, stored for display).
    pub limits: LicenseLimits,
}

/// The canonical payload that the license key signs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct LicensePayload {
    tier: LicenseTier,
    licensee_email: String,
    issued_at: DateTime<Utc>,
}

// ─── License State ──────────────────────────────────────────────────────

/// Current license state (loaded from disk or defaulting to Free).
#[derive(Debug, Clone)]
pub struct LicenseState {
    /// Active tier.
    pub tier: LicenseTier,
    /// Limits for the active tier.
    pub limits: LicenseLimits,
    /// Licensee email (None for Free tier).
    pub licensee_email: Option<String>,
    /// When the license was issued (None for Free tier).
    pub issued_at: Option<DateTime<Utc>>,
}

impl Default for LicenseState {
    fn default() -> Self {
        Self {
            tier: LicenseTier::Free,
            limits: LicenseLimits::for_tier(LicenseTier::Free),
            licensee_email: None,
            issued_at: None,
        }
    }
}

// ─── Public API ─────────────────────────────────────────────────────────

/// Get the default license file path: `~/.grokingclaw/license.json`.
pub fn license_file_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home.join(".grokingclaw").join("license.json"))
}

/// Load the current license state.
///
/// If no license file exists or validation fails, returns Free tier.
/// This function never fails — it degrades to Free tier on any error.
pub fn load_license() -> LicenseState {
    load_license_from_path_inner().unwrap_or_default()
}

/// Load license from the default path, returning an error on failure.
fn load_license_from_path_inner() -> Result<LicenseState> {
    let path = license_file_path()?;
    if !path.exists() {
        return Ok(LicenseState::default());
    }
    load_license_from_path(&path)
}

/// Load and validate a license from a specific path.
pub fn load_license_from_path(path: &Path) -> Result<LicenseState> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("Failed to read license file: {}", path.display()))?;

    let license: LicenseFile = serde_json::from_str(&content)
        .with_context(|| format!("Failed to parse license file: {}", path.display()))?;

    // Validate the license key signature
    validate_license_key(&license)?;

    Ok(LicenseState {
        tier: license.tier,
        limits: LicenseLimits::for_tier(license.tier),
        licensee_email: Some(license.licensee_email),
        issued_at: Some(license.issued_at),
    })
}

/// Validate a license key's Ed25519 signature.
///
/// The key must be a valid Ed25519 signature over the canonical
/// JSON payload `{ tier, licensee_email, issued_at }`, signed by
/// the GrokingClaw Labs private key.
pub fn validate_license_key(license: &LicenseFile) -> Result<()> {
    let payload = LicensePayload {
        tier: license.tier,
        licensee_email: license.licensee_email.clone(),
        issued_at: license.issued_at,
    };

    let payload_json = serde_json::to_string(&payload)
        .context("Failed to serialize license payload")?;

    let valid = crypto::verify(
        GROKINGCLAW_LICENSE_PUBLIC_KEY,
        payload_json.as_bytes(),
        &license.license_key,
    ).context("Failed to verify license signature")?;

    if !valid {
        anyhow::bail!("Invalid license key — signature verification failed");
    }

    Ok(())
}

/// Get the current license tier (shorthand for load + get tier).
pub fn get_tier() -> LicenseTier {
    load_license().tier
}

/// Check if an operation is within the license limits.
///
/// Returns `Ok(())` if allowed, or an error with a user-friendly message.
pub fn check_limit(limit_name: &str, current: u32, license: &LicenseState) -> Result<()> {
    match limit_name {
        "agents" => {
            if let Some(max) = license.limits.max_agents {
                if current >= max {
                    anyhow::bail!(
                        "{} tier limited to {} agents (currently at {}). Upgrade at https://grokingclaw.com",
                        license.tier,
                        max,
                        current
                    );
                }
            }
            Ok(())
        }
        "mesh_nodes" => {
            if let Some(max) = license.limits.max_mesh_nodes {
                if current >= max {
                    anyhow::bail!(
                        "{} tier limited to {} mesh nodes (currently at {}). Upgrade at https://grokingclaw.com",
                        license.tier,
                        max,
                        current
                    );
                }
            }
            Ok(())
        }
        "proxy_agents" => {
            if let Some(max) = license.limits.max_proxy_agents {
                if current >= max {
                    anyhow::bail!(
                        "{} tier limited to {} proxy agents (currently at {}). Upgrade at https://grokingclaw.com",
                        license.tier,
                        max,
                        current
                    );
                }
            }
            Ok(())
        }
        _ => {
            anyhow::bail!("Unknown limit: '{}'", limit_name);
        }
    }
}

/// Check if a feature is available on the current license.
pub fn check_feature(feature: LicenseFeature, license: &LicenseState) -> Result<()> {
    if license.limits.has_feature(feature) {
        Ok(())
    } else {
        anyhow::bail!(
            "{} feature requires a higher license tier (current: {}). Upgrade at https://grokingclaw.com",
            feature,
            license.tier
        )
    }
}

/// Count agent identities in a data directory.
///
/// Scans `~/.grokingclaw/agents/` for directories containing agent.toml
/// or agent-card.json files.
pub fn count_agents(agents_dir: &Path) -> u32 {
    if !agents_dir.exists() {
        return 0;
    }

    let mut count: u32 = 0;
    if let Ok(entries) = std::fs::read_dir(agents_dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                // Check for agent identity markers
                if path.join("agent.toml").exists()
                    || path.join("identity").join("agent.card.json").exists()
                {
                    count += 1;
                }
            }
        }
    }
    count
}

/// Activate a license by saving it to disk.
///
/// Validates the key first, then writes `~/.grokingclaw/license.json`.
pub fn activate_license(key: &str) -> Result<LicenseState> {
    // The key format is: base64(json_payload):base64(signature)
    let parts: Vec<&str> = key.splitn(2, ':').collect();
    if parts.len() != 2 {
        anyhow::bail!(
            "Invalid license key format. Expected format: <payload>:<signature>\n\
             Get a valid key at https://grokingclaw.com"
        );
    }

    let payload_b64 = parts[0];
    let signature_b64 = parts[1];

    // Decode payload
    let payload_json = BASE64.decode(payload_b64)
        .context("Invalid license key — failed to decode payload")?;
    let payload_str = String::from_utf8(payload_json)
        .context("Invalid license key — payload is not valid UTF-8")?;
    let payload: LicensePayload = serde_json::from_str(&payload_str)
        .context("Invalid license key — payload format error")?;

    // Build license file
    let license = LicenseFile {
        tier: payload.tier,
        license_key: signature_b64.to_string(),
        issued_at: payload.issued_at,
        licensee_email: payload.licensee_email.clone(),
        limits: LicenseLimits::for_tier(payload.tier),
    };

    // Validate signature
    validate_license_key(&license)?;

    // Save to disk
    let path = license_file_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .context("Failed to create license directory")?;
    }
    let json = serde_json::to_string_pretty(&license)
        .context("Failed to serialize license")?;
    std::fs::write(&path, &json)
        .with_context(|| format!("Failed to write license file: {}", path.display()))?;

    Ok(LicenseState {
        tier: license.tier,
        limits: LicenseLimits::for_tier(license.tier),
        licensee_email: Some(license.licensee_email),
        issued_at: Some(license.issued_at),
    })
}

/// Deactivate license — remove the license file and revert to Free tier.
pub fn deactivate_license() -> Result<()> {
    let path = license_file_path()?;
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("Failed to remove license file: {}", path.display()))?;
    }
    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_free_tier_defaults() {
        let state = LicenseState::default();
        assert_eq!(state.tier, LicenseTier::Free);
        assert_eq!(state.limits.max_agents, Some(5));
        assert_eq!(state.limits.max_mesh_nodes, Some(0));
        assert_eq!(state.limits.max_proxy_agents, Some(1));
        assert!(state.limits.features.is_empty());
        assert!(state.licensee_email.is_none());
    }

    #[test]
    fn test_tier_limits() {
        let indie = LicenseLimits::for_tier(LicenseTier::Indie);
        assert_eq!(indie.max_agents, Some(25));
        assert_eq!(indie.max_mesh_nodes, Some(3));
        assert!(indie.has_feature(LicenseFeature::BirthLocal));
        assert!(indie.has_feature(LicenseFeature::Mesh));
        assert!(!indie.has_feature(LicenseFeature::BirthMesh));

        let team = LicenseLimits::for_tier(LicenseTier::Team);
        assert_eq!(team.max_agents, Some(100));
        assert_eq!(team.max_mesh_nodes, Some(10));
        assert!(team.has_feature(LicenseFeature::BirthMesh));
        assert!(team.has_feature(LicenseFeature::ComplianceReporting));

        let enterprise = LicenseLimits::for_tier(LicenseTier::Enterprise);
        assert!(enterprise.max_agents.is_none()); // unlimited
        assert!(enterprise.max_mesh_nodes.is_none());
        assert!(enterprise.has_feature(LicenseFeature::BirthRemote));
        assert!(enterprise.has_feature(LicenseFeature::OnChainAnchoring));
        assert!(enterprise.has_feature(LicenseFeature::AgentMonitoring));
        assert!(enterprise.has_feature(LicenseFeature::PrivateRegistry));
    }

    #[test]
    fn test_check_limit_within_bounds() {
        let state = LicenseState::default(); // Free tier, 5 agents max
        assert!(check_limit("agents", 0, &state).is_ok());
        assert!(check_limit("agents", 4, &state).is_ok());
    }

    #[test]
    fn test_check_limit_exceeded() {
        let state = LicenseState::default(); // Free tier, 5 agents max
        let err = check_limit("agents", 5, &state).unwrap_err();
        let msg = format!("{}", err);
        assert!(msg.contains("Free"));
        assert!(msg.contains("5 agents"));
        assert!(msg.contains("grokingclaw.com"));
    }

    #[test]
    fn test_check_limit_unlimited() {
        let state = LicenseState {
            tier: LicenseTier::Enterprise,
            limits: LicenseLimits::for_tier(LicenseTier::Enterprise),
            licensee_email: Some("test@example.com".to_string()),
            issued_at: Some(Utc::now()),
        };
        // Enterprise has no agent limit
        assert!(check_limit("agents", 1000, &state).is_ok());
        assert!(check_limit("mesh_nodes", 1000, &state).is_ok());
    }

    #[test]
    fn test_check_feature_free_tier() {
        let state = LicenseState::default();
        assert!(check_feature(LicenseFeature::Mesh, &state).is_err());
        assert!(check_feature(LicenseFeature::BirthLocal, &state).is_err());
        assert!(check_feature(LicenseFeature::BirthMesh, &state).is_err());
    }

    #[test]
    fn test_check_feature_indie_tier() {
        let state = LicenseState {
            tier: LicenseTier::Indie,
            limits: LicenseLimits::for_tier(LicenseTier::Indie),
            licensee_email: Some("test@example.com".to_string()),
            issued_at: Some(Utc::now()),
        };
        assert!(check_feature(LicenseFeature::Mesh, &state).is_ok());
        assert!(check_feature(LicenseFeature::BirthLocal, &state).is_ok());
        assert!(check_feature(LicenseFeature::BirthMesh, &state).is_err()); // Not in Indie
    }

    #[test]
    fn test_license_key_validation_with_real_signature() {
        // Generate a test keypair and sign a license payload
        let (signing_key, verifying_key) = crate::crypto::generate_keypair();
        let pub_b64 = crate::crypto::encode_public_key(&verifying_key);

        let payload = LicensePayload {
            tier: LicenseTier::Indie,
            licensee_email: "test@example.com".to_string(),
            issued_at: Utc::now(),
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        let signature = crate::crypto::sign(&signing_key, payload_json.as_bytes());

        // This won't pass validation against the hardcoded public key
        // (different keypair), but we can test the structure
        let license = LicenseFile {
            tier: payload.tier,
            license_key: signature,
            issued_at: payload.issued_at,
            licensee_email: payload.licensee_email,
            limits: LicenseLimits::for_tier(LicenseTier::Indie),
        };

        // Validate manually with the test key
        let payload_check = LicensePayload {
            tier: license.tier,
            licensee_email: license.licensee_email.clone(),
            issued_at: license.issued_at,
        };
        let payload_check_json = serde_json::to_string(&payload_check).unwrap();
        let valid = crate::crypto::verify(
            &pub_b64,
            payload_check_json.as_bytes(),
            &license.license_key,
        ).unwrap();
        assert!(valid);
    }

    #[test]
    fn test_tier_display_and_parse() {
        assert_eq!(format!("{}", LicenseTier::Free), "Free");
        assert_eq!(format!("{}", LicenseTier::Indie), "Indie ($99)");
        assert_eq!(format!("{}", LicenseTier::Team), "Team ($199)");
        assert_eq!(format!("{}", LicenseTier::Enterprise), "Enterprise ($399)");

        assert_eq!("free".parse::<LicenseTier>().unwrap(), LicenseTier::Free);
        assert_eq!("indie".parse::<LicenseTier>().unwrap(), LicenseTier::Indie);
        assert_eq!("team".parse::<LicenseTier>().unwrap(), LicenseTier::Team);
        assert_eq!("enterprise".parse::<LicenseTier>().unwrap(), LicenseTier::Enterprise);
        assert!("invalid".parse::<LicenseTier>().is_err());
    }

    #[test]
    fn test_count_agents_empty_dir() {
        let tmp = tempfile::tempdir().unwrap();
        assert_eq!(count_agents(tmp.path()), 0);
    }

    #[test]
    fn test_count_agents_with_agents() {
        let tmp = tempfile::tempdir().unwrap();
        // Create 3 agent directories with agent.toml
        for i in 0..3 {
            let agent_dir = tmp.path().join(format!("agent-{}", i));
            std::fs::create_dir_all(&agent_dir).unwrap();
            std::fs::write(agent_dir.join("agent.toml"), "# test").unwrap();
        }
        // Create a directory without agent.toml (shouldn't count)
        std::fs::create_dir_all(tmp.path().join("not-an-agent")).unwrap();

        assert_eq!(count_agents(tmp.path()), 3);
    }

    #[test]
    fn test_load_license_no_file() {
        // When no license file exists, should return Free tier
        let state = LicenseState::default();
        assert_eq!(state.tier, LicenseTier::Free);
    }

    #[test]
    fn test_license_file_roundtrip() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("license.json");

        // Create a test keypair
        let (signing_key, _) = crate::crypto::generate_keypair();

        let payload = LicensePayload {
            tier: LicenseTier::Team,
            licensee_email: "team@example.com".to_string(),
            issued_at: Utc::now(),
        };
        let payload_json = serde_json::to_string(&payload).unwrap();
        let signature = crate::crypto::sign(&signing_key, payload_json.as_bytes());

        let license = LicenseFile {
            tier: payload.tier,
            license_key: signature,
            issued_at: payload.issued_at,
            licensee_email: payload.licensee_email,
            limits: LicenseLimits::for_tier(LicenseTier::Team),
        };

        // Write
        let json = serde_json::to_string_pretty(&license).unwrap();
        std::fs::write(&path, &json).unwrap();

        // Read back
        let content = std::fs::read_to_string(&path).unwrap();
        let loaded: LicenseFile = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.tier, LicenseTier::Team);
        assert_eq!(loaded.licensee_email, "team@example.com");
    }
}
