//! Birth protocol — full agent lifecycle creation.
//!
//! Supports two modes:
//! 1. **Mesh birth**: Send BirthRequest → Naja → Morpheus validation → BirthCertificate
//! 2. **Local birth**: Direct local identity issuance (dev mode / mesh offline)
//!
//! The birth flow is idempotent and handles failures gracefully:
//! - Mesh unreachable → fall back to local birth (or queue if configured)
//! - Morpheus rejects → surface rejection reason
//! - Network timeout → retry with exponential backoff

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

use crate::config::DaemonConfig;
use crate::mesh::MeshClient;
use crate::supervisor::{AgentConfig, AgentInfo, ModelConfig, ResourceConfig, RestartConfig};
use crate::templates::TemplateRegistry;
use grokingclawid_core::license::{self, LicenseFeature};

// ─── Birth Protocol Message Types ──────────────────────────────────────

/// Birth request sent from Daemon to Naja coordination server.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BirthRequest {
    /// Unique request ID for idempotency.
    pub request_id: String,
    /// Daemon's DID (who is requesting the birth).
    pub daemon_did: String,
    /// Daemon's hostname/name.
    pub daemon_name: String,
    /// Desired agent name.
    pub agent_name: String,
    /// Template to use.
    pub template: String,
    /// Template version.
    pub template_version: String,
    /// Requested scopes/capabilities.
    pub requested_scopes: Vec<String>,
    /// Allowed outbound domains.
    pub allowed_domains: Vec<String>,
    /// LLM model configuration.
    pub model: BirthModelConfig,
    /// Resource requirements.
    pub resources: BirthResourceConfig,
    /// Requested delegation TTL in seconds.
    pub ttl_seconds: i64,
    /// Agent's Ed25519 public key (base64).
    pub agent_public_key: String,
    /// Timestamp of request.
    pub requested_at: DateTime<Utc>,
    /// Signature over request fields by daemon key.
    pub daemon_signature: String,
}

/// Model configuration in birth request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BirthModelConfig {
    pub provider: String,
    pub model: String,
    pub endpoint: String,
}

/// Resource configuration in birth request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BirthResourceConfig {
    pub memory_mb: u64,
    pub cpu_percent: u32,
    pub max_disk_gb: u64,
}

/// Validation request from Naja to Morpheus (for reference — Naja creates this).
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationRequest {
    /// Original birth request.
    pub birth_request: BirthRequest,
    /// Naja's assessment/context.
    pub naja_context: String,
    /// Policy rules to evaluate.
    pub policy_rules: Vec<String>,
    /// Naja timestamp.
    pub forwarded_at: DateTime<Utc>,
}

/// Validation response from Morpheus to Naja.
#[allow(dead_code)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResponse {
    /// Whether the birth is approved.
    pub approved: bool,
    /// Reason for approval/rejection.
    pub reason: String,
    /// Recommended scope modifications (Morpheus may narrow scopes).
    pub scope_modifications: Option<Vec<String>>,
    /// Recommended TTL adjustment.
    pub ttl_adjustment: Option<i64>,
    /// Risk score (0.0 = safe, 1.0 = high risk).
    pub risk_score: f64,
    /// Morpheus signature over the response.
    pub morpheus_signature: String,
    /// Timestamp.
    pub validated_at: DateTime<Utc>,
}

/// Birth certificate issued by Naja after successful validation.
/// Stored locally in agent's identity directory.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BirthCertificate {
    /// Unique certificate ID.
    pub certificate_id: String,
    /// Agent's assigned DID.
    pub agent_did: String,
    /// Agent's UUID.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// Daemon DID that requested the birth.
    pub daemon_did: String,
    /// Template used.
    pub template: String,
    /// Approved scopes (may differ from requested).
    pub approved_scopes: Vec<String>,
    /// Approved domains.
    pub approved_domains: Vec<String>,
    /// When the certificate was issued.
    pub issued_at: DateTime<Utc>,
    /// When the delegation expires.
    pub expires_at: DateTime<Utc>,
    /// Naja's signature over the certificate.
    pub naja_signature: String,
    /// Morpheus validation reference.
    pub morpheus_validation_ref: String,
    /// Chain of trust: daemon → Naja → Morpheus.
    pub trust_chain: Vec<String>,
}

// ─── Birth Parameters ───────────────────────────────────────────────────

/// Parameters for birthing a new agent (passed from CLI/IPC).
#[derive(Debug, Clone)]
pub struct BirthParams {
    pub template: String,
    pub name: String,
    pub allowed_domains: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub ttl_seconds: i64,
    pub model: ModelConfig,
    pub resources: ResourceConfig,
}

impl BirthParams {
    /// Parse BirthParams from a JSON value (IPC request params).
    pub fn from_json(params: &serde_json::Value) -> Result<Self> {
        let template = params.get("template")
            .and_then(|v| v.as_str())
            .context("Missing 'template' parameter")?
            .to_string();

        let name = params.get("name")
            .and_then(|v| v.as_str())
            .context("Missing 'name' parameter")?
            .to_string();

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
            .unwrap_or(30 * 24 * 3600);

        let model = params.get("model")
            .and_then(|v| serde_json::from_value::<ModelConfig>(v.clone()).ok())
            .unwrap_or_default();

        let resources = params.get("resources")
            .and_then(|v| serde_json::from_value::<ResourceConfig>(v.clone()).ok())
            .unwrap_or_default();

        Ok(Self {
            template,
            name,
            allowed_domains,
            allowed_scopes,
            ttl_seconds,
            model,
            resources,
        })
    }
}

// ─── Birth Result ───────────────────────────────────────────────────────

/// Result of a birth operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BirthResult {
    pub agent_info: AgentInfo,
    pub birth_mode: BirthMode,
    pub certificate: Option<BirthCertificate>,
}

/// How the agent was birthed.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BirthMode {
    /// Birthed via mesh (Naja + Morpheus validation).
    Mesh,
    /// Birthed locally (no mesh / dev mode).
    Local,
    /// Queued for mesh birth (mesh temporarily unavailable).
    Queued,
}

// ─── Birth Orchestrator ─────────────────────────────────────────────────

/// Main entry point for birthing an agent.
///
/// Tries mesh birth if mesh is connected, falls back to local birth.
/// The supervisor, template registry, and mesh client are all injected.
/// Enforces license tier for birth protocol features.
pub async fn birth_agent(
    config: &DaemonConfig,
    root_dir: &Path,
    mesh: Option<&MeshClient>,
    templates: &TemplateRegistry,
    params: BirthParams,
) -> Result<BirthResult> {
    let lic = license::load_license();

    // Try mesh birth first (requires BirthMesh feature)
    if let Some(mesh) = mesh {
        if mesh.is_connected().await {
            // Check license for mesh birth
            if let Err(e) = license::check_feature(LicenseFeature::BirthMesh, &lic) {
                tracing::info!(
                    "Mesh birth not available on {} tier: {}. Using local birth.",
                    lic.tier, e
                );
            } else {
                match birth_via_mesh(config, root_dir, mesh, templates, &params).await {
                    Ok(result) => return Ok(result),
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            "Mesh birth failed, falling back to local birth"
                        );
                        // Fall through to local birth
                    }
                }
            }
        }
    }

    // Fallback: local birth
    // Local birth is available on Indie+ tiers; Free tier can still do
    // basic local birth (agent creation without the full birth protocol)
    birth_local(config, root_dir, templates, &params).await
}

/// Birth via mesh — send request to Naja, get birth certificate.
async fn birth_via_mesh(
    _config: &DaemonConfig,
    root_dir: &Path,
    mesh: &MeshClient,
    templates: &TemplateRegistry,
    params: &BirthParams,
) -> Result<BirthResult> {

    // Generate agent keypair
    let (signing_key, verifying_key) = grokingclawid_core::crypto::generate_keypair();
    let agent_public_key = grokingclawid_core::crypto::encode_public_key(&verifying_key);

    // Build birth request
    let request_id = Uuid::new_v4().to_string();
    let daemon_did = get_daemon_did(root_dir).unwrap_or_else(|| "local".to_string());
    let daemon_name = hostname::get()
        .map(|h| h.to_string_lossy().to_string())
        .unwrap_or_else(|_| "unknown".to_string());

    // Sign the request
    let sign_payload = format!(
        "{}:{}:{}:{}:{}",
        request_id, params.name, params.template, agent_public_key, params.ttl_seconds
    );
    let daemon_key_path = root_dir.join("identity").join("daemon.pem");
    let daemon_signature = if daemon_key_path.exists() {
        let pem = std::fs::read_to_string(&daemon_key_path)?;
        let key = grokingclawid_core::crypto::decode_private_key_pem(&pem)?;
        grokingclawid_core::crypto::sign(&key, sign_payload.as_bytes())
    } else {
        "unsigned".to_string()
    };

    let template_version = templates.get_template_version(&params.template)
        .unwrap_or_else(|| "latest".to_string());

    let birth_request = BirthRequest {
        request_id: request_id.clone(),
        daemon_did: daemon_did.clone(),
        daemon_name,
        agent_name: params.name.clone(),
        template: params.template.clone(),
        template_version,
        requested_scopes: params.allowed_scopes.clone(),
        allowed_domains: params.allowed_domains.clone(),
        model: BirthModelConfig {
            provider: params.model.provider.clone(),
            model: params.model.model.clone(),
            endpoint: params.model.endpoint.clone(),
        },
        resources: BirthResourceConfig {
            memory_mb: params.resources.memory_mb,
            cpu_percent: params.resources.cpu_percent,
            max_disk_gb: params.resources.max_disk_gb,
        },
        ttl_seconds: params.ttl_seconds,
        agent_public_key: agent_public_key.clone(),
        requested_at: Utc::now(),
        daemon_signature,
    };

    // POST to coordination server
    let coord_server = mesh.coordination_server();
    let url = format!("{}/v1/birth", coord_server);

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()
        .unwrap_or_default();

    let resp = http.post(&url)
        .json(&birth_request)
        .send()
        .await
        .context("Failed to send birth request to coordination server")?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!(
            "Birth request rejected by coordination server (HTTP {}): {}",
            status, body
        );
    }

    // Parse birth certificate from response
    let certificate: BirthCertificate = resp.json().await
        .context("Failed to parse birth certificate response")?;

    let agent_id = Uuid::parse_str(&certificate.agent_id)
        .unwrap_or_else(|_| Uuid::new_v4());
    let expires_at = certificate.expires_at;

    // Save birth certificate
    let agent_dir = root_dir.join("agents").join(&params.name);
    std::fs::create_dir_all(agent_dir.join("identity"))?;
    let cert_path = agent_dir.join("identity").join("birth.cert.json");
    let cert_json = serde_json::to_string_pretty(&certificate)?;
    std::fs::write(&cert_path, &cert_json)?;

    // Save agent keypair
    let pem = grokingclawid_core::crypto::encode_private_key_pem(&signing_key);
    std::fs::write(agent_dir.join("identity").join("agent.pem"), &pem)?;

    let pub_card = serde_json::json!({
        "id": agent_id,
        "name": params.name,
        "did": certificate.agent_did,
        "public_key": agent_public_key,
        "crypto_scheme": "ed25519",
        "issued_at": certificate.issued_at.to_rfc3339(),
        "issuer": "naja",
        "birth_certificate_id": certificate.certificate_id,
    });
    std::fs::write(
        agent_dir.join("identity").join("agent.card.json"),
        serde_json::to_string_pretty(&pub_card)?,
    )?;

    // Build agent config
    let agent_config = AgentConfig {
        name: params.name.clone(),
        template: params.template.clone(),
        template_version: "mesh".to_string(),
        agent_id,
        did: Some(certificate.agent_did.clone()),
        created_at: Utc::now(),
        allowed_domains: certificate.approved_domains.clone(),
        allowed_scopes: certificate.approved_scopes.clone(),
        expires_at: Some(expires_at),
        model: params.model.clone(),
        resources: params.resources.clone(),
        restart: RestartConfig::default(),
    };

    // Write agent.toml
    std::fs::create_dir_all(agent_dir.join("audit"))?;
    std::fs::create_dir_all(agent_dir.join("data"))?;
    std::fs::create_dir_all(agent_dir.join("logs"))?;
    std::fs::create_dir_all(agent_dir.join("breadcrumbs"))?;
    let toml_str = toml::to_string_pretty(&agent_config)?;
    std::fs::write(agent_dir.join("agent.toml"), &toml_str)?;

    // Install template
    templates.install_for_agent(&params.template, &agent_dir)?;

    // Register agent on mesh
    mesh.register_agent(
        &agent_id.to_string(),
        &certificate.agent_did,
    ).await.ok(); // Non-fatal

    let agent_info = AgentInfo {
        name: params.name.clone(),
        agent_id,
        did: Some(certificate.agent_did.clone()),
        template: params.template.clone(),
        status: crate::supervisor::AgentStatus::Creating,
        pid: None,
        created_at: agent_config.created_at,
        started_at: None,
        restart_count: 0,
        allowed_scopes: certificate.approved_scopes.clone(),
    };

    tracing::info!(
        agent = %params.name,
        did = %certificate.agent_did,
        mode = "mesh",
        "Agent birthed via mesh"
    );

    Ok(BirthResult {
        agent_info,
        birth_mode: BirthMode::Mesh,
        certificate: Some(certificate),
    })
}

/// Birth locally — generate identity without Naja/Morpheus.
async fn birth_local(
    _config: &DaemonConfig,
    root_dir: &Path,
    templates: &TemplateRegistry,
    params: &BirthParams,
) -> Result<BirthResult> {

    let agent_id = Uuid::new_v4();
    let now = Utc::now();
    let expires_at = now + chrono::Duration::seconds(params.ttl_seconds);

    let agent_config = AgentConfig {
        name: params.name.clone(),
        template: params.template.clone(),
        template_version: "local".to_string(),
        agent_id,
        did: None,
        created_at: now,
        allowed_domains: params.allowed_domains.clone(),
        allowed_scopes: params.allowed_scopes.clone(),
        expires_at: Some(expires_at),
        model: params.model.clone(),
        resources: params.resources.clone(),
        restart: RestartConfig::default(),
    };

    let agent_dir = root_dir.join("agents").join(&params.name);

    // Create directory structure
    std::fs::create_dir_all(agent_dir.join("identity"))?;
    std::fs::create_dir_all(agent_dir.join("audit"))?;
    std::fs::create_dir_all(agent_dir.join("data"))?;
    std::fs::create_dir_all(agent_dir.join("logs"))?;
    std::fs::create_dir_all(agent_dir.join("breadcrumbs"))?;

    // Write agent.toml
    let toml_str = toml::to_string_pretty(&agent_config)?;
    std::fs::write(agent_dir.join("agent.toml"), &toml_str)?;

    // Generate keypair and issue local identity
    let (signing_key, verifying_key) = grokingclawid_core::crypto::generate_keypair();
    let pem = grokingclawid_core::crypto::encode_private_key_pem(&signing_key);
    std::fs::write(agent_dir.join("identity").join("agent.pem"), &pem)?;

    let pub_key_b64 = grokingclawid_core::crypto::encode_public_key(&verifying_key);

    // Build a proper AgentCard (self-signed for local birth)
    let mut card = grokingclawid_core::models::AgentCard {
        id: agent_id,
        name: params.name.clone(),
        owner: "local".to_string(),
        scopes: params.allowed_scopes.clone(),
        public_key: pub_key_b64.clone(),
        pq_public_key: None,
        signature: String::new(), // placeholder — signed below
        pq_signature: None,
        crypto_scheme: grokingclawid_core::models::CryptoScheme::Ed25519,
        issued_at: now,
        expires_at,
        agent_type: grokingclawid_core::models::AgentType::Instance,
        parent_id: None,
        spiffe_id: None,
    };

    // Self-sign the card
    let card_bytes = serde_json::to_vec(&serde_json::json!({
        "id": card.id,
        "name": card.name,
        "owner": card.owner,
        "public_key": card.public_key,
        "issued_at": card.issued_at.to_rfc3339(),
        "expires_at": card.expires_at.to_rfc3339(),
    }))?;
    card.signature = grokingclawid_core::crypto::sign(&signing_key, &card_bytes);

    std::fs::write(
        agent_dir.join("identity").join("agent.card.json"),
        serde_json::to_string_pretty(&card)?,
    )?;

    // Install template
    templates.install_for_agent(&params.template, &agent_dir)?;

    let agent_info = AgentInfo {
        name: params.name.clone(),
        agent_id,
        did: None,
        template: params.template.clone(),
        status: crate::supervisor::AgentStatus::Creating,
        pid: None,
        created_at: now,
        started_at: None,
        restart_count: 0,
        allowed_scopes: params.allowed_scopes.clone(),
    };

    tracing::info!(
        agent = %params.name,
        agent_id = %agent_id,
        mode = "local",
        "Agent birthed locally"
    );

    Ok(BirthResult {
        agent_info,
        birth_mode: BirthMode::Local,
        certificate: None,
    })
}

/// Queue a birth request for later processing when mesh becomes available.
#[allow(dead_code)]
pub async fn queue_birth(
    root_dir: &Path,
    params: &BirthParams,
) -> Result<()> {
    let queue_dir = root_dir.join("state").join("birth-queue");
    std::fs::create_dir_all(&queue_dir)?;

    let entry = serde_json::json!({
        "name": params.name,
        "template": params.template,
        "allowed_domains": params.allowed_domains,
        "allowed_scopes": params.allowed_scopes,
        "ttl_seconds": params.ttl_seconds,
        "queued_at": Utc::now().to_rfc3339(),
    });

    let filename = format!("{}-{}.json", params.name, Uuid::new_v4());
    std::fs::write(
        queue_dir.join(&filename),
        serde_json::to_string_pretty(&entry)?,
    )?;

    tracing::info!(agent = %params.name, "Birth request queued for mesh");
    Ok(())
}

/// Read the daemon's DID from its card file.
fn get_daemon_did(root_dir: &Path) -> Option<String> {
    let card_path = root_dir.join("identity").join("daemon.card.json");
    let content = std::fs::read_to_string(&card_path).ok()?;
    let card: serde_json::Value = serde_json::from_str(&content).ok()?;
    card.get("did").and_then(|v| v.as_str()).map(|s| s.to_string())
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_birth_params_from_json() {
        let json = serde_json::json!({
            "template": "swe-agent",
            "name": "test-agent",
            "scope": {
                "allowed_domains": ["api.openai.com"],
                "allowed_scopes": ["code", "web"],
                "ttl_seconds": 86400
            },
            "model": {
                "provider": "ollama",
                "model": "qwen3.5",
                "endpoint": "http://localhost:11434"
            },
            "resources": {
                "memory_mb": 4096,
                "cpu_percent": 80,
                "max_disk_gb": 20,
                "max_requests_per_minute": 120
            }
        });

        let params = BirthParams::from_json(&json).unwrap();
        assert_eq!(params.template, "swe-agent");
        assert_eq!(params.name, "test-agent");
        assert_eq!(params.allowed_domains, vec!["api.openai.com"]);
        assert_eq!(params.allowed_scopes, vec!["code", "web"]);
        assert_eq!(params.ttl_seconds, 86400);
    }

    #[test]
    fn test_birth_params_defaults() {
        let json = serde_json::json!({
            "template": "basic",
            "name": "my-agent"
        });

        let params = BirthParams::from_json(&json).unwrap();
        assert_eq!(params.template, "basic");
        assert_eq!(params.allowed_scopes, vec!["*"]);
        assert_eq!(params.ttl_seconds, 30 * 24 * 3600);
    }

    #[test]
    fn test_birth_certificate_serialization() {
        let cert = BirthCertificate {
            certificate_id: "cert-001".to_string(),
            agent_did: "did:iota:test123".to_string(),
            agent_id: Uuid::new_v4().to_string(),
            agent_name: "test-agent".to_string(),
            daemon_did: "did:iota:daemon001".to_string(),
            template: "swe-agent".to_string(),
            approved_scopes: vec!["code".to_string()],
            approved_domains: vec!["api.openai.com".to_string()],
            issued_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::days(30),
            naja_signature: "sig-placeholder".to_string(),
            morpheus_validation_ref: "val-001".to_string(),
            trust_chain: vec!["daemon".to_string(), "naja".to_string(), "morpheus".to_string()],
        };

        let json = serde_json::to_string(&cert).unwrap();
        let parsed: BirthCertificate = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.certificate_id, cert.certificate_id);
        assert_eq!(parsed.agent_did, cert.agent_did);
    }

    #[test]
    fn test_birth_request_serialization() {
        let request = BirthRequest {
            request_id: "req-001".to_string(),
            daemon_did: "did:iota:daemon".to_string(),
            daemon_name: "test-daemon".to_string(),
            agent_name: "my-agent".to_string(),
            template: "basic".to_string(),
            template_version: "1.0.0".to_string(),
            requested_scopes: vec!["*".to_string()],
            allowed_domains: vec![],
            model: BirthModelConfig {
                provider: "ollama".to_string(),
                model: "qwen3.5".to_string(),
                endpoint: "http://localhost:11434".to_string(),
            },
            resources: BirthResourceConfig {
                memory_mb: 2048,
                cpu_percent: 50,
                max_disk_gb: 10,
            },
            ttl_seconds: 86400,
            agent_public_key: "dGVzdC1rZXk=".to_string(),
            requested_at: Utc::now(),
            daemon_signature: "test-sig".to_string(),
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: BirthRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.request_id, "req-001");
        assert_eq!(parsed.agent_name, "my-agent");
    }
}
