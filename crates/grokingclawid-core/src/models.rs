//! Data models for GrokingClawID.
//!
//! Defines the core types: AgentCard, DelegationToken, AuditEntry,
//! HybridSignature, SPIFFE ID, and A2A agent card export.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// The cryptographic scheme used for signing.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CryptoScheme {
    /// Ed25519 only (classical).
    #[serde(rename = "ed25519")]
    Ed25519,
    /// ML-DSA-65 only (post-quantum, FIPS 204).
    #[serde(rename = "ml-dsa-65")]
    MlDsa65,
    /// Hybrid: Ed25519 + ML-DSA-65 (both must validate).
    #[serde(rename = "hybrid")]
    Hybrid,
}

impl std::fmt::Display for CryptoScheme {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CryptoScheme::Ed25519 => write!(f, "ed25519"),
            CryptoScheme::MlDsa65 => write!(f, "ml-dsa-65"),
            CryptoScheme::Hybrid => write!(f, "hybrid (ed25519 + ml-dsa-65)"),
        }
    }
}

impl std::str::FromStr for CryptoScheme {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().replace('_', "-").as_str() {
            "ed25519" => Ok(CryptoScheme::Ed25519),
            "ml-dsa-65" | "mldsa65" | "dilithium" | "pq" => Ok(CryptoScheme::MlDsa65),
            "hybrid" => Ok(CryptoScheme::Hybrid),
            _ => Err(anyhow::anyhow!(
                "Invalid crypto scheme: '{}'. Expected: ed25519, ml-dsa-65, hybrid",
                s
            )),
        }
    }
}

/// The type classification for an agent identity.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AgentType {
    /// A persistent agent type definition (template).
    Type,
    /// A running instance of an agent.
    Instance,
    /// A short-lived session credential.
    Session,
}

impl std::fmt::Display for AgentType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentType::Type => write!(f, "type"),
            AgentType::Instance => write!(f, "instance"),
            AgentType::Session => write!(f, "session"),
        }
    }
}

impl std::str::FromStr for AgentType {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "type" => Ok(AgentType::Type),
            "instance" => Ok(AgentType::Instance),
            "session" => Ok(AgentType::Session),
            _ => Err(anyhow::anyhow!(
                "Invalid agent type: '{}'. Expected: type, instance, session",
                s
            )),
        }
    }
}

/// A hybrid signature containing both Ed25519 and ML-DSA-65 components.
/// Both must validate for the signature to be considered valid.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Base64-encoded Ed25519 signature.
    pub ed25519: String,
    /// Base64-encoded ML-DSA-65 signature.
    pub mldsa65: String,
}

/// An A2A-compatible agent identity card.
///
/// Contains the agent's public key(s), scopes, metadata, and signature(s)
/// proving the card was issued by the holder of the corresponding private key(s).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentCard {
    /// Unique identifier for this agent.
    pub id: Uuid,
    /// Human-readable agent name.
    pub name: String,
    /// Owner identifier (e.g., email).
    pub owner: String,
    /// Authorized scopes (e.g., ["read", "write"]).
    pub scopes: Vec<String>,
    /// Base64-encoded Ed25519 public key.
    pub public_key: String,
    /// Base64-encoded ML-DSA-65 public key (if hybrid or pq-only).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
    /// Ed25519 signature (for ed25519 or hybrid schemes).
    pub signature: String,
    /// ML-DSA-65 signature (for hybrid scheme).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
    /// Cryptographic scheme used.
    pub crypto_scheme: CryptoScheme,
    /// When this card was issued.
    pub issued_at: DateTime<Utc>,
    /// When this card expires.
    pub expires_at: DateTime<Utc>,
    /// Classification of this agent identity.
    pub agent_type: AgentType,
    /// If this agent was delegated from a parent, the parent's ID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<Uuid>,
    /// SPIFFE ID for workload identity (e.g., "spiffe://example.org/agent/my-agent").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spiffe_id: Option<String>,
}

/// A delegation token that grants a sub-agent narrowed permissions
/// derived from a parent agent's identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegationToken {
    /// Unique identifier for this delegation.
    pub id: Uuid,
    /// The parent agent's ID that issued this delegation.
    pub parent_id: Uuid,
    /// Name of the delegated sub-agent.
    pub agent_name: String,
    /// Scopes granted (must be a subset of parent's scopes).
    pub scopes: Vec<String>,
    /// When this delegation was issued.
    pub issued_at: DateTime<Utc>,
    /// When this delegation expires (must be before parent's expiry).
    pub expires_at: DateTime<Utc>,
    /// Ed25519 signature by the parent's key.
    pub signature: String,
    /// ML-DSA-65 signature by the parent's key (if hybrid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_signature: Option<String>,
    /// Cryptographic scheme used.
    pub crypto_scheme: CryptoScheme,
}

/// A single entry in the tamper-evident audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Auto-incremented row ID.
    pub id: i64,
    /// The agent that performed the action.
    pub agent_id: Uuid,
    /// What action was performed.
    pub action: String,
    /// The target of the action.
    pub target: String,
    /// Unix timestamp (seconds since epoch).
    pub timestamp: i64,
    /// Hash of the previous audit entry (or "genesis" for the first).
    pub prev_hash: String,
    /// SHA-256 hash of this entry (includes prev_hash for chaining).
    pub entry_hash: String,
    /// Base64-encoded Ed25519 signature over entry_hash.
    pub signature: String,
}

/// A transaction receipt with both classical and post-quantum signatures.
///
/// This is the PQ-native proof that an agent authorized a transaction.
/// Even when Ed25519 is broken by quantum computers, the ML-DSA-65
/// attestation proves who signed what.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletReceipt {
    /// Transaction digest on-chain.
    pub tx_digest: String,
    /// Sender IOTA address.
    pub sender: String,
    /// Recipient IOTA address.
    pub recipient: String,
    /// Amount in nanos.
    pub amount_nanos: u64,
    /// Network (testnet/devnet/mainnet).
    pub network: String,
    /// Agent ID that authorized the transfer.
    pub agent_id: String,
    /// Agent name.
    pub agent_name: String,
    /// Crypto scheme used for attestation.
    pub crypto_scheme: CryptoScheme,
    /// PQ attestation (ML-DSA-65 over the same tx digest).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_attestation: Option<PqAttestation>,
    /// ISO 8601 timestamp.
    pub timestamp: String,
}

/// Post-quantum attestation embedded in a wallet receipt.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PqAttestation {
    /// BLAKE2b-256 digest of (intent || tx_bytes).
    pub tx_digest: String,
    /// Base64-encoded ML-DSA-65 signature.
    pub mldsa65_signature: String,
    /// Base64-encoded ML-DSA-65 public key.
    pub mldsa65_public_key: String,
    /// When the attestation was created.
    pub attested_at: String,
}

/// A2A-compatible agent card export format.
/// Follows the Google A2A specification for agent discovery.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aAgentCard {
    /// Agent name.
    pub name: String,
    /// Agent description.
    pub description: String,
    /// Agent's public URL or identifier.
    pub url: String,
    /// Provider information.
    pub provider: A2aProvider,
    /// Agent capabilities.
    pub capabilities: A2aCapabilities,
    /// Authentication information.
    pub authentication: A2aAuthentication,
    /// Skills / scopes this agent supports.
    pub skills: Vec<A2aSkill>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aProvider {
    pub organization: String,
    pub url: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct A2aCapabilities {
    pub streaming: bool,
    pub push_notifications: bool,
    pub state_transition_history: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAuthentication {
    pub schemes: Vec<String>,
    /// Ed25519 public key for verification.
    pub public_key: String,
    /// ML-DSA-65 public key for PQ verification (if hybrid).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pq_public_key: Option<String>,
    /// Cryptographic scheme.
    pub crypto_scheme: CryptoScheme,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aSkill {
    pub id: String,
    pub name: String,
    pub description: String,
}

impl AgentCard {
    /// Generate a SPIFFE ID for this agent.
    /// Format: spiffe://<trust_domain>/agent/<agent_type>/<agent_name>
    pub fn generate_spiffe_id(trust_domain: &str, name: &str, agent_type: &AgentType) -> String {
        let type_segment = match agent_type {
            AgentType::Type => "type",
            AgentType::Instance => "instance",
            AgentType::Session => "session",
        };
        // Sanitize name for URI path
        let safe_name: String = name
            .chars()
            .map(|c| {
                if c.is_alphanumeric() || c == '-' || c == '_' {
                    c
                } else {
                    '-'
                }
            })
            .collect();
        format!(
            "spiffe://{}/agent/{}/{}",
            trust_domain, type_segment, safe_name
        )
    }

    /// Export this agent card to A2A format.
    pub fn to_a2a(&self, base_url: &str) -> A2aAgentCard {
        let skills: Vec<A2aSkill> = self
            .scopes
            .iter()
            .enumerate()
            .map(|(i, scope)| A2aSkill {
                id: format!("skill-{}", i),
                name: scope.clone(),
                description: format!("Authorized scope: {}", scope),
            })
            .collect();

        A2aAgentCard {
            name: self.name.clone(),
            description: format!(
                "Agent {} ({}), owner: {}",
                self.name, self.agent_type, self.owner
            ),
            url: format!("{}/agents/{}", base_url.trim_end_matches('/'), self.id),
            provider: A2aProvider {
                organization: self.owner.clone(),
                url: base_url.to_string(),
            },
            capabilities: A2aCapabilities {
                streaming: false,
                push_notifications: false,
                state_transition_history: true,
            },
            authentication: A2aAuthentication {
                schemes: vec!["ed25519-jws".to_string()],
                public_key: self.public_key.clone(),
                pq_public_key: self.pq_public_key.clone(),
                crypto_scheme: self.crypto_scheme.clone(),
            },
            skills,
        }
    }
}
