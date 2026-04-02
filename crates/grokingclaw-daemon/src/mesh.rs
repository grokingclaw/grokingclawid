//! Mesh networking — Headscale coordination + WireGuard mesh.
//!
//! Provides mesh connectivity for agent discovery and inter-daemon
//! communication. When mesh is unavailable (dev mode), all operations
//! gracefully degrade to local-only mode.
//!
//! Architecture:
//! - MeshTransport trait abstracts network calls (testable)
//! - MeshClient manages connection state and agent registration
//! - HeadscaleTransport implements real HTTP calls to coordination server
//! - MockTransport for testing

use anyhow::{Context, Result};
use async_trait::async_trait;
use base64::Engine;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;

// ─── Types ──────────────────────────────────────────────────────────────

/// Mesh network configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    /// Coordination server URL (e.g., "https://mesh.grokingclaw.com").
    pub coordination_server: String,
    /// Path to daemon identity card.
    pub daemon_card_path: PathBuf,
    /// Path to daemon signing key.
    pub daemon_key_path: PathBuf,
    /// Path to WireGuard private key.
    pub wireguard_key_path: PathBuf,
    /// Directory for mesh state files.
    pub mesh_dir: PathBuf,
    /// Whether to auto-connect on daemon start.
    #[serde(default = "default_true")]
    pub auto_connect: bool,
}

fn default_true() -> bool {
    true
}

impl Default for MeshConfig {
    fn default() -> Self {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        let root = home.join(".grokingclaw");
        Self {
            coordination_server: "https://mesh.grokingclaw.com".to_string(),
            daemon_card_path: root.join("identity").join("daemon.card.json"),
            daemon_key_path: root.join("identity").join("daemon.pem"),
            wireguard_key_path: root.join("mesh").join("wg-private.key"),
            mesh_dir: root.join("mesh"),
            auto_connect: true,
        }
    }
}

/// Current mesh connection state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum MeshState {
    Disconnected,
    Connecting,
    Connected {
        mesh_ip: String,
        peers: Vec<MeshPeer>,
        connected_at: DateTime<Utc>,
    },
}

impl MeshState {
    pub fn is_connected(&self) -> bool {
        matches!(self, MeshState::Connected { .. })
    }
}

/// A peer on the mesh network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshPeer {
    pub name: String,
    pub did: String,
    pub mesh_ip: String,
    pub last_seen: DateTime<Utc>,
    pub agent_count: u32,
}

/// Result of mesh authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResult {
    pub success: bool,
    pub mesh_ip: Option<String>,
    pub token: Option<String>,
    pub error: Option<String>,
}

/// Result of node registration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    pub node_id: String,
    pub mesh_ip: String,
    pub wireguard_config: String,
}

/// Result of a mesh ping.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub peer_did: String,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    pub error: Option<String>,
}

// ─── Transport Trait ────────────────────────────────────────────────────

/// Abstraction over mesh network calls.
///
/// Real implementation uses reqwest HTTP to coordination server.
/// Mock implementation for testing without infrastructure.
#[async_trait]
pub trait MeshTransport: Send + Sync {
    /// Authenticate with the coordination server using ClawID challenge-response.
    async fn authenticate(
        &self,
        card: &[u8],
        challenge_response: &[u8],
    ) -> Result<AuthResult>;

    /// Register this node's WireGuard public key.
    async fn register_node(
        &self,
        wireguard_pubkey: &str,
    ) -> Result<NodeRegistration>;

    /// Register an agent for mesh discovery.
    async fn register_agent(
        &self,
        agent_id: &str,
        agent_did: &str,
    ) -> Result<()>;

    /// Deregister an agent from mesh discovery.
    async fn deregister_agent(
        &self,
        agent_id: &str,
    ) -> Result<()>;

    /// List all peers on the mesh.
    async fn list_peers(&self) -> Result<Vec<MeshPeer>>;

    /// Ping a specific peer by DID.
    async fn ping_peer(&self, peer_did: &str) -> Result<PingResult>;
}

// ─── Headscale Transport (Real) ─────────────────────────────────────────

/// Real HTTP transport that communicates with the Headscale coordination server.
pub struct HeadscaleTransport {
    coordination_server: String,
    http: reqwest::Client,
    auth_token: RwLock<Option<String>>,
}

impl HeadscaleTransport {
    pub fn new(coordination_server: &str) -> Self {
        Self {
            coordination_server: coordination_server.trim_end_matches('/').to_string(),
            http: reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_default(),
            auth_token: RwLock::new(None),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.coordination_server, path)
    }
}

#[async_trait]
impl MeshTransport for HeadscaleTransport {
    async fn authenticate(
        &self,
        card: &[u8],
        challenge_response: &[u8],
    ) -> Result<AuthResult> {
        let payload = serde_json::json!({
            "card": base64::engine::general_purpose::STANDARD.encode(card),
            "challenge_response": base64::engine::general_purpose::STANDARD.encode(challenge_response),
        });

        let resp = self.http
            .post(&self.url("/v1/auth/challenge"))
            .json(&payload)
            .send()
            .await
            .context("Failed to connect to mesh coordination server")?;

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Ok(AuthResult {
                success: false,
                mesh_ip: None,
                token: None,
                error: Some(format!("HTTP {}: {}", status, body)),
            });
        }

        let result: AuthResult = resp.json().await
            .context("Failed to parse auth response")?;

        if result.success {
            if let Some(ref token) = result.token {
                let mut stored = self.auth_token.write().await;
                *stored = Some(token.clone());
            }
        }

        Ok(result)
    }

    async fn register_node(
        &self,
        wireguard_pubkey: &str,
    ) -> Result<NodeRegistration> {
        let token = self.auth_token.read().await;
        let token = token.as_deref().context("Not authenticated — call authenticate() first")?;

        let payload = serde_json::json!({
            "wireguard_pubkey": wireguard_pubkey,
        });

        let resp = self.http
            .post(&self.url("/v1/mesh/register"))
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .context("Failed to register node")?;

        let result: NodeRegistration = resp.json().await
            .context("Failed to parse node registration response")?;

        Ok(result)
    }

    async fn register_agent(
        &self,
        agent_id: &str,
        agent_did: &str,
    ) -> Result<()> {
        let token = self.auth_token.read().await;
        let token = token.as_deref().context("Not authenticated")?;

        let payload = serde_json::json!({
            "agent_id": agent_id,
            "agent_did": agent_did,
        });

        let resp = self.http
            .post(&self.url("/v1/agents/register"))
            .bearer_auth(token)
            .json(&payload)
            .send()
            .await
            .context("Failed to register agent on mesh")?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Agent registration failed: {}", body);
        }

        Ok(())
    }

    async fn deregister_agent(
        &self,
        agent_id: &str,
    ) -> Result<()> {
        let token = self.auth_token.read().await;
        let token = token.as_deref().context("Not authenticated")?;

        let resp = self.http
            .delete(&self.url(&format!("/v1/agents/{}", agent_id)))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to deregister agent")?;

        if !resp.status().is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("Agent deregistration failed: {}", body);
        }

        Ok(())
    }

    async fn list_peers(&self) -> Result<Vec<MeshPeer>> {
        let token = self.auth_token.read().await;
        let token = token.as_deref().context("Not authenticated")?;

        let resp = self.http
            .get(&self.url("/v1/mesh/peers"))
            .bearer_auth(token)
            .send()
            .await
            .context("Failed to list mesh peers")?;

        let peers: Vec<MeshPeer> = resp.json().await
            .context("Failed to parse peers response")?;

        Ok(peers)
    }

    async fn ping_peer(&self, peer_did: &str) -> Result<PingResult> {
        let token = self.auth_token.read().await;
        let token = token.as_deref().context("Not authenticated")?;

        let resp = self.http
            .post(&self.url("/v1/mesh/ping"))
            .bearer_auth(token)
            .json(&serde_json::json!({ "peer_did": peer_did }))
            .send()
            .await
            .context("Failed to ping peer")?;

        let result: PingResult = resp.json().await
            .context("Failed to parse ping response")?;

        Ok(result)
    }
}

// ─── Mock Transport (Testing) ───────────────────────────────────────────

/// Mock transport for testing without real infrastructure.
pub struct MockTransport {
    peers: RwLock<Vec<MeshPeer>>,
    agents: RwLock<Vec<(String, String)>>,
}

impl MockTransport {
    #[allow(dead_code)]
    pub fn new() -> Self {
        Self {
            peers: RwLock::new(vec![]),
            agents: RwLock::new(vec![]),
        }
    }

    #[allow(dead_code)]
    pub fn with_peers(peers: Vec<MeshPeer>) -> Self {
        Self {
            peers: RwLock::new(peers),
            agents: RwLock::new(vec![]),
        }
    }
}

#[async_trait]
impl MeshTransport for MockTransport {
    async fn authenticate(
        &self,
        _card: &[u8],
        _challenge_response: &[u8],
    ) -> Result<AuthResult> {
        Ok(AuthResult {
            success: true,
            mesh_ip: Some("100.64.0.1".to_string()),
            token: Some("mock-token-12345".to_string()),
            error: None,
        })
    }

    async fn register_node(
        &self,
        _wireguard_pubkey: &str,
    ) -> Result<NodeRegistration> {
        Ok(NodeRegistration {
            node_id: "mock-node-001".to_string(),
            mesh_ip: "100.64.0.1".to_string(),
            wireguard_config: "[Interface]\nAddress = 100.64.0.1/32\n".to_string(),
        })
    }

    async fn register_agent(
        &self,
        agent_id: &str,
        agent_did: &str,
    ) -> Result<()> {
        let mut agents = self.agents.write().await;
        agents.push((agent_id.to_string(), agent_did.to_string()));
        Ok(())
    }

    async fn deregister_agent(
        &self,
        agent_id: &str,
    ) -> Result<()> {
        let mut agents = self.agents.write().await;
        agents.retain(|(id, _)| id != agent_id);
        Ok(())
    }

    async fn list_peers(&self) -> Result<Vec<MeshPeer>> {
        Ok(self.peers.read().await.clone())
    }

    async fn ping_peer(&self, peer_did: &str) -> Result<PingResult> {
        let peers = self.peers.read().await;
        let reachable = peers.iter().any(|p| p.did == peer_did);
        Ok(PingResult {
            peer_did: peer_did.to_string(),
            reachable,
            latency_ms: if reachable { Some(1) } else { None },
            error: if reachable { None } else { Some("Peer not found".to_string()) },
        })
    }
}

// ─── MeshClient ─────────────────────────────────────────────────────────

/// The mesh client manages mesh connectivity and agent registration.
///
/// Wraps a MeshTransport implementation and manages connection state.
/// All methods are safe to call when disconnected — they return
/// appropriate errors or no-ops.
pub struct MeshClient {
    config: MeshConfig,
    state: RwLock<MeshState>,
    transport: Arc<dyn MeshTransport>,
}

impl MeshClient {
    /// Create a new mesh client with the given config and transport.
    pub fn new(config: MeshConfig, transport: Arc<dyn MeshTransport>) -> Self {
        Self {
            config,
            state: RwLock::new(MeshState::Disconnected),
            transport,
        }
    }

    /// Create a mesh client using the real Headscale transport.
    pub fn with_headscale(config: MeshConfig) -> Self {
        let transport = Arc::new(HeadscaleTransport::new(&config.coordination_server));
        Self::new(config, transport)
    }

    /// Check if the mesh is currently connected.
    pub async fn is_connected(&self) -> bool {
        self.state.read().await.is_connected()
    }

    /// Get the current mesh state.
    pub async fn status(&self) -> MeshState {
        self.state.read().await.clone()
    }

    /// Get the coordination server URL.
    pub fn coordination_server(&self) -> &str {
        &self.config.coordination_server
    }

    /// Connect to the mesh network.
    ///
    /// Performs:
    /// 1. Load daemon card + key
    /// 2. Challenge-response auth with coordination server
    /// 3. Register WireGuard public key
    /// 4. Set up WireGuard interface (via wg-quick)
    ///
    /// Gracefully handles failures — mesh is optional.
    pub async fn connect(&self) -> Result<()> {
        // Set state to connecting
        {
            let mut state = self.state.write().await;
            *state = MeshState::Connecting;
        }

        let result = self.do_connect().await;

        match result {
            Ok(()) => {
                tracing::info!("Mesh connected successfully");
                Ok(())
            }
            Err(e) => {
                // Reset to disconnected on failure
                let mut state = self.state.write().await;
                *state = MeshState::Disconnected;
                Err(e)
            }
        }
    }

    async fn do_connect(&self) -> Result<()> {
        // Load daemon card
        let card_bytes = std::fs::read(&self.config.daemon_card_path)
            .with_context(|| format!(
                "Failed to read daemon card: {}",
                self.config.daemon_card_path.display()
            ))?;

        // Load daemon signing key for challenge-response
        let key_pem = std::fs::read_to_string(&self.config.daemon_key_path)
            .with_context(|| format!(
                "Failed to read daemon key: {}",
                self.config.daemon_key_path.display()
            ))?;
        let signing_key = grokingclawid_core::crypto::decode_private_key_pem(&key_pem)
            .context("Failed to decode daemon signing key")?;

        // Sign the card as challenge response (simplified for Phase C)
        let challenge_response = grokingclawid_core::crypto::sign(&signing_key, &card_bytes);

        // Authenticate with coordination server
        let auth = self.transport
            .authenticate(&card_bytes, challenge_response.as_bytes())
            .await
            .context("Mesh authentication failed")?;

        if !auth.success {
            anyhow::bail!(
                "Mesh authentication rejected: {}",
                auth.error.unwrap_or_else(|| "unknown reason".to_string())
            );
        }

        let mesh_ip = auth.mesh_ip
            .context("Auth succeeded but no mesh IP assigned")?;

        // Set up WireGuard if key exists
        if self.config.wireguard_key_path.exists() {
            self.setup_wireguard().await.ok(); // WireGuard setup is best-effort
        }

        // Fetch initial peer list
        let peers = self.transport.list_peers().await.unwrap_or_default();

        // Update state to connected
        let mut state = self.state.write().await;
        *state = MeshState::Connected {
            mesh_ip,
            peers,
            connected_at: Utc::now(),
        };

        Ok(())
    }

    /// Set up WireGuard interface using wg-quick.
    async fn setup_wireguard(&self) -> Result<()> {
        let wg_config = self.config.mesh_dir.join("wg0.conf");
        if !wg_config.exists() {
            tracing::warn!("No WireGuard config found at {}, skipping", wg_config.display());
            return Ok(());
        }

        tracing::info!("Setting up WireGuard interface");
        let output = tokio::process::Command::new("wg-quick")
            .args(["up", &wg_config.to_string_lossy()])
            .output()
            .await;

        match output {
            Ok(out) if out.status.success() => {
                tracing::info!("WireGuard interface up");
                Ok(())
            }
            Ok(out) => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                tracing::warn!("WireGuard setup failed (non-fatal): {}", stderr);
                Ok(()) // Non-fatal
            }
            Err(e) => {
                tracing::warn!("wg-quick not available (non-fatal): {}", e);
                Ok(()) // Non-fatal — wg-quick may not be installed
            }
        }
    }

    /// Disconnect from the mesh network.
    pub async fn disconnect(&self) -> Result<()> {
        // Tear down WireGuard
        let wg_config = self.config.mesh_dir.join("wg0.conf");
        if wg_config.exists() {
            let _ = tokio::process::Command::new("wg-quick")
                .args(["down", &wg_config.to_string_lossy()])
                .output()
                .await;
        }

        let mut state = self.state.write().await;
        *state = MeshState::Disconnected;
        tracing::info!("Mesh disconnected");
        Ok(())
    }

    /// Register an agent on the mesh for discovery.
    pub async fn register_agent(&self, agent_id: &str, agent_did: &str) -> Result<()> {
        if !self.is_connected().await {
            tracing::debug!(agent = %agent_id, "Mesh not connected, skipping agent registration");
            return Ok(());
        }

        self.transport.register_agent(agent_id, agent_did).await
            .with_context(|| format!("Failed to register agent {} on mesh", agent_id))?;

        tracing::info!(agent = %agent_id, "Agent registered on mesh");
        Ok(())
    }

    /// Deregister an agent from the mesh.
    pub async fn deregister_agent(&self, agent_id: &str) -> Result<()> {
        if !self.is_connected().await {
            return Ok(());
        }

        self.transport.deregister_agent(agent_id).await
            .with_context(|| format!("Failed to deregister agent {} from mesh", agent_id))?;

        tracing::info!(agent = %agent_id, "Agent deregistered from mesh");
        Ok(())
    }

    /// List connected mesh peers.
    pub async fn list_peers(&self) -> Result<Vec<MeshPeer>> {
        if !self.is_connected().await {
            return Ok(vec![]);
        }

        // Refresh peer list from server
        let peers = self.transport.list_peers().await?;

        // Update cached state
        let mut state = self.state.write().await;
        if let MeshState::Connected { peers: ref mut cached_peers, .. } = *state {
            *cached_peers = peers.clone();
        }

        Ok(peers)
    }

    /// Ping a peer on the mesh.
    pub async fn ping(&self, peer_did: &str) -> Result<PingResult> {
        if !self.is_connected().await {
            return Ok(PingResult {
                peer_did: peer_did.to_string(),
                reachable: false,
                latency_ms: None,
                error: Some("Not connected to mesh".to_string()),
            });
        }

        self.transport.ping_peer(peer_did).await
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> MeshConfig {
        MeshConfig {
            coordination_server: "https://test.mesh.example.com".to_string(),
            daemon_card_path: PathBuf::from("/tmp/test-card.json"),
            daemon_key_path: PathBuf::from("/tmp/test-key.pem"),
            wireguard_key_path: PathBuf::from("/tmp/test-wg.key"),
            mesh_dir: PathBuf::from("/tmp/test-mesh"),
            auto_connect: false,
        }
    }

    #[tokio::test]
    async fn test_mock_transport_auth() {
        let transport = MockTransport::new();
        let result = transport.authenticate(b"card", b"response").await.unwrap();
        assert!(result.success);
        assert!(result.mesh_ip.is_some());
    }

    #[tokio::test]
    async fn test_mock_transport_agents() {
        let transport = MockTransport::new();
        transport.register_agent("agent-1", "did:iota:test1").await.unwrap();
        transport.register_agent("agent-2", "did:iota:test2").await.unwrap();

        let agents = transport.agents.read().await;
        assert_eq!(agents.len(), 2);
        drop(agents);

        transport.deregister_agent("agent-1").await.unwrap();
        let agents = transport.agents.read().await;
        assert_eq!(agents.len(), 1);
    }

    #[tokio::test]
    async fn test_mesh_client_disconnected_status() {
        let config = test_config();
        let transport = Arc::new(MockTransport::new());
        let client = MeshClient::new(config, transport);

        assert!(!client.is_connected().await);
        let state = client.status().await;
        assert!(matches!(state, MeshState::Disconnected));
    }

    #[tokio::test]
    async fn test_mesh_client_register_agent_when_disconnected() {
        let config = test_config();
        let transport = Arc::new(MockTransport::new());
        let client = MeshClient::new(config, transport);

        // Should not error when disconnected — just no-op
        client.register_agent("agent-1", "did:iota:test1").await.unwrap();
    }

    #[tokio::test]
    async fn test_mesh_client_list_peers_when_disconnected() {
        let config = test_config();
        let transport = Arc::new(MockTransport::new());
        let client = MeshClient::new(config, transport);

        let peers = client.list_peers().await.unwrap();
        assert!(peers.is_empty());
    }

    #[tokio::test]
    async fn test_mesh_client_ping_when_disconnected() {
        let config = test_config();
        let transport = Arc::new(MockTransport::new());
        let client = MeshClient::new(config, transport);

        let result = client.ping("did:iota:test1").await.unwrap();
        assert!(!result.reachable);
        assert!(result.error.is_some());
    }

    #[tokio::test]
    async fn test_mock_transport_ping() {
        let peers = vec![MeshPeer {
            name: "node-1".to_string(),
            did: "did:iota:abc".to_string(),
            mesh_ip: "100.64.0.2".to_string(),
            last_seen: Utc::now(),
            agent_count: 3,
        }];
        let transport = MockTransport::with_peers(peers);

        let result = transport.ping_peer("did:iota:abc").await.unwrap();
        assert!(result.reachable);
        assert_eq!(result.latency_ms, Some(1));

        let result = transport.ping_peer("did:iota:unknown").await.unwrap();
        assert!(!result.reachable);
    }
}
