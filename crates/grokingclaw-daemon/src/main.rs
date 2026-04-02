//! GrokingClaw Daemon — the agent host.
//!
//! The daemon manages agent lifecycles: birth, run, monitor, stop.
//! CLI communicates via Unix domain socket (JSON-RPC 2.0).

mod anchor;
mod birth;
mod config;
mod daemon;
mod ipc;
mod mesh;
mod supervisor;
mod templates;
mod updates;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

/// GrokingClaw Daemon — AI Agent Host
#[derive(Parser)]
#[command(name = "grokingclaw")]
#[command(version)]
#[command(about = "The GrokingClaw daemon — birth, run, and manage AI agents")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Path to daemon config file
    #[arg(long, global = true)]
    config: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon
    Start {
        /// Run in foreground (don't daemonize)
        #[arg(long)]
        foreground: bool,
    },

    /// Stop the daemon
    Stop,

    /// Show daemon status
    Status,

    /// Birth a new agent
    Birth {
        /// Template name (e.g., "swe-agent", "personal")
        template: String,

        /// Agent name
        #[arg(long)]
        name: String,

        /// Allowed outbound domains (comma-separated)
        #[arg(long)]
        scope: Option<String>,

        /// Allowed capability scopes (comma-separated)
        #[arg(long)]
        scopes: Option<String>,

        /// LLM model (format: provider/model, e.g., "ollama/qwen3.5")
        #[arg(long)]
        model: Option<String>,

        /// Memory limit in MB
        #[arg(long)]
        memory: Option<u64>,

        /// Delegation TTL (e.g., "30d", "24h")
        #[arg(long, default_value = "30d")]
        ttl: String,
    },

    /// Agent management
    Agents {
        #[command(subcommand)]
        action: AgentsAction,
    },

    /// Mesh network management
    Mesh {
        #[command(subcommand)]
        action: MeshAction,
    },

    /// Template management
    Templates {
        #[command(subcommand)]
        action: TemplatesAction,
    },

    /// View agent audit trail
    Audit {
        /// Agent name
        name: String,
        /// Number of entries
        #[arg(long, default_value = "20")]
        last: u64,
        /// Verify hash chain
        #[arg(long)]
        verify: bool,
    },

    /// Update management
    Update {
        #[command(subcommand)]
        action: UpdateAction,
    },
}

#[derive(Subcommand)]
enum AgentsAction {
    /// List all agents
    List,
    /// Inspect an agent
    Inspect {
        /// Agent name
        name: String,
    },
    /// View agent logs
    Logs {
        /// Agent name
        name: String,
        /// Number of lines
        #[arg(long, default_value = "50")]
        lines: u64,
    },
    /// Start an agent
    Start {
        /// Agent name
        name: String,
    },
    /// Stop an agent
    Stop {
        /// Agent name
        name: String,
    },
    /// Delete an agent (stop + remove all data)
    Delete {
        /// Agent name
        name: String,
        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },
}

#[derive(Subcommand)]
enum MeshAction {
    /// Show mesh status
    Status,
    /// Connect to mesh network
    Connect,
    /// Disconnect from mesh network
    Disconnect,
    /// List connected mesh peers
    Peers,
    /// Ping a peer on the mesh
    Ping {
        /// Peer DID
        did: String,
    },
}

#[derive(Subcommand)]
enum TemplatesAction {
    /// List installed templates
    List,
    /// Inspect a template
    Inspect {
        /// Template name
        name: String,
    },
    /// Install a template from registry
    Install {
        /// Template name
        name: String,
        /// Template version
        #[arg(long, default_value = "latest")]
        version: String,
    },
    /// Create a template from a local directory
    Create {
        /// Template name
        name: String,
        /// Source directory
        source: PathBuf,
    },
}

#[derive(Subcommand)]
enum UpdateAction {
    /// Check for available updates
    Check,
    /// Apply available updates
    Apply,
    /// Show update status
    Status,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Load config
    let root = config::daemon_root()?;
    let config_path = cli.config.unwrap_or_else(|| root.join("daemon.toml"));
    let config = config::DaemonConfig::load(&config_path)?;

    match cli.command {
        Commands::Start { foreground } => cmd_start(config, root, foreground).await,
        Commands::Stop => cmd_ipc("shutdown", serde_json::json!({}), &config).await,
        Commands::Status => cmd_ipc("status", serde_json::json!({}), &config).await,
        Commands::Birth {
            template,
            name,
            scope,
            scopes,
            model,
            memory,
            ttl,
        } => {
            let allowed_domains: Vec<String> = scope
                .map(|s| s.split(',').map(|d| d.trim().to_string()).collect())
                .unwrap_or_default();
            let allowed_scopes: Vec<String> = scopes
                .map(|s| s.split(',').map(|d| d.trim().to_string()).collect())
                .unwrap_or_else(|| vec!["*".to_string()]);

            let ttl_seconds = parse_ttl(&ttl)?;

            let mut model_config = serde_json::json!({});
            if let Some(m) = model {
                let parts: Vec<&str> = m.splitn(2, '/').collect();
                if parts.len() == 2 {
                    model_config = serde_json::json!({
                        "provider": parts[0],
                        "model": parts[1],
                        "endpoint": match parts[0] {
                            "ollama" => "http://localhost:11434",
                            "openai" => "https://api.openai.com/v1",
                            "anthropic" => "https://api.anthropic.com",
                            _ => "http://localhost:11434",
                        }
                    });
                }
            }

            let mut resources = serde_json::json!({});
            if let Some(mem) = memory {
                resources = serde_json::json!({"memory_mb": mem});
            }

            let params = serde_json::json!({
                "template": template,
                "name": name,
                "scope": {
                    "allowed_domains": allowed_domains,
                    "allowed_scopes": allowed_scopes,
                    "ttl_seconds": ttl_seconds,
                },
                "model": model_config,
                "resources": resources,
            });

            cmd_ipc("birth", params, &config).await
        }
        Commands::Agents { action } => match action {
            AgentsAction::List => {
                cmd_ipc("agents.list", serde_json::json!({}), &config).await
            }
            AgentsAction::Inspect { name } => {
                cmd_ipc("agents.get", serde_json::json!({"name": name}), &config).await
            }
            AgentsAction::Logs { name, lines } => {
                cmd_ipc("agents.logs", serde_json::json!({"name": name, "lines": lines}), &config).await
            }
            AgentsAction::Start { name } => {
                cmd_ipc("agents.start", serde_json::json!({"name": name}), &config).await
            }
            AgentsAction::Stop { name } => {
                cmd_ipc("agents.stop", serde_json::json!({"name": name}), &config).await
            }
            AgentsAction::Delete { name, force } => {
                if !force {
                    eprintln!("Are you sure you want to delete agent '{}'? This removes all data.", name);
                    eprintln!("Use --force to skip this confirmation.");
                    std::process::exit(1);
                }
                cmd_ipc("agents.delete", serde_json::json!({"name": name}), &config).await
            }
        },
        Commands::Mesh { action } => match action {
            MeshAction::Status => {
                cmd_ipc("mesh.status", serde_json::json!({}), &config).await
            }
            MeshAction::Connect => {
                cmd_ipc("mesh.connect", serde_json::json!({}), &config).await
            }
            MeshAction::Disconnect => {
                cmd_ipc("mesh.disconnect", serde_json::json!({}), &config).await
            }
            MeshAction::Peers => {
                cmd_ipc("mesh.peers", serde_json::json!({}), &config).await
            }
            MeshAction::Ping { did } => {
                cmd_ipc("mesh.ping", serde_json::json!({"did": did}), &config).await
            }
        },
        Commands::Templates { action } => match action {
            TemplatesAction::List => {
                cmd_ipc("templates.list", serde_json::json!({}), &config).await
            }
            TemplatesAction::Inspect { name } => {
                cmd_ipc("templates.inspect", serde_json::json!({"name": name}), &config).await
            }
            TemplatesAction::Install { name, version } => {
                cmd_ipc("templates.install", serde_json::json!({"name": name, "version": version}), &config).await
            }
            TemplatesAction::Create { name, source } => {
                cmd_ipc("templates.create", serde_json::json!({"name": name, "source": source.to_string_lossy()}), &config).await
            }
        },
        Commands::Audit { name, last, verify } => {
            cmd_ipc("audit.query", serde_json::json!({"name": name, "last": last, "verify": verify}), &config).await
        }
        Commands::Update { action } => match action {
            UpdateAction::Check => {
                cmd_ipc("update.check", serde_json::json!({}), &config).await
            }
            UpdateAction::Apply => {
                cmd_ipc("update.apply", serde_json::json!({}), &config).await
            }
            UpdateAction::Status => {
                cmd_ipc("update.status", serde_json::json!({}), &config).await
            }
        },
    }
}

/// Start the daemon.
async fn cmd_start(
    config: config::DaemonConfig,
    root: PathBuf,
    _foreground: bool,
) -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| config.daemon.log_level.parse().unwrap_or_default())
        )
        .init();

    // Check if already running
    let pid_path = config.pid_path()?;
    if let Some(pid) = daemon::check_already_running(&pid_path)? {
        anyhow::bail!("Daemon is already running (PID {})", pid);
    }

    // Ensure root directory structure
    std::fs::create_dir_all(root.join("agents"))?;
    std::fs::create_dir_all(root.join("templates"))?;
    std::fs::create_dir_all(root.join("identity"))?;
    std::fs::create_dir_all(root.join("mesh"))?;
    std::fs::create_dir_all(root.join("state"))?;

    // Write PID file
    daemon::write_pid_file(&pid_path)?;

    // Create template registry
    let template_registry = Arc::new(templates::TemplateRegistry::new(
        root.join("templates"),
        config.registry.url.clone(),
    ));
    template_registry.init()?;

    // Create mesh client (optional)
    let mesh_client = if config.mesh.enabled {
        let mesh_config = mesh::MeshConfig {
            coordination_server: config.mesh.coordination_server.clone(),
            daemon_card_path: root.join("identity").join("daemon.card.json"),
            daemon_key_path: root.join("identity").join("daemon.pem"),
            wireguard_key_path: root.join("mesh").join("wg-private.key"),
            mesh_dir: root.join("mesh"),
            auto_connect: config.mesh.auto_connect,
        };
        Some(Arc::new(mesh::MeshClient::with_headscale(mesh_config)))
    } else {
        None
    };

    // Create shared state
    let state = Arc::new(daemon::DaemonState::new(
        config.clone(),
        root.clone(),
        template_registry.clone(),
        mesh_client.clone(),
    ));

    // Initialize supervisor (load existing agents)
    state.supervisor.init().await?;

    // Auto-connect mesh if configured
    if let Some(ref mesh) = mesh_client {
        if config.mesh.auto_connect {
            match mesh.connect().await {
                Ok(()) => tracing::info!("Mesh connected"),
                Err(e) => tracing::warn!(error = %e, "Mesh connection failed (non-fatal)"),
            }
        }
    }

    // Create shutdown channel
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // Start anchor worker
    if config.anchoring.enabled {
        let anchor_worker = Arc::new(anchor::AnchorWorker::new(
            config.clone(),
            root.join("agents"),
            root.join("state"),
        ));
        let anchor_state = Arc::clone(&anchor_worker);
        {
            let mut s = state.anchor_worker.write().await;
            *s = Some(anchor_state);
        }
        let shutdown_rx_anchor = shutdown_rx.clone();
        tokio::spawn(async move {
            anchor_worker.run_loop(shutdown_rx_anchor).await;
        });
    }

    // Start update checker
    {
        let update_checker = Arc::new(updates::UpdateChecker::new(
            config.clone(),
            template_registry.clone(),
            config.registry.url.clone(),
        ));
        {
            let mut u = state.update_checker.write().await;
            *u = Some(Arc::clone(&update_checker));
        }
        let shutdown_rx_update = shutdown_rx.clone();
        tokio::spawn(async move {
            update_checker.run_loop(shutdown_rx_update).await;
        });
    }

    // Get socket path
    let socket_path = config.socket_path()?;

    // Start IPC server in background
    let ipc_state = Arc::clone(&state);
    let ipc_socket = socket_path.clone();
    tokio::spawn(async move {
        if let Err(e) = ipc::start_ipc_server(&ipc_socket, ipc_state).await {
            tracing::error!(error = %e, "IPC server error");
        }
    });

    println!("\u{1f980} GrokingClaw daemon started");
    println!("   Socket: {}", socket_path.display());
    println!("   PID:    {}", std::process::id());
    if config.mesh.enabled {
        println!("   Mesh:   {}", config.mesh.coordination_server);
    }
    if config.anchoring.enabled {
        println!("   Anchor: every {}m, batch {}", config.anchoring.interval_minutes, config.anchoring.batch_size);
    }

    // Main loop: health checks + restart agents
    let health_interval = tokio::time::Duration::from_secs(5);

    loop {
        if state.should_shutdown() {
            tracing::info!("Shutdown requested, stopping all agents");
            // Signal background workers
            let _ = shutdown_tx.send(true);
            state.supervisor.stop_all().await?;
            break;
        }

        // Check agent health
        state.supervisor.check_health().await?;

        // Restart agents that need it
        let needs_start = state.supervisor.agents_needing_start().await;
        for name in needs_start {
            if let Err(e) = state.supervisor.start_agent(&name).await {
                tracing::error!(agent = %name, error = %e, "Failed to restart agent");
            }
        }

        tokio::time::sleep(health_interval).await;
    }

    // Cleanup
    daemon::remove_pid_file(&pid_path);
    if socket_path.exists() {
        let _ = std::fs::remove_file(&socket_path);
    }

    println!("\u{1f980} GrokingClaw daemon stopped");
    Ok(())
}

/// Send a JSON-RPC request to the daemon via Unix socket.
async fn cmd_ipc(
    method: &str,
    params: serde_json::Value,
    config: &config::DaemonConfig,
) -> Result<()> {
    let socket_path = config.socket_path()?;

    if !socket_path.exists() {
        eprintln!("Daemon is not running. Start it with: grokingclaw start");
        std::process::exit(1);
    }

    let stream = UnixStream::connect(&socket_path)
        .await
        .context("Failed to connect to daemon. Is it running?")?;

    let (reader, mut writer) = stream.into_split();

    // Send request
    let request = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params,
    });
    let mut request_str = serde_json::to_string(&request)?;
    request_str.push('\n');
    writer.write_all(request_str.as_bytes()).await?;
    writer.flush().await?;

    // Read response
    let mut reader = BufReader::new(reader);
    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;

    let response: serde_json::Value = serde_json::from_str(response_line.trim())?;

    if let Some(error) = response.get("error") {
        let message = error.get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("Unknown error");
        eprintln!("Error: {}", message);
        std::process::exit(1);
    }

    if let Some(result) = response.get("result") {
        // Pretty print based on method
        match method {
            "status" => print_status(result),
            "agents.list" => print_agents_list(result),
            "agents.get" => println!("{}", serde_json::to_string_pretty(result)?),
            "agents.logs" => {
                if let Some(logs) = result.get("logs").and_then(|l| l.as_str()) {
                    println!("{}", logs);
                }
            }
            "birth" => print_birth_result(result),
            "mesh.status" => print_mesh_status(result),
            "mesh.peers" => print_mesh_peers(result),
            "templates.list" => print_templates_list(result),
            "templates.inspect" => println!("{}", serde_json::to_string_pretty(result)?),
            "update.check" | "update.status" => print_update_status(result),
            "audit.query" => print_audit_entries(result),
            _ => println!("{}", serde_json::to_string_pretty(result)?),
        }
    }

    Ok(())
}

// ─── Pretty Printers ───────────────────────────────────────────────────

/// Pretty-print daemon status.
fn print_status(v: &serde_json::Value) {
    println!("\u{1f980} GrokingClaw Daemon");
    println!("   Status:  {}", v.get("daemon").and_then(|d| d.as_str()).unwrap_or("unknown"));
    println!("   Version: {}", v.get("version").and_then(|d| d.as_str()).unwrap_or("?"));
    println!("   Uptime:  {}s", v.get("uptime_seconds").and_then(|d| d.as_u64()).unwrap_or(0));
    println!("   Agents:  {}", v.get("agents_count").and_then(|d| d.as_u64()).unwrap_or(0));
    if let Some(mesh) = v.get("mesh") {
        println!("   Mesh:    {}", mesh.get("state").and_then(|s| s.as_str()).unwrap_or("disabled"));
    }
    if let Some(anchor) = v.get("anchor") {
        let enabled = anchor.get("enabled").and_then(|e| e.as_bool()).unwrap_or(false);
        if enabled {
            println!("   Anchor:  enabled (pending: {})",
                anchor.get("pending_count").and_then(|p| p.as_u64()).unwrap_or(0)
            );
        }
    }

    if let Some(agents) = v.get("agents").and_then(|a| a.as_array()) {
        if !agents.is_empty() {
            println!();
            print_agents_list(&serde_json::Value::Array(agents.clone()));
        }
    }
}

/// Pretty-print agent list as table.
fn print_agents_list(v: &serde_json::Value) {
    let agents = match v.as_array() {
        Some(a) => a,
        None => {
            println!("No agents.");
            return;
        }
    };

    if agents.is_empty() {
        println!("No agents.");
        return;
    }

    println!("{:<20} {:<12} {:<10} {:<8} {:<20}",
        "NAME", "TEMPLATE", "STATUS", "PID", "CREATED");
    println!("{}", "-".repeat(70));

    for agent in agents {
        let name = agent.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let template = agent.get("template").and_then(|t| t.as_str()).unwrap_or("?");
        let status = agent.get("status").and_then(|s| s.as_str()).unwrap_or("?");
        let pid = agent.get("pid")
            .and_then(|p| p.as_u64())
            .map(|p| p.to_string())
            .unwrap_or_else(|| "-".to_string());
        let created = agent.get("created_at")
            .and_then(|c| c.as_str())
            .map(|c| if c.len() >= 19 { c[..19].replace('T', " ") } else { c.to_string() })
            .unwrap_or_else(|| "?".to_string());

        println!("{:<20} {:<12} {:<10} {:<8} {:<20}",
            name, template, status, pid, created);
    }
}

/// Pretty-print birth result.
fn print_birth_result(v: &serde_json::Value) {
    let name = v.get("name").and_then(|n| n.as_str()).unwrap_or("?");
    let agent_id = v.get("agent_id").and_then(|a| a.as_str()).unwrap_or("?");
    let template = v.get("template").and_then(|t| t.as_str()).unwrap_or("?");
    let mode = v.get("birth_mode").and_then(|m| m.as_str()).unwrap_or("local");

    println!("  \u{2713} Agent '{}' birthed ({} mode)", name, mode);
    println!("  \u{2713} Template: {}", template);
    println!("  \u{2713} Agent ID: {}", agent_id);
    if let Some(did) = v.get("did").and_then(|d| d.as_str()) {
        println!("  \u{2713} DID: {}", did);
    }
    println!();
    println!("  Start with: grokingclaw agents start {}", name);
}

/// Pretty-print mesh status.
fn print_mesh_status(v: &serde_json::Value) {
    let state = v.get("state").and_then(|s| s.as_str()).unwrap_or("unknown");
    println!("Mesh Status: {}", state);
    if let Some(ip) = v.get("mesh_ip").and_then(|i| i.as_str()) {
        println!("  Mesh IP: {}", ip);
    }
    if let Some(peers) = v.get("peer_count").and_then(|p| p.as_u64()) {
        println!("  Peers:   {}", peers);
    }
    if let Some(since) = v.get("connected_at").and_then(|c| c.as_str()) {
        println!("  Since:   {}", since);
    }
}

/// Pretty-print mesh peers.
fn print_mesh_peers(v: &serde_json::Value) {
    let peers = match v.get("peers").and_then(|p| p.as_array()) {
        Some(p) => p,
        None => {
            println!("No peers connected.");
            return;
        }
    };

    if peers.is_empty() {
        println!("No peers connected.");
        return;
    }

    println!("{:<20} {:<30} {:<16} {:<8}",
        "NAME", "DID", "MESH IP", "AGENTS");
    println!("{}", "-".repeat(74));

    for peer in peers {
        let name = peer.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let did = peer.get("did").and_then(|d| d.as_str()).unwrap_or("?");
        let ip = peer.get("mesh_ip").and_then(|i| i.as_str()).unwrap_or("?");
        let agents = peer.get("agent_count").and_then(|a| a.as_u64()).unwrap_or(0);
        println!("{:<20} {:<30} {:<16} {:<8}", name, did, ip, agents);
    }
}

/// Pretty-print templates list.
fn print_templates_list(v: &serde_json::Value) {
    let templates = match v.get("templates").and_then(|t| t.as_array()) {
        Some(t) => t,
        None => {
            println!("No templates installed.");
            return;
        }
    };

    if templates.is_empty() {
        println!("No templates installed.");
        return;
    }

    println!("{:<20} {:<12} {:<40}",
        "NAME", "VERSION", "DESCRIPTION");
    println!("{}", "-".repeat(72));

    for tmpl in templates {
        let name = tmpl.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let version = tmpl.get("version").and_then(|v| v.as_str()).unwrap_or("?");
        let desc = tmpl.get("description").and_then(|d| d.as_str()).unwrap_or("");
        println!("{:<20} {:<12} {:<40}", name, version, desc);
    }
}

/// Pretty-print update status.
fn print_update_status(v: &serde_json::Value) {
    let updates = match v.get("available_updates").and_then(|u| u.as_array()) {
        Some(u) => u,
        None => {
            println!("Everything is up to date.");
            return;
        }
    };

    if updates.is_empty() {
        println!("Everything is up to date.");
        return;
    }

    println!("{:<12} {:<20} {:<12} {:<12} {:<8}",
        "TYPE", "NAME", "CURRENT", "LATEST", "MAJOR");
    println!("{}", "-".repeat(64));

    for u in updates {
        let kind = u.get("kind").and_then(|k| k.as_str()).unwrap_or("?");
        let name = u.get("name").and_then(|n| n.as_str()).unwrap_or("?");
        let current = u.get("current_version").and_then(|c| c.as_str()).unwrap_or("?");
        let latest = u.get("latest_version").and_then(|l| l.as_str()).unwrap_or("?");
        let is_major = u.get("is_major").and_then(|m| m.as_bool()).unwrap_or(false);
        println!("{:<12} {:<20} {:<12} {:<12} {:<8}",
            kind, name, current, latest, if is_major { "YES" } else { "no" });
    }
}

/// Pretty-print audit entries.
fn print_audit_entries(v: &serde_json::Value) {
    let entries = match v.get("entries").and_then(|e| e.as_array()) {
        Some(e) => e,
        None => {
            println!("No audit entries.");
            return;
        }
    };

    if entries.is_empty() {
        println!("No audit entries.");
        return;
    }

    if let Some(verified) = v.get("chain_valid").and_then(|v| v.as_bool()) {
        if verified {
            println!("\u{2705} Audit chain verified ({} entries)", entries.len());
        } else {
            println!("\u{274c} Audit chain INVALID");
        }
        println!();
    }

    println!("{:<6} {:<20} {:<20} {:<20}",
        "ID", "ACTION", "TARGET", "TIMESTAMP");
    println!("{}", "-".repeat(66));

    for entry in entries {
        let id = entry.get("id").and_then(|i| i.as_i64()).unwrap_or(0);
        let action = entry.get("action").and_then(|a| a.as_str()).unwrap_or("?");
        let target = entry.get("target").and_then(|t| t.as_str()).unwrap_or("?");
        let ts = entry.get("timestamp").and_then(|t| t.as_i64()).unwrap_or(0);
        let dt = chrono::DateTime::from_timestamp(ts, 0)
            .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
            .unwrap_or_else(|| ts.to_string());
        println!("{:<6} {:<20} {:<20} {:<20}", id, action, target, dt);
    }
}

/// Parse TTL string (e.g., "30d", "24h", "30m") to seconds.
fn parse_ttl(ttl: &str) -> Result<i64> {
    let ttl = ttl.trim();
    if ttl.is_empty() {
        return Ok(30 * 24 * 3600); // 30 days default
    }

    let (num_str, unit) = ttl.split_at(ttl.len() - 1);
    let num: i64 = num_str.parse()
        .with_context(|| format!("Invalid TTL number: '{}'", num_str))?;

    match unit {
        "s" => Ok(num),
        "m" => Ok(num * 60),
        "h" => Ok(num * 3600),
        "d" => Ok(num * 86400),
        "w" => Ok(num * 604800),
        _ => anyhow::bail!("Invalid TTL unit: '{}'. Expected: s, m, h, d, w", unit),
    }
}
