//! GrokingClaw Daemon — the agent host.
//!
//! The daemon manages agent lifecycles: birth, run, monitor, stop.
//! CLI communicates via Unix domain socket (JSON-RPC 2.0).
//!
//! Phase A: Standalone daemon with local birth (no mesh, no Naja/Morpheus).

mod config;
mod daemon;
mod ipc;
mod supervisor;

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

    // Create shared state
    let state = Arc::new(daemon::DaemonState::new(config.clone(), root));

    // Initialize supervisor (load existing agents)
    state.supervisor.init().await?;

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

    println!("🦀 GrokingClaw daemon started");
    println!("   Socket: {}", socket_path.display());
    println!("   PID:    {}", std::process::id());

    // Main loop: health checks + restart agents
    let health_interval = tokio::time::Duration::from_secs(5);

    loop {
        if state.should_shutdown() {
            tracing::info!("Shutdown requested, stopping all agents");
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

    println!("🦀 GrokingClaw daemon stopped");
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
            _ => println!("{}", serde_json::to_string_pretty(result)?),
        }
    }

    Ok(())
}

/// Pretty-print daemon status.
fn print_status(v: &serde_json::Value) {
    println!("🦀 GrokingClaw Daemon");
    println!("   Status:  {}", v.get("daemon").and_then(|d| d.as_str()).unwrap_or("unknown"));
    println!("   Version: {}", v.get("version").and_then(|d| d.as_str()).unwrap_or("?"));
    println!("   Uptime:  {}s", v.get("uptime_seconds").and_then(|d| d.as_u64()).unwrap_or(0));
    println!("   Agents:  {}", v.get("agents_count").and_then(|d| d.as_u64()).unwrap_or(0));

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
            .map(|c| c[..19].replace('T', " "))
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
    let status = v.get("status").and_then(|s| s.as_str()).unwrap_or("?");

    println!("  ✓ Agent '{}' birthed (local mode)", name);
    println!("  ✓ Template: {}", template);
    println!("  ✓ Agent ID: {}", agent_id);
    println!("  ✓ Status: {}", status);
    println!();
    println!("  Start with: grokingclaw agents start {}", name);
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
