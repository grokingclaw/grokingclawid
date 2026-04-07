//! GrokingClawID — AI Agent Identity Management CLI
//!
//! A standalone tool for issuing, verifying, and delegating cryptographic
//! identities for AI agents, with a tamper-evident audit trail.
//!
//! ## Subcommands
//!
//! - `issue`    — Generate a new agent identity (keypair + signed card)
//! - `verify`   — Validate an agent card's signature and expiration
//! - `delegate` — Create a narrowed delegation token for a sub-agent
//! - `audit`    — Query the tamper-evident audit log
//! - `export`   — Export agent card to A2A format
//! - `wallet`   — IOTA testnet wallet operations

mod commands;

use clap::{Parser, Subcommand};
use std::path::PathBuf;

/// GrokingClawID — AI Agent Identity Management
#[derive(Parser)]
#[command(name = "grokingclawid")]
#[command(version = "0.4.0")]
#[command(about = "Cryptographic identity management for AI agents")]
#[command(
    long_about = "GrokingClawID provides hybrid Ed25519 + ML-DSA-65 (post-quantum) identity \n\
    issuance, verification, delegation, and tamper-evident audit logging for \n\
    AI agents. Compatible with A2A and SPIFFE identity standards."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Issue a new agent identity card with cryptographic keypair
    Issue {
        /// Human-readable agent name
        #[arg(long)]
        name: String,

        /// Owner identifier (e.g., email address)
        #[arg(long)]
        owner: String,

        /// Comma-separated list of scopes (e.g., "read,write")
        #[arg(long)]
        scope: String,

        /// Time-to-live (e.g., "24h", "30m", "7d")
        #[arg(long, default_value = "24h")]
        ttl: String,

        /// Agent type: "type", "instance", or "session"
        #[arg(long = "type", default_value = "instance")]
        agent_type: String,

        /// Cryptographic scheme: "ed25519", "ml-dsa-65", or "hybrid"
        #[arg(long, default_value = "hybrid")]
        crypto: String,

        /// SPIFFE trust domain (e.g., "example.org"). Generates spiffe:// URI.
        #[arg(long)]
        trust_domain: Option<String>,

        /// Output directory for agent-card.json and agent-key.pem
        #[arg(long, short, default_value = ".")]
        output: PathBuf,
    },

    /// Verify an agent card's signature(s) and expiration
    Verify {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,
    },

    /// Delegate narrowed permissions to a sub-agent
    Delegate {
        /// Path to the parent's agent-card.json
        #[arg(long)]
        from: PathBuf,

        /// Path to the parent's agent-key.pem
        #[arg(long)]
        key: PathBuf,

        /// Name for the delegated sub-agent
        #[arg(long)]
        to: String,

        /// Comma-separated scopes to delegate (must be subset of parent's)
        #[arg(long)]
        scope: String,

        /// Time-to-live for the delegation (must be shorter than parent's)
        #[arg(long, default_value = "30m")]
        ttl: String,

        /// Output directory for delegation-token.json
        #[arg(long, short, default_value = ".")]
        output: PathBuf,
    },

    /// Query the tamper-evident audit log
    Audit {
        /// Filter by agent ID
        #[arg(long)]
        agent: Option<String>,

        /// Show entries from the last N time (e.g., "24h", "7d")
        #[arg(long)]
        last: Option<String>,
    },

    /// Export agent card to A2A (Agent-to-Agent) format
    Export {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Base URL for the agent service (e.g., "https://api.example.com")
        #[arg(long, default_value = "https://localhost")]
        base_url: String,

        /// Output file path (default: a2a-agent-card.json)
        #[arg(long, short)]
        output: Option<PathBuf>,
    },

    /// Sign an HTTP request with RFC 9421 message signatures
    Sign {
        /// HTTP method
        #[arg(long, default_value = "GET")]
        method: String,

        /// Target URL
        #[arg(long)]
        url: String,

        /// Path to agent-card.json (for public key / keyid)
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Path to agent-key.pem
        #[arg(long)]
        key: PathBuf,

        /// Headers to include (format: "name:value"), repeatable
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,

        /// Output format: headers (default) or curl
        #[arg(long, default_value = "headers")]
        format: String,
    },

    /// Issue a verification challenge for agent-to-agent handshakes
    Challenge {
        /// Your agent card (the challenger)
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Required scopes the peer must have (comma-separated)
        #[arg(long, default_value = "read")]
        require_scope: String,

        /// Challenge TTL in seconds
        #[arg(long, default_value = "30")]
        ttl: i64,

        /// Require post-quantum signing from the peer
        #[arg(long)]
        require_pq: bool,

        /// Output file for the challenge JSON
        #[arg(long, short, default_value = "challenge.json")]
        output: PathBuf,
    },

    /// Respond to a verification challenge
    Respond {
        /// Path to the challenge JSON
        #[arg(long)]
        challenge: PathBuf,

        /// Your agent card
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Your agent key
        #[arg(long)]
        key: PathBuf,

        /// Output file for the response JSON
        #[arg(long, short, default_value = "response.json")]
        output: PathBuf,
    },

    /// Verify a challenge response from a peer agent
    VerifyResponse {
        /// Path to the original challenge JSON
        #[arg(long)]
        challenge: PathBuf,

        /// Path to the response JSON
        #[arg(long)]
        response: PathBuf,
    },

    /// Verify an RFC 9421 signed HTTP request
    VerifySig {
        /// HTTP method
        #[arg(long, default_value = "GET")]
        method: String,

        /// Target URL
        #[arg(long)]
        url: String,

        /// Signature-Input header value
        #[arg(long)]
        signature_input: String,

        /// Signature header value
        #[arg(long)]
        signature: String,

        /// PQ Signature header value (optional, for hybrid)
        #[arg(long)]
        pq_signature: Option<String>,

        /// Path to agent-card.json (for public key)
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Headers to include (format: "name:value"), repeatable
        #[arg(long = "header", short = 'H')]
        headers: Vec<String>,
    },

    /// Rotate an agent card's keys (generate new keypair, re-sign, archive old)
    Rotate {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Path to agent-key.pem (current key, proves ownership)
        #[arg(long)]
        key: PathBuf,

        /// New time-to-live (e.g., "24h", "30d")
        #[arg(long, default_value = "24h")]
        ttl: String,

        /// Output directory for new card + key (old key is archived here)
        #[arg(long, short, default_value = ".")]
        output: PathBuf,
    },

    /// Revoke an agent card (mark as permanently invalid)
    Revoke {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Path to agent-key.pem (proves authority to revoke)
        #[arg(long)]
        key: PathBuf,

        /// Reason for revocation
        #[arg(long, default_value = "key compromised")]
        reason: String,
    },

    /// List all revoked agent cards
    RevocationList,

    /// MCP auth guard — wrap any MCP server with identity verification
    Guard {
        /// Required scopes (comma-separated). Agent must have ALL of these.
        #[arg(long, default_value = "read")]
        scope: String,

        /// Require post-quantum (ML-DSA-65) signatures
        #[arg(long)]
        require_pq: bool,

        /// Allow unauthenticated requests during initialization
        #[arg(long)]
        allow_init: bool,

        /// MCP server command (everything after --)
        #[arg(trailing_var_arg = true, required = true)]
        server: Vec<String>,
    },

    /// OAuth 2.0 bridge — register providers, manage tokens, exchange identity
    Oauth {
        #[command(subcommand)]
        action: OAuthAction,
    },

    /// IOTA testnet wallet operations
    Wallet {
        #[command(subcommand)]
        action: WalletAction,
    },

    /// Manage license (show, activate, deactivate)
    License {
        #[command(subcommand)]
        action: Option<LicenseAction>,
    },
}

/// License sub-subcommands.
#[derive(Subcommand)]
enum LicenseAction {
    /// Activate a license key
    Activate {
        /// License key string
        key: String,
    },
    /// Deactivate current license (revert to Free tier)
    Deactivate,
}

/// OAuth sub-subcommands.
#[derive(Subcommand)]
enum OAuthAction {
    /// Register an OAuth provider for an agent
    Register {
        /// Agent name
        #[arg(long)]
        agent: String,
        /// Provider name (github, google, openai, etc.)
        #[arg(long)]
        provider: String,
        /// OAuth client ID
        #[arg(long)]
        client_id: String,
        /// OAuth client secret (omit for public clients)
        #[arg(long)]
        client_secret: Option<String>,
        /// Authorization endpoint URL
        #[arg(long)]
        authorization_url: Option<String>,
        /// Token endpoint URL
        #[arg(long)]
        token_url: String,
        /// Space-separated scopes
        #[arg(long)]
        scopes: String,
        /// Comma-separated domains for token injection
        #[arg(long)]
        domains: String,
        /// Grant type: authorization_code, device_code, client_credentials
        #[arg(long, default_value = "authorization_code")]
        grant_type: String,
    },
    /// Start an OAuth authorization flow
    Authorize {
        /// Agent name
        #[arg(long)]
        agent: String,
        /// Registration ID
        #[arg(long)]
        registration: String,
    },
    /// Check OAuth token status
    Status {
        /// Agent name
        #[arg(long)]
        agent: String,
        /// Optional: specific registration ID
        #[arg(long)]
        registration: Option<String>,
    },
    /// Revoke OAuth tokens
    Revoke {
        /// Agent name
        #[arg(long)]
        agent: String,
        /// Registration ID to revoke
        #[arg(long)]
        registration: String,
    },
    /// Exchange ClawID identity for OAuth token (RFC 8693)
    Exchange {
        /// Agent name
        #[arg(long)]
        agent: String,
        /// Registration ID
        #[arg(long)]
        registration: String,
    },
}

/// Wallet sub-subcommands.
#[derive(Subcommand)]
enum WalletAction {
    /// Initialize wallet — derive IOTA address from agent card
    Init {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,
    },

    /// Check IOTA balance
    Balance {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Network: testnet (default) or devnet
        #[arg(long, default_value = "testnet")]
        network: String,
    },

    /// Request test IOTA from faucet
    Faucet {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Network: testnet (default) or devnet
        #[arg(long, default_value = "testnet")]
        network: String,
    },

    /// List coin objects owned by the agent
    Coins {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Network: testnet (default) or devnet
        #[arg(long, default_value = "testnet")]
        network: String,
    },

    /// Send IOTA to another address
    Send {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Path to agent-key.pem
        #[arg(long)]
        key: PathBuf,

        /// Recipient IOTA address (0x...)
        #[arg(long)]
        to: String,

        /// Amount to send (in IOTA, e.g. "1.5", or nanos e.g. "1500000000")
        #[arg(long)]
        amount: String,

        /// Network: testnet (default) or devnet
        #[arg(long, default_value = "testnet")]
        network: String,
    },

    /// Watch real-time events for an agent's wallet via WebSocket
    Watch {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Network: testnet (default) or devnet
        #[arg(long, default_value = "testnet")]
        network: String,

        /// Maximum number of events to display (0 = unlimited)
        #[arg(long, default_value = "0")]
        limit: u32,
    },

    /// Query historical events for an agent's wallet
    Events {
        /// Path to agent-card.json
        #[arg(long = "agent-card")]
        agent_card: PathBuf,

        /// Network: testnet (default) or devnet
        #[arg(long, default_value = "testnet")]
        network: String,

        /// Maximum number of events to return
        #[arg(long, default_value = "10")]
        limit: u32,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Issue {
            name,
            owner,
            scope,
            ttl,
            agent_type,
            crypto,
            trust_domain,
            output,
        } => commands::issue::execute(
            &name,
            &owner,
            &scope,
            &ttl,
            &agent_type,
            &crypto,
            trust_domain.as_deref(),
            &output,
        ),

        Commands::Verify { agent_card } => commands::verify::execute(&agent_card),

        Commands::Delegate {
            from,
            key,
            to,
            scope,
            ttl,
            output,
        } => commands::delegate::execute(&from, &key, &to, &scope, &ttl, &output),

        Commands::Audit { agent, last } => {
            commands::audit::execute(agent.as_deref(), last.as_deref())
        }

        Commands::Export {
            agent_card,
            base_url,
            output,
        } => commands::export::execute(&agent_card, &base_url, output.as_deref()),

        Commands::Challenge {
            agent_card,
            require_scope,
            ttl,
            require_pq,
            output,
        } => commands::challenge::execute_challenge(
            &agent_card,
            &require_scope,
            ttl,
            require_pq,
            &output,
        ),

        Commands::Respond {
            challenge,
            agent_card,
            key,
            output,
        } => commands::challenge::execute_respond(&challenge, &agent_card, &key, &output),

        Commands::VerifyResponse {
            challenge,
            response,
        } => commands::challenge::execute_verify_response(&challenge, &response),

        Commands::Sign {
            method,
            url,
            agent_card,
            key,
            headers,
            format,
        } => commands::sign::execute_sign(&method, &url, &agent_card, &key, &headers, &format),

        Commands::VerifySig {
            method,
            url,
            signature_input,
            signature,
            pq_signature,
            agent_card,
            headers,
        } => commands::sign::execute_verify(
            &method,
            &url,
            &signature_input,
            &signature,
            pq_signature.as_deref(),
            &agent_card,
            &headers,
        ),

        Commands::Rotate {
            agent_card,
            key,
            ttl,
            output,
        } => commands::rotate::execute(&agent_card, &key, &ttl, &output),

        Commands::Revoke {
            agent_card,
            key,
            reason,
        } => commands::revoke::execute(&agent_card, &key, &reason),

        Commands::RevocationList => commands::revoke::execute_list(),

        Commands::Guard {
            scope,
            require_pq,
            allow_init,
            server,
        } => commands::guard::execute(&scope, require_pq, allow_init, &server),

        Commands::License { action } => match action {
            None => commands::license::execute_show(),
            Some(LicenseAction::Activate { key }) => commands::license::execute_activate(&key),
            Some(LicenseAction::Deactivate) => commands::license::execute_deactivate(),
        },

        Commands::Oauth { action } => match action {
            OAuthAction::Register {
                agent, provider, client_id, client_secret, authorization_url,
                token_url, scopes, domains, grant_type,
            } => commands::oauth::execute_register(
                &agent, &provider, &client_id, client_secret.as_deref(),
                authorization_url.as_deref(), &token_url, &scopes, &domains, &grant_type,
            ),
            OAuthAction::Authorize { agent, registration } => {
                commands::oauth::execute_authorize(&agent, &registration)
            }
            OAuthAction::Status { agent, registration } => {
                commands::oauth::execute_status(&agent, registration.as_deref())
            }
            OAuthAction::Revoke { agent, registration } => {
                commands::oauth::execute_revoke(&agent, &registration)
            }
            OAuthAction::Exchange { agent, registration } => {
                commands::oauth::execute_exchange(&agent, &registration)
            }
        },

        Commands::Wallet { action } => match action {
            WalletAction::Init { agent_card } => commands::wallet::execute_init(&agent_card),
            WalletAction::Balance {
                agent_card,
                network,
            } => commands::wallet::execute_balance(&agent_card, &network),
            WalletAction::Faucet {
                agent_card,
                network,
            } => commands::wallet::execute_faucet(&agent_card, &network),
            WalletAction::Coins {
                agent_card,
                network,
            } => commands::wallet::execute_coins(&agent_card, &network),
            WalletAction::Send {
                agent_card,
                key,
                to,
                amount,
                network,
            } => commands::wallet::execute_send(&agent_card, &key, &to, &amount, &network),
            WalletAction::Watch {
                agent_card,
                network,
                limit,
            } => commands::wallet::execute_watch(&agent_card, &network, limit),
            WalletAction::Events {
                agent_card,
                network,
                limit,
            } => commands::wallet::execute_events(&agent_card, &network, limit),
        },
    };

    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}
