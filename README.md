# 🦀 GrokingClawID

**Cryptographic identity for AI agents.** Post-quantum ready.

GrokingClawID is a standalone CLI tool that creates, manages, and verifies cryptographic identities for AI agents. It's the foundation layer that agent authorization systems, governance platforms, and runtime brokers build on top of.

## Why

Every agent security company builds locks. Nobody makes unforgeable keys. GrokingClawID does.

500K lines of defensive code in modern agent harnesses. Zero lines of cryptographic identity. Agents impersonate each other, leak credentials, and operate without provable identity. We fix that.

## Features

- **Post-quantum cryptography** — Ed25519 + ML-DSA-65 (FIPS 204) hybrid signatures
- **Agent identity cards** — A2A-compatible, machine-readable, cryptographically signed
- **SPIFFE ID generation** — Standard workload identity format
- **Delegation chains** — Scoped, time-bounded authority transfer between agents
- **Challenge-response auth** — Prove identity without revealing keys
- **HTTP message signatures** — RFC 9421 compatible request signing
- **Hash-chained audit log** — Tamper-evident identity event trail
- **IOTA Rebased wallet** — Testnet agent-to-agent payments (Ed25519 → IOTA address derivation)
- **MCP server** — Expose identity operations to any MCP-compatible agent

## Install

```bash
# From source
cargo install --path .

# Or build directly
cargo build --release
# Binary at target/release/grokingclawid (4.3MB)
```

**Requirements:** Rust 1.70+, no external dependencies at runtime.

## Quick Start

```bash
# Create a new agent identity (Ed25519 + ML-DSA-65 hybrid)
grokingclawid issue --name "my-agent" --hybrid

# Export the agent card (A2A-compatible JSON)
grokingclawid export --name "my-agent" --format agent-card

# Sign a message
echo "hello" | grokingclawid sign --name "my-agent"

# Verify a signature
echo "hello" | grokingclawid verify --name "my-agent" --signature <sig>

# Challenge-response authentication
grokingclawid challenge --name "my-agent" --mode prove

# Delegate authority to another agent
grokingclawid delegate --from "parent-agent" --to "child-agent" \
  --scope "read,write" --expires "2026-12-31"

# View audit log
grokingclawid audit --name "my-agent"
```

## Architecture

```
┌─────────────────────────────────────────┐
│         Authorization Layer             │
│  (IndyKite, Aembit, Astrix, Opal, etc.) │
├─────────────────────────────────────────┤
│        GrokingClawID (this)             │
│   Cryptographic Identity Foundation     │
│                                         │
│  Ed25519 + ML-DSA │ DIDs │ SPIFFE │ A2A │
│  Delegation │ Challenge │ Audit │ HTTP  │
├─────────────────────────────────────────┤
│            Agent Runtime                │
│   (Claude Code, Codex, Gemini, etc.)    │
└─────────────────────────────────────────┘
```

GrokingClawID sits between the agent runtime and authorization layer. It answers one question: **"Who IS this agent, provably?"**

## Crypto

| Algorithm | Purpose | Standard |
|-----------|---------|----------|
| Ed25519 | Classical signatures | RFC 8032 |
| ML-DSA-65 | Post-quantum signatures | FIPS 204 |
| Hybrid | Both simultaneously | GrokingClaw spec |
| BLAKE2b-256 | Hashing (audit, wallet) | RFC 7693 |
| SHA-256 | Content addressing | FIPS 180-4 |

All crypto runs locally. No key material leaves your machine. No cloud dependencies.

## Standards

- **W3C DID** — Decentralized Identifiers for agents
- **SPIFFE** — Secure Production Identity Framework
- **A2A** — Google's Agent-to-Agent protocol agent cards
- **RFC 9421** — HTTP Message Signatures
- **FIPS 204** — ML-DSA post-quantum digital signatures
- **MCP** — Model Context Protocol server integration

## Project Structure

```
src/
├── main.rs          # CLI entry + Clap commands
├── crypto.rs        # Ed25519 + ML-DSA-65 hybrid crypto
├── models.rs        # Identity, AgentCard, DelegationChain types
├── audit.rs         # Hash-chained tamper-evident audit log
├── challenge.rs     # Challenge-response authentication
├── httpsig.rs       # HTTP message signature (RFC 9421)
├── iota.rs          # IOTA Rebased wallet integration
├── ws.rs            # WebSocket transport
└── commands/        # CLI subcommands
    ├── issue.rs     # Create new identities
    ├── sign.rs      # Sign messages/files
    ├── verify.rs    # Verify signatures
    ├── export.rs    # Export agent cards
    ├── delegate.rs  # Delegation chains
    ├── challenge.rs # Challenge-response
    ├── wallet.rs    # IOTA wallet ops
    └── audit.rs     # Audit log queries
tests/
└── integration_tests.rs
mcp-server/          # MCP server (Node.js)
├── index.js
├── test.js
└── README.md
```

## NIST Submission

GrokingClawID is the reference implementation for our public comment submission to NIST NCCoE on AI Agent Identity & Authorization (April 2026). See [our submission](https://grokingclaw.com) for details.

## License

Apache 2.0 — free to use, modify, and distribute.

## Links

- **Website:** [grokingclaw.com](https://grokingclaw.com)
- **Contact:** huynguyenusa@icloud.com
- **Author:** GrokingClaw Labs
