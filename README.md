# 🦀 GrokingClawID

**Cryptographic identity for AI agents.** Post-quantum ready.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)
[![Tests](https://img.shields.io/badge/tests-119%20passing-green.svg)](#tests)
[![Version](https://img.shields.io/badge/version-0.4.1-brightgreen.svg)](CHANGELOG.md)
[![CI](https://github.com/grokingclaw/grokingclawid/actions/workflows/ci.yml/badge.svg)](https://github.com/grokingclaw/grokingclawid/actions/workflows/ci.yml)

GrokingClawID creates, manages, and verifies unforgeable cryptographic identities for AI agents. It's the foundation layer that authorization systems, governance platforms, and agent runtimes build on.

500K lines of defensive code in modern agent harnesses. Zero lines of cryptographic identity. We fix that.

## Features

| Feature | Description |
|---|---|
| **Post-quantum crypto** | Ed25519 + ML-DSA-65 (FIPS 204) hybrid — both must validate |
| **Agent identity cards** | A2A-compatible, signed, with SPIFFE IDs |
| **Key rotation** | Generate new keys, re-sign card, archive old key |
| **Revocation** | Permanent invalidation with signed revocation registry |
| **Delegation chains** | Scope-narrowing, time-bounded authority transfer |
| **MCP auth guard** | Wrap any MCP server with identity enforcement |
| **Challenge-response** | Mutual authentication without shared secrets |
| **HTTP signatures** | RFC 9421 request signing (classical + PQ) |
| **Audit log** | Hash-chained, signed, tamper-evident (\x00-delimited fields) |
| **IOTA wallet** | Agent-to-agent payments (same Ed25519 key), testnet funded |
| **MCP tool server** | Expose all operations to MCP-compatible agents |
| **A2A protocol server** | Google A2A JSON-RPC 2.0 — discovery, tasks, PQ-verified |
| **Daemon** | Agent host with mesh networking, birth protocol, Merkle anchoring |
| **E2E lab** | 12-step integration test — 33 assertions, single script |

## Install

```bash
# From source
cargo install --path crates/grokingclawid-cli

# Or build everything (CLI + daemon)
cargo build --release
# → target/release/grokingclawid  (CLI, ~4.7MB)
# → target/release/grokingclaw    (daemon)
```

**Requirements:** Rust 1.70+. No runtime dependencies.

## Quick Start

```bash
# Issue a hybrid identity (Ed25519 + ML-DSA-65)
grokingclawid issue \
  --name "my-agent" \
  --owner "me@example.com" \
  --scope "read,write" \
  --ttl 7d \
  --crypto hybrid \
  --output ./id

# Verify the card
grokingclawid verify --agent-card ./id/agent-card.json

# Rotate keys (new keypair, same identity)
grokingclawid rotate \
  --agent-card ./id/agent-card.json \
  --key ./id/agent-key.pem \
  --ttl 7d \
  --output ./id

# Delegate to a sub-agent (narrowed scope)
grokingclawid delegate \
  --from ./id/agent-card.json \
  --key ./id/agent-key.pem \
  --to "sub-agent" \
  --scope "read" \
  --ttl 1h

# Sign an HTTP request (RFC 9421)
grokingclawid sign \
  --method POST \
  --url "https://api.example.com/deploy" \
  --agent-card ./id/agent-card.json \
  --key ./id/agent-key.pem

# Mutual authentication
grokingclawid challenge --agent-card ./id/agent-card.json --require-scope write
grokingclawid respond --challenge challenge.json --agent-card ./id/agent-card.json --key ./id/agent-key.pem
grokingclawid verify-response --challenge challenge.json --response response.json

# Export as A2A Agent Card
grokingclawid export --agent-card ./id/agent-card.json --base-url "https://api.example.com"

# View audit log
grokingclawid audit --last 24h

# Revoke a compromised card
grokingclawid revoke --agent-card ./id/agent-card.json --key ./id/agent-key.pem --reason "key compromised"
```

## MCP Auth Guard

Wrap **any** MCP server with identity enforcement. Zero changes to the server.

```bash
grokingclawid guard --scope read,write -- node my-mcp-server.js
```

The guard intercepts all JSON-RPC requests over stdio:
1. Agents must call `clawid_authenticate` with their card first
2. Guard verifies signatures, expiration, revocation, and scopes
3. Authenticated requests are forwarded; unauthorized requests are blocked

```
Agent ──stdio──► GrokingClawID Guard ──stdio──► MCP Server
                 ├─ verify card
                 ├─ check scopes
                 ├─ check revocation
                 └─ forward or block
```

Works with Claude Code, Codex, Cursor, or any MCP-compatible runtime.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Authorization Layer                       │
│           (IndyKite, Aembit, Astrix, Opal, etc.)            │
├─────────────────────────────────────────────────────────────┤
│                    GrokingClawID (this)                      │
│              Cryptographic Identity Foundation               │
│                                                             │
│  Ed25519 + ML-DSA-65 │ A2A │ SPIFFE │ RFC 9421 │ MCP Guard │
│  Delegation │ Challenge │ Rotation │ Revocation │ Audit     │
├─────────────────────────────────────────────────────────────┤
│                      Agent Runtime                          │
│         (Claude Code, Codex, Gemini, CrewAI, etc.)          │
└─────────────────────────────────────────────────────────────┘
```

## Cryptography

| Algorithm | Purpose | Standard | Size |
|---|---|---|---|
| Ed25519 | Classical signatures | RFC 8032 | 64B sig |
| ML-DSA-65 | Post-quantum signatures | FIPS 204 | 3,309B sig |
| Hybrid | Both simultaneously | Both must validate | |
| SHA-256 | Audit chain hashing | FIPS 180-4 | |

All crypto runs locally. No key material leaves your machine. No cloud dependencies.

**Why hybrid?** Defense in depth. If ML-DSA-65 has an undiscovered weakness, Ed25519 still protects. If quantum computers break Ed25519, ML-DSA-65 still protects. Both must validate — AND, not OR.

## Project Structure

```
grokingclawid/
├── crates/
│   ├── grokingclawid-core/       # Shared library (crypto, models, audit, revocation)
│   ├── grokingclawid-cli/        # CLI binary — issue, verify, rotate, revoke, guard, etc.
│   ├── grokingclaw-proxy/        # Sidecar HTTP proxy (scope, RFC 9421 signing, audit)
│   └── grokingclaw-daemon/       # Agent host daemon (mesh, birth protocol, anchoring)
├── mcp-server/                   # MCP tool server (Node.js, zero deps)
├── docs/
│   └── NCCOE-REFERENCE-GUIDE.md  # NIST NCCoE reference implementation guide
├── COMMERCIAL.md                 # Pricing (free tier: 5 agents)
├── SECURITY.md                   # Security policy + crypto assumptions
└── LICENSE                       # Apache 2.0
```

**~15,500 lines of Rust** across 4 crates. 119 tests. Security audited.

## Tests

```bash
cargo test
# 119 passed, 0 failed, 0 warnings
#   44 — core (crypto, license, audit, revocation, challenge, httpsig)
#   10 — proxy (scope, signing, tunneling)
#    9 — daemon (config, supervisor, birth, mesh, templates, A2A)
#   13 — CLI integration tests
#   42 — core unit tests
#    1 — doctest (httpsig example)
```

### E2E Lab

```bash
./examples/run-lab.sh         # 12 steps, 33 assertions
./examples/run-lab.sh --keep  # Leave daemon running after tests
```

Exercises: identity → template → birth → A2A → challenge → rotation → revocation → audit.

## Standards Compliance

| Standard | Implementation |
|---|---|
| NIST FIPS 204 | ML-DSA-65 post-quantum signatures |
| RFC 8032 | Ed25519 signatures |
| RFC 9421 | HTTP Message Signatures |
| Google A2A | Agent Card export |
| SPIFFE | Workload identity URIs |
| MCP | Auth guard + tool server |

## NIST Submission

GrokingClawID was submitted to NIST NCCoE as a working reference implementation for the AI Agent Identity & Authorization project (April 2026). See [`docs/NCCOE-REFERENCE-GUIDE.md`](docs/NCCOE-REFERENCE-GUIDE.md) for the full guide.

## License

[Apache 2.0](LICENSE) — free to use, modify, and distribute.

## Contributing

**We're actively seeking collaborators.** If you're working on AI agent infrastructure, multi-agent security, post-quantum cryptography, or MCP tooling — we'd love to work with you.

Areas where help would have the most impact:
- **Language bindings** — Python, Go, TypeScript wrappers around the CLI/library
- **Framework integrations** — CrewAI, LangGraph, AutoGen, OpenAI Agents SDK
- **MCP ecosystem** — more guard middleware, tool server extensions
- **Formal verification** — proving the delegation chain and crypto properties
- **Documentation** — tutorials, integration guides, architecture deep-dives

Open an issue, submit a PR, or reach out at contact@grokingclaw.com. See [CONTRIBUTING.md](CONTRIBUTING.md) for build instructions and PR process.

## Links

- **Changelog:** [CHANGELOG.md](CHANGELOG.md)
- **Security audit:** 0 critical, 0 high, 0 medium — [details](CHANGELOG.md#041--2026-04-03)
- **Website:** [grokingclaw.com](https://grokingclaw.com)
- **Author:** Michael Thornton, GrokingClaw Labs
- **Contact:** contact@grokingclaw.com
