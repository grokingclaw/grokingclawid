# Commercial Licensing — GrokingClawID

## Open Source (Apache 2.0)

The **core identity library** and **CLI tool** are free and open source under the Apache 2.0 license. You can use them in any project — personal, commercial, or government — without paying GrokingClaw Labs anything.

This includes:
- `grokingclawid-core` — crypto, models, audit, challenge, HTTP signatures, IOTA wallet
- `grokingclawid-cli` — issue, sign, verify, export, delegate, audit commands
- `mcp-server` — MCP integration for agent runtimes

**No limits. No telemetry. No account required.**

---

## Free Tier — 5 Agents

For individuals, researchers, and small teams getting started:

| | Free |
|---|---|
| **Agent identities** | **5** |
| **Post-quantum crypto** | ✅ Ed25519 + ML-DSA-65 |
| **Agent cards (A2A)** | ✅ |
| **Delegation chains** | ✅ |
| **Challenge-response auth** | ✅ |
| **HTTP message signatures** | ✅ |
| **Hash-chained audit log** | ✅ |
| **IOTA wallet** | ✅ (testnet) |
| **MCP server** | ✅ |
| **Daemon (agent hosting)** | ✅ Local mode |
| **Sidecar proxy** | ✅ Single agent |
| **Mesh networking** | ❌ |
| **Birth protocol** | ❌ |
| **Template registry** | Community only |
| **Support** | Community (GitHub Issues) |
| **Price** | **$0 forever** |

---

## Paid Plans

### Indie — $99 lifetime

For solo developers and small startups running agents in production.

| | Indie |
|---|---|
| **Agent identities** | **25** |
| **Daemon** | ✅ Full (local + remote) |
| **Sidecar proxy** | ✅ Unlimited agents |
| **Mesh networking** | ✅ Up to 3 nodes |
| **Birth protocol** | ✅ Local birth |
| **Template registry** | Community + verified |
| **Support** | Email (48hr response) |
| **Price** | **$99 one-time** |

### Team — $199 lifetime

For teams running multiple agents across machines.

| | Team |
|---|---|
| **Agent identities** | **100** |
| **Daemon** | ✅ Full |
| **Sidecar proxy** | ✅ Unlimited |
| **Mesh networking** | ✅ Up to 10 nodes |
| **Birth protocol** | ✅ Local + mesh birth |
| **Template registry** | All tiers + custom |
| **Delegation depth** | Unlimited |
| **Compliance reporting** | ✅ Basic |
| **Support** | Email (24hr response) |
| **Price** | **$199 one-time** |

### Enterprise — $399 lifetime

For organizations that need compliance, audit, and scale.

| | Enterprise |
|---|---|
| **Agent identities** | **Unlimited** |
| **Daemon** | ✅ Full + HA clustering |
| **Sidecar proxy** | ✅ Unlimited + custom scopes |
| **Mesh networking** | ✅ Unlimited nodes |
| **Birth protocol** | ✅ All modes (local, mesh, remote) |
| **Template registry** | All tiers + private registry |
| **On-chain breadcrumbs** | ✅ IOTA mainnet anchoring |
| **Compliance reporting** | ✅ Full (SOC 2, NIST AI RMF) |
| **GrokingClawWatch** | ✅ Agent monitoring + anomaly detection |
| **Support** | Priority (4hr response + SLA) |
| **Price** | **$399 one-time** |

---

## API (Pay-Per-Call)

For hosted verification, identity lookups, and managed infrastructure:

| API | Price |
|---|---|
| **Identity verification** | $0.001/call |
| **Agent birth (hosted)** | $5–50/agent |
| **Breadcrumb anchoring** | $0.01/anchor |
| **Compute (run on our infra)** | $0.02–0.10/hr |

---

## FAQ

**Is the CLI really free forever?**
Yes. The core identity toolkit is Apache 2.0 open source. Create identities, sign messages, verify signatures, export agent cards — no limits, no expiration, no account.

**What counts as an "agent identity"?**
Each unique cryptographic identity you create with `grokingclawid issue`. One agent = one identity. Rotating keys on the same agent doesn't count as a new identity.

**Are lifetime licenses really lifetime?**
Yes. One payment, use forever. You get all updates to your tier. No subscriptions, no renewals.

**Can I use the open-source parts commercially?**
Yes. Apache 2.0 allows commercial use, modification, and distribution. Attribution required.

**What if I need more than 5 agents but don't need the daemon?**
The CLI itself has no agent limit — the 5-agent limit applies to managed features (daemon hosting, proxy, monitoring). You can create unlimited identities with the CLI for free.

---

## Contact

- **Website:** [grokingclaw.com](https://grokingclaw.com)
- **Email:** contact@grokingclaw.com
- **Enterprise inquiries:** contact@grokingclaw.com

© 2026 GrokingClaw Labs. All rights reserved.
