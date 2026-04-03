# Changelog

All notable changes to GrokingClawID are documented here.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.4.1] — 2026-04-03

### Security
- **Key file permissions** — private key PEM files now written as 0o600 (was default umask). Fixed in `issue`, `rotate`, and daemon `birth`.
- **Audit hash chain** — fields now separated by `\x00` to prevent boundary collision attacks.
- **A2A auth enforcement** — RPC endpoints require ClawID signature by default (`require_auth = true`). Agent card discovery remains public.
- **Proxy HTTPS guard** — forward proxy rejects HTTPS requests with clear error (use CONNECT tunnel instead).
- **PQ variable cleanup** — renamed dead `_pq_ok` → `_pq_checked` in challenge verification.
- **WebSocket replay protection** — sequence tracking for signed WS messages.
- **IOTA address derivation** — added flag byte prefix per IOTA Rebased spec.
- **Graceful agent shutdown** — SIGTERM before SIGKILL with configurable timeout.
- **Canonical JSON signing** — card signing payload uses sorted keys.
- **Rate limiter** — sliding window (was wall-clock reset).
- **Agent name validation** — reject characters unsafe for directory names.
- **Proxy audit lock** — reduced Mutex scope for async SQLite writes.

### Added
- **A2A protocol server** — `GET /.well-known/agent-card.json` (daemon + per-agent), `POST /a2a/rpc` (JSON-RPC 2.0: `message/send`, `tasks/get`, `tasks/list`, `tasks/cancel`).
- **Daemon control channel** — `POST /control/revoke` for forced agent revocation (PQ signature mandatory).
- **IOTA anchoring** — real `IotaClient` submission (was stub). Self-transfer with Merkle root as proof.
- **E2E lab** — `examples/run-lab.sh` (12 steps, 33 assertions), `examples/hello-agent/` template.
- **A2A config** — `[a2a]` section in daemon.toml: `enabled`, `port`, `base_url`, `require_auth`.

### Changed
- Version bumped to 0.4.1 across all crates
- Test suite expanded to **119 tests** (from 97)
- Full security audit: 0 critical vulnerabilities, all High and Medium findings resolved
- IOTA testnet wallet funded (10 IOTA)

## [0.4.0] — 2026-04-02

### Added
- **Key rotation** — generate new keypair, re-sign agent card, archive old key (`grokingclawid rotate`)
- **Revocation registry** — permanently invalidate compromised cards with signed entries (`grokingclawid revoke`)
- **MCP auth guard** — wrap any MCP server with identity enforcement, zero changes to the server (`grokingclawid guard`)
- **Free tier license enforcement** — local validation, 5-agent limit for daemon, unlimited CLI usage
- **NCCoE reference guide** — NIST reference implementation documentation (`docs/NCCOE-REFERENCE-GUIDE.md`)
- GitHub Actions CI workflow (ubuntu + macOS matrix)
- `CONTRIBUTING.md` guide

### Changed
- Version bumped to 0.4.0 across all 4 crates
- `SECURITY.md` updated to reflect 0.4.x as current supported version
- Test suite expanded to **97 tests** (from 79)

## [0.3.0] — 2026-03-28

### Added
- **Cargo workspace restructure** — 4-crate layout (`grokingclawid-core`, `grokingclawid-cli`, `grokingclaw-proxy`, `grokingclaw-daemon`)
- **Daemon** — full agent host with 4-phase lifecycle:
  - Phase 1: Supervisor (agent templates, spawn/stop/status)
  - Phase 2: Sidecar proxy (scope enforcement, RFC 9421 signing, audit logging)
  - Phase 3: Mesh networking (WireGuard tunnels, peer discovery, gossip protocol)
  - Phase 4: Birth protocol (parent-spawned child agents, Merkle tree anchoring)
- Sidecar HTTP proxy crate (`grokingclaw-proxy`) with scope enforcement and request signing
- Agent templates with YAML configuration
- Merkle tree anchoring for tamper-evident agent lineage
- 79 tests across all crates

### Changed
- CLI moved from standalone binary to `grokingclawid-cli` crate
- Core library extracted to `grokingclawid-core` for sharing across crates
- Release profile: LTO, strip, single codegen unit, abort on panic

## [0.2.0] — 2026-03-25

### Added
- **Core cryptography** — Ed25519 (RFC 8032) + ML-DSA-65 (FIPS 204) hybrid signatures
- **CLI commands:**
  - `issue` — create agent identity with hybrid post-quantum crypto
  - `verify` — validate agent cards (signatures, expiration, revocation)
  - `sign` — RFC 9421 HTTP message signatures
  - `delegate` — scope-narrowing, time-bounded authority transfer
  - `challenge` / `respond` / `verify-response` — mutual authentication
  - `audit` — hash-chained, signed, tamper-evident audit log
  - `export` — A2A-compatible agent card export
- **A2A agent cards** — Google A2A protocol compatible identity cards
- **SPIFFE IDs** — workload identity URI generation
- **HTTP signatures** — RFC 9421 request signing (classical + post-quantum)
- **IOTA wallet** — agent-to-agent payments using the same Ed25519 key
- **MCP tool server** — expose all operations to MCP-compatible agents (`mcp-server/`)
- Apache 2.0 license
- Security policy (`SECURITY.md`)
- Commercial licensing guide (`COMMERCIAL.md`)

[0.4.1]: https://github.com/grokingclaw/grokingclawid/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/grokingclaw/grokingclawid/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/grokingclaw/grokingclawid/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/grokingclaw/grokingclawid/releases/tag/v0.2.0
