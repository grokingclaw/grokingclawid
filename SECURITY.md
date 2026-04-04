# Security Policy

## Reporting Vulnerabilities

Email **contact@grokingclaw.com** with:
- Description of the vulnerability
- Steps to reproduce
- Impact assessment

We'll acknowledge within 48 hours and aim to patch critical issues within 7 days.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.4.x   | ✅ Current |
| < 0.4   | ❌         |

## Cryptographic Assumptions

- **Ed25519** — classical security, ~128-bit equivalent
- **ML-DSA-65** — NIST FIPS 204, Level 3 post-quantum security
- **Hybrid mode** — both signatures must validate (AND, not OR)
- Key generation uses `OsRng` (OS-provided CSPRNG)

## Key Storage

Private keys are stored as PEM files on disk with `0o600` permissions (owner-only, enforced automatically on Unix since v0.4.1).

**You** are responsible for:
- Not committing keys to version control
- Rotating keys before expiration
- Using encrypted storage for production deployments

## Audit Log Integrity

The audit log uses SHA-256 hash chaining with `\x00`-delimited fields (preventing boundary collision attacks). Each entry references the previous entry's hash, making retroactive tampering detectable. Entries are signed with the agent's Ed25519 key.

## A2A Authentication

The A2A protocol server requires ClawID signature authentication by default (`require_auth = true`). All RPC requests must include RFC 9421 `Signature` and `Signature-Input` headers verified against a known agent card. Agent card discovery endpoints (`/.well-known/`) remain public.

The daemon control channel (`/control/revoke`) requires ML-DSA-65 post-quantum signatures with no fallback — classical-only signatures are rejected.

## Security Audit

v0.4.1 underwent a full security audit (April 2026). Results:
- **0 Critical** — No critical vulnerabilities found
- **5 High → Fixed** — Key perms, hash delimiters, A2A auth, proxy TLS, PQ variable
- **7 Medium → Fixed** — Replay protection, rate limiting, graceful shutdown, JSON canonicalization, IOTA addressing, agent name validation, async lock scope
- **7 Low** — Cosmetic (clippy warnings, documentation)

Cryptographic foundations confirmed sound: hybrid Ed25519 + ML-DSA-65 "both must pass" logic correct, `OsRng` for key generation, no timing oracles in ed25519-dalek.

## Supply Chain

- All dependencies are pinned in `Cargo.lock`
- Release builds use `strip = true` and LTO
- No network calls at build time
- No post-install scripts
