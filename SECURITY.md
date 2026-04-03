# Security Policy

## Reporting Vulnerabilities

Email **huynguyenusa@icloud.com** with:
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

Private keys are stored as PEM files on disk. **You** are responsible for:
- Setting appropriate file permissions (`chmod 600 agent-key.pem`)
- Not committing keys to version control
- Rotating keys before expiration

## Audit Log Integrity

The audit log uses SHA-256 hash chaining. Each entry references the previous entry's hash, making retroactive tampering detectable. Entries are signed with the agent's Ed25519 key.

## Supply Chain

- All dependencies are pinned in `Cargo.lock`
- Release builds use `strip = true` and LTO
- No network calls at build time
- No post-install scripts
