# Contributing to GrokingClawID

Thanks for your interest in contributing! Here's how to get started.

## Building

```bash
# Clone the repo
git clone https://github.com/grokingclaw/grokingclawid.git
cd grokingclawid

# Build everything (CLI + daemon)
cargo build --release
```

**Requirements:** Rust 1.70+ (stable).

## Testing

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test -p grokingclawid-core
cargo test -p grokingclawid-cli
cargo test -p grokingclaw-proxy
cargo test -p grokingclaw-daemon
```

All 97 tests must pass before submitting a PR.

## Pull Request Process

1. **Fork** the repository
2. **Branch** from `main` (`git checkout -b feature/your-feature`)
3. **Make your changes** — keep commits focused and well-described
4. **Run the checks:**
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   cargo test
   ```
5. **Open a PR** against `main` with a clear description of what and why

## Code Style

- Format with `cargo fmt` (default rustfmt settings)
- Lint with `cargo clippy` — warnings are treated as errors in CI
- Write tests for new functionality
- Keep public APIs documented with `///` doc comments

## Security Vulnerabilities

Do **not** open a public issue for security vulnerabilities. Instead, follow the process in [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
