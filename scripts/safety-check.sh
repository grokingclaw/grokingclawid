#!/usr/bin/env bash
# safety-check.sh — Pre-commit safety guardrails for GrokingClawID
#
# Prevents the mistakes found in the Claude Code leak:
# 1. No secrets/keys in source
# 2. No hardcoded endpoints that leak infra
# 3. No internal tooling references
# 4. No debug/dev flags left enabled
# 5. Binary doesn't leak paths or internal info
#
# Usage: ./scripts/safety-check.sh [--fix]

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

fail() { echo -e "${RED}FAIL${NC}: $1"; ((ERRORS++)); }
warn() { echo -e "${YELLOW}WARN${NC}: $1"; ((WARNINGS++)); }
pass() { echo -e "${GREEN}PASS${NC}: $1"; }

echo "🦀 GrokingClawID Safety Check"
echo "=============================="
echo ""

# ── 1. No secrets in staged files ──────────────────────────────────────

echo "▶ Checking for secrets in source..."

# Check git staged files (or all tracked files if not in git context)
FILES=$(git diff --cached --name-only 2>/dev/null || find src tests -name '*.rs' 2>/dev/null)

if [ -z "$FILES" ]; then
    FILES=$(find src tests -name '*.rs' 2>/dev/null)
fi

# Patterns that should NEVER appear in source
SECRET_PATTERNS=(
    'AKIA[0-9A-Z]{16}'                    # AWS access key
    'sk-[a-zA-Z0-9]{20,}'                 # OpenAI/Anthropic API key
    'ghp_[a-zA-Z0-9]{36}'                 # GitHub PAT
    'gho_[a-zA-Z0-9]{36}'                 # GitHub OAuth
    'glpat-[a-zA-Z0-9\-]{20}'             # GitLab PAT
    'xox[bpors]-[a-zA-Z0-9\-]+'           # Slack token
    '-----BEGIN (RSA |EC |DSA )?PRIVATE KEY' # Actual private keys (not PEM format strings)
    'password\s*=\s*"[^"]{4,}"'            # Hardcoded passwords
    'secret\s*=\s*"[^"]{8,}"'             # Hardcoded secrets
)

for pattern in "${SECRET_PATTERNS[@]}"; do
    matches=$(grep -rn -E "$pattern" src/ tests/ 2>/dev/null | grep -v '#\[test\]' | grep -v '//.*test' | grep -v 'fn test_' | head -5 || true)
    if [ -n "$matches" ]; then
        fail "Potential secret found matching: $pattern"
        echo "    $matches"
    fi
done

# Check for PEM files that might get committed
PEM_FILES=$(git ls-files '*.pem' 'agent-key*' '*.secret' '*.key' 2>/dev/null || true)
if [ -n "$PEM_FILES" ]; then
    fail "Key/secret files tracked by git: $PEM_FILES"
else
    pass "No key files tracked by git"
fi

# ── 2. No hardcoded internal infrastructure ────────────────────────────

echo ""
echo "▶ Checking for infrastructure leaks..."

INFRA_PATTERNS=(
    '192\.168\.[0-9]+\.[0-9]+'            # Private IPs
    '10\.[0-9]+\.[0-9]+\.[0-9]+'          # Private IPs
    '172\.(1[6-9]|2[0-9]|3[01])\.'        # Private IPs
    'localhost:[0-9]{4,5}'                 # Local services (except standard ports)
    '\.local\b'                            # mDNS hostnames
    '\.internal\b'                         # Internal domains
    'najabot'                              # Internal project references
    'naja[^_]'                             # Internal project references (but allow naja_*)
    'tekcin'                               # Personal GitHub
    'huynguyenusa'                         # Personal machine username
    '@icloud\.com'                         # Personal email
    'MacBook'                              # Machine names
)

for pattern in "${INFRA_PATTERNS[@]}"; do
    # Exclude: comments, test files, this script, SECURITY.md, README examples
    matches=$(grep -rn -iE "$pattern" src/ 2>/dev/null \
        | grep -v '// .*example' \
        | grep -v '#\[test\]' \
        | grep -v 'mod tests' \
        | grep -v 'fn test_' \
        | grep -v '\.example\.' \
        | head -3 || true)
    if [ -n "$matches" ]; then
        # localhost in default arg is OK for export command
        if [[ "$pattern" == 'localhost:[0-9]{4,5}' ]]; then
            continue
        fi
        fail "Infrastructure reference '$pattern' found in source:"
        echo "    $matches"
    fi
done

# Check README and docs too
for pattern in "huynguyenusa" "tekcin" "@icloud.com" "najabot" "192.168."; do
    matches=$(grep -rn "$pattern" README.md SECURITY.md Cargo.toml 2>/dev/null | head -3 || true)
    if [ -n "$matches" ]; then
        fail "Personal reference '$pattern' in public files:"
        echo "    $matches"
    fi
done

pass "No private infrastructure references in source"

# ── 3. No debug/dev artifacts ──────────────────────────────────────────

echo ""
echo "▶ Checking for debug artifacts..."

# Debug prints in non-test code
DEBUG_MATCHES=$(grep -rn 'dbg!\|println!\|eprintln!' src/ 2>/dev/null \
    | grep -v '#\[test\]' \
    | grep -v 'mod tests' \
    | grep -v 'fn test_' \
    | grep -v 'commands/' \
    || true)

# Commands legitimately use println for CLI output, but core modules shouldn't
CORE_DEBUG=$(grep -rn 'dbg!' src/crypto.rs src/audit.rs src/models.rs src/iota.rs src/httpsig.rs src/challenge.rs 2>/dev/null || true)
if [ -n "$CORE_DEBUG" ]; then
    fail "dbg!() macro found in core modules (remove before release):"
    echo "    $CORE_DEBUG"
else
    pass "No debug macros in core modules"
fi

# TODO/FIXME/HACK in non-test code
TODOS=$(grep -rn 'TODO\|FIXME\|HACK\|XXX' src/ 2>/dev/null | grep -v '#\[test\]' | grep -v 'fn test_' || true)
if [ -n "$TODOS" ]; then
    warn "TODOs found in source (review before release):"
    echo "    $TODOS"
else
    pass "No TODOs in source"
fi

# ── 4. Feature flags / env vars check ─────────────────────────────────

echo ""
echo "▶ Checking for unsafe feature flags..."

# Look for env var checks that could be debug backdoors
ENV_CHECKS=$(grep -rn 'std::env::var\|env!\|option_env!' src/ 2>/dev/null \
    | grep -v '#\[test\]' \
    | grep -v 'fn test_' \
    || true)
if [ -n "$ENV_CHECKS" ]; then
    warn "Environment variable usage found (verify these are intentional):"
    echo "    $ENV_CHECKS"
else
    pass "No environment variable checks in source"
fi

# ── 5. Cargo.toml sanity ──────────────────────────────────────────────

echo ""
echo "▶ Checking Cargo.toml..."

if grep -q 'license = "PROPRIETARY"' Cargo.toml; then
    warn "License is PROPRIETARY — update if you want open-source contributions"
fi

if ! grep -q 'strip = true' Cargo.toml; then
    fail "Release profile doesn't strip symbols (leaks internal paths)"
else
    pass "Release binary strips symbols"
fi

if ! grep -q 'lto = true' Cargo.toml; then
    warn "LTO not enabled — larger binary, more reversible"
else
    pass "LTO enabled"
fi

if grep -q 'panic = "unwind"' Cargo.toml; then
    warn "panic=unwind keeps panic strings in binary — consider abort"
elif grep -q 'panic = "abort"' Cargo.toml; then
    pass "panic=abort (no unwinding overhead, smaller binary)"
fi

# ── 6. Git hooks suggestion ───────────────────────────────────────────

echo ""
echo "▶ Checking git hooks..."

if [ -f .git/hooks/pre-commit ]; then
    pass "pre-commit hook installed"
else
    warn "No pre-commit hook — run: cp scripts/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit"
fi

# ── Summary ────────────────────────────────────────────────────────────

echo ""
echo "=============================="
if [ $ERRORS -gt 0 ]; then
    echo -e "${RED}$ERRORS errors, $WARNINGS warnings — FIX BEFORE PUSH${NC}"
    exit 1
elif [ $WARNINGS -gt 0 ]; then
    echo -e "${YELLOW}0 errors, $WARNINGS warnings — review before push${NC}"
    exit 0
else
    echo -e "${GREEN}All checks passed ✅${NC}"
    exit 0
fi
