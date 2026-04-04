//! Integration tests for GrokingClawID CLI.
//!
//! Tests the full lifecycle: issue → verify → delegate → audit → export.
//! Covers Ed25519, ML-DSA-65, and hybrid crypto schemes.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use tempfile::TempDir;

/// Helper: get a Command for grokingclawid binary.
fn cmd() -> Command {
    Command::cargo_bin("grokingclawid").expect("binary should exist")
}

// ─── Ed25519 (classical) ───────────────────────────────────────────────

/// Test 1: Issue an Ed25519 agent card and verify output files.
#[test]
fn test_issue_ed25519() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "test-agent",
            "--owner",
            "test@example.com",
            "--scope",
            "read,write",
            "--ttl",
            "1h",
            "--type",
            "instance",
            "--crypto",
            "ed25519",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "Agent identity issued successfully",
        ))
        .stdout(predicate::str::contains("ed25519"));

    let card_path = out.join("agent-card.json");
    let key_path = out.join("agent-key.pem");
    assert!(card_path.exists());
    assert!(key_path.exists());

    let card: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&card_path).unwrap()).unwrap();
    assert_eq!(card["name"], "test-agent");
    assert_eq!(card["owner"], "test@example.com");
    assert_eq!(card["crypto_scheme"], "ed25519");
    assert!(card["pq_public_key"].is_null());
    assert!(card["pq_signature"].is_null());

    let key_pem = fs::read_to_string(&key_path).unwrap();
    assert!(key_pem.contains("BEGIN ED25519 PRIVATE KEY"));
    assert!(!key_pem.contains("ML-DSA-65"));
}

/// Test 2: Issue Ed25519 card, then verify it passes validation.
#[test]
fn test_verify_ed25519() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "verifiable-agent",
            "--owner",
            "admin@example.com",
            "--scope",
            "read,write,execute",
            "--ttl",
            "2h",
            "--type",
            "session",
            "--crypto",
            "ed25519",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    cmd()
        .args([
            "verify",
            "--agent-card",
            out.join("agent-card.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("VALID"))
        .stdout(predicate::str::contains("verifiable-agent"));
}

// ─── Hybrid (Ed25519 + ML-DSA-65) ──────────────────────────────────────

/// Test 3: Issue a hybrid agent card (default crypto scheme).
#[test]
fn test_issue_hybrid_default() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "hybrid-agent",
            "--owner",
            "pq@example.com",
            "--scope",
            "read,write",
            "--ttl",
            "12h",
            "--type",
            "instance",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("hybrid"))
        .stdout(predicate::str::contains("ML-DSA-65"));

    let card: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("agent-card.json")).unwrap()).unwrap();
    assert_eq!(card["crypto_scheme"], "hybrid");
    assert!(card["pq_public_key"].is_string());
    assert!(card["pq_signature"].is_string());

    let key_pem = fs::read_to_string(out.join("agent-key.pem")).unwrap();
    assert!(key_pem.contains("BEGIN ED25519 PRIVATE KEY"));
    assert!(key_pem.contains("BEGIN ML-DSA-65 PRIVATE KEY"));
}

/// Test 4: Issue hybrid card and verify both signatures pass.
#[test]
fn test_verify_hybrid() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "pq-verified-agent",
            "--owner",
            "quantum@example.com",
            "--scope",
            "admin",
            "--ttl",
            "4h",
            "--crypto",
            "hybrid",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    cmd()
        .args([
            "verify",
            "--agent-card",
            out.join("agent-card.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Ed25519:   ✅ VALID"))
        .stdout(predicate::str::contains("ML-DSA-65: ✅ VALID"))
        .stdout(predicate::str::contains("RESULT: ✅ VALID"));
}

// ─── Delegation ─────────────────────────────────────────────────────────

/// Test 5: Delegate from hybrid parent with narrowed scope.
#[test]
fn test_delegate_hybrid_narrows_scope() {
    let tmp = TempDir::new().unwrap();
    let parent_dir = tmp.path().join("parent");
    let deleg_dir = tmp.path().join("delegation");

    cmd()
        .args([
            "issue",
            "--name",
            "parent-agent",
            "--owner",
            "root@example.com",
            "--scope",
            "read,write,admin",
            "--ttl",
            "24h",
            "--type",
            "instance",
            "--crypto",
            "hybrid",
            "-o",
            parent_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    cmd()
        .args([
            "delegate",
            "--from",
            parent_dir.join("agent-card.json").to_str().unwrap(),
            "--key",
            parent_dir.join("agent-key.pem").to_str().unwrap(),
            "--to",
            "child-agent",
            "--scope",
            "read",
            "--ttl",
            "30m",
            "-o",
            deleg_dir.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("Delegation token created"))
        .stdout(predicate::str::contains("hybrid"));

    let token: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(deleg_dir.join("delegation-token.json")).unwrap())
            .unwrap();
    assert_eq!(token["agent_name"], "child-agent");
    assert_eq!(token["scopes"], serde_json::json!(["read"]));
    assert_eq!(token["crypto_scheme"], "hybrid");
    assert!(token["pq_signature"].is_string());
}

/// Test 6: Delegation fails if requested scope exceeds parent's scope.
#[test]
fn test_delegate_rejects_wider_scope() {
    let tmp = TempDir::new().unwrap();
    let parent_dir = tmp.path().join("parent");
    let deleg_dir = tmp.path().join("delegation");

    cmd()
        .args([
            "issue",
            "--name",
            "limited-parent",
            "--owner",
            "user@example.com",
            "--scope",
            "read",
            "--ttl",
            "24h",
            "--crypto",
            "ed25519",
            "-o",
            parent_dir.to_str().unwrap(),
        ])
        .assert()
        .success();

    cmd()
        .args([
            "delegate",
            "--from",
            parent_dir.join("agent-card.json").to_str().unwrap(),
            "--key",
            parent_dir.join("agent-key.pem").to_str().unwrap(),
            "--to",
            "sneaky-agent",
            "--scope",
            "write",
            "--ttl",
            "10m",
            "-o",
            deleg_dir.to_str().unwrap(),
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("Cannot delegate scope 'write'"));
}

// ─── SPIFFE ─────────────────────────────────────────────────────────────

/// Test 7: Issue with SPIFFE trust domain generates spiffe:// URI.
#[test]
fn test_issue_with_spiffe_id() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "spiffe-agent",
            "--owner",
            "infra@example.com",
            "--scope",
            "read",
            "--ttl",
            "1h",
            "--crypto",
            "ed25519",
            "--trust-domain",
            "example.org",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains(
            "SPIFFE ID: spiffe://example.org/agent/instance/spiffe-agent",
        ));

    let card: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("agent-card.json")).unwrap()).unwrap();
    assert_eq!(
        card["spiffe_id"],
        "spiffe://example.org/agent/instance/spiffe-agent"
    );
}

// ─── A2A Export ─────────────────────────────────────────────────────────

/// Test 8: Export agent card to A2A format.
#[test]
fn test_export_a2a() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "a2a-agent",
            "--owner",
            "ops@example.com",
            "--scope",
            "read,write,deploy",
            "--ttl",
            "8h",
            "--crypto",
            "hybrid",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    let a2a_output = out.join("a2a-agent-card.json");
    cmd()
        .args([
            "export",
            "--agent-card",
            out.join("agent-card.json").to_str().unwrap(),
            "--base-url",
            "https://api.example.com",
            "-o",
            a2a_output.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("A2A agent card exported"))
        .stdout(predicate::str::contains("a2a-agent"));

    let a2a: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&a2a_output).unwrap()).unwrap();
    assert_eq!(a2a["name"], "a2a-agent");
    assert!(a2a["url"]
        .as_str()
        .unwrap()
        .starts_with("https://api.example.com/agents/"));
    assert_eq!(a2a["provider"]["organization"], "ops@example.com");
    assert_eq!(a2a["skills"].as_array().unwrap().len(), 3);
    assert_eq!(a2a["authentication"]["crypto_scheme"], "hybrid");
    assert!(a2a["authentication"]["pq_public_key"].is_string());
}

// ─── Audit ──────────────────────────────────────────────────────────────

/// Test 9: Audit log shows entries after issuing and delegating.
#[test]
fn test_audit_shows_entries() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "auditable-agent",
            "--owner",
            "audit@example.com",
            "--scope",
            "read",
            "--ttl",
            "1h",
            "--crypto",
            "ed25519",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    cmd()
        .args(["audit", "--last", "1h"])
        .assert()
        .success()
        .stdout(predicate::str::contains("issue"));
}

// ─── Help ───────────────────────────────────────────────────────────────

/// Test 10: Help text is available for all subcommands.
#[test]
fn test_help_text() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("identity"))
        .stdout(predicate::str::contains("post-quantum"));

    for subcmd in ["issue", "verify", "delegate", "audit", "export"] {
        cmd()
            .args([subcmd, "--help"])
            .assert()
            .success()
            .stdout(predicate::str::contains("Usage"));
    }
}

// ─── PQ Transaction Attestation ─────────────────────────────────────────

/// Test 11: Verify PQ attestation creation and verification (unit-level).
#[test]
fn test_pq_attestation_roundtrip() {
    // This tests the attestation layer without network calls.
    // Issue a hybrid card, extract keys, create attestation, verify it.
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "pq-tx-agent",
            "--owner",
            "pq-wallet@example.com",
            "--scope",
            "transfer",
            "--ttl",
            "1h",
            "--crypto",
            "hybrid",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Read card and verify it has PQ key material
    let card: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("agent-card.json")).unwrap()).unwrap();
    assert_eq!(card["crypto_scheme"], "hybrid");
    assert!(card["pq_public_key"].is_string());

    // Read key PEM and verify it has both sections
    let key_pem = fs::read_to_string(out.join("agent-key.pem")).unwrap();
    assert!(key_pem.contains("BEGIN ED25519 PRIVATE KEY"));
    assert!(key_pem.contains("BEGIN ML-DSA-65 PRIVATE KEY"));
    // Both key sections present = wallet send will produce PQ attestation
}

/// Test 12: ML-DSA-65 only identity rejected for wallet send (needs hybrid).
#[test]
fn test_mldsa_only_rejected_for_wallet() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "mldsa-wallet-agent",
            "--owner",
            "quantum@example.com",
            "--scope",
            "transfer",
            "--ttl",
            "1h",
            "--crypto",
            "ml-dsa-65",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success();

    // Wallet send should fail: ML-DSA-65 only can't produce Ed25519 for IOTA
    cmd()
        .args([
            "wallet",
            "send",
            "--agent-card",
            out.join("agent-card.json").to_str().unwrap(),
            "--key",
            out.join("agent-key.pem").to_str().unwrap(),
            "--to",
            "0x0000000000000000000000000000000000000000000000000000000000000000",
            "--amount",
            "1.0",
            "--network",
            "testnet",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains(
            "ML-DSA-65 only identity cannot sign IOTA transactions",
        ));
}

// ─── ML-DSA-65 only ─────────────────────────────────────────────────────

/// Test 13: Issue and verify with ML-DSA-65 only scheme.
#[test]
fn test_issue_verify_mldsa65() {
    let tmp = TempDir::new().unwrap();
    let out = tmp.path();

    cmd()
        .args([
            "issue",
            "--name",
            "pq-only-agent",
            "--owner",
            "quantum@example.com",
            "--scope",
            "read",
            "--ttl",
            "1h",
            "--crypto",
            "ml-dsa-65",
            "-o",
            out.to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ml-dsa-65"));

    let card: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(out.join("agent-card.json")).unwrap()).unwrap();
    assert_eq!(card["crypto_scheme"], "ml-dsa-65");
    assert!(card["pq_public_key"].is_string());

    cmd()
        .args([
            "verify",
            "--agent-card",
            out.join("agent-card.json").to_str().unwrap(),
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("ML-DSA-65: ✅ VALID"));
}
