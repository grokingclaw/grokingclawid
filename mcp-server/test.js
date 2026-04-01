#!/usr/bin/env node
/**
 * Quick smoke test for clawid-mcp server
 * Sends MCP protocol messages over stdio and checks responses
 */
import { spawn } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const server = spawn("node", [join(__dirname, "index.js")], {
  stdio: ["pipe", "pipe", "pipe"],
});

let responses = [];
let buffer = "";

server.stdout.on("data", (data) => {
  buffer += data.toString();
  const lines = buffer.split("\n");
  buffer = lines.pop(); // keep incomplete line
  for (const line of lines) {
    if (line.trim()) {
      try {
        responses.push(JSON.parse(line));
      } catch (e) {
        console.error("Failed to parse:", line);
      }
    }
  }
});

server.stderr.on("data", (data) => {
  // Server logs go to stderr — that's expected
});

function send(obj) {
  server.stdin.write(JSON.stringify(obj) + "\n");
}

function wait(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

async function runTests() {
  let passed = 0;
  let failed = 0;

  // Test 1: Initialize
  send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2024-11-05", capabilities: {}, clientInfo: { name: "test", version: "0.1" } } });
  await wait(500);

  const initResp = responses.find((r) => r.id === 1);
  if (initResp?.result?.serverInfo?.name === "grokingclawid") {
    console.log("✅ Test 1: Initialize — PASS");
    passed++;
  } else {
    console.log("❌ Test 1: Initialize — FAIL", initResp);
    failed++;
  }

  // Test 2: List Tools
  send({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
  await wait(500);

  const listResp = responses.find((r) => r.id === 2);
  if (listResp?.result?.tools?.length === 12) {
    console.log(`✅ Test 2: List Tools — PASS (${listResp.result.tools.length} tools)`);
    passed++;
  } else {
    console.log(`❌ Test 2: List Tools — FAIL (expected 12, got ${listResp?.result?.tools?.length})`, listResp);
    failed++;
  }

  // Test 3: Tool names check
  const toolNames = listResp?.result?.tools?.map((t) => t.name) || [];
  const expected = ["clawid_issue", "clawid_verify", "clawid_challenge", "clawid_respond", "clawid_verify_response", "clawid_delegate", "clawid_export", "clawid_sign", "clawid_audit", "clawid_wallet_init", "clawid_wallet_balance", "clawid_wallet_send"];
  const allPresent = expected.every((n) => toolNames.includes(n));
  if (allPresent) {
    console.log("✅ Test 3: All tool names present — PASS");
    passed++;
  } else {
    const missing = expected.filter((n) => !toolNames.includes(n));
    console.log(`❌ Test 3: Missing tools — FAIL:`, missing);
    failed++;
  }

  // Test 4: Ping
  send({ jsonrpc: "2.0", id: 4, method: "ping", params: {} });
  await wait(300);

  const pingResp = responses.find((r) => r.id === 4);
  if (pingResp?.result !== undefined) {
    console.log("✅ Test 4: Ping — PASS");
    passed++;
  } else {
    console.log("❌ Test 4: Ping — FAIL", pingResp);
    failed++;
  }

  // Test 5: Unknown method
  send({ jsonrpc: "2.0", id: 5, method: "nonexistent", params: {} });
  await wait(300);

  const unknownResp = responses.find((r) => r.id === 5);
  if (unknownResp?.error?.code === -32601) {
    console.log("✅ Test 5: Unknown method error — PASS");
    passed++;
  } else {
    console.log("❌ Test 5: Unknown method error — FAIL", unknownResp);
    failed++;
  }

  // Test 6: Call clawid_audit (should work even with no data)
  send({ jsonrpc: "2.0", id: 6, method: "tools/call", params: { name: "clawid_audit", arguments: { last: 5 } } });
  await wait(2000);

  const auditResp = responses.find((r) => r.id === 6);
  if (auditResp?.result?.content?.[0]?.type === "text") {
    console.log("✅ Test 6: Tool call (audit) — PASS");
    passed++;
  } else {
    console.log("❌ Test 6: Tool call (audit) — FAIL", auditResp);
    failed++;
  }

  console.log(`\n${passed}/${passed + failed} tests passed`);
  server.kill();
  process.exit(failed > 0 ? 1 : 0);
}

runTests();
