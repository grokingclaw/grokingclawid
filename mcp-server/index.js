#!/usr/bin/env node
/**
 * GrokingClawID MCP Tool Server
 * 
 * Exposes GrokingClawID CLI as MCP tools for any MCP-compatible agent.
 * Zero dependencies — uses Node.js child_process to call the Rust binary.
 * 
 * Protocol: MCP (Model Context Protocol) over stdio (JSON-RPC 2.0)
 * 
 * Usage:
 *   node index.js                    # stdio transport (default)
 *   CLAWID_BIN=/path/to/clawid node index.js  # custom binary path
 */

import { execFile } from "node:child_process";
import { createInterface } from "node:readline";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

// Locate the clawid binary
const __dirname = dirname(fileURLToPath(import.meta.url));
const CLAWID_BIN = process.env.CLAWID_BIN
  || (existsSync(join(__dirname, "..", "target", "release", "grokingclawid"))
    ? join(__dirname, "..", "target", "release", "grokingclawid")
    : existsSync(join(__dirname, "..", "target", "debug", "grokingclawid"))
      ? join(__dirname, "..", "target", "debug", "grokingclawid")
      : "grokingclawid"); // fall back to PATH

const SERVER_INFO = {
  name: "grokingclawid",
  version: "0.1.0",
};

// ─── Tool Definitions ──────────────────────────────────────────────

const TOOLS = [
  {
    name: "clawid_issue",
    description: "Issue a new agent identity card with Ed25519 + ML-DSA-65 (post-quantum) hybrid keypair. Returns the agent card JSON.",
    inputSchema: {
      type: "object",
      properties: {
        name: { type: "string", description: "Human-readable agent name" },
        owner: { type: "string", description: "Owner identifier (e.g., email)" },
        scope: { type: "string", description: "Comma-separated scopes (e.g., 'read,write,execute')" },
        ttl: { type: "string", description: "Time-to-live (e.g., '24h', '7d', '30m')", default: "24h" },
        crypto: { type: "string", enum: ["ed25519", "ml-dsa-65", "hybrid"], description: "Cryptographic scheme", default: "hybrid" },
        trust_domain: { type: "string", description: "SPIFFE trust domain (optional, generates spiffe:// URI)" },
        output: { type: "string", description: "Output directory for card + key files", default: "." },
      },
      required: ["name", "owner", "scope"],
    },
  },
  {
    name: "clawid_verify",
    description: "Verify an agent card's cryptographic signature(s) and expiration. Returns verification result.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to agent-card.json file" },
      },
      required: ["card"],
    },
  },
  {
    name: "clawid_challenge",
    description: "Issue a verification challenge for agent-to-agent mutual authentication. Returns a challenge object with nonce and timestamp.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to YOUR agent-card.json" },
        key: { type: "string", description: "Path to YOUR agent-key.pem" },
        peer_card: { type: "string", description: "Path to PEER's agent-card.json" },
      },
      required: ["card", "key", "peer_card"],
    },
  },
  {
    name: "clawid_respond",
    description: "Respond to a verification challenge from a peer agent.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to YOUR agent-card.json" },
        key: { type: "string", description: "Path to YOUR agent-key.pem" },
        challenge: { type: "string", description: "Path to challenge.json received from peer" },
      },
      required: ["card", "key", "challenge"],
    },
  },
  {
    name: "clawid_verify_response",
    description: "Verify a challenge response from a peer agent. Completes mutual authentication.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to PEER's agent-card.json" },
        response: { type: "string", description: "Path to response.json from peer" },
        challenge: { type: "string", description: "Path to original challenge.json you issued" },
      },
      required: ["card", "response", "challenge"],
    },
  },
  {
    name: "clawid_delegate",
    description: "Delegate narrowed permissions to a sub-agent. Creates a scoped delegation token.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to parent agent-card.json" },
        key: { type: "string", description: "Path to parent agent-key.pem" },
        sub_name: { type: "string", description: "Sub-agent name" },
        sub_scope: { type: "string", description: "Comma-separated scopes (must be subset of parent)" },
        ttl: { type: "string", description: "Delegation TTL (must be <= parent TTL)", default: "1h" },
        output: { type: "string", description: "Output directory", default: "." },
      },
      required: ["card", "key", "sub_name", "sub_scope"],
    },
  },
  {
    name: "clawid_export",
    description: "Export agent card to interoperable formats: A2A (Google Agent-to-Agent), SPIFFE, or DID.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to agent-card.json" },
        format: { type: "string", enum: ["a2a", "spiffe", "did"], description: "Export format", default: "a2a" },
      },
      required: ["card"],
    },
  },
  {
    name: "clawid_sign",
    description: "Sign an HTTP request with RFC 9421 message signatures using agent's private key.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to agent-card.json" },
        key: { type: "string", description: "Path to agent-key.pem" },
        method: { type: "string", description: "HTTP method (GET, POST, etc.)" },
        url: { type: "string", description: "Request URL" },
        body: { type: "string", description: "Request body (optional)" },
      },
      required: ["card", "key", "method", "url"],
    },
  },
  {
    name: "clawid_audit",
    description: "Query the tamper-evident audit log. Shows all identity operations with hash chain verification.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to agent-card.json (filters by agent)" },
        last: { type: "number", description: "Number of recent entries to show", default: 20 },
        verify: { type: "boolean", description: "Verify hash chain integrity", default: false },
      },
      required: [],
    },
  },
  {
    name: "clawid_wallet_init",
    description: "Initialize an agent wallet — derives an address on GrokingClaw Chain from the agent's Ed25519 key.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to agent-card.json" },
      },
      required: ["card"],
    },
  },
  {
    name: "clawid_wallet_balance",
    description: "Check the agent's wallet balance on GrokingClaw Chain.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to agent-card.json" },
      },
      required: ["card"],
    },
  },
  {
    name: "clawid_wallet_send",
    description: "Send tokens from agent's wallet to another agent on GrokingClaw Chain.",
    inputSchema: {
      type: "object",
      properties: {
        card: { type: "string", description: "Path to sender agent-card.json" },
        key: { type: "string", description: "Path to sender agent-key.pem" },
        to: { type: "string", description: "Recipient address or agent card path" },
        amount: { type: "number", description: "Amount to send" },
      },
      required: ["card", "key", "to", "amount"],
    },
  },
  // ─── OAuth 2.0 Bridge Tools ─────────────────────────────────────
  {
    name: "clawid_oauth_register",
    description:
      "Register an OAuth 2.0 provider for an agent. Configures client credentials, scopes, and domain bindings so the proxy can auto-inject Bearer tokens.",
    inputSchema: {
      type: "object",
      properties: {
        agent: { type: "string", description: "Agent name" },
        provider: { type: "string", description: "Provider name (github, google, openai, etc.)" },
        client_id: { type: "string", description: "OAuth client ID" },
        client_secret: { type: "string", description: "OAuth client secret (omit for public clients)" },
        authorization_url: { type: "string", description: "Authorization endpoint URL" },
        token_url: { type: "string", description: "Token endpoint URL" },
        scopes: { type: "string", description: "Space-separated scopes to request" },
        domains: { type: "string", description: "Comma-separated domains for token injection" },
        grant_type: { type: "string", description: "Grant type: authorization_code, device_code, client_credentials" },
      },
      required: ["agent", "provider", "client_id", "token_url", "scopes", "domains"],
    },
  },
  {
    name: "clawid_oauth_authorize",
    description:
      "Start an OAuth authorization flow for an agent. Returns a user code (device flow) or authorization URL (code flow).",
    inputSchema: {
      type: "object",
      properties: {
        agent: { type: "string", description: "Agent name" },
        registration_id: { type: "string", description: "OAuth registration ID" },
      },
      required: ["agent", "registration_id"],
    },
  },
  {
    name: "clawid_oauth_status",
    description:
      "Check OAuth token status for an agent — shows valid/expired/missing for each registration.",
    inputSchema: {
      type: "object",
      properties: {
        agent: { type: "string", description: "Agent name" },
        registration_id: { type: "string", description: "Optional: specific registration ID" },
      },
      required: ["agent"],
    },
  },
  {
    name: "clawid_oauth_revoke",
    description:
      "Revoke OAuth tokens for a registration. Cascades to child delegations.",
    inputSchema: {
      type: "object",
      properties: {
        agent: { type: "string", description: "Agent name" },
        registration_id: { type: "string", description: "OAuth registration ID to revoke" },
      },
      required: ["agent", "registration_id"],
    },
  },
  {
    name: "clawid_oauth_exchange",
    description:
      "Exchange a ClawID agent identity for an OAuth token via RFC 8693 token exchange.",
    inputSchema: {
      type: "object",
      properties: {
        agent: { type: "string", description: "Agent name" },
        registration_id: { type: "string", description: "OAuth registration ID" },
      },
      required: ["agent", "registration_id"],
    },
  },
];

// ─── CLI Execution ─────────────────────────────────────────────────

async function runClawId(args, timeoutMs = 30000) {
  try {
    const { stdout, stderr } = await execFileAsync(CLAWID_BIN, args, {
      timeout: timeoutMs,
      maxBuffer: 1024 * 1024,
    });
    return { success: true, output: stdout.trim(), stderr: stderr.trim() };
  } catch (err) {
    return {
      success: false,
      output: err.stdout?.trim() || "",
      error: err.stderr?.trim() || err.message,
      code: err.code,
    };
  }
}

function buildArgs(toolName, params) {
  switch (toolName) {
    case "clawid_issue": {
      const args = ["issue", "--name", params.name, "--owner", params.owner, "--scope", params.scope];
      if (params.ttl) args.push("--ttl", params.ttl);
      if (params.crypto) args.push("--crypto", params.crypto);
      if (params.trust_domain) args.push("--trust-domain", params.trust_domain);
      if (params.output) args.push("-o", params.output);
      return args;
    }
    case "clawid_verify":
      return ["verify", params.card];
    case "clawid_challenge":
      return ["challenge", "--card", params.card, "--key", params.key, "--peer-card", params.peer_card];
    case "clawid_respond":
      return ["respond", "--card", params.card, "--key", params.key, "--challenge", params.challenge];
    case "clawid_verify_response":
      return ["verify-response", "--card", params.card, "--response", params.response, "--challenge", params.challenge];
    case "clawid_delegate": {
      const args = ["delegate", "--card", params.card, "--key", params.key, "--sub-name", params.sub_name, "--sub-scope", params.sub_scope];
      if (params.ttl) args.push("--ttl", params.ttl);
      if (params.output) args.push("-o", params.output);
      return args;
    }
    case "clawid_export": {
      const args = ["export", params.card];
      if (params.format) args.push("--format", params.format);
      return args;
    }
    case "clawid_sign": {
      const args = ["sign", "--card", params.card, "--key", params.key, "--method", params.method, "--url", params.url];
      if (params.body) args.push("--body", params.body);
      return args;
    }
    case "clawid_audit": {
      const args = ["audit"];
      if (params.card) args.push("--card", params.card);
      if (params.last) args.push("--last", String(params.last));
      if (params.verify) args.push("--verify");
      return args;
    }
    case "clawid_wallet_init":
      return ["wallet", "init", "--card", params.card];
    case "clawid_wallet_balance":
      return ["wallet", "balance", "--card", params.card];
    case "clawid_wallet_send":
      return ["wallet", "send", "--card", params.card, "--key", params.key, "--to", params.to, "--amount", String(params.amount)];
    // ─── OAuth 2.0 Bridge ────────────────────────────────────────
    case "clawid_oauth_register": {
      const args = ["oauth", "register", "--agent", params.agent, "--provider", params.provider, "--client-id", params.client_id, "--token-url", params.token_url, "--scopes", params.scopes, "--domains", params.domains];
      if (params.client_secret) args.push("--client-secret", params.client_secret);
      if (params.authorization_url) args.push("--authorization-url", params.authorization_url);
      if (params.grant_type) args.push("--grant-type", params.grant_type);
      return args;
    }
    case "clawid_oauth_authorize":
      return ["oauth", "authorize", "--agent", params.agent, "--registration", params.registration_id];
    case "clawid_oauth_status": {
      const args = ["oauth", "status", "--agent", params.agent];
      if (params.registration_id) args.push("--registration", params.registration_id);
      return args;
    }
    case "clawid_oauth_revoke":
      return ["oauth", "revoke", "--agent", params.agent, "--registration", params.registration_id];
    case "clawid_oauth_exchange":
      return ["oauth", "exchange", "--agent", params.agent, "--registration", params.registration_id];
    default:
      throw new Error(`Unknown tool: ${toolName}`);
  }
}

// ─── MCP Protocol Handler ──────────────────────────────────────────

function handleRequest(request) {
  const { method, params, id } = request;

  switch (method) {
    case "initialize":
      return {
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: SERVER_INFO,
        },
      };

    case "notifications/initialized":
      return null; // no response for notifications

    case "tools/list":
      return {
        jsonrpc: "2.0",
        id,
        result: { tools: TOOLS },
      };

    case "tools/call":
      return null; // handled async

    case "ping":
      return { jsonrpc: "2.0", id, result: {} };

    default:
      return {
        jsonrpc: "2.0",
        id,
        error: { code: -32601, message: `Method not found: ${method}` },
      };
  }
}

async function handleToolCall(request) {
  const { params, id } = request;
  const { name, arguments: toolArgs } = params;

  const tool = TOOLS.find((t) => t.name === name);
  if (!tool) {
    return {
      jsonrpc: "2.0",
      id,
      error: { code: -32602, message: `Unknown tool: ${name}` },
    };
  }

  const args = buildArgs(name, toolArgs || {});
  const result = await runClawId(args);

  return {
    jsonrpc: "2.0",
    id,
    result: {
      content: [
        {
          type: "text",
          text: result.success
            ? result.output
            : `Error: ${result.error}\n${result.output}`,
        },
      ],
      isError: !result.success,
    },
  };
}

// ─── Stdio Transport ───────────────────────────────────────────────

const rl = createInterface({ input: process.stdin, terminal: false });
let buffer = "";

rl.on("line", async (line) => {
  buffer += line;
  let request;
  try {
    request = JSON.parse(buffer);
    buffer = "";
  } catch {
    return; // incomplete JSON, wait for more
  }

  let response;
  if (request.method === "tools/call") {
    response = await handleToolCall(request);
  } else {
    response = handleRequest(request);
  }

  if (response) {
    process.stdout.write(JSON.stringify(response) + "\n");
  }
});

rl.on("close", () => process.exit(0));

// Log to stderr (MCP convention)
process.stderr.write(`[clawid-mcp] Server started. Binary: ${CLAWID_BIN}\n`);
