# GrokingClawID MCP Tool Server

Cryptographic agent identity, authentication, and payments — exposed as [MCP](https://modelcontextprotocol.io/) tools for any compatible agent runtime.

## What This Does

Any MCP-compatible agent (Claude Code, OpenClaw, Cursor, Codex, etc.) gets access to:

| Tool | Description |
|------|-------------|
| `clawid_issue` | Create a new agent identity (Ed25519 + ML-DSA-65 hybrid post-quantum) |
| `clawid_verify` | Verify another agent's identity card |
| `clawid_challenge` | Mutual authentication with another agent |
| `clawid_respond` | Respond to an auth challenge |
| `clawid_verify_response` | Complete mutual authentication |
| `clawid_delegate` | Delegate scoped permissions to a sub-agent |
| `clawid_export` | Export identity as A2A, SPIFFE, or DID format |
| `clawid_sign` | Sign HTTP requests (RFC 9421) |
| `clawid_audit` | Query tamper-evident audit log |
| `clawid_wallet_init` | Create wallet on GrokingClaw Chain |
| `clawid_wallet_balance` | Check wallet balance |
| `clawid_wallet_send` | Send tokens to another agent |

## Prerequisites

- Node.js 18+
- GrokingClawID binary (`cargo build --release` from parent directory, or install from releases)

## Usage

### With Claude Code

Add to your MCP config (`~/.claude/claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "grokingclawid": {
      "command": "node",
      "args": ["/path/to/grokingclawid/mcp-server/index.js"]
    }
  }
}
```

### With OpenClaw

```bash
# In your OpenClaw MCP config
claw mcp add grokingclawid -- node /path/to/mcp-server/index.js
```

### Standalone

```bash
node index.js  # starts on stdio
```

### Custom Binary Path

```bash
CLAWID_BIN=/usr/local/bin/grokingclawid node index.js
```

## Architecture

```
Agent (Claude/OpenClaw/etc.)
    ↓ MCP protocol (JSON-RPC 2.0 over stdio)
clawid-mcp server (this)
    ↓ execFile()
GrokingClawID binary (Rust)
    ↓
Local crypto ops + GrokingClaw Chain RPC
```

Zero runtime dependencies. The server is a thin adapter between MCP's JSON-RPC protocol and the GrokingClawID CLI.

## Testing

```bash
npm test  # runs smoke tests against the server
```

## License

Apache-2.0
