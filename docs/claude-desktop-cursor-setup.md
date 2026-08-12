---
type: "Reference"
title: "Claude Desktop and Cursor setup"
description: "MCP client configuration for the OPNsense MCP server: Claude Desktop, Cursor, CLI flags, testing, and troubleshooting."
timestamp: "2026-07-17"
---

# Claude Desktop / Cursor setup

How MCP clients register this server. Parent: [README.md](../README.md).

## Claude Desktop

Config file:

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "npx",
      "args": ["-y", "@richard-stovall/opnsense-mcp-server"],
      "env": {
        "OPNSENSE_URL": "https://192.168.1.1",
        "OPNSENSE_API_KEY": "your-api-key",
        "OPNSENSE_API_SECRET": "your-api-secret",
        "OPNSENSE_VERIFY_SSL": "false"
      }
    }
  }
}
```

Screenshots of the server in use: Claude Desktop
([network architecture](https://github.com/user-attachments/assets/c7742683-7f25-437a-9747-250f48472a6a))
and Claude Code
([session](https://github.com/user-attachments/assets/7833e6c6-45e3-4c98-a234-46a0da8c362d));
local copies in `images/`.

## CLI-argument alternative

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "node",
      "args": [
        "/path/to/opnsense-mcp-server/index.js",
        "--url", "https://YOUR-OPNSENSE-IP",
        "--api-key", "YOUR-API-KEY",
        "--api-secret", "YOUR-API-SECRET",
        "--no-verify-ssl"
      ]
    }
  }
}
```

**Plugin tools**: add `"--plugins"` to the args or set
`"INCLUDE_PLUGINS": "true"` in env to include all 64 plugin module tools.

## Cursor

Add the same npx block to `.cursor/mcp.json` in your project or
`~/.cursor/mcp.json` globally.

## Testing the setup

Ask the assistant:

- "What MCP tools are available?"
- "Use core_manage to get the system status"
- "Use firewall_manage to search for all aliases"
- "Use interfaces_manage to list all network interfaces"

Or test manually before wiring up a client:

```bash
node /path/to/opnsense-mcp-server/index.js \
  --url https://YOUR-OPNSENSE-IP \
  --api-key YOUR-API-KEY \
  --api-secret YOUR-API-SECRET \
  --no-verify-ssl
```

Expected output:

```
OPNsense MCP server v0.7.0 (modular) started
Core tools: 24 modules
Plugin tools: 64 modules (disabled)
Total available: 24 modules
```

## Troubleshooting

Connection issues:

1. Verify the OPNsense API is enabled.
2. Check that the API key has appropriate permissions.
3. Ensure the IP/hostname is reachable from your machine.
4. For self-signed certificates, use `--no-verify-ssl` or set
   `"OPNSENSE_VERIFY_SSL": "false"`.

Server logs: check the Claude Desktop logs for MCP server error messages.
