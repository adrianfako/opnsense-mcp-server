---
type: "Index"
title: "OPNsense MCP Server"
description: "Modular MCP server exposing OPNsense firewall management as 88 module-based tools; fleet fork with live-validated write-route fixes."
timestamp: "2026-07-17"
---

# OPNsense MCP Server

A modular Model Context Protocol (MCP) server that exposes **88 module-based
tools** covering 2000+ OPNsense firewall management methods (752 core, 1271
plugin) through a type-safe TypeScript interface built on
[@richard-stovall/opnsense-typescript-client](https://www.npmjs.com/package/@richard-stovall/opnsense-typescript-client)
v0.5.3. It bridges AI assistants (Claude Desktop, Claude Code, Cursor) and an
OPNsense firewall over its API. This repo is a fork of
[richard-stovall/opnsense-mcp-server](https://github.com/richard-stovall/opnsense-mcp-server)
carrying write-route re-maps and embedded write-body schemas the upstream
client gets wrong (firewall/NAT, WireGuard, Kea/dhcpv4); the fleet's
opnsense-homelab / eu-2 / eu-6 MCP servers run this fork via the npx-cached
GitHub install (cache refresh procedure in [TODO.md](TODO.md)).

## Shape

```
opnsense-mcp-server/
  index.js               # built single-file server (committed artifact)
  tools-generated.json   # generated tool definitions, embedded into index.js
  src/generate-tools.ts  # generates tools-generated.json
  src/build.ts           # builds index.js; write-route re-maps live here
  images/                # usage screenshots
  docs/                  # client setup, tool reference, write-schema cheat-sheet
```

## Install

Requires Node.js 18+, an OPNsense firewall with API access enabled, and an
API key + secret from that installation.

```bash
npm install -g @richard-stovall/opnsense-mcp-server
```

MCP clients launch it via `npx -y @richard-stovall/opnsense-mcp-server` with
env vars: `OPNSENSE_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`
(required); `INCLUDE_PLUGINS=true` enables the 64 plugin module tools;
`OPNSENSE_VERIFY_SSL=false` disables SSL verification (development only).
CLI-flag equivalents, Claude Desktop / Cursor config blocks, testing, and
troubleshooting:
[docs/claude-desktop-cursor-setup.md](docs/claude-desktop-cursor-setup.md).

## Usage

Each tool is one OPNsense module and takes a `method` plus `params`:

```json
{
  "tool": "firewall_manage",
  "arguments": { "method": "aliasSearchItem", "params": { "searchPhrase": "web" } }
}
```

24 core tools (`core_manage`, `firewall_manage`, `interfaces_manage`,
`diagnostics_manage`, `wireguard_manage`, ...) plus 64 plugin tools when
enabled (`plugin_nginx_manage`, `plugin_haproxy_manage`, ...). Tables and
example prompts:
[docs/module-tools-usage-reference.md](docs/module-tools-usage-reference.md).
Firewall/NAT writes use per-family body schemas; mirror the `*GetRule`
template, never the search output:
[docs/firewall-write-schema-cheatsheet.md](docs/firewall-write-schema-cheatsheet.md).

## Development

```bash
yarn install         # Yarn 4.9.2 (Plug'n'Play)
yarn generate-tools  # regenerate tools-generated.json
yarn build           # build index.js
yarn build:all       # both
yarn dev             # hot reload
yarn type-check      # tsc --noEmit
yarn start           # run the built server
```

Stack: Node.js with tsx, TypeScript 5.3+, @modelcontextprotocol/sdk, Zod
validation, Jest tests. Contributions via fork + feature branch + PR are
welcome. MIT licensed (see LICENSE). Built on the
[Model Context Protocol](https://modelcontextprotocol.io/) by Anthropic.

## See also

- [docs/claude-desktop-cursor-setup.md](docs/claude-desktop-cursor-setup.md) - client setup + troubleshooting
- [docs/module-tools-usage-reference.md](docs/module-tools-usage-reference.md) - module tool tables + prompts
- [docs/firewall-write-schema-cheatsheet.md](docs/firewall-write-schema-cheatsheet.md) - proven write bodies
- [TODO.md](TODO.md) - open items
- [log.md](log.md) - history
- Upstream: [richard-stovall/opnsense-mcp-server](https://github.com/richard-stovall/opnsense-mcp-server)
