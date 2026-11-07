---
type: "Index"
title: "OPNsense MCP Server"
description: "Modular MCP server exposing OPNsense firewall management as 92 module-based tools; fleet fork with a live-discovered route table and write-route fixes."
timestamp: "2026-08-12"
---

# OPNsense MCP Server

A modular Model Context Protocol (MCP) server that exposes **92 module-based
tools** covering 2000+ OPNsense firewall management methods through a type-safe TypeScript interface built on
[@richard-stovall/opnsense-typescript-client](https://www.npmjs.com/package/@richard-stovall/opnsense-typescript-client)
v0.5.3. It bridges AI assistants (Claude Desktop, Claude Code, Cursor) and an
OPNsense firewall over its API. This repo is a fork of
[richard-stovall/opnsense-mcp-server](https://github.com/richard-stovall/opnsense-mcp-server)
carrying write-route re-maps and embedded write-body schemas the upstream
client gets wrong (firewall/NAT, WireGuard, Kea/dhcpv4), plus a route table
discovered from a live box so the whole current API surface is reachable even
where the client's bundled spec is stale. The fleet's opnsense-homelab / eu-2 /
eu-6 / eu-8 MCP servers run this checkout directly (a rebuild takes effect when Claude Code restarts; see Development).

## Shape

```
opnsense-mcp-server/
  index.js               # built single-file server (committed artifact)
  tools-generated.json   # generated tool definitions, embedded into index.js
  src/generate-tools.ts  # generates tools-generated.json
  src/build.ts           # builds index.js; write-route re-maps live here
  src/api-routes.json    # discovered MVC API surface (route, verb, path params)
  tools/discover_routes.py  # rebuilds api-routes.json from a box's controllers
  tools/probe_verbs.py      # live GET probe that settles GET-vs-POST
  tools/smoke.mjs        # end-to-end read-only check against a live firewall
  images/                # usage screenshots
```

## Route discovery

`@richard-stovall/opnsense-typescript-client` 0.5.3 ships a spec several
OPNsense releases old: whole controllers are missing, some base paths are wrong,
and 26.7 both added and removed actions. Rather than patch method by method,
`src/api-routes.json` holds the API surface read off a live box, and
`src/build.ts` attaches every entry to the client at startup (the hand-written
fork fixes below it still win where they exist). To refresh it against a newer
release:

```bash
ssh <fw> 'tar czf - -C /usr/local/opnsense/mvc/app controllers' | tar xz -C /tmp/ctl
python tools/discover_routes.py /tmp/ctl/controllers src/api-routes.json          # pass 1
python tools/probe_verbs.py src/api-routes.json <mcp-server-name> /tmp/probe.json # live probe
python tools/discover_routes.py /tmp/ctl/controllers src/api-routes.json /tmp/probe.json
yarn build && node tools/smoke.mjs <mcp-server-name>
```

The probe only ever issues GETs, and only to actions whose names do not imply a
mutation. That is safe because OPNsense guards every mutating action with
`isPost()` and answers a GET with a bare `{"status":"failed"}` - which is
exactly the signal used to mark an action POST-only.

## Install

Requires Node.js 18+, an OPNsense firewall with API access enabled, and an
API key + secret from that installation.

```bash
npm install -g @richard-stovall/opnsense-mcp-server
```

MCP clients launch it via `npx -y @richard-stovall/opnsense-mcp-server` with
env vars: `OPNSENSE_URL`, `OPNSENSE_API_KEY`, `OPNSENSE_API_SECRET`
(required); `INCLUDE_PLUGINS=true` enables the 64 plugin module tools;
`OPNSENSE_VERIFY_SSL=false` disables SSL verification (development only);
`OPNSENSE_READ_ONLY=1` (or `true`) refuses every method that can change the firewall (the fleet
servers run with it: firewall changes go through `make firewall`).
Client setup and troubleshooting follow below.

## Usage

Each tool is one OPNsense module and takes a `method` plus `params`:

```json
{
  "tool": "firewall_manage",
  "arguments": { "method": "aliasSearchItem", "params": { "searchPhrase": "web" } }
}
```

28 core tools (`core_manage`, `firewall_manage`, `interfaces_manage`,
`diagnostics_manage`, `wireguard_manage`, ...) plus 64 plugin tools when
enabled (`plugin_nginx_manage`, `plugin_haproxy_manage`, ...). Firewall/NAT writes use per-family body schemas; mirror the `*GetRule`
template, never the search output (see [Firewall write schema](#firewall-write-schema)).

## Development

```bash
yarn install         # Yarn 4.9.2 (Plug'n'Play)
yarn generate-tools  # regenerate tools-generated.json
yarn build           # build index.js
yarn build:all       # both
yarn dev             # hot reload
yarn type-check      # tsc --noEmit
yarn start           # run the built server
node tools/smoke.mjs opnsense-eu-2   # read-only end-to-end check vs a live box
```

Stack: Node.js with tsx, TypeScript 5.3+, @modelcontextprotocol/sdk, Zod
validation, Jest tests. MIT licensed (see LICENSE).

The four fleet MCP servers launch `index.js` directly. After a rebuild, restart Claude Code to pick it up.

## See also

- [Handbook backlog](file:///home/adrian/STORAGE/VAULTS/handbook/backlog/todo/) - open work (repo ID `adrianfako/opnsense-mcp-server`)
- Upstream: [richard-stovall/opnsense-mcp-server](https://github.com/richard-stovall/opnsense-mcp-server)


## Client setup




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




## Troubleshooting

Connection issues:

1. Verify the OPNsense API is enabled.
2. Check that the API key has appropriate permissions.
3. Ensure the IP/hostname is reachable from your machine.
4. For self-signed certificates, use `--no-verify-ssl` or set
   `"OPNSENSE_VERIFY_SSL": "false"`.

Server logs: check the Claude Desktop logs for MCP server error messages.


## Firewall write schema


Per-family write bodies for `firewall_manage` add/set methods. Live validated on 2026-06-11.

The same schemas are embedded in the `firewall_manage` tool description
(`tools-generated.json`, built into `index.js` by `src/build.ts`): wrapper
objects, the nested-vs-flat split, flag/field dialects, and a worked dNat
example. The generic `{method, params}` fallback still works.

## Per-family schema

| family | source/dest | flag | descr | protocol keys | extras |
|---|---|---|---|---|---|
| dNat | **nested** `source{network,address,port,not}` | `disabled` | `descr` | lowercase `tcp` | `target`, `local-port`, `nordr` |
| filter | flat `source_net/_not/_port` | `enabled` | `description` | UPPERCASE `TCP` | `action`, `quick`, `direction`, `gateway` |
| source_nat | flat | `enabled` | `description` | UPPERCASE | `target`, `target_port`, `staticnatport`, `nonat` |
| one_to_one | flat | `enabled` | `description` | - | `external`, `type` (binat\|nat) |
| npt | flat | `enabled` | `description` | - | `trackif` |
| alias | - | `enabled` | `description` | - | `name`, `type`, `content` (newline-sep) |
| group | - | - | `descr` | - | `ifname` (= uuid), `members` (comma-sep) |
| category | - | - | - | - | `name`, `auto`, `color` (hex no #) |

## Rules

- **The trap**: flat dotted keys from `*SearchRule` sent to add/set return
  HTTP 200 with the fields silently dropped (the original bug). Always
  mirror the `*GetRule` / `*GetItem` template.
- The empty editable-model template is the authoritative write schema;
  `*GetRule` / `*GetItem` are uuid-optional in this fork so it is fetchable
  via MCP (upstream returned `[]` or 500).
- Writes stage only; follow with the family `*Apply` / `*Reconfigure`.

## Fork-added methods

Upstream client 0.5.3 omits these; this fork adds them (routes verified
live): `sourceNatSearchRule`/`sourceNatApply`,
`oneToOneSearchRule`/`oneToOneApply`, `nptSearchRule`/`nptApply`.


A partial WireGuard set previously reset omitted fields and interrupted a tunnel on 2026-11-04; the server now fetches the live item and preserves omitted fields.
