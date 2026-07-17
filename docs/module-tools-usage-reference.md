---
type: "Reference"
title: "Module tools and usage"
description: "How the 88 module-based tools work, the method/params call pattern, core and plugin module tables, and example prompts."
timestamp: "2026-07-17"
---

# Module tools and usage

How the modular tool surface works. Parent: [README.md](../README.md).

## How it works

The server exposes 88 module-based tools; each tool represents one OPNsense
module and accepts a `method` parameter selecting the operation, so the
assistant sees 88 logical tools instead of 2000+ individual ones. Related
operations group by module: all firewall operations live in
`firewall_manage`, VPN operations in `openvpn_manage` / `ipsec_manage` /
`wireguard_manage`.

**Tool usage pattern:**

```json
{
  "tool": "firewall_manage",
  "arguments": {
    "method": "aliasSearchItem",
    "params": {
      "searchPhrase": "web"
    }
  }
}
```

**Example prompts:**

- "Use core_manage to check system status"
- "Use firewall_manage to list all firewall aliases"
- "Use interfaces_manage to get network interface information"
- "Use plugin_nginx_manage to check the web server configuration"
- "Use diagnostics_manage to view the ARP table"

## Core modules (24 tools)

Each tool provides access to all methods within that module. Highlights:

| Tool name            | Description              | Example methods                                         |
| -------------------- | ------------------------ | ------------------------------------------------------- |
| `core_manage`        | Core system functions    | `backupBackups`, `systemReboot`, `firmwareInfo`         |
| `firewall_manage`    | Firewall rules & aliases | `aliasSearchItem`, `filterAddRule`, `natSearchRule`     |
| `interfaces_manage`  | Network interfaces       | `getInterfaces`, `vlanAddItem`, `setInterface`          |
| `diagnostics_manage` | System diagnostics       | `interfaceGetArp`, `systemActivityGetActivity`          |
| `auth_manage`        | Authentication           | `userSearchUser`, `groupSearchGroup`                    |
| `firmware_manage`    | Firmware updates         | `check`, `update`, `upgrade`, `changelog`               |
| `openvpn_manage`     | OpenVPN                  | `instancesSearch`, `instancesAdd`, `serviceReconfigure` |
| `ipsec_manage`       | IPsec VPN                | `tunnelSearchPhase1`, `connectionStatus`                |
| `wireguard_manage`   | WireGuard VPN            | `serverSearchServer`, `clientSearchClient`              |
| `unbound_manage`     | DNS resolver             | `hostOverrideSearchItem`, `serviceReconfigure`          |
| `dhcpv4_manage`      | DHCP server              | `searchLease`, `addReservation`                         |

## Plugin modules (64 tools when enabled)

Enabled with `--plugins` / `INCLUDE_PLUGINS=true`. Popular modules:

| Tool name                  | Description           | Example methods                             |
| -------------------------- | --------------------- | ------------------------------------------- |
| `plugin_nginx_manage`      | Nginx web server      | `generalGet`, `upstreamSearchUpstream`      |
| `plugin_haproxy_manage`    | HAProxy load balancer | `serverSearchServer`, `statsGet`            |
| `plugin_caddy_manage`      | Caddy web server      | `reverseProxySearchDomain`, `serviceStatus` |
| `plugin_bind_manage`       | BIND DNS              | `domainSearchDomain`, `recordSearchRecord`  |
| `plugin_acmeclient_manage` | Let's Encrypt         | `certificatesSearch`, `certificatesIssue`   |

## API client

Calls go through
[@richard-stovall/opnsense-typescript-client](https://www.npmjs.com/package/@richard-stovall/opnsense-typescript-client):
complete type safety, built-in error handling and retries, all 601 OPNsense
API endpoints, modern Fetch-based implementation.

Example tool implementation:

```typescript
const response = await client.system.getStatus();
return {
  content: [
    {
      type: 'text',
      text: JSON.stringify(response.data, null, 2),
    },
  ],
};
```
