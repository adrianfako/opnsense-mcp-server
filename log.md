---
type: "Log"
title: "LOG — opnsense-mcp-server"
description: "Dated record of completed work on the fork; newest first."
timestamp: "2026-07-13"
---

# LOG — opnsense-mcp-server

Completed work lands here (TODO.md keeps open items only). Newest first.

## 2026-06-11 — correct write-schemas embedded for firewall (and other MVC) methods

**DONE 2026-06-11** — live-validated against the homelab OPNsense firewall.
(Moved from TODO.md.)

What was done:

- `firewall_manage`'s tool description (in `tools-generated.json`, embedded into
  `index.js` by `src/build.ts`) now documents the per-family **editable-model write
  schemas**: wrapper objects, the nested-vs-flat split, flag/field dialects, and a
  worked dNat example. The generic `{method, params}` fallback still works.
- Fork-added the methods upstream 0.5.3 omits: `sourceNatSearchRule`/`sourceNatApply`,
  `oneToOneSearchRule`/`oneToOneApply`, `nptSearchRule`/`nptApply` (routes verified
  live), and made `*GetRule`/`*GetItem` uuid-optional so the empty editable-model
  template — the authoritative write schema — is fetchable via MCP (was `[]` or 500).
- Synced the stale `methodDocs.firewall` list (73 → 89 methods).
- **All 8 write families round-trip tested on homelab** (add inert → getRule assert
  every sent field persisted → del → apply, zero residue):
  filter, dNat, source_nat, one_to_one, npt, alias, group, category.

Schema cheat-sheet (proven, not theory):

| family | source/dest | flag | descr | protocol keys | extras |
|---|---|---|---|---|---|
| dNat | **nested** `source{network,address,port,not}` | `disabled` | `descr` | lowercase `tcp` | `target`, `local-port`, `nordr` |
| filter | flat `source_net/_not/_port` | `enabled` | `description` | UPPERCASE `TCP` | `action`, `quick`, `direction`, `gateway` |
| source_nat | flat | `enabled` | `description` | UPPERCASE | `target`, `target_port`, `staticnatport`, `nonat` |
| one_to_one | flat | `enabled` | `description` | — | `external`, `type` (binat\|nat) |
| npt | flat | `enabled` | `description` | — | `trackif` |
| alias | — | `enabled` | `description` | — | `name`, `type`, `content` (newline-sep) |
| group | — | — | `descr` | — | `ifname` (= uuid), `members` (comma-sep) |
| category | — | — | — | — | `name`, `auto`, `color` (hex no #) |

Flat dotted keys from `*SearchRule` sent to add/set ⇒ HTTP 200 + silently dropped
fields (the original bug). Always mirror the GetRule template. Writes stage only —
follow with the family `*Apply` / `*Reconfigure`.
