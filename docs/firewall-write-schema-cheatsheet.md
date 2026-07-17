---
type: "Reference"
title: "Firewall write-schema cheat-sheet"
description: "Proven per-family editable-model write bodies for firewall and NAT methods, live-validated on OPNsense; the flat-dotted-key trap."
timestamp: "2026-07-17"
---

# Firewall write-schema cheat-sheet

Per-family write bodies for `firewall_manage` add/set methods. Proven, not
theory: all 8 families round-trip tested live on the homelab OPNsense on
2026-06-11 (add inert rule, `getRule` assert every sent field persisted,
del, apply, zero residue). Parent: [README.md](../README.md); provenance:
[log.md](../log.md) 2026-06-11.

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
| one_to_one | flat | `enabled` | `description` | — | `external`, `type` (binat\|nat) |
| npt | flat | `enabled` | `description` | — | `trackif` |
| alias | — | `enabled` | `description` | — | `name`, `type`, `content` (newline-sep) |
| group | — | — | `descr` | — | `ifname` (= uuid), `members` (comma-sep) |
| category | — | — | — | — | `name`, `auto`, `color` (hex no #) |

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
`methodDocs.firewall` synced from 73 to 89 methods.
