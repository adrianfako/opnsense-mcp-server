# Log

Completed work lands here (TODO.md keeps open items only). Newest first.

## 2026-07-17

- **Docs pass (repo-docs).** README rewritten to the operator card; setup,
  module tables, and the write-schema cheat-sheet routed to `docs/`.

## 2026-06-11

- **Firewall write-schemas embedded, live-validated on the homelab OPNsense.**
  `firewall_manage`'s tool description (`tools-generated.json`, embedded into
  `index.js` by `src/build.ts`) now documents the per-family editable-model
  write schemas; the generic `{method, params}` fallback still works.
- **Missing NAT methods fork-added.** `sourceNatSearchRule`/`sourceNatApply`,
  `oneToOneSearchRule`/`oneToOneApply`, `nptSearchRule`/`nptApply` (routes
  verified live); `*GetRule`/`*GetItem` made uuid-optional so the empty
  editable-model template is fetchable via MCP (was `[]` or 500).
- **All 8 write families round-trip tested** (add inert, getRule assert every
  sent field persisted, del, apply, zero residue): filter, dNat, source_nat,
  one_to_one, npt, alias, group, category. `methodDocs.firewall` synced 73 to
  89. Schema table: [docs/firewall-write-schema-cheatsheet.md](docs/firewall-write-schema-cheatsheet.md).
