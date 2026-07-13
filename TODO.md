---
type: "Backlog"
title: "TODO — opnsense-mcp-server"
timestamp: "2026-07-13"
---

# TODO — opnsense-mcp-server

Open items only; completed work lives in [log.md](log.md) (write-schema embed
DONE 2026-06-11, incl. the proven per-family schema cheat-sheet).

## Remaining (operator step)

The live MCPs run the npx-cached GitHub install. After the 2026-06-11 push:
`npx clear-npx-cache` (or delete `~/AppData/Local/npm-cache/_npx`) **and restart
Claude Code** so opnsense-homelab / eu-2 / eu-6 pick up the new build.

## References

- Memory `reference_opnsense_mcp_write_overrides` — write-override history.
- `infrastructure/tools/firewall/reconcile_firewall.py` — non-MCP fallback with correct bodies.
