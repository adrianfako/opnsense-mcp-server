---
type: "Backlog"
title: "TODO - opnsense-mcp-server"
timestamp: "2026-10-12"
---

# TODO - opnsense-mcp-server

Open items only; completed work lives in [log.md](log.md).

## Remaining (operator step)

The four fleet MCP servers (`opnsense-eu-2` / `-eu-6` / `-eu-8` / `-homelab`)
launch `<CODE>/tools/opnsense-mcp-server/index.js` directly (`~/CODE` on the
laptop, `~/code` on the agents VM), so a rebuild is
picked up by **restarting Claude Code** - no npx cache to clear.

## Open

- `src/api-routes.json` is a snapshot of OPNsense 26.7.3_11. Re-run the
  discovery + probe pass (recipe in [README.md](README.md)) after a fleet
  upgrade, or new actions stay invisible and removed ones linger.
  Verified current 2026-09-22: all four boxes report 26.7.3_11.
- Only `firewall_manage` carries embedded write-body schemas. The 315 methods
  added on 2026-08-12 are documented by route and verb only; the model has to
  fetch the editable-model template (`*Get*` with no uuid) to learn a body.

## References

- Memory `reference_opnsense_mcp_write_overrides` - write-override history.
- `infrastructure/tools/firewall/reconcile_firewall.py` - non-MCP fallback with correct bodies.
