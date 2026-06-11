# TODO — embed correct write-schemas for firewall (and other MVC) methods

_Owner: next agent. Created 2026-06-11 after live-validating the OPNsense eu-2 firewall API._

## Goal
Make `firewall_manage` (and the other `*_manage` tools) carry the **correct request-body
schema per write method**, so a caller can add/set rules without first reverse-engineering
the shape from `*GetRule`. Today the tools accept a generic `{method, params}` and pass
`params` straight to the upstream client — callers must already know the exact nested body,
which is error-prone (see root cause).

## Root cause (PROVEN, not a theory)
The routes are **fine**. The breakage is **request-body shape**:
- `*SearchRule` / `*SearchItem` **return FLAT dotted keys** (`"destination.port"`, `"destination.network"`).
- `*AddRule` / `*SetRule` **require the NESTED editable model** (`destination: {network, port, not}`).
- If you send the flat dotted keys to add/set, OPNsense **saves the rule but silently drops**
  those fields (e.g. `target`/`local-port` persist, `destination` ends up empty → a rule that
  matches everything). HTTP is still 200 — no error. Nasty.
- The authoritative shape for any rule type is what its **`*GetRule` / `getItem`** returns
  (nested objects + option-maps). Mirror that.

### Concrete, validated example — `dNatAddRule`
Wrap in `item.rule.{...}` with **nested** `source` / `destination`:
```jsonc
{
  "item": { "rule": {
    "interface": "wan",
    "ipprotocol": "inet",
    "protocol": "tcp",
    "source":      { "network": "", "address": "", "port": "", "not": "0" },
    "destination": { "network": "wanip", "address": "", "port": "29998", "not": "0" },
    "target": "10.1.2.249",
    "local-port": "22",
    "descr": "…",
    "nordr": "0",
    "disabled": "0"
  }}
}
```
This was created live on eu-2, `dNatGetRule` confirmed `destination.port` persisted, then
deleted — clean. The earlier flat-dot-key attempt saved with `destination` EMPTY.

Full lifecycle confirmed working via the API (`/api/api.php`, not GUI):
`dNatAddRule` → `dNatApply` → `dNatSearchRule`/`dNatGetRule` → `dNatDelRule` → `dNatApply`.

## Tasks
1. For each firewall write family, capture the editable model from its `*GetRule`/`getItem`
   and encode it as the tool's documented input schema (or at least a worked example in the
   tool description). Cover at minimum:
   - `filter` (filterAddRule / filterSetRule)
   - `dNat`   (dNatAddRule / dNatSetRule)        ← schema above, done
   - `alias`  (aliasAddItem / aliasSetItem)
   - `source_nat`, `one_to_one`, `npt`, `group`, `category`
2. Decide the mechanism: enrich `tools-generated.json` / `src/generate-tools.ts` with per-method
   `inputSchema` (preferred — schema shows up in the MCP tool list), or add examples to the
   method docs. Keep the generic `{method, params}` working as a fallback.
3. Regenerate + verify: `npx tsx src/build.ts` (rewrites `index.js`), `node --check index.js`.
4. Commit + push to `adrianfako/opnsense-mcp-server`. **Then bust the npx cache** so the live MCP
   picks it up: `npx clear-npx-cache` (or delete `~/AppData/Local/npm-cache/_npx`) **and restart
   Claude Code** — npx caches the github install.

## How to test (live, SAFE — prod firewall fronts VAST + the PVE API)
Use the `opnsense-eu-2` MCP (`firewall_manage`). For each write method:
1. Add a throwaway rule on an **unused** ext port (e.g. 29990-29998) → **unused** target IP
   (`10.1.2.249`). No WAN filter-pass exists for that port → **zero exposure** even while it lives.
2. `*GetRule` the new uuid → assert every field you sent **persisted** (esp. the nested ones).
3. `*DelRule` + `*Apply` → `*SearchRule` to confirm it's gone.
4. **Never leave test rules.** Always delete + apply. Prefix `descr` with `POLICY-TEST … SAFE-DELETE`.
Do **not** mass-test by spraying writes; one add/get/del per method is enough to lock the schema.

## Why this matters now
The HostBill customer-access build (see `CODE/hostbill` + memory `project_hostbill_customer_access_nat`)
will drive these dNAT/filter writes from policy-as-code (`infrastructure/tools/firewall/*`). Correct
schemas here = that build doesn't silently create broken rules.

## References
- Memory `reference_opnsense_mcp_write_overrides` — the write-override history + this nested-shape rule.
- `infrastructure/tools/firewall/reconcile_firewall.py` — already applies **filter** rules via direct
  `requests` POST (savepoint/rollback); good reference for correct bodies + a non-MCP fallback.
- Upstream client: `@richard-stovall/opnsense-typescript-client` (routes live here; the fork remaps the broken ones in `src/build.ts`).
