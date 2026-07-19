---
type: "Agent Config"
title: "AGENTS"
description: "Working rules for agents in this repo."
timestamp: "2026-07-19"
---

# AGENTS

<!-- fleet-memory:begin -->

## Fleet memory

Shared cross-project facts live in the handbook at `C:\STORAGE\VAULTS\handbook\memory\` (other machines: wherever the handbook repo is cloned). Read `memory/INDEX.md` when a task needs fleet context (infrastructure, regions, identity, services, tenants), then grep `memory/` for detail. Files under `memory/inbox/` are unverified hints, not truth. Verify load-bearing values against live systems before destructive actions.

When you learn a durable fleet-scope fact during a session (topology change, new service or endpoint, cross-repo convention, gotcha that cost real debugging time), write it to `memory/inbox/` as one markdown file in the format shown in `memory/README.md`, with `verified: false`. Never write secret values; locations of secrets are fine.

<!-- fleet-memory:end -->
