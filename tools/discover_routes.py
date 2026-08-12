"""Derive the full OPNsense MVC API route table from the controller sources.

Reads the `controllers/` tree pulled off a live box and emits, for every
`<name>Action` a controller effectively exposes (own + inherited), the route,
the HTTP verb and whether the action takes path parameters. Output is the JSON
route table that `src/build.ts` embeds and attaches to the client.

Verb rule, derived from source rather than guessed: an action that calls
`$this->request->isPost()` refuses anything else, so it is POST. Everything
else is GET, which is the safe direction — a GET cannot fall into the mutating
branch of an action that switches on the method. `search*` is forced to POST
because the grid parameters travel in the body.
"""
import json
import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1])
OUT = Path(sys.argv[2])

FUNC = re.compile(r"function\s+(\w+Action)\s*\(([^)]*)\)")
CLS = re.compile(r"(abstract\s+)?class\s+(\w+)(?:\s+extends\s+([\w\\]+))?")

# Actions whose names don't start with a verb from MUTATING but which still
# guard on isPost(). Found by probing, not by guessing: OPNsense answers a GET
# on a POST-only action with HTTP 200 and a bare {"status":"failed"} body.
POST_CORRECTIONS = {
    "core.dashboardPicture", "core.dashboardRestoreDefaults", "core.systemDismissStatus",
    "core.systemHalt", "diagnostics.netflowSetconfig", "ids.serviceDropAlertLog",
    "ids.serviceReloadRules", "routes.routesAddroute", "trafficshaper.serviceFlushreload",
    "unbound.diagnosticsDumpinfra", "unbound.serviceDnsbl",
    # source-verified mutators the name rule alone misses:
    # cleanup delegates to auditHelper(), which queues a firmware job.
    "firmware.firmwareCleanup",
}

# The MCP tool for these OPNsense modules is named differently, or the module is
# split out. Everything else maps by lowercasing the namespace directory.
MODULE_ALIAS = {"core.Firmware": "firmware"}

# An action whose name starts with one of these changes state, so it is POST and
# must never be probed. Everything else is treated as a read (GET) and gets
# verified against a live box; `probe_verbs.py` flips the ones that answer
# `{"status":"error"}` because they guard on isPost().
MUTATING = {
    "abort", "add", "apply", "audit", "check", "cleanup", "clear", "configure",
    "connect", "copy", "create", "del", "delete", "disable", "disconnect",
    "duplicate", "edit", "enable", "exec", "factory", "flush", "gen", "generate",
    "import", "init", "install", "kill", "lock", "move", "new", "poweroff",
    "probe", "reboot", "reconfigure", "reinstall", "rekey", "remove", "rename",
    "renew", "reset", "restart", "resync", "revoke", "run", "save", "scan",
    "send", "set", "sign", "start", "stop", "sync", "test", "toggle", "trigger",
    "unlock", "update", "upgrade", "upload",
}


def body_of(src: str, start: int) -> str:
    """Source of one function, by brace matching from its signature."""
    i = src.find("{", start)
    if i < 0:
        return ""
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i:j]
        j += 1
    return src[i:]


def parse_file(p: Path):
    src = p.read_text(encoding="utf-8", errors="replace")
    m = CLS.search(src)
    if not m:
        return None
    cls, parent = m.group(2), (m.group(3) or "").split("\\")[-1]
    is_abstract = bool(m.group(1))
    actions = {}
    for f in FUNC.finditer(src):
        name, params = f.group(1), f.group(2).strip()
        b = body_of(src, f.end())
        # The isPost() guard usually is not in the action body but in the
        # *Base helper it delegates to (setroute -> setBase, toggleRuleLog ->
        # toggleRuleLogBase). Every such helper is a mutation except the read
        # family, so invert the test and list the readers.
        helpers = re.findall(r"->(\w+)Base\(", b)
        writes = any(not h.startswith(("search", "get", "list", "export", "download", "form"))
                     for h in helpers)
        actions[name[: -len("Action")]] = {
            "post": "isPost()" in b or "hasPost(" in b or writes,
            "delegates": re.findall(r"(?:\$this->|parent::)(\w+)Action\(", b),
            "nparams": 0 if not params else len([x for x in params.split(",") if x.strip()]),
        }
    return {"path": p, "cls": cls, "parent": parent, "abstract": is_abstract, "actions": actions}


def snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).lower()


def main():
    files = [parse_file(p) for p in ROOT.rglob("*.php")]
    files = [f for f in files if f]
    by_cls = {f["cls"]: f for f in files}

    table: dict[str, dict[str, dict]] = {}
    for f in files:
        parts = f["path"].parts
        if "Api" not in parts or "OPNsense" not in parts:
            continue
        cls = f["cls"]
        # `abstract` is the only reliable "not routable" marker: Kea's
        # LeasesController is abstract and only Leases4/Leases6 are real routes.
        if not cls.endswith("Controller") or f["abstract"]:
            continue
        ctrl = cls[: -len("Controller")]
        module = parts[parts.index("OPNsense") + 1]

        # fold inherited actions in, own definitions winning
        eff, node, hops = {}, f, 0
        chain = []
        while node and hops < 8:
            chain.append(node)
            node, hops = by_cls.get(node["parent"]), hops + 1
        for node in reversed(chain):
            eff.update(node["actions"])
        # addClientAction is just `return $this->setClientAction(null)` — follow
        # one hop of delegation so the verb comes from where the work happens.
        for meta in eff.values():
            for target in meta.get("delegates", []):
                head = re.match(r"[a-z]+", target)
                if eff.get(target, {}).get("post") or (head and head.group(0) in MUTATING):
                    meta["post"] = True

        key = MODULE_ALIAS.get(f"{module.lower()}.{ctrl}", module.lower())
        route_mod = module.lower()
        for action, meta in eff.items():
            name = ctrl[0].lower() + ctrl[1:] + action[0].upper() + action[1:]
            first = re.match(r"[a-z]+", action)
            table.setdefault(key, {})[name] = {
                "path": f"/api/{route_mod}/{snake(ctrl)}/{action}",
                # An action that references isPost() either requires POST or
                # merely does something extra on POST; the live probe below
                # demotes the second kind back to GET.
                "post": meta["post"] or action.startswith("search")
                or f"{key}.{name}" in POST_CORRECTIONS,
                "params": meta["nparams"],
                "search": action.startswith("search"),
                # Probe guard only: never GET-probe something whose name says it
                # changes state, even though OPNsense guards those with isPost().
                "mutating": bool(first and first.group(0) in MUTATING)
                or f"{key}.{name}" in POST_CORRECTIONS,
            }

    # Fold in the live probe: it is the authoritative verb for everything it
    # touched. Real data back = the action serves GET; a bare {"status":"failed"}
    # = it guards on isPost().
    if len(sys.argv) > 3:
        fail = re.compile(r'^\s*\{\s*"(status|result)"\s*:\s*"(failed|error)"\s*\}\s*$')
        flips = 0
        for e in json.loads(Path(sys.argv[3]).read_text(encoding="utf-8")):
            row = table.get(e["module"], {}).get(e["name"])
            if not row or e["code"] != "200":
                continue
            post = bool(fail.match(e["body"]))
            flips += post != row["post"]
            row["post"] = post
        print(f"probe corrected {flips} verbs")

    OUT.write_text(json.dumps(table, indent=1, sort_keys=True), encoding="utf-8")
    n = sum(len(v) for v in table.values())
    print(f"{len(table)} modules, {n} actions -> {OUT}")
    for k in sorted(table):
        print(f"  {k:16s} {len(table[k])}")


main()
