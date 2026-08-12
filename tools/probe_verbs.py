"""GET every read-shaped route in the generated table against a live box.

Two jobs: prove the route exists (not 404), and catch reads that actually guard
on isPost() — OPNsense answers those with HTTP 200 and a body of
`{"status":"error"}` / `{"result":"failed"}` rather than a 405, so the verb has
to be corrected from the response, not the status code.

Only entries with `mutating=false` and no path parameters are called, and
anything streaming is skipped (those sockets never close). Credentials are read
straight out of the Claude MCP config so no secret is written to disk here.
"""
import base64
import json
import ssl
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

SCRATCH = Path(__file__).parent
TABLE = SCRATCH / sys.argv[1]
SERVER = sys.argv[2]                      # e.g. opnsense-eu-2
OUT = SCRATCH / sys.argv[3]

cfg = json.loads(Path("C:/Users/Administrator/.claude.json").read_text(encoding="utf-8"))
env = cfg["mcpServers"][SERVER]["env"]
BASE = env["OPNSENSE_URL"]
AUTH = base64.b64encode(f"{env['OPNSENSE_API_KEY']}:{env['OPNSENSE_API_SECRET']}".encode()).decode()
CTX = ssl._create_unverified_context()

table = json.loads(TABLE.read_text(encoding="utf-8"))


def probe(job):
    module, name, meta = job
    req = urllib.request.Request(BASE + meta["path"], headers={"Authorization": "Basic " + AUTH})
    try:
        with urllib.request.urlopen(req, timeout=20, context=CTX) as r:
            body = r.read(4096).decode("utf-8", "replace")
            code = r.status
    except urllib.error.HTTPError as e:
        code, body = e.code, e.read(400).decode("utf-8", "replace")
    except Exception as e:
        return module, name, "ERR", str(e)[:120]
    low = body.lstrip()[:200].lower()
    if code == 200 and ('"status":"error"' in low.replace(" ", "")
                        or '"result":"failed"' in low.replace(" ", "")):
        return module, name, "NEEDS_POST", body[:120]
    return module, name, str(code), body[:100]


jobs = [(m, n, meta) for m, d in table.items() for n, meta in d.items()
        if not meta["mutating"] and meta["params"] == 0 and "stream" not in n.lower()]
print(f"probing {len(jobs)} read routes against {SERVER} ({BASE})")

results = []
with ThreadPoolExecutor(max_workers=8) as ex:
    for r in ex.map(probe, jobs):
        results.append(r)

by_code = {}
for m, n, code, body in results:
    by_code.setdefault(code, []).append((m, n, body))
for code in sorted(by_code):
    print(f"  {code:12s} {len(by_code[code])}")

OUT.write_text(json.dumps([{"module": m, "name": n, "code": c, "body": b}
                           for m, n, c, b in results], indent=1), encoding="utf-8")
for code in ("NEEDS_POST", "404", "ERR", "500", "400"):
    for m, n, b in by_code.get(code, []):
        print(f"{code:11s} {m}.{n}  {b[:90]!r}")
