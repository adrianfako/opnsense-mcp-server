"""Shared .okfignore support for the OKF tree-walkers (okf-frontmatter, okf-validate).

ADR-0027 makes every .md in a fleet repo an OKF doc — but repos that vendor
third-party code (node_modules, .venv, test fixtures, bundled SDKs) carry
hundreds of .md that cannot and must not get frontmatter. A repo declares those
trees in a `.okfignore` at its root; the walkers skip anything matching.

Format: gitignore-ish, one glob per line, `#` comments, blank lines ignored.
Matching (kept deliberately simple — directory exclusion, not full gitignore):

  legacy            # a bare name matches that dir/file anywhere in the tree
  **/.venv          # `**/` prefix is also "anywhere" (same effect as bare name)
  archives/         # trailing slash is stripped; matches the dir + its subtree
  *.lock            # a glob with no slash matches the basename anywhere
  tools/x/*.md      # a glob with a slash is matched against the full relpath
"""

import fnmatch
import os


def load(root):
    """Return the list of patterns from `<root>/.okfignore` (empty if none)."""
    path = os.path.join(root, ".okfignore")
    pats = []
    if os.path.isfile(path):
        with open(path, encoding="utf-8") as f:
            for ln in f:
                ln = ln.strip()
                if ln and not ln.startswith("#"):
                    pats.append(ln.rstrip("/"))
    return pats


def is_ignored(rel, pats):
    """True if the relpath (a dir or file, posix or os-sep) matches any pattern."""
    if not pats:
        return False
    rel = rel.replace(os.sep, "/").strip("/")
    if not rel:
        return False
    segs = rel.split("/")
    base = segs[-1]
    for pat in pats:
        core = pat[3:] if pat.startswith("**/") else pat
        # bare name (no glob, no slash): match any path segment
        if "/" not in core and "*" not in core and "?" not in core:
            if core in segs:
                return True
            continue
        # basename glob (no slash): match the basename
        if "/" not in core:
            if fnmatch.fnmatch(base, core):
                return True
            continue
        # path glob (has slash): match the full relpath (+ subtree)
        if fnmatch.fnmatch(rel, core) or fnmatch.fnmatch(rel, core + "/*"):
            return True
    return False


def prune(root, dirpath, dirnames, pats):
    """In-place prune os.walk dirnames so we never descend into ignored dirs."""
    if not pats:
        return
    dirnames[:] = [
        d for d in dirnames
        if not is_ignored(os.path.relpath(os.path.join(dirpath, d), root), pats)
    ]
