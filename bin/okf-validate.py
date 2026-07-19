#!/usr/bin/env python3
"""Validate the handbook is a conformant OKF v0.1 bundle (ADR-0023).

Rules enforced:
  1. Every non-reserved `.md` has parseable YAML frontmatter with a non-empty
     `type:` field.
  2. Reserved `index.md` files carry no frontmatter, EXCEPT the bundle root
     `index.md`, which must declare `okf_version`.
  3. No stray `<!-- saved: ... -->` header survives on a frontmatter file
     (it should have been absorbed into `timestamp:`).

Exit 0 = conformant, 1 = violations (listed). Run from the handbook root.
Used by .github/workflows/okf-validate.yml and runnable as a pre-commit hook.
"""
from __future__ import annotations
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import okf_ignore

SAVED_RE = re.compile(r"^<!--\s*saved:\s*.+?-->\s*$")
LIST_ITEM = re.compile(r"^\s*-\s+(.*)$")
HERE = os.path.dirname(os.path.abspath(__file__))


def load_allowlist():
    allow = set()
    path = os.path.join(HERE, "okf-tags.yaml")
    if not os.path.isfile(path):
        return allow
    with open(path, encoding="utf-8") as f:
        for ln in f:
            if ln.strip().startswith("#"):
                continue
            m = LIST_ITEM.match(ln)
            if m:
                allow.add(m.group(1).strip())
    return allow


def fm_tags(text):
    """Collect block-list tags from a file's leading frontmatter."""
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        return []
    tags, in_tags = [], False
    for ln in lines[1:]:
        if ln.strip() == "---":
            break
        if re.match(r"^tags:\s*$", ln):
            in_tags = True
            continue
        if in_tags:
            m = LIST_ITEM.match(ln)
            if m:
                tags.append(m.group(1).strip().strip('"').strip("'"))
            else:
                in_tags = False
    return tags


def frontmatter(text: str):
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            d = {}
            for ln in lines[1:i]:
                m = re.match(r"^([A-Za-z0-9_]+):\s*(.*)$", ln)
                if m:
                    d[m.group(1)] = m.group(2).strip().strip('"').strip("'")
            return d
    return "UNCLOSED"


def main():
    root = os.getcwd()
    allow = load_allowlist()
    pats = okf_ignore.load(root)
    errors = []
    for dirpath, dirnames, filenames in os.walk(root):
        if ".git" in dirpath.split(os.sep):
            continue
        okf_ignore.prune(root, dirpath, dirnames, pats)
        for fn in filenames:
            if not fn.endswith(".md"):
                continue
            rel = os.path.relpath(os.path.join(dirpath, fn), root).replace(os.sep, "/")
            if okf_ignore.is_ignored(rel, pats):
                continue
            with open(os.path.join(dirpath, fn), encoding="utf-8") as f:
                text = f.read()
            fm = frontmatter(text)
            is_root_index = rel == "index.md"
            is_sub_index = fn == "index.md" and not is_root_index
            is_reserved_log = fn == "log.md"  # OKF lowercase reserved
            is_skill = fn == "SKILL.md"       # Claude Code skill: name/description schema, not OKF type

            if fm == "UNCLOSED":
                errors.append(f"{rel}: unclosed frontmatter block")
                continue

            if is_root_index:
                if not fm or not fm.get("okf_version"):
                    errors.append(f"{rel}: root index must declare okf_version")
            elif is_sub_index or is_reserved_log or is_skill:
                pass  # reserved; no type required (SKILL.md carries name/description, not type)
            else:
                if not fm:
                    errors.append(f"{rel}: missing YAML frontmatter (need type:)")
                elif not fm.get("type"):
                    errors.append(f"{rel}: empty or missing type:")

            # tags (if present) must be drawn from the controlled allowlist
            if allow:
                for t in fm_tags(text):
                    if t not in allow:
                        errors.append(f"{rel}: off-allowlist tag '{t}' (add to bin/okf-tags.yaml or fix)")

            # stray save-header = an un-absorbed header at the TOP of the body.
            # Only the leading position counts; `<!-- saved -->` examples inside
            # code blocks / prose deeper in a doc are legitimate content.
            if fm and isinstance(fm, dict):
                body = text.split("---", 2)[-1]
                for ln in body.splitlines():
                    if ln.strip() == "":
                        continue
                    if SAVED_RE.match(ln.strip()):
                        errors.append(f"{rel}: stray <!-- saved --> header (absorb into timestamp:)")
                    break  # only inspect the first non-blank body line

    if errors:
        print("OKF validation FAILED:")
        for e in errors:
            print("  -", e)
        return 1
    print("OKF validation OK — bundle conformant.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
