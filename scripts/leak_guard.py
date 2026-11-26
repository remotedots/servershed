#!/usr/bin/env python3
"""Leak guard: refuse commits that contain real estate data.

Search terms are built locally and never committed:
  * inventory.yaml (git-ignored): asset names, ssh aliases, sites, docroots,
    client names, plus HostName/User that `ssh -G <alias>` resolves to
  * .servershed/denylist (git-ignored): extra terms, one per line, # comments

Terms that also occur in inventory.example.yaml are not secret and are skipped.
Matching is case-insensitive substring on added lines, file paths and the
commit message. Bypass for a false positive: `git commit --no-verify`.

Usage (from git hooks):
  leak_guard.py staged            # pre-commit
  leak_guard.py message FILE      # commit-msg
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, check=True).stdout.strip())
INVENTORY = ROOT / "inventory.yaml"
EXAMPLE = ROOT / "inventory.example.yaml"
DENYLIST = ROOT / ".servershed" / "denylist"
MIN_LEN = 4
# paths that must never be committed, even with git add -f
FORBIDDEN_PATHS = [re.compile(p) for p in (
    r"(^|/)inventory\.yaml$",
    r"(^|/)inventory\.(?!example\.)[^/]*\.yaml$",
    r"^tests/fixtures/local/",
    r"\.(sqlite3?|db)$",
    r"(^|/)\.servershed/",
    r"^dev-docs/",
)]


def inventory_terms() -> set[str]:
    if not INVENTORY.exists():
        return set()
    try:
        import yaml
    except ImportError:
        print("leak-guard: PyYAML missing, inventory terms skipped", file=sys.stderr)
        return set()
    data = yaml.safe_load(INVENTORY.read_text()) or {}
    terms: set[str] = set()
    aliases: set[str] = set()
    for client in data.get("clients", []) or []:
        terms.add(str(client.get("name", "")))
        for a in client.get("assets", []) or []:
            for key in ("name", "ssh", "docroot"):
                if a.get(key):
                    terms.add(str(a[key]))
            terms.update(str(s) for s in a.get("sites", []) or [])
            if a.get("ssh"):
                aliases.add(str(a["ssh"]))
    for alias in aliases:
        r = subprocess.run(["ssh", "-G", alias], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            k, _, v = line.partition(" ")
            if k in ("hostname", "user") and v and v != alias:
                terms.add(v)
    return terms


def denylist_terms() -> set[str]:
    if not DENYLIST.exists():
        return set()
    return {ln.strip() for ln in DENYLIST.read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith("#")}


def all_terms() -> list[str]:
    example = EXAMPLE.read_text().lower() if EXAMPLE.exists() else ""
    terms = inventory_terms() | denylist_terms()
    return sorted({t for t in terms
                   if len(t) >= MIN_LEN and t.lower() not in example
                   and t.lower() not in {"root", "user", "admin"}}, key=str.lower)


def scan(text: str, terms: list[str]) -> list[str]:
    low = text.lower()
    return [t for t in terms if t.lower() in low]


def report(hits: list[tuple[str, str]]) -> int:
    print("\nleak-guard: commit blocked, real estate data found:\n", file=sys.stderr)
    for where, term in hits:
        print(f"  {where}: matches '{term}'", file=sys.stderr)
    print("\nRemove it (or unstage the file). False positive? git commit --no-verify\n",
          file=sys.stderr)
    return 1


def check_staged() -> int:
    terms = all_terms()
    hits: list[tuple[str, str]] = []
    names = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACMR"],
                           capture_output=True, text=True, check=True).stdout.split("\n")
    for name in filter(None, names):
        if any(p.search(name) for p in FORBIDDEN_PATHS):
            hits.append((name, "<forbidden path>"))
        hits += [(f"{name} (path)", t) for t in scan(name, terms)]
        diff = subprocess.run(["git", "diff", "--cached", "-U0", "--no-color", "--", name],
                              capture_output=True, text=True, errors="replace").stdout
        added = "\n".join(ln[1:] for ln in diff.splitlines()
                          if ln.startswith("+") and not ln.startswith("+++"))
        hits += [(name, t) for t in scan(added, terms)]
    return report(hits) if hits else 0


def check_message(path: str) -> int:
    text = "\n".join(ln for ln in Path(path).read_text().splitlines()
                     if not ln.startswith("#"))
    hits = [("commit message", t) for t in scan(text, all_terms())]
    return report(hits) if hits else 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["staged"]:
        return check_staged()
    if argv[:1] == ["message"] and len(argv) == 2:
        return check_message(argv[1])
    if argv[:1] == ["terms"]:           # debugging: how many terms are active
        print(f"{len(all_terms())} terms active")
        return 0
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
