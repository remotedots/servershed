"""Step-1 entry point: `servershed probe [asset...]` prints raw probe facts.

The TUI comes next; this exists to see what the probe returns per host.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys
from pathlib import Path

from .core import collect, inventory


def default_inventory() -> Path:
    env = os.environ.get("SERVERSHED_INVENTORY")
    if env:
        return Path(env)
    here = Path.cwd() / "inventory.yaml"
    if here.exists():
        return here
    xdg = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return xdg / "servershed" / "inventory.yaml"


def cmd_probe(args: argparse.Namespace) -> int:
    inv = inventory.load(args.inventory)
    pairs = inv.assets()
    if args.assets:
        wanted = set(args.assets)
        pairs = [(c, a) for c, a in pairs if a.name in wanted]
        missing = wanted - {a.name for _, a in pairs}
        if missing:
            print(f"unknown asset(s): {', '.join(sorted(missing))}", file=sys.stderr)
            return 2
    targets = [a for _, a in pairs if a.probes]
    skipped = [a for _, a in pairs if not a.probes]

    results = asyncio.run(collect.probe_all(targets))
    if args.save:
        out = Path(args.save)
        out.mkdir(parents=True, exist_ok=True)
        for r in results:
            if r.raw:
                (out / f"{r.asset}.txt").write_text(r.raw)

    for r in results:
        state = "ok" if r.ok else f"FAIL ({r.error})"
        print(f"\n== {r.asset}  [{state}, {r.seconds:.1f}s]")
        for key, values in r.facts.items():
            for v in values:
                print(f"  {key:18} {v}")
    for a in skipped:
        print(f"\n== {a.name}  [no ssh probe: {a.kind.value}]")
    return 0 if all(r.ok for r in results) else 1


def main() -> int:
    p = argparse.ArgumentParser(prog="servershed")
    p.add_argument("-i", "--inventory", default=default_inventory())
    sub = p.add_subparsers(dest="cmd", required=True)
    pr = sub.add_parser("probe", help="run the read-only probe and print raw facts")
    pr.add_argument("assets", nargs="*")
    pr.add_argument("--save", metavar="DIR", help="also save raw output per asset")
    pr.set_defaults(func=cmd_probe)
    sub.add_parser("lint", help="validate inventory.yaml").set_defaults(
        func=lambda a: (inventory.load(a.inventory), print("inventory ok"))[1] or 0)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
