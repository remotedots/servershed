"""Run the read-only probe on hosts over the system ssh binary."""
from __future__ import annotations

import asyncio
import shlex
import time
from dataclasses import dataclass, field
from importlib.resources import files

from .inventory import Asset

PROBE = files("servershed.core").joinpath("probe.sh").read_text()

SSH_OPTS = [
    "-T",                         # no tty: probe is piped on stdin
    "-o", "BatchMode=yes",        # never prompt for passwords
    "-o", "ConnectTimeout=10",
    "-o", "ServerAliveInterval=5",
    "-o", "ServerAliveCountMax=2",
]


def docroots(asset: Asset) -> list[str]:
    return asset.docroots


@dataclass
class ProbeResult:
    asset: str
    ok: bool
    facts: dict[str, list[str]] = field(default_factory=dict)
    error: str | None = None
    raw: str = ""
    seconds: float = 0.0

    def get(self, key: str, default: str | None = None) -> str | None:
        v = self.facts.get(key)
        return v[0] if v else default

    def all(self, key: str) -> list[str]:
        return self.facts.get(key, [])


def parse(raw: str) -> dict[str, list[str]]:
    facts: dict[str, list[str]] = {}
    for line in raw.splitlines():
        key, sep, value = line.partition("=")
        if sep and key and key.replace("_", "").isalnum():
            facts.setdefault(key, []).append(value.strip())
    return facts


async def probe(asset: Asset, timeout: float = 90) -> ProbeResult:
    if not asset.probes:
        return ProbeResult(asset.name, ok=False, error="probe disabled")
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        "ssh", *SSH_OPTS, asset.ssh, "sh", "-s", "--",
        *(shlex.quote(d) for d in docroots(asset)),
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    try:
        out, err = await asyncio.wait_for(proc.communicate(PROBE.encode()), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return ProbeResult(asset.name, ok=False, error=f"timeout after {timeout:.0f}s",
                           seconds=time.monotonic() - start)
    raw = out.decode(errors="replace")
    facts = parse(raw)
    done = "probe_done" in facts
    error = None
    if proc.returncode != 0 or not done:
        error = (err.decode(errors="replace").strip().splitlines() or
                 [f"ssh exit {proc.returncode}"])[-1]
    return ProbeResult(asset.name, ok=done, facts=facts, error=error, raw=raw,
                       seconds=time.monotonic() - start)


async def probe_all(assets: list[Asset], limit: int = 8) -> list[ProbeResult]:
    sem = asyncio.Semaphore(limit)

    async def one(a: Asset) -> ProbeResult:
        async with sem:
            return await probe(a)

    return await asyncio.gather(*(one(a) for a in assets))
