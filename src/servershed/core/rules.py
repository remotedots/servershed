"""Rules: probe facts -> findings (severity, one-line reason, suggested command).

The tool never runs a suggested command; it only shows it (and later pastes it with `p`).
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from datetime import date
from typing import Callable, Literal

from . import eol
from .collect import ProbeResult
from .inventory import Asset, Kind

Severity = Literal["info", "warn", "fail"]
RANK = {"info": 0, "warn": 1, "fail": 2}
SOON = 180          # days before an end date that a warning starts


def _today() -> date:      # tests patch this
    return date.today()


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: Severity
    title: str
    reason: str
    cmd: str | None = None
    action: str | None = None      # what to do, in words ("→ …" line)


# ---------- kernel helpers ----------
_KERNEL = re.compile(r"^(\d+(?:\.\d+)*(?:-\d+)?)(.*)$")


def kernel_split(release: str) -> tuple[tuple[int, ...], str]:
    """'6.1.0-56-cloud-amd64' -> ((6, 1, 0, 56), '-cloud-amd64'): version key and flavor."""
    m = _KERNEL.match(release)
    if not m:
        return (), release
    return tuple(int(x) for x in re.split(r"[.-]", m.group(1))), m.group(2)


def newer_kernels(r: ProbeResult) -> list[str]:
    """Installed kernels of the running flavor that are newer than the running one, oldest first."""
    running = r.get("kernel")
    if not running:
        return []
    key, flavor = kernel_split(running)
    if not key:
        return []
    newer = [k for k in set(r.all("kernel_installed"))
             if kernel_split(k)[1] == flavor and kernel_split(k)[0] > key]
    return sorted(newer, key=lambda k: kernel_split(k)[0])


def grub_pinned_kernel(r: ProbeResult) -> str | None:
    """Kernel named in GRUB_DEFAULT ('...>Debian GNU/Linux, with Linux 6.1.0-54-amd64'), if any."""
    m = re.search(r"with Linux (\S+)", r.get("grub_default") or "")
    return m.group(1) if m else None


def _days(r: ProbeResult) -> int | None:
    try:
        return int(r.get("uptime_s") or "") // 86400
    except ValueError:
        return None


# ---------- rules ----------
def reboot_pending(asset: Asset, r: ProbeResult) -> list[Finding]:
    """A newer kernel is installed than the one running, or the system asks for a reboot
    (/var/run/reboot-required). With GRUB pinned to an older kernel a plain reboot would
    boot the old one again, so the command boots the newest one once (grub-reboot); the
    pin stays, so a failed boot falls back to the known-good kernel on the next reset."""
    if asset.kind is not Kind.vps:          # shared hosting: the provider reboots
        return []
    newer = newer_kernels(r)
    flagged = bool(r.get("reboot_required"))
    if not newer and not flagged:
        return []

    running = r.get("kernel") or "?"
    why = []
    if newer:
        why.append(f"running {running}, {newer[-1]} installed")
    if flagged:
        why.append("reboot-required flag set")
    days = _days(r)
    if days is not None:
        why.append(f"up {days} day{'' if days == 1 else 's'}")

    cmd = "sudo systemctl reboot"
    action = f"reboot into {newer[-1]}" if newer else "reboot"
    pinned = grub_pinned_kernel(r)
    if newer and pinned and pinned != newer[-1]:
        why.append(f"GRUB pinned to {pinned}")
        entry = (r.get("grub_default") or "").replace(pinned, newer[-1])
        cmd = f"sudo grub-reboot {shlex.quote(entry)} && sudo systemctl reboot"
        action += " once (the GRUB pin stays as fallback)"
    return [Finding("reboot-pending", "warn", "reboot pending", "; ".join(why), cmd, action)]


def _ago(d: date, today: date) -> str:
    n = (today - d).days
    if abs(n) < 60:
        return f"{abs(n)} days {'ago' if n >= 0 else 'from now'}"
    months = round(abs(n) / 30.4)
    return f"{months} months {'ago' if n >= 0 else 'from now'}"


def os_end_of_life(asset: Asset, r: ProbeResult) -> list[Finding]:
    """OS release past (fail) or within SOON days of (warn) the end of free security
    support; Debian past regular security support but still on LTS is info.
    Shared hosting: the provider's OS, not ours to upgrade."""
    if asset.kind is not Kind.vps:
        return []
    os_id = r.get("os_id")
    rel = eol.lookup(os_id, r.get("os_version"))
    if rel is None:
        return []
    today = _today()
    name = f"{rel.distro} {rel.version} ({rel.codename})"
    if os_id == "raspbian":
        name = f"Raspbian {rel.version} ({rel.codename})"

    if rel.distro == "Ubuntu":
        target = eol.latest(eol.UBUNTU)
        action = f"upgrade to Ubuntu {target.version} LTS ({target.codename})"
        cmd = "sudo do-release-upgrade"
        after = "; after that only Ubuntu Pro (ESM)"
        what = "standard support"
    else:
        target = eol.latest(eol.DEBIAN)
        steps = [d for v, d in eol.DEBIAN.items() if int(v) > int(rel.version)]
        if os_id == "raspbian":
            action = (f"reinstall with current Raspberry Pi OS (Debian {target.version} "
                      f"based); in-place upgrades are not supported")
        else:
            action = "upgrade to Debian " + " → ".join(f"{d.version} ({d.codename})" for d in steps)
            action += ", one release at a time" if len(steps) > 1 else ""
        cmd = None              # a release upgrade is several steps, not one line
        after = ""
        what = "security support (incl. Debian LTS)"

    if today >= rel.end:
        return [Finding("os-eol", "fail", f"{name} is end of life",
                        f"{what} ended {rel.end} ({_ago(rel.end, today)}){after}", cmd, action)]
    if (rel.end - today).days <= SOON:
        return [Finding("os-eol", "warn", f"{name} support ends soon",
                        f"{what} ends {rel.end} ({_ago(rel.end, today)}){after}", cmd, action)]
    if rel.distro == "Debian" and today >= rel.security_end:
        return [Finding("os-eol", "info", f"{name} is on LTS",
                        f"regular security support ended {rel.security_end}; "
                        f"Debian LTS until {rel.end}", cmd, action)]
    return []


def _names(units: list[str], limit: int = 4) -> str:
    shown = ", ".join(units[:limit])
    return shown + (f" +{len(units) - limit} more" if len(units) > limit else "")


def _oneoffs(r: ProbeResult) -> dict[str, str]:
    """Failed units systemd marks Transient=yes (systemd-run one-offs) -> what they ran
    ("node setup-stripe.mjs"; empty when unknown). From probe_version 2 on; older
    probe output has none, so every failed unit counts as a real one."""
    out = {}
    for line in r.all("unit_transient"):
        unit, _, ran = line.partition(" ")
        out[unit] = ran
    return out


def systemd_failed(asset: Asset, r: ProbeResult) -> list[Finding]:
    """systemd not "running". Failed services: `systemctl status` to see why. Failed one-off
    runs (systemd-run, Transient=yes) are no broken service, but they keep the state
    "degraded" until reset-failed, so the next real failure would go unnoticed: also a warning."""
    if asset.kind is not Kind.vps:
        return []
    state = r.get("systemd_state")
    if state in (None, "", "running", "offline", "unknown"):
        return []
    if state in ("initializing", "starting"):
        return [Finding("systemd", "info", "system still booting",
                        f"systemd state is {state}", None, "check again in a minute")]
    failed = r.all("unit_failed")
    oneoff = _oneoffs(r)
    real = [u for u in failed if u not in oneoff]
    runs = [u for u in failed if u in oneoff]
    out = []
    if real:
        n = len(real)
        out.append(Finding(
            "systemd", "warn", f"{n} failed unit{'s' if n > 1 else ''}",
            f"systemd {state}: {_names(real)}",
            "systemctl status --no-pager -n 5 " + " ".join(real),
            "see why it failed, then fix and restart it, or disable it if no longer needed"
            if n == 1 else
            "see why they failed, then fix and restart them, or disable what is no longer needed"))
    if runs:
        n = len(runs)
        what = _names([f"{oneoff[u]} ({u})" if oneoff[u] else u for u in runs], 3)
        out.append(Finding(
            "systemd-oneoff", "warn", f"{n} failed one-off run{'s' if n > 1 else ''}",
            f"systemd-run commands that failed keep systemd {state}: {what}",
            "sudo systemctl reset-failed " + " ".join(runs),
            "clear them so a real failure shows again; start one-offs with "
            "`systemd-run --collect` next time"))
    if not failed:
        out.append(Finding("systemd", "warn", f"systemd {state}",
                           "no failed units listed", "systemctl --failed --no-pager",
                           "list what systemd considers broken"))
    return out


RULES: list[Callable[[Asset, ProbeResult], list[Finding]]] = [
    os_end_of_life,
    reboot_pending,
    systemd_failed,
]


def evaluate(asset: Asset, r: ProbeResult | None) -> list[Finding]:
    """All findings for one asset, worst first. Nothing for a missing or failed probe."""
    if r is None or not r.ok:
        return []
    out = [f for rule in RULES for f in rule(asset, r)]
    return sorted(out, key=lambda f: -RANK[f.severity])
