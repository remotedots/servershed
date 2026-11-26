"""End-of-life dates for the operating systems the probe sees (os-release ID + VERSION_ID).

A built-in table instead of a live lookup: the dates rarely move and the tool stays offline.
Source: endoflife.date / the distributions' own pages, checked on CHECKED. Refresh when a
release is added or a date shifts.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

CHECKED = date(2026, 11, 27)


@dataclass(frozen=True)
class Release:
    distro: str             # display name
    version: str
    codename: str
    security_end: date      # regular security support
    end: date               # last support of any kind that needs no paid plan
    lts: bool = True


_D = lambda y, m, d: date(y, m, d)  # noqa: E731

# Debian: security_end = regular security team, end = Debian LTS (free, volunteer/sponsored)
DEBIAN = {r.version: r for r in [
    Release("Debian", "9", "stretch", _D(2020, 7, 6), _D(2022, 6, 30)),
    Release("Debian", "10", "buster", _D(2022, 9, 10), _D(2024, 6, 30)),
    Release("Debian", "11", "bullseye", _D(2024, 8, 14), _D(2026, 8, 31)),
    Release("Debian", "12", "bookworm", _D(2026, 6, 10), _D(2028, 6, 30)),
    Release("Debian", "13", "trixie", _D(2028, 8, 9), _D(2030, 6, 30)),
]}

# Ubuntu: end = standard support. ESM after that needs Ubuntu Pro (not visible to the probe).
UBUNTU = {r.version: r for r in [
    Release("Ubuntu", "18.04", "bionic", _D(2023, 5, 31), _D(2023, 5, 31)),
    Release("Ubuntu", "20.04", "focal", _D(2025, 5, 29), _D(2025, 5, 29)),
    Release("Ubuntu", "22.04", "jammy", _D(2027, 6, 1), _D(2027, 6, 1)),
    Release("Ubuntu", "24.04", "noble", _D(2029, 5, 31), _D(2029, 5, 31)),
    Release("Ubuntu", "24.10", "oracular", _D(2025, 7, 10), _D(2025, 7, 10), lts=False),
    Release("Ubuntu", "25.04", "plucky", _D(2026, 1, 15), _D(2026, 1, 15), lts=False),
    Release("Ubuntu", "25.10", "questing", _D(2026, 7, 9), _D(2026, 7, 9), lts=False),
    Release("Ubuntu", "26.04", "resolute", _D(2031, 5, 31), _D(2031, 5, 31)),
]}


def lookup(os_id: str | None, version: str | None) -> Release | None:
    """Release for an os-release ID/VERSION_ID pair; Raspbian follows its Debian base."""
    if not os_id or not version:
        return None
    if os_id in ("debian", "raspbian"):
        return DEBIAN.get(version.split(".")[0])
    if os_id == "ubuntu":
        return UBUNTU.get(version)
    return None


def latest(table: dict[str, Release], lts_only: bool = True) -> Release:
    """Newest release in a table (the upgrade target)."""
    rel = [r for r in table.values() if r.lts or not lts_only]
    return max(rel, key=lambda r: tuple(int(x) for x in r.version.split(".")))
