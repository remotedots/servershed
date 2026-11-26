"""Render one asset's probe result as Rich renderables for the detail pane."""
from __future__ import annotations

from rich.console import Group
from rich.table import Table
from rich.style import Style
from rich.text import Text

from ..core.collect import ProbeResult
from ..core.inventory import Asset, Client


KEY_WIDTH = 16          # same key column in every section, so values line up


def _mb(kb: str | None) -> str:
    try:
        return f"{int(kb) / 1024:,.0f} MB"
    except (TypeError, ValueError):
        return "?"


def _uptime(s: str | None) -> str:
    try:
        sec = int(s)
    except (TypeError, ValueError):
        return "?"
    d, rem = divmod(sec, 86400)
    return f"{d}d {rem // 3600}h"


def _section(title: str, rows: list[tuple[str, str | Text]]) -> Table | None:
    rows = [(k, v) for k, v in rows if v is not None and str(v).strip()]
    if not rows:
        return None
    t = Table.grid(padding=(0, 2))
    t.add_column(style="dim", width=KEY_WIDTH, no_wrap=True)
    t.add_column()
    for k, v in rows:
        t.add_row(k, v)
    t.title = title
    t.title_justify = "left"
    t.title_style = "bold"
    return t


def _kernel(r: ProbeResult) -> Text:
    """Running kernel (+ "GRUB pinned" on the same line), newer installed ones below."""
    running = r.get("kernel") or "?"
    out = Text(running)
    grub = r.get("grub_default") or ""
    if running and running in grub:
        out.append("  (GRUB pinned)", style="dim")
    newer = sorted(k for k in r.all("kernel_installed") if k != running and k > running)
    if newer:
        out.append("\n" + "\n".join(newer), style="dim")
    return out


def _disk(r: ProbeResult) -> Text:
    out = Text()
    seen = set()
    for line in r.all("disk"):
        parts = line.split()
        if len(parts) < 4 or parts[1] in seen:      # same fs mounted twice
            continue
        seen.add(parts[1])
        mount, total, _, pct = parts[:4]
        style = "red" if int(pct.rstrip("%") or 0) >= 90 else (
            "yellow" if int(pct.rstrip("%") or 0) >= 80 else "")
        if out:
            out.append("\n")
        out.append(f"{mount}  {pct} of {int(total) / 1048576:,.0f} GB", style=style)
    return out


def _php_bins(bins: list[str]) -> Text:
    """Few binaries: one per line. Many (shared hosts ship 4.4 to 8.6): one compact line."""
    if len(bins) <= 4:
        return _lines(bins)
    versions = set()
    for b in bins:
        parts = b.split()
        if len(parts) >= 2:
            versions.add(".".join(parts[1].split(".")[:2]))
    ordered = sorted(versions, key=lambda v: tuple(int(x) for x in v.split(".") if x.isdigit()))
    out = Text("  ".join(ordered))
    out.append(f"   ({len(bins)} binaries)", style="dim")
    return out


def _site_links(sites: list[str]) -> Text:
    """One clickable line per site; a click opens https://<site> in the browser."""
    out = Text()
    for i, site in enumerate(sites):
        if i:
            out.append("\n")
        url = site if "://" in site else f"https://{site}"
        out.append(site, style=Style(meta={"@click": f"app.open_site({url!r})"}))
    return out


def _lines(values: list[str], style: str = "") -> Text:
    return Text("\n".join(values), style=style) if values else Text("")


def _systemd(r: ProbeResult) -> Text:
    state = r.get("systemd_state")
    if not state:
        return Text("")
    out = Text(state, style="green" if state == "running" else "yellow")
    failed = r.all("unit_failed")
    if failed:
        out.append(f"   failed: {', '.join(failed)}", style="yellow")
    return out


def _apt(r: ProbeResult) -> Text:
    up, sec = r.get("apt_upgradable"), r.get("apt_security")
    if up is None:
        return Text("")
    if up == "0":
        return Text("up to date", style="green")
    return Text(f"{up} upgradable ({sec or 0} security)",
                style="red" if sec not in (None, "0") else "yellow")


def render(client: Client, asset: Asset, r: ProbeResult | None, raw: bool = False):
    head = Text()
    head.append(asset.name, style="bold")
    head.append(f"   {client.name} · {asset.kind.value}")
    if asset.provider:
        head.append(f" · {asset.provider}")
    parts: list = [head, Text("")]
    if asset.notes:
        parts.append(Text(asset.notes, style="italic dim"))

    if not asset.probes:
        parts.append(Text("\nNot probed over SSH (external / client-owned).", style="dim"))
        parts.append(_section("\nSites", [("watched sites", _site_links(asset.sites))]) or Text(""))
        return Group(*parts)
    if r is None:
        parts.append(Text("\nprobing…", style="dim"))
        return Group(*parts)
    if not r.ok:
        parts.append(Text(f"\nprobe failed: {r.error}", style="red"))
        return Group(*parts)

    if raw:
        parts.append(Text("\n" + r.raw.rstrip(), style="dim"))
        parts.append(Text(f"probed in {r.seconds:.1f}s", style="dim"))
        return Group(*parts)

    php = [b for b in r.all("php_bin")]
    sections = [
        _section("\nSystem", [
            ("os", r.get("os_name")),
            ("kernel", _kernel(r)),
            ("uptime", _uptime(r.get("uptime_s")) if r.get("uptime_s") else None),
            ("load", r.get("load1")),
            ("systemd", _systemd(r)),
            ("target", r.get("default_target")),
            ("updates", _apt(r)),
        ]),
        _section("\nResources", [
            ("memory", f"{_mb(r.get('mem_avail_kb'))} free of {_mb(r.get('mem_total_kb'))}"
                       if r.get("mem_total_kb") else None),
            ("swap", f"{_mb(r.get('swap_free_kb'))} free of {_mb(r.get('swap_total_kb'))}"
                     if r.get("swap_total_kb") not in (None, "0") else None),
            ("disk", _disk(r)),
        ]),
        _section("\nSoftware", [
            ("php cli", r.get("php_cli")),
            ("php local", r.get("php_local")),
            ("php binaries", _php_bins(php)),
            ("php-fpm", _lines(r.all("php_fpm_sock"))),
            ("wordpress", _lines(r.all("wordpress"))),
            ("drupal", _lines(r.all("drupal"))),
            ("containers", _lines(r.all("container"))),
            ("htaccess php", _lines(r.all("htaccess_php_handler"), "yellow")),
            ("docroot missing", _lines(r.all("docroot_missing"), "red")),
        ]),
        _section("\nWeb", [
            ("watched sites", _site_links(asset.sites)),
            ("nginx enabled", _lines(r.all("nginx_site"))),
        ]),
        _section("\nNetwork", [("ipv6", _lines(r.all("ipv6")))]),
    ]
    parts += [s for s in sections if s is not None]
    return Group(*parts)
