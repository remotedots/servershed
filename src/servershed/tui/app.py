"""servershed TUI: clients and assets on the left, probe details on the right."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import Footer, Header, OptionList, Static
from textual.widgets.option_list import Option

from ..core import collect
from ..core.collect import ProbeResult
from ..core.inventory import Asset, Client, Inventory
from ..core.rules import evaluate
from . import detail

MARK = {
    "pending": ("…", "dim"),
    "ok": ("●", "green"),
    "warn": ("▲", "yellow"),
    "fail": ("✖", "red"),          # probe failed: unreachable
    "crit": ("■", "red"),          # reachable, but a finding needs action now
    "external": ("○", "dim"),
}


def status(asset: Asset, r: ProbeResult | None) -> str:
    """Worst finding, plus stand-in signals for checks that have no rule yet."""
    if not asset.probes:
        return "external"
    if r is None:
        return "pending"
    if not r.ok:
        return "fail"
    found = evaluate(asset, r)
    if found and found[0].severity == "fail":
        return "crit"
    if found and found[0].severity == "warn":
        return "warn"
    # stand-ins until their rules exist (step 2A)
    if (r.get("apt_security") not in (None, "0")
            or any(detail.container_in_trouble(c) for c in r.all("container"))):
        return "warn"
    return "ok"


class ServershedApp(App):
    TITLE = "servershed"
    CSS_PATH = "app.tcss"
    BINDINGS = [
        Binding("r", "refresh", "refresh"),
        Binding("R", "refresh_all", "refresh all"),
        Binding("s", "ssh", "ssh"),
        Binding("v", "toggle_raw", "raw facts"),
        Binding("q", "quit", "quit"),
    ]

    def __init__(self, inventory: Inventory, concurrency: int = 8, dev: bool = False):
        # ANSI mode: the terminal's own background shows through in the main panel
        # (header/footer get their theme colors back in app.tcss)
        # dev: reload app.tcss whenever it is saved
        super().__init__(ansi_color=True, watch_css=dev)
        self.inventory = inventory
        self.results: dict[str, ProbeResult | None] = {}
        self.assets: dict[str, tuple[Client, Asset]] = {
            a.name: (c, a) for c, a in inventory.assets()}
        self.raw = False
        self._sem = asyncio.Semaphore(concurrency)

    # ---------- layout ----------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        yield OptionList(*self._options(), id="estate")
        with VerticalScroll(id="detail-scroll"):
            yield Static(id="detail")
        yield Footer()

    def _options(self) -> list[Option]:
        """Client headers and blank spacers are disabled, so the cursor skips them."""
        opts: list[Option] = []
        for i, client in enumerate(self.inventory.clients):
            if i:
                opts.append(Option("", disabled=True))
            head = Text()
            head.append("▾ ", style="bright_black")
            head.append(client.name, style="bold")
            opts.append(Option(head, disabled=True))
            for asset in client.assets:
                self.results[asset.name] = None
                opts.append(Option(self._label(asset), id=asset.name))
        return opts

    def on_mount(self) -> None:
        estate = self.query_one("#estate", OptionList)
        estate.focus()
        estate.action_first()           # first selectable row = first asset
        self.action_refresh_all()
        self._update_subtitle()

    # ---------- labels / detail ----------
    def _label(self, asset: Asset) -> Text:
        mark, style = MARK[status(asset, self.results.get(asset.name))]
        t = Text("  ")
        t.append(f"{mark} ", style=style)
        t.append(asset.name)
        return t

    def _selected(self) -> tuple[Client, Asset] | None:
        opt = self.query_one("#estate", OptionList).highlighted_option
        if opt is None or opt.id is None:
            return None
        return self.assets.get(opt.id)

    def _show(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        client, asset = sel
        self.query_one("#detail", Static).update(
            detail.render(client, asset, self.results.get(asset.name), self.raw))

    def _update_subtitle(self) -> None:
        counts: dict[str, int] = {}
        for _, a in self.inventory.assets():
            s = status(a, self.results.get(a.name))
            counts[s] = counts.get(s, 0) + 1
        parts = [f"{MARK[k][0]} {counts[k]}" for k in ("fail", "crit", "warn", "ok", "pending", "external")
                 if counts.get(k)]
        self.sub_title = "   ".join(parts)

    def on_option_list_option_highlighted(self, event: OptionList.OptionHighlighted) -> None:
        self._show()

    # ---------- probing ----------
    async def _probe(self, asset: Asset) -> None:
        self.results[asset.name] = None
        self._refresh_asset(asset)
        async with self._sem:
            r = await collect.probe(asset)
        self.results[asset.name] = r
        self._refresh_asset(asset)

    def _refresh_asset(self, asset: Asset) -> None:
        self.query_one("#estate", OptionList).replace_option_prompt(
            asset.name, self._label(asset))
        self._update_subtitle()
        sel = self._selected()
        if sel and sel[1].name == asset.name:
            self._show()

    def action_refresh_all(self) -> None:
        for _, asset in self.inventory.assets():
            if asset.probes:
                self.run_worker(self._probe(asset), group="probe")

    def action_refresh(self) -> None:
        sel = self._selected()
        if sel and sel[1].probes:
            self.run_worker(self._probe(sel[1]), group="probe")

    # ---------- actions ----------
    def action_open_site(self, url: str) -> None:
        """Clicked a watched site in the detail pane: open it in the browser."""
        self.open_url(url)
        self.notify(f"opening {url}", timeout=2)

    def action_toggle_raw(self) -> None:
        self.raw = not self.raw
        self._show()

    def action_ssh(self) -> None:
        sel = self._selected()
        if sel is None:
            return
        asset = sel[1]
        if not asset.probes or not asset.ssh:
            self.notify(f"{asset.name}: no ssh for this asset", severity="warning")
            return
        if os.environ.get("TMUX") and shutil.which("tmux"):
            # session in a split below; the TUI keeps running above
            subprocess.run(["tmux", "split-window", "-v", "-l", "40%",
                            "ssh", asset.ssh], check=False)
            return
        with self.suspend():
            subprocess.run(["ssh", asset.ssh], check=False)
