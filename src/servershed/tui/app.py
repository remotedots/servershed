"""servershed TUI: client/asset tree on the left, probe details on the right."""
from __future__ import annotations

import asyncio
import os
import shutil
import subprocess

from rich.text import Text
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import VerticalScroll
from textual.widgets import Footer, Header, Static, Tree
from textual.widgets.tree import TreeNode

from ..core import collect
from ..core.collect import ProbeResult
from ..core.inventory import Asset, Client, Inventory
from . import detail

MARK = {
    "pending": ("…", "dim"),
    "ok": ("●", "green"),
    "warn": ("▲", "yellow"),
    "fail": ("✖", "red"),
    "external": ("○", "dim"),
}


def status(asset: Asset, r: ProbeResult | None) -> str:
    """Until the rules exist, status is reachability plus a few obvious signals."""
    if not asset.probes:
        return "external"
    if r is None:
        return "pending"
    if not r.ok:
        return "fail"
    if (r.get("systemd_state") not in (None, "running")
            or r.get("apt_security") not in (None, "0")
            or r.get("reboot_required")):
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

    def __init__(self, inventory: Inventory, concurrency: int = 8):
        # use the terminal's own background and palette; no painted backgrounds
        super().__init__(ansi_color=True)
        self.inventory = inventory
        self.results: dict[str, ProbeResult | None] = {}
        self.nodes: dict[str, TreeNode] = {}
        self.raw = False
        self._sem = asyncio.Semaphore(concurrency)

    # ---------- layout ----------
    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)
        tree: Tree = Tree("estate", id="tree")
        tree.show_root = False
        tree.guide_depth = 3
        yield tree
        with VerticalScroll(id="detail-scroll"):
            yield Static(id="detail")
        yield Footer()

    def on_mount(self) -> None:
        tree = self.query_one(Tree)
        for client in self.inventory.clients:
            cnode = tree.root.add(client.name, data=client, expand=True)
            for asset in client.assets:
                self.results[asset.name] = None
                self.nodes[asset.name] = cnode.add_leaf(self._label(asset), data=(client, asset))
        tree.focus()
        first = next((n for n in self.nodes.values()), None)
        if first is not None:
            # tree lines only exist after the first layout
            self.call_after_refresh(tree.move_cursor, first)
        self.action_refresh_all()
        self._update_subtitle()

    # ---------- labels / detail ----------
    def _label(self, asset: Asset) -> Text:
        mark, style = MARK[status(asset, self.results.get(asset.name))]
        t = Text()
        t.append(f"{mark} ", style=style)
        t.append(asset.name)
        return t

    def _selected(self) -> tuple[Client, Asset] | None:
        node = self.query_one(Tree).cursor_node
        if node is not None and isinstance(node.data, tuple):
            return node.data
        return None

    def _show(self) -> None:
        sel = self._selected()
        box = self.query_one("#detail", Static)
        if sel is None:
            node = self.query_one(Tree).cursor_node
            if node is not None and isinstance(node.data, Client):
                box.update(self._client_summary(node.data))
            return
        client, asset = sel
        box.update(detail.render(client, asset, self.results.get(asset.name), self.raw))

    def _client_summary(self, client: Client) -> Text:
        t = Text(client.name + "\n\n", style="bold")
        for a in client.assets:
            mark, style = MARK[status(a, self.results.get(a.name))]
            t.append(f"{mark} ", style=style)
            t.append(f"{a.name}  ", style="bold")
            t.append(f"{a.kind.value}", style="dim")
            if a.sites:
                t.append(f"  {', '.join(a.sites)}", style="dim")
            t.append("\n")
        return t

    def _update_subtitle(self) -> None:
        counts: dict[str, int] = {}
        for _, a in self.inventory.assets():
            s = status(a, self.results.get(a.name))
            counts[s] = counts.get(s, 0) + 1
        parts = [f"{MARK[k][0]} {counts[k]}" for k in ("fail", "warn", "ok", "pending", "external")
                 if counts.get(k)]
        self.sub_title = "   ".join(parts)

    def on_tree_node_highlighted(self, event: Tree.NodeHighlighted) -> None:
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
        node = self.nodes.get(asset.name)
        if node is not None:
            node.set_label(self._label(asset))
        self._update_subtitle()
        sel = self._selected()
        cur = self.query_one(Tree).cursor_node
        if (sel and sel[1].name == asset.name) or (cur is not None and isinstance(cur.data, Client)):
            self._show()

    def action_refresh_all(self) -> None:
        for _, asset in self.inventory.assets():
            if asset.probes:
                self.run_worker(self._probe(asset), group="probe")

    def action_refresh(self) -> None:
        sel = self._selected()
        if sel is None:
            node = self.query_one(Tree).cursor_node
            if node is not None and isinstance(node.data, Client):
                for a in node.data.assets:
                    if a.probes:
                        self.run_worker(self._probe(a), group="probe")
            return
        if sel[1].probes:
            self.run_worker(self._probe(sel[1]), group="probe")

    # ---------- actions ----------
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
