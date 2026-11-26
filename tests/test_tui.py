"""Drive the TUI headless with fixture data instead of ssh."""
import asyncio
from pathlib import Path

from servershed.core import collect, inventory
from servershed.core.collect import ProbeResult, parse
from servershed.tui import app as tui_app

ROOT = Path(__file__).parent.parent
FIX = Path(__file__).parent / "fixtures"
MAP = {"vps-main": "example-vps.txt", "kade-shared": "example-shared.txt"}


async def fake_probe(asset, timeout=90):
    await asyncio.sleep(0)
    raw = (FIX / MAP[asset.name]).read_text()
    return ProbeResult(asset.name, ok=True, facts=parse(raw), raw=raw, seconds=0.1)


def test_tui_loads_and_navigates(monkeypatch):
    monkeypatch.setattr(collect, "probe", fake_probe)
    inv = inventory.load(ROOT / "inventory.example.yaml")

    async def run():
        app = tui_app.ServershedApp(inv)
        async with app.run_test(size=(120, 40)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            # degraded systemd in the fixture -> warn; shared -> ok; external -> not probed
            assert tui_app.status(inv.clients[0].assets[0], app.results["vps-main"]) == "warn"
            assert app.results["kade-shared"].ok
            assert "nordwerk-vps" not in [n for n, r in app.results.items() if r]
            screen = app.export_screenshot().replace("&#160;", " ")
            assert "Debian GNU/Linux 12" in screen        # detail of vps-main
            assert "newer installed: 6.1.0-56-amd64" in screen
            assert "GRUB" in screen and "pinned" in screen
            await pilot.press("v")          # raw view
            await pilot.pause()
            assert "probe_done=1" in app.export_screenshot()
            await pilot.press("down", "up")
            await pilot.press("q")

    asyncio.run(run())
