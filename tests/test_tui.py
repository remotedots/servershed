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
            assert "6.1.0-54-amd64" in screen and "(GRUB pinned)" in screen
            assert "6.1.0-56-amd64" in screen                  # newer kernel listed
            await pilot.press("v")          # raw view
            await pilot.pause()
            assert "probe_done=1" in app.export_screenshot()
            await pilot.press("down", "up")
            await pilot.press("q")

    asyncio.run(run())


def test_watched_site_click_opens_browser(monkeypatch):
    monkeypatch.setattr(collect, "probe", fake_probe)
    inv = inventory.load(ROOT / "inventory.example.yaml")
    opened = []

    async def run():
        app = tui_app.ServershedApp(inv)
        monkeypatch.setattr(app, "open_url", lambda url, **kw: opened.append(url))
        async with app.run_test(size=(120, 50)) as pilot:
            await app.workers.wait_for_complete()
            await pilot.pause()
            region = app.query_one("#detail").region
            spot = next(((x, y) for y in range(region.y, region.bottom)
                         for x in range(region.x, region.right)
                         if "@click" in app.screen.get_style_at(x, y).meta), None)
            assert spot, "no clickable site found in the detail pane"
            await pilot.click(offset=spot)
            await pilot.pause()

    asyncio.run(run())
    assert opened == ["https://example.org"]


def test_unhealthy_container_makes_asset_warn():
    inv = inventory.load(ROOT / "inventory.example.yaml")
    shared = next(a for _, a in inv.assets() if a.name == "kade-shared")
    base = (FIX / "example-shared.txt").read_text()
    healthy = parse(base + "container=app-web-1 example/web:1 Up 5 minutes (healthy)\n")
    sick = parse(base + "container=app-web-1 example/web:1 Up 5 minutes (unhealthy)\n")
    stopped = parse(base + "container=app-web-1 example/web:1 Exited (1) 2 hours ago\n")
    mk = lambda f: ProbeResult("kade-shared", ok=True, facts=f)
    assert tui_app.status(shared, mk(healthy)) == "ok"
    assert tui_app.status(shared, mk(sick)) == "warn"
    assert tui_app.status(shared, mk(stopped)) == "warn"
