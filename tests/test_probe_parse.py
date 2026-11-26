from pathlib import Path

from servershed.core import inventory
from servershed.core.collect import parse

FIX = Path(__file__).parent / "fixtures"
ROOT = Path(__file__).parent.parent


def test_fixtures_parse_and_complete():
    # committed synthetic fixtures + real ones in fixtures/local/ (git-ignored) if present
    files = sorted(FIX.glob("*.txt")) + sorted((FIX / "local").glob("*.txt"))
    assert files
    for f in files:
        facts = parse(f.read_text())
        assert facts.get("probe_done") == ["1"], f.name
        # unit names only, never wrapped description fragments
        for u in facts.get("unit_failed", []):
            assert " " not in u and "." in u, (f.name, u)
        # each php binary listed once
        bins = facts.get("php_bin", [])
        assert len(bins) == len(set(bins)), f.name


def test_parse_ignores_noise():
    assert parse("a=1\na=2\n  junk line\n=x\nkey with space=y\n") == {"a": ["1", "2"]}


def test_inventory_loads():
    inv = inventory.load(ROOT / "inventory.example.yaml")
    assets = {a.name: a for _, a in inv.assets()}
    assert assets["vps-main"].probes
    assert not assets["nordwerk-vps"].probes   # external is never probed


def test_real_inventory_if_present():
    real = ROOT / "inventory.yaml"
    if real.exists():
        inventory.load(real)
