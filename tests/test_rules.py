from pathlib import Path

from servershed.core.collect import ProbeResult, parse
from servershed.core.inventory import Asset
from servershed.core.rules import evaluate, kernel_split, newer_kernels

FIX = Path(__file__).parent / "fixtures"
VPS = Asset(name="vps-main", kind="vps", ssh="vps-main")
SHARED = Asset(name="kade-shared", kind="shared", ssh="kade-shared")


def mk(raw: str) -> ProbeResult:
    return ProbeResult("x", ok=True, facts=parse(raw))


def base(**facts) -> str:
    lines = {"kernel": "6.1.0-56-amd64", "uptime_s": "86400", "probe_done": "1"} | facts
    return "".join(f"{k}={v}\n" for k, v in lines.items())


def test_kernel_versions_compare_numerically():
    assert kernel_split("6.1.0-56-cloud-amd64") == ((6, 1, 0, 56), "-cloud-amd64")
    r = mk(base(kernel="6.1.0-9-amd64") + "kernel_installed=6.1.0-10-amd64\n"
           "kernel_installed=6.1.0-11-cloud-amd64\nkernel_installed=6.1.0-8-amd64\n")
    assert newer_kernels(r) == ["6.1.0-10-amd64"]      # other flavors and older ones ignored


def test_reboot_with_grub_pin_boots_newest_once():
    r = mk((FIX / "example-vps.txt").read_text())
    [f] = [f for f in evaluate(VPS, r) if f.rule == "reboot-pending"]
    assert f.severity == "warn"
    assert "running 6.1.0-54-amd64, 6.1.0-56-amd64 installed" in f.reason
    assert "GRUB pinned to 6.1.0-54-amd64" in f.reason and "up 10 days" in f.reason
    assert f.cmd == ("sudo grub-reboot 'Advanced options for Debian GNU/Linux>"
                     "Debian GNU/Linux, with Linux 6.1.0-56-amd64' && sudo systemctl reboot")


def test_reboot_required_flag_plain_reboot():
    [f] = evaluate(VPS, mk(base(reboot_required="1")))
    assert f.reason == "reboot-required flag set; up 1 day"
    assert f.cmd == "sudo systemctl reboot"


def test_no_reboot_when_current_or_shared():
    assert evaluate(VPS, mk(base() + "kernel_installed=6.1.0-56-amd64\n")) == []
    assert evaluate(SHARED, mk(base(reboot_required="1"))) == []
    assert evaluate(VPS, None) == []


# ---------- OS end of life ----------
from datetime import date

from servershed.core import eol, rules


def os_findings(monkeypatch, os_id, version, today=date(2026, 11, 27), asset=VPS):
    monkeypatch.setattr(rules, "_today", lambda: today)
    r = mk(base(os_id=os_id, os_version=version) + "kernel_installed=6.1.0-56-amd64\n")
    return [f for f in evaluate(asset, r) if f.rule == "os-eol"]


def test_os_past_end_is_fail(monkeypatch):
    [f] = os_findings(monkeypatch, "raspbian", "11")
    assert f.severity == "fail" and f.title == "Raspbian 11 (bullseye) is end of life"
    assert "ended 2026-08-31 (3 months ago)" in f.reason
    assert "reinstall" in f.action and f.cmd is None
    [f] = os_findings(monkeypatch, "debian", "10")
    assert f.action == "upgrade to Debian 11 (bullseye) → 12 (bookworm) → 13 (trixie), one release at a time"
    [f] = os_findings(monkeypatch, "ubuntu", "20.04")
    assert f.severity == "fail" and f.cmd == "sudo do-release-upgrade" and "Ubuntu Pro" in f.reason


def test_os_end_soon_is_warn_lts_is_info(monkeypatch):
    [f] = os_findings(monkeypatch, "ubuntu", "22.04", today=date(2027, 1, 15))
    assert f.severity == "warn" and "ends 2027-06-01" in f.reason
    [f] = os_findings(monkeypatch, "debian", "12")
    assert f.severity == "info" and "Debian LTS until 2028-06-30" in f.reason


def test_os_supported_unknown_or_shared_gives_nothing(monkeypatch):
    assert os_findings(monkeypatch, "debian", "13") == []
    assert os_findings(monkeypatch, "ubuntu", "24.04") == []
    assert os_findings(monkeypatch, "alpine", "3.20") == []
    assert os_findings(monkeypatch, "raspbian", "11", asset=SHARED) == []


def test_eol_table_is_ordered():
    for table in (eol.DEBIAN, eol.UBUNTU):
        for r in table.values():
            assert r.security_end <= r.end


# ---------- systemd ----------
def systemd(state, *units, asset=VPS):
    raw = base(systemd_state=state) + "".join(
        u if "=" in u else f"unit_failed={u}\n" for u in units)
    return [f for f in evaluate(asset, mk(raw)) if f.rule.startswith("systemd")]


def test_failed_services_warn_with_status_cmd():
    [f] = systemd("degraded", "dhcpcd.service", "motioneye.service")
    assert f.severity == "warn" and f.title == "2 failed units"
    assert f.reason == "systemd degraded: dhcpcd.service, motioneye.service"
    assert f.cmd == "systemctl status --no-pager -n 5 dhcpcd.service motioneye.service"


def test_oneoff_runs_by_transient_flag_are_warn_with_reset_failed():
    found = systemd("degraded", "run-u178.service", "nginx.service", "stripe-setup.service",
                    "run-backup.service",
                    "unit_transient=run-u178.service node setup-stripe.mjs\n"
                    "unit_transient=stripe-setup.service")
    assert [(f.rule, f.severity) for f in found] == [("systemd", "warn"), ("systemd-oneoff", "warn")]
    # the name does not decide: run-backup.service is a real unit, stripe-setup.service a one-off
    assert found[0].cmd.endswith(" nginx.service run-backup.service")
    assert found[1].title == "2 failed one-off runs"
    assert "node setup-stripe.mjs (run-u178.service), stripe-setup.service" in found[1].reason
    assert found[1].cmd == "sudo systemctl reset-failed run-u178.service stripe-setup.service"
    assert "--collect" in found[1].action


def test_old_probe_without_transient_flag_counts_all_as_real():
    [f] = systemd("degraded", "run-u178.service")
    assert f.rule == "systemd" and f.title == "1 failed unit"


def test_systemd_quiet_cases():
    assert systemd("running") == []
    assert systemd("offline") == []                 # no systemd as init (containers)
    assert systemd("degraded", "x.service", asset=SHARED) == []
    [f] = systemd("starting")
    assert f.severity == "info"
    [f] = systemd("degraded")                       # degraded, but nothing listed
    assert f.severity == "warn" and f.cmd == "systemctl --failed --no-pager"


def test_fact_colour_comes_from_findings():
    from servershed.tui.detail import _fact_styles
    raw = (FIX / "example-vps.txt").read_text()
    styles = _fact_styles(evaluate(VPS, mk(raw)))
    assert styles["kernel"] == "yellow"         # reboot pending
    assert styles["systemd"] == "yellow"        # failed unit
    assert "os" not in styles                   # Debian 12 on LTS is only info
    assert "disk" not in styles                 # no disk rule yet: plain
