"""/stats — host vitals for the OCT server-status dashboard.

The security-relevant bit is the token: on web2 this endpoint is reachable from
the internet through httpd, so most of these tests pin the auth behaviour.
"""
import importlib

import pytest
from fastapi.testclient import TestClient

from watchtower import stats


# --- unit spec parsing -------------------------------------------------------

def test_parse_units_basic():
    assert stats.parse_units("oct@kalshi.service=OCT Kalshi") == [
        ("oct@kalshi.service", "OCT Kalshi", True)
    ]


def test_parse_units_bang_means_expected_stopped():
    """A retired daemon shown permanently red trains the eye to ignore red."""
    assert stats.parse_units("!old.service=Old") == [("old.service", "Old", False)]


def test_parse_units_adds_service_suffix_and_defaults_label():
    assert stats.parse_units("httpd") == [("httpd.service", "httpd.service", True)]


def test_parse_units_tolerates_blanks_and_spacing():
    assert stats.parse_units(" a.service=A , , b.service=B ") == [
        ("a.service", "A", True),
        ("b.service", "B", True),
    ]


def test_parse_units_empty():
    assert stats.parse_units("") == []


# --- verdict -----------------------------------------------------------------

def _host(**over):
    base = {
        "filesystems": [], "services": [], "mem_used_pct": 10.0,
        "swap_used_pct": 0.0, "load_pct": 10.0, "oom_kills": 0,
    }
    base.update(over)
    return base


def test_verdict_green_when_quiet():
    assert stats.verdict(_host()) == "green"


def test_verdict_red_on_unhealthy_service():
    svc = {"healthy": False, "restarts": 0}
    assert stats.verdict(_host(services=[svc])) == "red"


def test_verdict_ignores_undated_oom_kills():
    """The bug this replaces: /proc/vmstat's counter is cumulative since boot, so
    keying the verdict off it left a host red for weeks over one old kill."""
    assert stats.verdict(_host(oom_kills=1, oom_last_kill_secs=None)) == "green"
    assert stats.verdict(_host(oom_kills=99, oom_last_kill_secs=None)) == "green"


def test_verdict_red_on_fresh_oom_kill():
    assert stats.verdict(_host(oom_kills=1, oom_last_kill_secs=0)) == "red"
    assert stats.verdict(
        _host(oom_kills=1, oom_last_kill_secs=stats.OOM_RED_SECS)) == "red"


def test_verdict_yellow_on_oom_kill_within_a_day():
    assert stats.verdict(
        _host(oom_kills=1, oom_last_kill_secs=stats.OOM_RED_SECS + 1)) == "yellow"
    assert stats.verdict(
        _host(oom_kills=1, oom_last_kill_secs=stats.OOM_YELLOW_SECS)) == "yellow"


def test_verdict_green_once_the_oom_kill_ages_out():
    assert stats.verdict(
        _host(oom_kills=1, oom_last_kill_secs=stats.OOM_YELLOW_SECS + 1)) == "green"


# --- OOM dating (the state file) ---------------------------------------------

@pytest.fixture
def oom_state(tmp_path, monkeypatch):
    monkeypatch.setattr(stats, "_STATE_DIR", str(tmp_path))
    monkeypatch.setattr(stats, "_OOM_STATE", str(tmp_path / "oom_kills.state"))
    return tmp_path


def test_first_reading_only_baselines_and_dates_nothing(oom_state):
    """web1 today: one kill of unknown age. It must not colour anything."""
    assert stats._oom_last_kill_secs(1, 1000.0) is None
    assert stats._oom_last_kill_secs(1, 9999.0) is None      # still undated later


def test_a_rise_after_the_baseline_is_dated(oom_state):
    stats._oom_last_kill_secs(1, 1000.0)
    assert stats._oom_last_kill_secs(2, 1500.0) == 0
    assert stats._oom_last_kill_secs(2, 1500.0 + 90) == 90   # ages from the rise


def test_counter_going_down_is_a_reboot(oom_state):
    stats._oom_last_kill_secs(5, 1000.0)
    # vmstat reset and already shows a kill -> it happened after that boot
    assert stats._oom_last_kill_secs(1, 2000.0) == 0
    # a clean counter after a reboot dates nothing
    stats._oom_last_kill_secs(9, 3000.0)
    assert stats._oom_last_kill_secs(0, 4000.0) is None


def test_unwritable_state_never_nags(oom_state, monkeypatch):
    """If we cannot remember, we must not colour — the old failure mode was a
    signal that could never clear."""
    monkeypatch.setattr(stats, "_OOM_STATE", "/proc/nonexistent/oom.state")
    monkeypatch.setattr(stats, "_STATE_DIR", "/proc/nonexistent")
    assert stats._oom_last_kill_secs(3, 1000.0) is None


def test_readable_but_unpersistable_rise_does_not_stick_red(oom_state, monkeypatch):
    """A baseline we can read but not update would otherwise re-stamp the same
    rise as 'just now' on every poll — permanent red, the original bug."""
    stats._oom_last_kill_secs(1, 1000.0)                     # baseline persists
    monkeypatch.setattr(stats, "_write_oom_state", lambda *a: False)
    assert stats._oom_last_kill_secs(2, 2000.0) is None
    assert stats._oom_last_kill_secs(2, 3000.0) is None


def test_verdict_red_on_full_disk_or_inodes():
    assert stats.verdict(_host(filesystems=[{"used_pct": 91, "inode_pct": 1}])) == "red"
    assert stats.verdict(_host(filesystems=[{"used_pct": 1, "inode_pct": 95}])) == "red"


def test_verdict_yellow_on_restarts():
    svc = {"healthy": True, "restarts": 2}
    assert stats.verdict(_host(services=[svc])) == "yellow"


def test_expected_stopped_service_is_healthy_when_inactive():
    """The whole point of the `!` prefix."""
    from datetime import datetime, timezone
    svc = stats._service("definitely-not-a-unit.service", "Retired", False,
                         datetime.now(timezone.utc))
    assert svc["healthy"] is True


# --- endpoint auth -----------------------------------------------------------

def _client(monkeypatch, token):
    monkeypatch.setenv("WATCHTOWER_STATS_TOKEN", token)
    monkeypatch.setenv("WATCHTOWER_STATS_UNITS", "")
    import watchtower.health as health
    importlib.reload(health)  # module reads the token at import time
    return TestClient(health.app)


def test_stats_open_when_no_token_configured(monkeypatch):
    """web1 is loopback-only and needs no token."""
    c = _client(monkeypatch, "")
    assert c.get("/stats").status_code == 200


def test_stats_rejects_missing_token(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    assert c.get("/stats").status_code == 404


def test_stats_rejects_wrong_token(monkeypatch):
    c = _client(monkeypatch, "s3cret")
    assert c.get("/stats", headers={"X-WatchTower-Token": "nope"}).status_code == 404


@pytest.mark.parametrize("headers", [
    {"X-WatchTower-Token": "s3cret"},
    {"Authorization": "Bearer s3cret"},
])
def test_stats_accepts_valid_token_either_header(monkeypatch, headers):
    c = _client(monkeypatch, "s3cret")
    assert c.get("/stats", headers=headers).status_code == 200


def test_stats_payload_shape(monkeypatch):
    c = _client(monkeypatch, "")
    body = c.get("/stats").json()
    for key in ("name", "hostname", "ip", "kernel", "cores", "load_pct",
                "mem_used_pct", "oom_kills", "filesystems", "services",
                "verdict", "collected_at", "reachable"):
        assert key in body, key
    assert body["verdict"] in {"green", "yellow", "red"}
