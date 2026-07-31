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


def test_verdict_red_on_oom_kill():
    assert stats.verdict(_host(oom_kills=1)) == "red"


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
