"""OCT process liveness check.

Watches whether the trading *processes* are actually up and still emitting
output:

  * systemctl is-active for each unit, and
  * log-file mtime freshness — the daemons write continuously (each v2 venue
    emits an 'oct.observability heartbeat' every ~3 min), so a wedged-but-running
    process is caught too.

Used three ways:
  * Daily 12:00 UTC report — one line per unit (up/down + log age).
  * The public /health/oct endpoint (health.py), which UptimeRobot polls every
    5 min — this is the notification path.
  * Standalone every-2-min cron (python -m watchtower.checks.oct_liveness) —
    LOG-ONLY as of 2026-08-03. It records state changes to oct_liveness.log for
    forensic history (2-min resolution) but sends no notifications; state is
    persisted so the log doesn't repeat on every tick.
"""
import json
import os
import socket
import subprocess
import time

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL

# Single source of truth for both the report path and the cron path.
DEFAULT_UNITS = [
    # OCT v1 (one_cent_trader_ws, Kalshi) is retired — the Kalshi book migrated
    # to the v2 oct@kalshi unit. Removed here 2026-07-18. Re-add it (+ a
    # UptimeRobot monitor) only if v1 is ever brought back as a fallback.
    # v2 core runs per-venue (oct@<venue>), each logging oct.<venue>.log with a
    # ~3-min observability heartbeat; 5-min freshness threshold tolerates that.
    {"name": "OCT v2 PM.us", "service": "oct@polymarket_us",
     "log_path": "/var/www/html/OneCentTrader/logs/oct.polymarket_us.log",
     "max_log_age_min": 5},
    {"name": "OCT v2 Kalshi", "service": "oct@kalshi",
     "log_path": "/var/www/html/OneCentTrader/logs/oct.kalshi.log",
     "max_log_age_min": 5},
    {"name": "OCT v2 web", "service": "oct-web",
     "log_path": None, "max_log_age_min": None},
]
DEFAULT_STATE = "/var/www/html/WatchTower/state/oct_liveness.json"
DEFAULT_REALERT_MIN = 30

# Restart grace: OCT venue daemons (esp. oct@kalshi, which holds the full ~1.1GB
# Kalshi book) take up to ~90s to drain + restart — a window that reads as DOWN
# and, without grace, flaps /health/oct (UptimeRobot) and the Discord alert on
# every restart. run_with_grace() suppresses a down state until it has persisted
# >= OCT_LIVENESS_GRACE_SEC. The root cron and the apache health endpoint each
# pass their OWN grace-state path so neither writes the other's (root vs apache).
DEFAULT_GRACE_SEC = 150
DEFAULT_GRACE_STATE = "/var/www/html/WatchTower/state/oct_liveness_grace.json"          # root cron
DEFAULT_GRACE_STATE_ENDPOINT = "/var/www/html/WatchTower/state/oct_liveness_grace_ep.json"  # apache /health/oct


def _is_active(service: str) -> bool:
    try:
        out = subprocess.run(
            ["systemctl", "is-active", f"{service}.service"],
            capture_output=True, text=True, timeout=5,
        )
        return out.stdout.strip() == "active"
    except Exception:
        return False


def _log_age_min(log_path: str):
    try:
        return (time.time() - os.stat(log_path).st_mtime) / 60.0
    except Exception:
        return None


def _check_unit(unit: dict) -> CheckResult:
    name = unit["name"]
    service = unit["service"]
    if not _is_active(service):
        return CheckResult(name, CRITICAL, f"{service}.service NOT active — DOWN")

    log_path = unit.get("log_path")
    max_age = unit.get("max_log_age_min")
    if log_path and max_age:
        age = _log_age_min(log_path)
        if age is None:
            return CheckResult(name, WARNING, f"active, but log unreadable ({log_path})")
        if age > max_age:
            return CheckResult(
                name, CRITICAL,
                f"active but log stale {age:.0f}m (>{max_age}m) — possibly wedged")
        return CheckResult(name, OK, f"up, log {age:.1f}m fresh")
    return CheckResult(name, OK, "up")


def run(config: dict) -> list[CheckResult]:
    units = config.get("units") or DEFAULT_UNITS
    return [_check_unit(u) for u in units]


# --- cron entrypoint: state-change alerting -------------------------------

def _load_state(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(path: str, state: dict):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(state, f)
    except Exception:
        pass


def run_with_grace(config: dict | None = None, grace_sec: float | None = None,
                   state_path: str | None = None) -> list[CheckResult]:
    """run(), but hold a newly-down unit as OK ('restarting Ns') until it has
    been continuously down >= grace_sec — then report the real down/wedged status.

    Suppresses the ~90s oct@kalshi restart window so it doesn't flap /health/oct
    (UptimeRobot) or the Discord alert. A recovery clears the timer immediately,
    so two restarts with an up-tick between them are two short events, not one
    long one. Each caller passes its own state_path (root cron vs apache endpoint)
    so there is no cross-user write conflict. A genuine outage still surfaces once
    it outlasts the grace window.
    """
    config = config or {}
    if grace_sec is None:
        grace_sec = float(os.getenv("OCT_LIVENESS_GRACE_SEC", DEFAULT_GRACE_SEC))
    state_path = state_path or os.getenv("OCT_LIVENESS_GRACE_STATE", DEFAULT_GRACE_STATE)

    results = run(config)
    state = _load_state(state_path)
    now = time.time()
    new_state = {}
    graced = []
    for r in results:
        if r.status == OK:
            graced.append(r)  # healthy -> drop down_since (not carried forward)
            continue
        down_since = state.get(r.name, {}).get("down_since") or now
        new_state[r.name] = {"down_since": down_since}
        down_for = now - down_since
        if down_for < grace_sec:
            graced.append(CheckResult(
                r.name, OK,
                f"restarting {down_for:.0f}s (<{grace_sec:.0f}s grace) — {r.summary}"))
        else:
            graced.append(r)
    _save_state(state_path, new_state)
    return graced


def _cron_main():
    from dotenv import load_dotenv
    load_dotenv()

    state_path = os.getenv("OCT_LIVENESS_STATE", DEFAULT_STATE)
    realert_min = float(os.getenv("OCT_LIVENESS_REALERT_MIN", DEFAULT_REALERT_MIN))
    host = socket.gethostname()

    results = run_with_grace()
    state = _load_state(state_path)
    now = time.time()
    new_state = {}

    for r in results:
        key = r.name
        healthy = r.status == OK
        prev = state.get(key, {})
        prev_healthy = prev.get("healthy", True)
        last_alert = prev.get("last_alert", 0)

        fire = None
        if healthy and not prev_healthy:
            fire = "recovered"
        elif not healthy and prev_healthy:
            fire = "down"
        elif not healthy and (now - last_alert) >= realert_min * 60:
            fire = "still-down"

        # Log-only as of 2026-08-03: state transitions are recorded to
        # oct_liveness.log (2-min resolution uptime history for forensics).
        # Notification is UptimeRobot's, via the public /health/oct endpoint.
        if fire == "recovered":
            print(f"STATE-CHANGE recovered — {host} {r.name}: {r.summary}")
            last_alert = 0
        elif fire in ("down", "still-down"):
            print(f"STATE-CHANGE {fire} — {host} {r.name}: {r.summary}")
            last_alert = now

        new_state[key] = {"healthy": healthy, "last_alert": (last_alert if not healthy else 0)}
        print(f"{r.icon} {r.name}: {r.summary}")

    _save_state(state_path, new_state)


if __name__ == "__main__":
    _cron_main()
