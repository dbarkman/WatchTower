"""OCT WebSocket liveness check.

The OCT fills/positions WebSocket can die *silently*: the socket stays open
but Kalshi stops delivering events, and the daemon never reconnects. The REST
reconciliation loop keeps running, so the process looks healthy while
settlements and fills stop being recorded (happened 2026-06-10, ~11h blind).

This check reads the trader log and reports the age of the most recent
WS-sourced event — a WON ``🏁 SETTLEMENT`` or a ``📬 WS Fill`` (both INFO).
While the socket is alive these flow continuously; the instant it dies the age
climbs. Used two ways:

  * Daily 12:00 UTC report — always shows "last WS event HH:MM UTC (X ago)"
    so the freshness is visible at a glance.
  * Standalone every-3h cron (``python -m watchtower.checks.oct_ws_liveness``)
    — pushes ntfy + Discord only when the last event is older than the
    threshold (default 3h; David has never seen the normal gap exceed it).
"""
import os
import re
import socket
import subprocess
from datetime import datetime, timezone

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL

DEFAULT_LOG = "/var/www/html/WeatherForcaster/logs/one_cent_trader.log"

# Log lines: "2026-06-10 13:56:58,932 - INFO - 📬 WS Fill: ..."
#            "2026-06-10 01:58:09,346 - INFO - 🏁 SETTLEMENT: ... WON ..."
# ASCII substrings (no emoji) avoid grep locale issues; both are INFO-level.
_EVENT_PATTERN = "SETTLEMENT:|WS Fill:"
_TS_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})")


def _humanize(seconds: float) -> str:
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m = rem // 60
    if h and m:
        return f"{h}h {m}m"
    if h:
        return f"{h}h"
    return f"{m}m"


def _last_event_ts(log_path: str):
    """UTC datetime of the most recent settlement/fill line, or None."""
    try:
        out = subprocess.run(
            ["grep", "-hE", _EVENT_PATTERN, log_path],
            capture_output=True, text=True, timeout=30,
        )
    except Exception:
        return None
    last = None
    for line in out.stdout.splitlines():
        m = _TS_RE.match(line)
        if m:
            last = m.group(1)
    if not last:
        return None
    try:
        # OCT logs in UTC; servers run UTC.
        return datetime.strptime(last, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def run(config: dict) -> list[CheckResult]:
    log_path = config.get("log_path", DEFAULT_LOG)
    warn_hours = config.get("warn_hours", 3)
    crit_hours = config.get("critical_hours", 6)

    ts = _last_event_ts(log_path)
    if ts is None:
        return [CheckResult("OCT WS", WARNING, "no settlement/fill event found in trader log")]

    age = (datetime.now(timezone.utc) - ts).total_seconds()
    summary = f"last WS event {ts:%H:%M UTC} ({_humanize(age)} ago)"

    if age >= crit_hours * 3600:
        status = CRITICAL
    elif age >= warn_hours * 3600:
        status = WARNING
    else:
        status = OK
    if status != OK:
        summary += f" — WS may be dead (>{warn_hours}h)"
    return [CheckResult("OCT WS", status, summary)]


if __name__ == "__main__":
    # Every-3h cron entrypoint: alert (ntfy + Discord) only when stale.
    from dotenv import load_dotenv
    load_dotenv()
    from watchtower.alerts import send_ntfy, send_discord

    res = run({})[0]
    print(f"{res.icon} {res.name}: {res.summary}")
    if res.status != OK:
        server = socket.gethostname()
        topic = os.getenv("WT_NTFY_TOPIC", "WT-Health")
        send_ntfy(
            topic,
            f"{server}: OCT WS {res.status.upper()}",
            f"{res.icon} {res.summary}",
            priority="urgent" if res.status == CRITICAL else "high",
        )
        send_discord(
            f"{res.icon} {server} — OCT WS {res.status}",
            res.summary,
            color=0xFF0000 if res.status == CRITICAL else 0xFFAA00,
        )
