"""
Alert Dispatcher
================
Sends the daily WatchTower report to Discord. Self-contained — no external
project dependencies.

Scope note: Discord carries the DAILY REPORT ONLY (report.py). Intraday
down-alerting is UptimeRobot's job — it polls the public /health/* endpoints
served by health.py every 5 min and pushes to David's phone. The intraday
check paths (monitor.py, oct_liveness.py, oct_down_alert.py) are therefore
log-only: they still record state to their log files for forensics, but do
not notify. ntfy was removed entirely on 2026-08-03 (app retired).
"""
import logging
import os

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10


def send_discord(title: str, message: str, color: int = 0xFF0000):
    """Send an embed to Discord. Fails silently."""
    webhook_url = os.getenv('DISCORD_WEBHOOK_URL', '')
    if not webhook_url:
        return
    try:
        requests.post(
            webhook_url,
            json={'embeds': [{'title': title, 'description': message, 'color': color}]},
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as e:
        logger.warning(f'Discord alert failed: {e}')
