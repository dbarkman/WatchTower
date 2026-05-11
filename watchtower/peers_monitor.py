#!/usr/bin/env python3
"""
Peer Monitor
============
High-cadence cross-server reachability monitor. Pings each configured peer's
/health endpoint and alerts via Discord + ntfy on state transitions
(up→down, down→up), with periodic re-alerts while a peer remains down.

State is persisted per-peer under state/peer_<name>.state so successive
invocations (e.g., every 15 minutes via cron) don't spam on sustained
outages.

Usage:
  uv run python -m watchtower.peers_monitor --config config/checks.yaml
"""
import argparse
import json
import logging
import os
import socket
import time
from datetime import datetime, timezone
from pathlib import Path

import requests
import yaml
from dotenv import load_dotenv

from watchtower.alerts import send_discord, send_ntfy

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

STATE_DIR = Path(__file__).resolve().parent.parent / "state"


def _probe(url: str, timeout: int) -> tuple[bool, str]:
    """Probe a peer URL. Returns (is_up, detail)."""
    try:
        resp = requests.get(url, timeout=timeout)
        if resp.status_code == 200:
            return True, "ok"
        return False, f"HTTP {resp.status_code}"
    except requests.exceptions.Timeout:
        return False, f"timeout after {timeout}s"
    except requests.exceptions.ConnectionError:
        return False, "connection refused / unreachable"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _state_path(peer_name: str) -> Path:
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in peer_name)
    return STATE_DIR / f"peer_{safe}.state"


def _load_state(peer_name: str) -> dict:
    path = _state_path(peer_name)
    if not path.exists():
        return {"status": "up", "since": int(time.time()), "last_alert_at": 0}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {"status": "up", "since": int(time.time()), "last_alert_at": 0}


def _save_state(peer_name: str, state: dict) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    _state_path(peer_name).write_text(json.dumps(state))


def _alert_down(observer: str, peer_name: str, url: str, detail: str, since_epoch: int, repeat: bool) -> None:
    since_str = datetime.fromtimestamp(since_epoch, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title_prefix = "STILL DOWN" if repeat else "DOWN"
    title = f"\U0001f534 {observer} cannot reach {peer_name} — {title_prefix}"
    body = (
        f"Observer: {observer}\n"
        f"Peer: {peer_name} ({url})\n"
        f"Detail: {detail}\n"
        f"Down since: {since_str}"
    )
    send_discord(title, body, color=0xFF0000)
    send_ntfy(os.getenv("NTFY_TOPIC", "WT-Health"), title, body, priority="urgent")


def _alert_recovered(observer: str, peer_name: str, url: str, downtime_seconds: int) -> None:
    minutes = downtime_seconds // 60
    title = f"✅ {observer} → {peer_name} RECOVERED"
    body = (
        f"Observer: {observer}\n"
        f"Peer: {peer_name} ({url})\n"
        f"Was down for ~{minutes} minute(s)"
    )
    send_discord(title, body, color=0x00FF00)
    send_ntfy(os.getenv("NTFY_TOPIC", "WT-Health"), title, body, priority="default")


def check_peers(observer: str, peers_config: dict) -> None:
    hosts = peers_config.get("hosts", [])
    timeout = peers_config.get("timeout_seconds", 5)
    repeat_hours = peers_config.get("alert_repeat_hours", 4)
    repeat_seconds = int(repeat_hours * 3600)

    if not hosts:
        logger.info("No peers configured")
        return

    now = int(time.time())

    for host in hosts:
        name = host.get("name") or host.get("url", "?")
        url = host.get("url")
        if not url:
            logger.warning(f"Peer {name} missing url; skipping")
            continue

        is_up, detail = _probe(url, timeout)
        state = _load_state(name)
        was_up = state.get("status", "up") == "up"

        if is_up and was_up:
            logger.info(f"{name}: up")
            continue

        if is_up and not was_up:
            downtime = now - state.get("since", now)
            logger.info(f"{name}: RECOVERED after {downtime}s")
            _alert_recovered(observer, name, url, downtime)
            _save_state(name, {"status": "up", "since": now, "last_alert_at": 0})
            continue

        if not is_up and was_up:
            logger.warning(f"{name}: DOWN ({detail})")
            _alert_down(observer, name, url, detail, now, repeat=False)
            _save_state(name, {"status": "down", "since": now, "last_alert_at": now})
            continue

        if not is_up and not was_up:
            last_alert = state.get("last_alert_at", 0)
            if now - last_alert >= repeat_seconds:
                since = state.get("since", now)
                logger.warning(f"{name}: STILL DOWN ({detail}) — re-alerting")
                _alert_down(observer, name, url, detail, since, repeat=True)
                state["last_alert_at"] = now
                _save_state(name, state)
            else:
                logger.info(f"{name}: still down (suppressed; last alert {(now - last_alert) // 60}m ago)")


def main() -> int:
    parser = argparse.ArgumentParser(description="WatchTower — peer monitor")
    parser.add_argument("--config", required=True, help="Path to checks.yaml")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    observer = config.get("server_name", socket.gethostname())
    peers_config = config.get("checks", {}).get("peers", {}) or {}

    check_peers(observer, peers_config)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
