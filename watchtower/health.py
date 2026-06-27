#!/usr/bin/env python3
"""
Health Endpoint
===============
Lightweight HTTP health endpoint that any server can expose.
Checks whether a configured process is running and its log is fresh.

Usage:
  uvicorn watchtower.health:app --host 127.0.0.1 --port 8100

Configure via environment variables:
  WATCHTOWER_PROCESS_NAME  — process name to check via pgrep (optional)
  WATCHTOWER_LOG_PATH      — log file to check freshness (optional)
  WATCHTOWER_STALE_SECONDS — max log age before "stale" (default: 300)
"""
import os
import subprocess
import time

from fastapi import FastAPI
from fastapi.responses import JSONResponse

app = FastAPI()

PROCESS_NAME = os.getenv('WATCHTOWER_PROCESS_NAME', '')
LOG_PATH = os.getenv('WATCHTOWER_LOG_PATH', '')
STALE_THRESHOLD = int(os.getenv('WATCHTOWER_STALE_SECONDS', '300'))


def _process_running(name: str) -> bool | None:
    """Check if a process is running. Returns None if no process configured."""
    if not name:
        return None
    try:
        result = subprocess.run(['pgrep', '-f', name], capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


def _log_age_seconds(path: str) -> float | None:
    """Get the age of a log file in seconds. Returns None if no log configured."""
    if not path:
        return None
    try:
        return time.time() - os.path.getmtime(path)
    except OSError:
        return None


@app.api_route('/health', methods=['GET', 'HEAD'])
def health():
    running = _process_running(PROCESS_NAME)
    age = _log_age_seconds(LOG_PATH)
    stale = age is not None and age > STALE_THRESHOLD

    # Healthy if: process check passes (or not configured) AND log is fresh (or not configured)
    process_ok = running is None or running is True
    log_ok = not stale
    healthy = process_ok and log_ok

    response = {'status': 'healthy' if healthy else 'unhealthy'}

    if running is not None:
        response['daemon_running'] = running
    if age is not None:
        response['log_age_seconds'] = round(age, 1)
        response['log_stale'] = stale

    return JSONResponse(
        status_code=200 if healthy else 503,
        content=response,
    )


@app.api_route('/health/daemon', methods=['GET', 'HEAD'])
def health_daemon():
    """Alias with age_seconds for compatibility with heartbeat-style monitors."""
    running = _process_running(PROCESS_NAME)
    age = _log_age_seconds(LOG_PATH)
    stale = age is not None and age > STALE_THRESHOLD

    process_ok = running is None or running is True
    log_ok = not stale
    healthy = process_ok and log_ok

    response = {'status': 'healthy' if healthy else 'unhealthy'}

    if age is not None:
        response['age_seconds'] = round(age, 1)
    if running is not None:
        response['daemon_running'] = running

    return JSONResponse(
        status_code=200 if healthy else 503,
        content=response,
    )
