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


@app.api_route('/health/oct', methods=['GET', 'HEAD'])
def health_oct():
    """OCT trading liveness (v1 + v2) for external monitors (e.g. UptimeRobot).

    Returns 200 when every OCT unit is up with a fresh log, 503 if any is
    down or wedged. Same signal as the every-2-min oct_liveness cron; exposes
    only up/down + unit names (no financial data).

    Uses run_with_grace so a brief venue restart (oct@kalshi drains for ~90s)
    doesn't flap this endpoint — a unit must stay down past the grace window
    before we report 503. Its own grace-state file (apache-owned) keeps this
    independent of the root cron's grace state.
    """
    from watchtower.checks import oct_liveness, OK as _OK
    results = oct_liveness.run_with_grace(
        state_path=oct_liveness.DEFAULT_GRACE_STATE_ENDPOINT)
    healthy = all(r.status == _OK for r in results)
    return JSONResponse(
        status_code=200 if healthy else 503,
        content={
            'status': 'healthy' if healthy else 'unhealthy',
            'units': {r.name: r.summary for r in results},
        },
    )


# --- Resource-exhaustion check (intraday runaway / pre-crash detection) -----

DISK_CRIT_PCT = float(os.getenv('WATCHTOWER_DISK_CRIT_PCT', '90'))
INODE_CRIT_PCT = float(os.getenv('WATCHTOWER_INODE_CRIT_PCT', '90'))
SWAP_CRIT_PCT = float(os.getenv('WATCHTOWER_SWAP_CRIT_PCT', '85'))
MEM_AVAIL_MIN_PCT = float(os.getenv('WATCHTOWER_MEM_AVAIL_MIN_PCT', '3'))


def _disk_pct(path: str = '/') -> float:
    import shutil
    try:
        u = shutil.disk_usage(path)
        return round(u.used / u.total * 100, 1)
    except Exception:
        return 0.0


def _inode_pct(path: str = '/') -> float:
    try:
        s = os.statvfs(path)
        if not s.f_files:
            return 0.0
        return round((s.f_files - s.f_ffree) / s.f_files * 100, 1)
    except Exception:
        return 0.0


def _mem_swap_pct():
    """Return (swap_used_pct, mem_available_pct) from /proc/meminfo."""
    try:
        info = {}
        with open('/proc/meminfo') as f:
            for line in f:
                k, _, v = line.partition(':')
                info[k] = int(v.strip().split()[0])  # kB
        mt, ma = info.get('MemTotal', 0), info.get('MemAvailable', 0)
        st, sf = info.get('SwapTotal', 0), info.get('SwapFree', 0)
        swap_used_pct = round((st - sf) / st * 100, 1) if st else 0.0
        mem_avail_pct = round(ma / mt * 100, 1) if mt else 100.0
        return swap_used_pct, mem_avail_pct
    except Exception:
        return 0.0, 100.0


def _root_readonly() -> bool:
    """True if / is mounted read-only (kernel remounts ro on serious FS/disk errors)."""
    try:
        with open('/proc/mounts') as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[1] == '/':
                    return 'ro' in parts[3].split(',')
    except Exception:
        pass
    return False


_REAL_FS = {'ext4', 'ext3', 'ext2', 'xfs', 'btrfs'}


def _real_mounts() -> list[str]:
    """Mount points backed by a real block-device filesystem (e.g. /, /var).
    Auto-adapts per server — web1 has separate / and /var disks, web2 just /."""
    mounts = []
    try:
        with open('/proc/mounts') as f:
            for line in f:
                dev, mp, fstype = line.split()[:3]
                if dev.startswith('/dev/') and fstype in _REAL_FS and mp not in mounts:
                    mounts.append(mp)
    except Exception:
        pass
    return mounts or ['/']


@app.api_route('/health/resources', methods=['GET', 'HEAD'])
def health_resources():
    """Intraday resource-exhaustion / pre-crash check for external monitors.

    Returns 503 the moment a runaway process pushes the box toward a crash —
    BETWEEN the daily WatchTower reports. Checks EVERY mounted disk (web1 has
    separate / and /var), plus swap saturation, severe memory pressure, and
    root filesystem remounted read-only. If the box is so far gone the endpoint
    can't respond, the monitor sees it down — also an alert. Body is only
    resource metrics (no other data).
    """
    swap_pct, mem_avail_pct = _mem_swap_pct()
    root_ro = _root_readonly()

    reasons = []
    disks = {}
    for mp in _real_mounts():
        d, i = _disk_pct(mp), _inode_pct(mp)
        disks[mp] = {'disk_pct': d, 'inode_pct': i}
        if d >= DISK_CRIT_PCT:
            reasons.append(f'disk {mp} {d}%>={DISK_CRIT_PCT}%')
        if i >= INODE_CRIT_PCT:
            reasons.append(f'inodes {mp} {i}%>={INODE_CRIT_PCT}%')
    if swap_pct >= SWAP_CRIT_PCT:
        reasons.append(f'swap {swap_pct}%>={SWAP_CRIT_PCT}%')
    if mem_avail_pct <= MEM_AVAIL_MIN_PCT:
        reasons.append(f'mem_avail {mem_avail_pct}%<={MEM_AVAIL_MIN_PCT}%')
    if root_ro:
        reasons.append('root filesystem READ-ONLY')

    critical = bool(reasons)
    return JSONResponse(
        status_code=503 if critical else 200,
        content={
            'status': 'critical' if critical else 'ok',
            'reasons': reasons,
            'disks': disks,
            'swap_pct': swap_pct,
            'mem_avail_pct': mem_avail_pct,
            'root_readonly': root_ro,
        },
    )


# --- EveryEarthquake ingest freshness (web2) -------------------------------

EE_MARKER = os.getenv('WATCHTOWER_EE_MARKER', '')
EE_MAX_AGE_MIN = float(os.getenv('WATCHTOWER_EE_MAX_AGE_MIN', '5'))


@app.api_route('/health/ee-ingest', methods=['GET', 'HEAD'])
def health_ee_ingest():
    """EveryEarthquake per-minute ingest freshness for external monitors.

    The minute-fetch systemd unit touches WATCHTOWER_EE_MARKER on each SUCCESSFUL
    run (ExecStartPost only fires on exit 0). This returns 503 when that marker
    is older than WATCHTOWER_EE_MAX_AGE_MIN — i.e. the fetch has been failing
    (USGS down, DB down, or timer stopped) that long. 200 if fresh. Returns
    200 'not-configured' where the marker isn't set (e.g. web1).
    """
    if not EE_MARKER:
        return JSONResponse(status_code=200, content={'status': 'not-configured'})
    try:
        age_min = (time.time() - os.stat(EE_MARKER).st_mtime) / 60.0
    except OSError:
        return JSONResponse(
            status_code=503,
            content={'status': 'critical', 'reason': 'ingest marker missing'})
    stale = age_min > EE_MAX_AGE_MIN
    return JSONResponse(
        status_code=503 if stale else 200,
        content={
            'status': 'critical' if stale else 'ok',
            'last_success_min_ago': round(age_min, 1),
            'max_age_min': EE_MAX_AGE_MIN,
        },
    )
