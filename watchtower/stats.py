#!/usr/bin/env python3
"""
Host + daemon vitals for the OCT server-status dashboard.

WatchTower already runs on every box in the fleet, so it is the natural place to
collect this: the alternative was deploying the whole OCT trading platform to web2
(venue API keys and a MariaDB schema, on a box that does not trade) just to read
/proc. This module is the read side of that decision — the dashboard fetches one
of these per host and renders them side by side.

Deliberately unprivileged: everything comes from /proc, statvfs, or
`systemctl show`, all readable by the `apache` service user with no sudo. The one
write is a small state file under `state/` that dates OOM-kill increases (see
`_oom_last_kill_secs`), and nothing reaches another host.

Configuration (all env, matching the rest of WatchTower):
  WATCHTOWER_STATS_NAME   — short host label ("web1"); defaults to the hostname
  WATCHTOWER_STATS_UNITS  — which systemd units to report, comma separated, as
                            `unit=Label`. Prefix a unit with `!` when it is
                            EXPECTED to be stopped (a retired daemon shown as
                            permanently red just trains the eye to ignore red).
                            e.g. "oct@kalshi.service=OCT Kalshi,!old.service=Old"
  WATCHTOWER_STATS_TOKEN  — shared secret. When set, /stats requires it. web2
                            reaches the internet through httpd, so it MUST set
                            one; web1 is loopback-only and need not.
"""
import json
import os
import platform
import re
import socket
import subprocess
from datetime import datetime, timezone

_SYSTEMCTL_PROPS = (
    'ActiveState,SubState,ExecMainPID,ExecMainStartTimestamp,NRestarts,MemoryCurrent'
)

_STATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'state')
_OOM_STATE = os.path.join(_STATE_DIR, 'oom_kills.state')

# How long a dated OOM kill colours the host. An OOM is worth reacting to while
# it is fresh; days later it is forensics, and the count still renders on the
# page regardless. Current memory distress has its own mem/swap thresholds below.
OOM_RED_SECS = 3600
OOM_YELLOW_SECS = 86400


def _read(path: str) -> str:
    try:
        with open(path, 'r', encoding='utf-8', errors='replace') as fh:
            return fh.read()
    except OSError:
        return ''


def _primary_ip() -> str:
    """The host's primary outbound IP.

    Opens a UDP socket toward a public address and reads back the local end. UDP is
    connectionless so NO packet is sent — this only asks the kernel which interface
    would route there. `gethostbyname(gethostname())` returns 127.0.0.1 on a stock
    Rocky box, so it cannot be used for this.
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.settimeout(0.2)
            s.connect(('198.51.100.1', 53))  # TEST-NET-3, never routed
            return str(s.getsockname()[0])
    except OSError:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except OSError:
        return ''


def _meminfo() -> dict:
    """/proc/meminfo as bytes (the file reports kB)."""
    out = {}
    for line in _read('/proc/meminfo').splitlines():
        m = re.match(r'^(\w+):\s+(\d+)', line)
        if m:
            out[m.group(1)] = int(m.group(2)) * 1024
    return out


def _oom_kills() -> int:
    for line in _read('/proc/vmstat').splitlines():
        if line.startswith('oom_kill '):
            try:
                return int(line.split()[1])
            except (IndexError, ValueError):
                return 0
    return 0


def _read_oom_state() -> tuple | None:
    """(count, last_increase_epoch_or_None) from the state file, or None if absent
    or unreadable — the two cases behave identically on purpose."""
    try:
        with open(_OOM_STATE, encoding='utf-8') as fh:
            raw = json.load(fh)
        return int(raw['count']), raw.get('last_increase')
    except (OSError, ValueError, TypeError, KeyError):
        return None


def _write_oom_state(count: int, last_increase) -> bool:
    """Persist the counter; True if it stuck. Best-effort and atomic — /stats can
    be hit concurrently, and a failed write must never break the endpoint."""
    try:
        os.makedirs(_STATE_DIR, exist_ok=True)
        tmp = f'{_OOM_STATE}.tmp'
        with open(tmp, 'w', encoding='utf-8') as fh:
            json.dump({'count': count, 'last_increase': last_increase}, fh)
        os.replace(tmp, _OOM_STATE)
        return True
    except OSError:
        return False


def _oom_last_kill_secs(count: int, now_ts: float) -> int | None:
    """Seconds since the most recent OOM kill, or None when it cannot be dated.

    /proc/vmstat's `oom_kill` is cumulative SINCE BOOT and carries no timestamp,
    so reading it alone cannot distinguish a kill a minute ago from one three
    weeks ago — which is why a single kill used to pin a host red until the next
    reboot. Persisting the counter makes an INCREASE datable: the first reading
    only establishes a baseline (kills already counted stay undated, because we
    genuinely do not know when they happened) and every rise after that is
    stamped now.

    A counter that went DOWN means the box rebooted and vmstat reset, so whatever
    it now reports happened after that boot and is dated now.

    Returns None when the kills are undatable OR the state cannot be read or
    written — and an undated count deliberately does NOT colour the verdict. The
    number still renders on the page, live memory distress has its own
    thresholds, and the daily report alerts on OOM over a real 24h window. A
    monitor that cannot remember must not nag forever; that is the bug this
    replaces, so every degraded path here fails toward silence.
    """
    prev = _read_oom_state()
    if prev is None:
        _write_oom_state(count, None)
        return None

    prev_count, last_increase = prev
    if count != prev_count:
        # Rose (new kills) or fell (reboot reset vmstat); either way whatever it
        # now reports is fresh. A counter that fell to zero dates nothing.
        last_increase = now_ts if count > 0 else None
        if not _write_oom_state(count, last_increase):
            # Unpersisted, so the next poll would see the same rise and re-stamp
            # it as "just now" forever — a permanent red, the very failure this
            # function exists to remove. Report undatable instead.
            return None

    if last_increase is None:
        return None
    return max(0, int(now_ts - float(last_increase)))


def _proc_rss(pid: int) -> int | None:
    for line in _read(f'/proc/{pid}/status').splitlines():
        if line.startswith('VmRSS:'):
            try:
                return int(line.split()[1]) * 1024
            except (IndexError, ValueError):
                return None
    return None


def _systemctl_show(unit: str) -> dict:
    try:
        proc = subprocess.run(
            ['systemctl', 'show', unit, '-p', _SYSTEMCTL_PROPS],
            capture_output=True, text=True, timeout=5, check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    props = {}
    for line in proc.stdout.splitlines():
        if '=' in line:
            k, _, v = line.partition('=')
            props[k] = v
    return props


def _parse_systemd_ts(value: str):
    """systemd prints e.g. 'Thu 2026-07-30 21:05:51 UTC'."""
    if not value or value in ('n/a', '0'):
        return None
    m = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', value)
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1), '%Y-%m-%d %H:%M:%S').replace(
            tzinfo=timezone.utc)
    except ValueError:
        return None


def parse_units(spec: str) -> list:
    """Parse WATCHTOWER_STATS_UNITS into (unit, label, expect_active) triples."""
    out = []
    for chunk in spec.split(','):
        chunk = chunk.strip()
        if not chunk:
            continue
        expect_active = True
        if chunk.startswith('!'):
            expect_active = False
            chunk = chunk[1:]
        unit, _, label = chunk.partition('=')
        unit = unit.strip()
        if not unit:
            continue
        if '.' not in unit:
            unit = f'{unit}.service'
        out.append((unit, (label.strip() or unit), expect_active))
    return out


def _service(unit: str, label: str, expect_active: bool, now: datetime) -> dict:
    props = _systemctl_show(unit)
    state = props.get('ActiveState', 'unknown')
    try:
        restarts = int(props.get('NRestarts', '0') or 0)
    except ValueError:
        restarts = 0

    pid_raw = props.get('ExecMainPID', '0')
    pid = int(pid_raw) if pid_raw.isdigit() and int(pid_raw) > 0 else None

    since = uptime = None
    started = _parse_systemd_ts(props.get('ExecMainStartTimestamp', ''))
    if started and state == 'active':
        since = started.isoformat()
        uptime = max(0, int((now - started).total_seconds()))

    # RSS and cgroup are DIFFERENT numbers and conflating them misleads. RSS is the
    # main process's resident memory — what you watch for a leak. cgroup
    # memory.current also counts forked children and page cache, which is why
    # MariaDB reads ~4.4GB against a 1GB buffer pool. Report both.
    rss = _proc_rss(pid) if pid else None
    mem = props.get('MemoryCurrent', '')
    cgroup = int(mem) if mem.isdigit() and int(mem) > 0 else None

    active = state == 'active'
    return {
        'unit': unit,
        'label': label,
        'expect_active': expect_active,
        'state': state,
        'sub': props.get('SubState', ''),
        'pid': pid,
        'since': since,
        'uptime_seconds': uptime,
        'restarts': restarts,
        'rss_bytes': rss,
        'cgroup_bytes': cgroup,
        'healthy': active if expect_active else not active,
    }


def collect_stats(mounts, disk_pct, inode_pct) -> dict:
    """Full host vitals. Mount helpers are injected so this reuses health.py's
    existing, already-deployed disk logic rather than forking a second copy."""
    now = datetime.now(timezone.utc)
    mi = _meminfo()

    cores = os.cpu_count() or 1
    load1 = load5 = load15 = 0.0
    parts = _read('/proc/loadavg').split()
    if len(parts) >= 3:
        try:
            load1, load5, load15 = (float(parts[i]) for i in range(3))
        except ValueError:
            pass

    uptime_seconds = 0
    up = _read('/proc/uptime').split()
    if up:
        try:
            uptime_seconds = int(float(up[0]))
        except ValueError:
            pass

    mem_total = mi.get('MemTotal', 0)
    mem_avail = mi.get('MemAvailable', 0)
    swap_total = mi.get('SwapTotal', 0)
    swap_used = swap_total - mi.get('SwapFree', 0) if swap_total else 0

    filesystems = []
    for mp in mounts():
        try:
            s = os.statvfs(mp)
        except OSError:
            continue
        total = s.f_frsize * s.f_blocks
        if total <= 0:
            continue
        filesystems.append({
            'mount': mp,
            'total_bytes': total,
            'used_bytes': total - (s.f_frsize * s.f_bfree),
            'used_pct': disk_pct(mp),
            'inode_pct': inode_pct(mp),
        })

    units = parse_units(os.getenv('WATCHTOWER_STATS_UNITS', ''))
    services = [_service(u, lbl, exp, now) for u, lbl, exp in units]

    oom_kills = _oom_kills()
    oom_last_kill_secs = _oom_last_kill_secs(oom_kills, now.timestamp())

    host = {
        'name': os.getenv('WATCHTOWER_STATS_NAME', '') or socket.gethostname().split('.')[0],
        'hostname': socket.gethostname(),
        'ip': _primary_ip(),
        'reachable': True,
        'error': None,
        'kernel': platform.release(),
        'uptime_seconds': uptime_seconds,
        'cores': cores,
        'load1': load1,
        'load5': load5,
        'load15': load15,
        # Load alone says little — 1.0 is idle on 4 cores and pegged on 1.
        'load_pct': round(100.0 * load1 / cores, 1) if cores else 0.0,
        'mem_total_bytes': mem_total,
        'mem_available_bytes': mem_avail,
        'mem_used_pct': round(100.0 * (mem_total - mem_avail) / mem_total, 1) if mem_total else 0.0,
        'swap_total_bytes': swap_total,
        'swap_used_bytes': swap_used,
        'swap_used_pct': round(100.0 * swap_used / swap_total, 1) if swap_total else 0.0,
        'oom_kills': oom_kills,
        # None when the kills predate our first reading (undatable) — see
        # _oom_last_kill_secs. Only a DATED kill colours the verdict.
        'oom_last_kill_secs': oom_last_kill_secs,
        'filesystems': filesystems,
        'services': services,
        'collected_at': now.isoformat(),
    }
    host['verdict'] = verdict(host)
    return host


def verdict(h: dict) -> str:
    """Worst-of across the signals that would actually make someone act."""
    fs = h.get('filesystems', [])
    services = h.get('services', [])
    # An OOM kill only counts while it is DATED and recent. The raw count is
    # cumulative since boot, so keying off it directly pinned a host red for
    # weeks over a single kill.
    oom_age = h.get('oom_last_kill_secs')
    if (
        any(not s['healthy'] for s in services)
        or any((f.get('used_pct') or 0) >= 90 or (f.get('inode_pct') or 0) >= 90 for f in fs)
        or h.get('mem_used_pct', 0) >= 95
        or (oom_age is not None and oom_age <= OOM_RED_SECS)
    ):
        return 'red'
    if (
        any((f.get('used_pct') or 0) >= 80 or (f.get('inode_pct') or 0) >= 80 for f in fs)
        or h.get('mem_used_pct', 0) >= 85
        or h.get('swap_used_pct', 0) >= 50
        or h.get('load_pct', 0) >= 100
        or any(s['restarts'] > 0 for s in services)
        or (oom_age is not None and oom_age <= OOM_YELLOW_SECS)
    ):
        return 'yellow'
    return 'green'
