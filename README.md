# WatchTower

Lightweight server health monitoring. Check remote endpoints, expose local health, get alerts when things go down.

## What It Does

- **Remote monitoring** — hit health endpoints on your servers, alert after consecutive failures
- **Health endpoint** — expose a `/health` route on any server for others to check
- **Alerts** — Discord webhooks and [ntfy](https://ntfy.sh) push notifications
- **Zero infrastructure** — no database, no message queue, just cron + flat files

## Quick Start

```bash
# Clone and install
git clone https://github.com/dbarkman/WatchTower.git
cd WatchTower
uv sync

# Configure
cp .env.example .env
cp config/targets.yaml.example config/targets.yaml
# Edit both files for your setup

# Run once (single target)
uv run python -m watchtower.monitor --url https://example.com/health --name "My Server" --ntfy-topic MY-Up

# Run once (all targets from config)
uv run python -m watchtower.monitor --config config/targets.yaml

# Set up cron for continuous monitoring (every minute)
# * * * * * cd /path/to/WatchTower && /path/to/uv run python -m watchtower.monitor --config config/targets.yaml >> logs/monitor.log 2>&1
```

## Health Endpoint

Expose a health check on any server so other WatchTower instances can monitor it:

```bash
uv run uvicorn watchtower.health:app --host 127.0.0.1 --port 8100
```

Configure what it checks via environment variables:

| Variable | Description | Default |
|---|---|---|
| `WATCHTOWER_PROCESS_NAME` | Process name to check via `pgrep` | *(none — skip check)* |
| `WATCHTOWER_LOG_PATH` | Log file to check freshness | *(none — skip check)* |
| `WATCHTOWER_STALE_SECONDS` | Max log age before "stale" | `300` |

With no process or log configured, `/health` returns `{"status": "healthy"}` as a basic liveness check.

### Endpoints

- `GET /health` — full health status with process and log checks
- `GET /health/daemon` — same data, `age_seconds` field for heartbeat-style monitors

### systemd Service

```ini
[Unit]
Description=WatchTower Health Endpoint
After=network.target

[Service]
Type=simple
User=david
WorkingDirectory=/path/to/WatchTower
ExecStart=/path/to/uv run uvicorn watchtower.health:app --host 127.0.0.1 --port 8100
Restart=always
RestartSec=5
Environment=WATCHTOWER_PROCESS_NAME=my_daemon.py
Environment=WATCHTOWER_LOG_PATH=/path/to/logs/my_daemon.log

[Install]
WantedBy=multi-user.target
```

Pair with an Apache/Nginx reverse proxy to expose on port 443:

```apache
<Location /health>
    ProxyPass http://localhost:8100/health
    ProxyPassReverse http://localhost:8100/health
    Require all granted
</Location>
```

## Configuration

### targets.yaml

```yaml
targets:
  - name: "Web Server"
    url: "https://example.com/health"
    ntfy_topic: "WEB1-Up"
    failure_threshold: 2    # consecutive failures before alerting (default: 2)
    timeout: 10             # request timeout in seconds (default: 10)

  - name: "API Server"
    url: "https://api.example.com/health/daemon"
    ntfy_topic: "API1-Up"
```

### .env

```bash
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
NTFY_URL=https://ntfy.sh
```

## Alert Behavior

- Alerts fire after `failure_threshold` consecutive failures (default: 2)
- Recovery alerts fire when a previously-down target comes back
- Both Discord and ntfy are optional — leave unconfigured to skip
- All alerts are fire-and-forget — a notification failure never crashes the monitor

## Architecture

```
WatchTower/
├── watchtower/
│   ├── monitor.py     # Remote health checker (cron-driven)
│   ├── health.py      # Local health endpoint (FastAPI)
│   └── alerts.py      # Discord + ntfy dispatchers
├── config/
│   └── targets.yaml   # What to monitor
├── state/             # Consecutive failure counters (auto-created)
├── logs/              # Cron output (auto-created)
└── .env               # Webhook URLs, ntfy config
```

## Server Health Checks

Daily local auditing — a summary of how each server is doing. The monitor checks *remote reachability*; health checks cover *local system state*.

```bash
# Configure checks for this server
cp config/checks.yaml.example config/checks.yaml
# Edit thresholds, expected services, process names, etc.

# Run once
uv run python -m watchtower.report --config config/checks.yaml

# Set up cron for daily reports (e.g., 7am)
# 0 7 * * * cd /path/to/WatchTower && /path/to/uv run python -m watchtower.report --config config/checks.yaml >> logs/report.log 2>&1
```

### Available Checks

| Check | What It Does | Severity |
|---|---|---|
| **Disk space** | Alert when partitions exceed 80%/90% usage | High |
| **Memory/swap** | Alert on high swap usage (50%/80%) | High |
| **OOM kills** | Scan syslog for out-of-memory kills in last 24h | High |
| **Service status** | Verify configured systemd services are running, detect failed units | High |
| **Auth logs** | Scan `/var/log/secure` for failed SSH attempts | High |
| **fail2ban** | Report jail status and active bans | High |
| **SSL certificates** | Warn when certs approach expiry (14/7 days). Auto-discovers from `/etc/letsencrypt/live/` | Medium |
| **Process RSS** | Track memory of specific processes, catch leaks before they cause OOM | High |

### Digest Format

Reports are sorted by severity (critical first) and sent to Discord. Push alerts via ntfy only fire when issues are found (configurable).

```
Server Health — web1 (2026-04-11)

🔴 OOM: 3 OOM kills in last 24h — victims: python3, python3
🔴 Services: 3/4 running — DOWN: scrollforge

⚠️  Memory: RAM 430/3800 MB available | Swap 59% (298/512 MB)
⚠️  Failed units: 2 failed: exits-check.service, morning-filter.service

✅ Disk: / 27%
✅ Auth: 8 failed SSH attempts (3 IPs)
✅ fail2ban: 3 jails active, 1 IPs currently banned
✅ SSL: dbarkman.com expires in 40d | redmesastudios.com expires in 33d
✅ Process: one_cent_trader_ws.py: 262 MB RSS

2 critical, 2 warnings, 5 OK
```

### checks.yaml

```yaml
server_name: web1
ntfy_topic: "WT-Health"

checks:
  disk:
    partitions: ["/"]
    warn_pct: 80
    critical_pct: 90

  memory:
    swap_warn_pct: 50
    swap_critical_pct: 80

  oom:
    log_path: /var/log/messages
    warn_count: 1
    critical_count: 5

  services:
    expected:
      - httpd
      - mariadb
      - one_cent_trader_ws
      - watchtower-health

  auth:
    log_path: /var/log/secure
    warn_threshold: 50
    critical_threshold: 200

  fail2ban: {}

  ssl:
    warn_days: 14
    critical_days: 7

  process_rss:
    processes:
      - name: one_cent_trader_ws.py
        warn_mb: 500
        critical_mb: 1000
```

See `config/checks.yaml.example` for the full template with all options documented.

### Roadmap

| Check | What It Does | Status |
|---|---|---|
| System updates | Report available security updates | Planned |
| CPU load | Alert on sustained high load average | Planned |
| Log rotation | Verify log files aren't growing unbounded | Planned |
| Open ports | Compare listening ports against expected list | Planned |

## License

MIT — see [LICENSE](LICENSE) for details.
