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

## Roadmap: Server Health Checks

Future versions will add local server auditing — a daily summary of how each server is doing. The monitor currently checks *remote reachability*; health checks will cover *local system state*.

### Planned Checks

| Check | What It Does | Priority |
|---|---|---|
| **Disk space** | Alert when any partition exceeds 80%/90% usage | High |
| **Auth logs** | Scan `/var/log/secure` for failed SSH attempts, brute force patterns | High |
| **fail2ban** | Report banned IPs, jail status, recent bans | High |
| **Syslog** | Scan `/var/log/messages` for errors, OOM kills, hardware warnings | Medium |
| **Service status** | Verify configured systemd services are running | Medium |
| **SSL certificates** | Warn when certs are within 14/7 days of expiry | Medium |
| **System updates** | Report available security updates | Medium |
| **Memory/swap** | Alert on high memory usage or swap activity | Low |
| **CPU load** | Alert on sustained high load average | Low |
| **Log rotation** | Verify log files aren't growing unbounded | Low |
| **Open ports** | Compare listening ports against expected list, flag surprises | Low |
| **Zombie processes** | Detect and report zombie/defunct processes | Low |

### Design Goals

- **Daily digest** — one summary per server per day, not a flood of individual alerts
- **Threshold-based** — only alert on things that need attention, not noise
- **Low overhead** — shell commands + Python, no agents or daemons
- **Portable** — works on Rocky/RHEL/Ubuntu/Debian without changes
- **Configurable** — YAML config for what to check and what thresholds to use

### Example Daily Report

```
📊 Server Health — web2 (2026-04-10)

Disk: / 45% | /var 62% — ✅
Auth: 12 failed SSH attempts (3 IPs) — ✅ (below threshold)
fail2ban: 2 IPs banned today, 5 total active bans — ✅
Services: 4/4 running — ✅
SSL: example.com expires in 47 days — ✅
Updates: 3 security updates available — ⚠️

No issues requiring attention.
```

## License

MIT — see [LICENSE](LICENSE) for details.
