"""Auth log check — scan for failed SSH attempts in the last 24 hours."""
import subprocess
from datetime import datetime, timedelta

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def run(config: dict) -> list[CheckResult]:
    log_path = config.get("log_path", "/var/log/secure")
    warn_threshold = config.get("warn_threshold", 50)
    critical_threshold = config.get("critical_threshold", 200)

    now = datetime.now()
    date_prefixes = set()
    for offset in range(2):
        d = now - timedelta(days=offset)
        date_prefixes.add(d.strftime("%b %_d").replace("  ", " "))

    try:
        out = subprocess.run(
            ["grep", "Failed password", log_path],
            capture_output=True, text=True, timeout=10,
        )
    except Exception as e:
        return [CheckResult("Auth", WARNING, f"Failed to scan auth log: {e}")]

    recent_count = 0
    ips = set()
    if out.returncode == 0:
        for line in out.stdout.splitlines():
            for prefix in date_prefixes:
                if line.startswith(prefix):
                    recent_count += 1
                    # Extract IP from "from <ip> port"
                    parts = line.split(" from ")
                    if len(parts) > 1:
                        ip = parts[-1].split()[0]
                        ips.add(ip)
                    break

    if recent_count >= critical_threshold:
        status = CRITICAL
    elif recent_count >= warn_threshold:
        status = WARNING
    else:
        status = OK

    ip_note = f" ({len(ips)} IPs)" if ips else ""
    summary = f"{recent_count} failed SSH attempts{ip_note}"

    return [CheckResult("Auth", status, summary)]
