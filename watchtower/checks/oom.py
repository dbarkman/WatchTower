"""OOM killer check — scan syslog for out-of-memory kills in the last 24 hours."""
import subprocess
from datetime import datetime, timedelta

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def run(config: dict) -> list[CheckResult]:
    log_path = config.get("log_path", "/var/log/messages")
    warn_count = config.get("warn_count", 1)
    critical_count = config.get("critical_count", 5)

    try:
        out = subprocess.run(
            ["grep", "-c", "oom-killer", log_path],
            capture_output=True, text=True, timeout=10,
        )
        # grep -c returns the match count; exit code 1 means zero matches
        total = int(out.stdout.strip()) if out.returncode == 0 else 0
    except Exception as e:
        return [CheckResult("OOM", WARNING, f"Failed to scan logs: {e}")]

    # For recent kills, check last 24h using today and yesterday date prefixes
    recent = 0
    now = datetime.now()
    date_prefixes = set()
    for offset in range(2):  # today and yesterday
        d = now - timedelta(days=offset)
        date_prefixes.add(d.strftime("%b %_d").replace("  ", " "))

    try:
        out = subprocess.run(
            ["grep", "Killed process", log_path],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode == 0:
            for line in out.stdout.splitlines():
                for prefix in date_prefixes:
                    if line.startswith(prefix):
                        recent += 1
                        break
    except Exception:
        pass  # fall back to total count

    if recent >= critical_count:
        status = CRITICAL
    elif recent >= warn_count:
        status = WARNING
    else:
        status = OK

    victims = ""
    if recent > 0:
        try:
            out = subprocess.run(
                ["grep", "Killed process", log_path],
                capture_output=True, text=True, timeout=10,
            )
            if out.returncode == 0:
                names = []
                for line in out.stdout.splitlines()[-5:]:
                    start = line.find("(")
                    end = line.find(")", start)
                    if start != -1 and end != -1:
                        names.append(line[start + 1:end])
                if names:
                    victims = f" — victims: {', '.join(names)}"
        except Exception:
            pass

    summary = f"{recent} OOM kills in last 24h" if recent > 0 else "No OOM kills"
    if total > 0 and recent == 0:
        summary += f" ({total} total in log)"

    return [CheckResult("OOM", status, summary + victims)]
