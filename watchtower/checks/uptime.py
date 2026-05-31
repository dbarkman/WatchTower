"""Uptime check — warn when server is overdue for a reboot."""
from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def run(config: dict) -> list[CheckResult]:
    warn_days = config.get("warn_days", 25)
    critical_days = config.get("critical_days", 30)

    try:
        with open("/proc/uptime") as f:
            seconds = float(f.read().split()[0])
    except (OSError, ValueError) as e:
        return [CheckResult("Uptime", WARNING, f"could not read /proc/uptime: {e}")]

    days = seconds / 86400

    if days >= critical_days:
        status = CRITICAL
        msg = f"{days:.1f}d — reboot now (>= {critical_days}d)"
    elif days >= warn_days:
        status = WARNING
        msg = f"{days:.1f}d — reboot soon (>= {warn_days}d)"
    else:
        status = OK
        msg = f"{days:.1f}d"

    return [CheckResult("Uptime", status, msg)]
