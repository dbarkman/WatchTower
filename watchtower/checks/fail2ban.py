"""fail2ban check — report jail status and active bans."""
import subprocess

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def run(config: dict) -> list[CheckResult]:
    try:
        out = subprocess.run(
            ["fail2ban-client", "status"],
            capture_output=True, text=True, timeout=10,
        )
        if out.returncode != 0:
            return [CheckResult("fail2ban", WARNING, "fail2ban-client not available or not running")]
    except FileNotFoundError:
        return [CheckResult("fail2ban", WARNING, "fail2ban not installed")]
    except Exception as e:
        return [CheckResult("fail2ban", WARNING, f"Failed to check fail2ban: {e}")]

    # Parse jail list from status output
    jails = []
    for line in out.stdout.splitlines():
        if "Jail list:" in line:
            jail_str = line.split(":", 1)[-1].strip()
            jails = [j.strip() for j in jail_str.split(",") if j.strip()]
            break

    total_banned = 0
    jail_details = []

    for jail in jails:
        try:
            out = subprocess.run(
                ["fail2ban-client", "status", jail],
                capture_output=True, text=True, timeout=5,
            )
            banned = 0
            for line in out.stdout.splitlines():
                if "Currently banned:" in line:
                    banned = int(line.split(":")[-1].strip())
                    break
            total_banned += banned
            if banned > 0:
                jail_details.append(f"{jail}: {banned}")
        except Exception:
            continue

    summary = f"{len(jails)} jails active, {total_banned} IPs currently banned"
    if jail_details:
        summary += f" ({', '.join(jail_details)})"

    return [CheckResult("fail2ban", OK, summary)]
