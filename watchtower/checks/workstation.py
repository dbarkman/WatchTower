"""macOS workstation security posture — read from the intake endpoint's state file.

The laptop holds the SSH key to production, the password manager and the vendor
dashboard session, so its posture is in scope for the same questionnaire as the
servers. It pushes a weekly report to POST /health/workstation; this reads what
landed.

⚠️ Be precise about what this is: **patch and configuration posture
verification**, NOT vulnerability scanning. It asserts that disk encryption,
the firewall and screen lock are on and that updates are not piling up. Calling
it a scan would overstate it.

Freshness is the whole point — "FileVault: on" from three weeks ago is not
evidence of anything, so a stale report is a finding regardless of its contents.
"""
import json
import time

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL

DEFAULT_PATH = "/var/www/html/WatchTower/state/workstation.json"


def run(config: dict) -> list[CheckResult]:
    path = config.get("path", DEFAULT_PATH)
    stale_days = float(config.get("stale_days", 10))

    try:
        with open(path) as f:
            d = json.load(f)
    except FileNotFoundError:
        return [CheckResult("Workstation", WARNING, "no posture report received yet")]
    except Exception as e:
        return [CheckResult("Workstation", WARNING, f"unreadable posture report: {e}")]

    age_d = (time.time() - d.get("received_at", 0)) / 86400.0
    host = d.get("hostname", "?")

    bad = []
    if not d.get("filevault"):
        bad.append("FileVault OFF")
    if not d.get("firewall"):
        bad.append("firewall OFF")
    if not d.get("screen_lock"):
        bad.append("screen lock OFF")

    sec = int(d.get("security_updates_pending", 0))
    pending = int(d.get("updates_pending", 0))
    if sec:
        bad.append(f"{sec} SECURITY update(s) pending")

    summary = (f"{host} {d.get('os_version', '?')} — "
               f"{pending} update(s) pending, reported {age_d:.1f}d ago")

    if bad:
        return [CheckResult("Workstation", CRITICAL, f"{'; '.join(bad)} — {summary}")]
    if age_d > stale_days:
        return [CheckResult("Workstation", WARNING,
                            f"posture report STALE ({age_d:.1f}d > {stale_days:.0f}d) — {summary}")]
    return [CheckResult("Workstation", OK, f"encrypted, firewalled, locking — {summary}")]
