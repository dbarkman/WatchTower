"""Dependency vulnerabilities — reads the weekly dep_audit_scan results.

The scan itself runs weekly (see watchtower/dep_audit_scan.py); this check only
reads its JSON output, so the daily report never blocks on network calls to the
advisory databases.

Fixable and unfixable findings are counted separately on purpose: a finding with
a fix version is ten minutes of work, one without needs a decision about whether
to accept, pin or replace. Reporting them as one number buries the decision.

Scan freshness is covered by the job_stamps check; the age here is informational
so the reader knows how old the numbers are.
"""
import json
import time

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL

DEFAULT_PATH = "/var/www/html/WatchTower/state/dep_audit.json"


def run(config: dict) -> list[CheckResult]:
    path = config.get("path", DEFAULT_PATH)
    stale_days = float(config.get("stale_days", 10))

    try:
        with open(path) as f:
            data = json.load(f)
    except FileNotFoundError:
        return [CheckResult("Dependency vulns", WARNING, "no scan has run yet")]
    except Exception as e:
        return [CheckResult("Dependency vulns", WARNING, f"unreadable scan output: {e}")]

    projects = data.get("projects", [])
    age_d = (time.time() - data.get("generated", 0)) / 86400.0
    errored = [p["name"] for p in projects if "error" in p]
    scanned = [p for p in projects if "error" not in p]

    total = sum(p.get("total", 0) for p in scanned)
    fixable = sum(p.get("fixable", 0) for p in scanned)
    unfixable = total - fixable

    bits = [f"{len(scanned)} projects"]
    if age_d > stale_days:
        bits.append(f"scan {age_d:.0f}d old")

    if errored:
        bits.append(f"FAILED TO SCAN: {', '.join(errored)}")

    if total == 0:
        status = WARNING if (errored or age_d > stale_days) else OK
        return [CheckResult("Dependency vulns", status,
                            f"0 known vulnerabilities ({', '.join(bits)})")]

    worst = [f"{p['name']}:{p['total']}" for p in
             sorted(scanned, key=lambda p: -p.get("total", 0)) if p.get("total")][:5]
    detail = (f"{total} vuln(s) — {fixable} fixable, {unfixable} no fix available "
              f"[{', '.join(worst)}] ({', '.join(bits)})")
    # Unfixable findings need a decision, not a patch — surface them harder.
    return [CheckResult("Dependency vulns",
                        CRITICAL if unfixable else WARNING, detail)]
