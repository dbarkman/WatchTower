"""Disk space check — alert when partitions exceed usage thresholds."""
import shutil

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def run(config: dict) -> list[CheckResult]:
    warn_pct = config.get("warn_pct", 80)
    critical_pct = config.get("critical_pct", 90)
    partitions = config.get("partitions", ["/"])

    results = []
    parts = []

    for mount in partitions:
        try:
            usage = shutil.disk_usage(mount)
            pct = round(usage.used / usage.total * 100)
        except OSError as e:
            results.append(CheckResult("Disk", CRITICAL, f"{mount}: error — {e}"))
            continue

        if pct >= critical_pct:
            status = CRITICAL
        elif pct >= warn_pct:
            status = WARNING
        else:
            status = OK
        parts.append((mount, pct, status))

    if not parts and not results:
        return [CheckResult("Disk", OK, "No partitions configured")]

    worst = max((p[2] for p in parts), key=[OK, WARNING, CRITICAL].index, default=OK)
    summary = " | ".join(f"{m} {p}%" for m, p, _ in parts)

    # Promote to worst status from any individual error results
    for r in results:
        if [OK, WARNING, CRITICAL].index(r.status) > [OK, WARNING, CRITICAL].index(worst):
            worst = r.status

    results.append(CheckResult("Disk", worst, summary))
    return results
