"""Job success stamps — did the scheduled work actually succeed recently?

A cron nobody checks the SUCCESS of fails silently for weeks. On web1 the
oct-kalshi-balance job failed 3,815 times over 40 days with no symptom, because
nothing ever asked whether it had run. `systemctl is-active` and "the timer is
enabled" both answer a different question.

The contract: every scheduled job touches a stamp file ON SUCCESS ONLY (see
scripts/wt-stamp). This check reads the mtimes and reports anything stale or
missing. It is deliberately generic — adding a new job is a config entry, not
code.

Severity:
  missing        -> CRITICAL (it has never succeeded, or someone deleted it)
  > max_age      -> WARNING  (a run was skipped or is failing)
  > 2x max_age   -> CRITICAL (sustained failure, not a blip)
"""
import os
import time

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def _age_hours(path: str) -> float | None:
    try:
        return (time.time() - os.stat(path).st_mtime) / 3600.0
    except OSError:
        return None


def _fmt(hours: float) -> str:
    if hours < 1:
        return f"{hours * 60:.0f}m"
    if hours < 48:
        return f"{hours:.1f}h"
    return f"{hours / 24:.1f}d"


def run(config: dict) -> list[CheckResult]:
    jobs = config.get("jobs", [])
    if not jobs:
        return []

    stale, missing, fresh = [], [], 0
    worst = OK

    for job in jobs:
        name = job["name"]
        max_age = float(job.get("max_age_hours", 24))
        age = _age_hours(job["path"])

        if age is None:
            missing.append(name)
            worst = CRITICAL
        elif age > max_age * 2:
            stale.append(f"{name} {_fmt(age)} (>{_fmt(max_age * 2)})")
            worst = CRITICAL
        elif age > max_age:
            stale.append(f"{name} {_fmt(age)} (>{_fmt(max_age)})")
            if worst != CRITICAL:
                worst = WARNING
        else:
            fresh += 1

    if worst == OK:
        return [CheckResult("Job stamps", OK, f"{fresh}/{len(jobs)} jobs fresh")]

    parts = []
    if missing:
        parts.append(f"NEVER SUCCEEDED: {', '.join(missing)}")
    if stale:
        parts.append(f"stale: {'; '.join(stale)}")
    return [CheckResult("Job stamps", worst,
                        f"{fresh}/{len(jobs)} fresh — " + " | ".join(parts))]
