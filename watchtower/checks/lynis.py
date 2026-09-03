"""Configuration hardening audit — reads the weekly lynis report.

⚠️ lynis is a CONFIGURATION AUDITOR, NOT a vulnerability scanner. It will never
say "CVE-2026-1234 affects this package" — that is cve_advisories' job. Keep the
distinction in any external description of the program: conflating the two
overstates what is actually in place.

Alerts on CHANGE, not on state. The hardening index will never reach 100 and
chasing the absolute number is noise; an index that DROPPED, or a warning that
is new, means something about the system's configuration changed — which is the
actual signal. Previous values live in a state file.

The scan is run by a weekly cron (nice'd, off-peak — it is CPU-bound and web2 is
single-core); this check only parses the report it leaves behind.
"""
import json
import os

from watchtower.checks import CheckResult, OK, WARNING

DEFAULT_REPORT = "/var/log/lynis-report.dat"
DEFAULT_STATE = "/var/www/html/WatchTower/state/lynis.json"


def _parse(path: str) -> dict | None:
    try:
        index, warnings, suggestions = None, 0, 0
        with open(path, errors="replace") as f:
            for line in f:
                if line.startswith("hardening_index="):
                    try:
                        index = int(line.split("=", 1)[1].strip())
                    except ValueError:
                        pass
                elif line.startswith("warning[]="):
                    warnings += 1
                elif line.startswith("suggestion[]="):
                    suggestions += 1
        if index is None:
            return None
        return {"index": index, "warnings": warnings, "suggestions": suggestions}
    except OSError:
        return None


def run(config: dict) -> list[CheckResult]:
    report = config.get("report_path", DEFAULT_REPORT)
    state_path = config.get("state_path", DEFAULT_STATE)

    cur = _parse(report)
    if cur is None:
        return [CheckResult("Hardening (lynis)", WARNING,
                            "no readable lynis report yet")]

    try:
        with open(state_path) as f:
            prev = json.load(f)
    except Exception:
        prev = {}

    try:
        os.makedirs(os.path.dirname(state_path), exist_ok=True)
        with open(state_path, "w") as f:
            json.dump(cur, f)
    except OSError:
        pass

    summary = (f"index {cur['index']}/100, {cur['warnings']} warnings, "
               f"{cur['suggestions']} suggestions")

    if not prev:
        return [CheckResult("Hardening (lynis)", OK, f"{summary} (first run — baseline)")]

    deltas = []
    if cur["index"] < prev.get("index", cur["index"]):
        deltas.append(f"index DROPPED {prev['index']} -> {cur['index']}")
    if cur["warnings"] > prev.get("warnings", cur["warnings"]):
        deltas.append(f"warnings {prev['warnings']} -> {cur['warnings']}")

    if deltas:
        return [CheckResult("Hardening (lynis)", WARNING,
                            f"{' | '.join(deltas)} ({summary})")]

    improved = ""
    if cur["index"] > prev.get("index", cur["index"]):
        improved = f" (improved from {prev['index']})"
    return [CheckResult("Hardening (lynis)", OK, summary + improved)]
