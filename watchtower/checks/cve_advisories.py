"""CVE-mapped security advisories for host packages — the actual vulnerability scan.

`dnf updateinfo` maps pending updates to published advisories (RLSA/RHSA ids) and
their severity. The data is already on the box; nothing surfaced it.

Zero is the normal case: dnf-automatic installs security updates nightly. So a
non-zero count is not itself interesting — advisories published since the last
run will be picked up within 24h. **What matters is an advisory that PERSISTS**,
because that means patching is not resolving it: the package is excluded, the
update is broken, or the fix needs a restart the automation will not do.

Hence first-seen tracking in a state file. An advisory younger than
persist_hours is reported informationally; one older than that is a finding.

Reads only — `dnf updateinfo` needs no root.
"""
import json
import os
import subprocess
import time

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL

DEFAULT_STATE = "/var/www/html/WatchTower/state/cve_advisories.json"
SEVERE = ("critical", "important")


def _scan(timeout: int) -> list[dict] | None:
    """[{id, severity, package}] or None if dnf could not answer."""
    try:
        out = subprocess.run(
            ["dnf", "updateinfo", "list", "--security", "--available", "-q"],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return None
    if out.returncode != 0:
        return None

    found = []
    for line in out.stdout.splitlines():
        parts = line.split()
        # RLSA-2026:61355 Moderate/Sec. dbus-broker-28-9.el9_8.x86_64
        if len(parts) >= 3 and "/Sec." in parts[1]:
            found.append({
                "id": parts[0],
                "severity": parts[1].split("/")[0].lower(),
                "package": parts[2],
            })
    return found


def _load(path: str) -> dict:
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(path: str, data: dict):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


def run(config: dict) -> list[CheckResult]:
    persist_h = float(config.get("persist_hours", 48))
    state_path = config.get("state_path", DEFAULT_STATE)
    timeout = int(config.get("timeout_secs", 120))

    found = _scan(timeout)
    if found is None:
        return [CheckResult("CVE advisories", WARNING, "dnf updateinfo did not answer")]

    now = time.time()
    prev = _load(state_path)
    # first-seen is keyed on advisory+package so a re-issued advisory restarts its clock
    state = {}
    for a in found:
        key = f"{a['id']}|{a['package']}"
        state[key] = prev.get(key, now)
    _save(state_path, state)

    if not found:
        return [CheckResult("CVE advisories", OK, "0 pending security advisories")]

    by_sev = {}
    persistent = []
    for a in found:
        by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
        age_h = (now - state[f"{a['id']}|{a['package']}"]) / 3600.0
        if age_h > persist_h:
            persistent.append((a, age_h))

    counts = ", ".join(f"{n} {s}" for s, n in
                       sorted(by_sev.items(), key=lambda kv: -kv[1]))

    if not persistent:
        return [CheckResult("CVE advisories", OK,
                            f"{len(found)} pending ({counts}) — within patch window")]

    worst = CRITICAL if any(a["severity"] in SEVERE for a, _ in persistent) else WARNING
    shown = "; ".join(f"{a['id']} {a['severity']} {a['package'].split('-')[0]} "
                      f"({age / 24:.0f}d)" for a, age in persistent[:4])
    if len(persistent) > 4:
        shown += f", +{len(persistent) - 4} more"
    return [CheckResult("CVE advisories", worst,
                        f"{len(persistent)} of {len(found)} UNPATCHED >{persist_h:.0f}h "
                        f"({counts}): {shown}")]
