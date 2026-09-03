"""End-of-life tracking for the platform components.

Silent unless something is inside the warning window, because an EOL date that
is three years out is not information — it is noise that trains you to skip the
line. The value is entirely in the one month it starts speaking up.

This is the check most likely to rot, since nothing breaks when the table goes
stale. Two guards against that:
  * `version` is recorded alongside each date, so a reader can see at a glance
    whether the table still describes the running system;
  * `reviewed` is a date, and the check warns when the table has not been
    reviewed in review_months — a stale TABLE is itself a finding.

Distro-packaged runtimes track the DISTRO's support date, not upstream's.
System Python 3.9 is upstream-EOL but Rocky backports fixes to it until the
Rocky 9 date; using the upstream date would raise a false alarm every day.
"""
from datetime import date, datetime

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def _parse(s: str) -> date | None:
    try:
        return datetime.strptime(str(s), "%Y-%m-%d").date()
    except (ValueError, TypeError):
        return None


def _months_until(d: date, today: date) -> float:
    return (d - today).days / 30.44


def run(config: dict) -> list[CheckResult]:
    components = config.get("components", [])
    if not components:
        return []
    warn_m = float(config.get("warn_months", 6))
    review_m = float(config.get("review_months", 12))
    today = date.today()

    approaching, expired, bad = [], [], []
    for c in components:
        eol = _parse(c.get("eol"))
        if eol is None:
            bad.append(c.get("name", "?"))
            continue
        months = _months_until(eol, today)
        label = f"{c.get('name')} {c.get('version', '')}".strip()
        if months <= 0:
            expired.append(f"{label} EOL {c['eol']}")
        elif months <= warn_m:
            approaching.append(f"{label} EOL {c['eol']} ({months:.1f}mo)")

    notes = []
    status = OK

    if expired:
        status = CRITICAL
        notes.append(f"PAST EOL: {'; '.join(expired)}")
    if approaching:
        status = CRITICAL if status == CRITICAL else WARNING
        notes.append(f"within {warn_m:.0f}mo: {'; '.join(approaching)}")
    if bad:
        status = CRITICAL if status == CRITICAL else WARNING
        notes.append(f"unparseable eol date: {', '.join(bad)}")

    reviewed = _parse(config.get("reviewed"))
    if reviewed is None:
        notes.append("table has no `reviewed` date")
        status = CRITICAL if status == CRITICAL else WARNING
    elif -_months_until(reviewed, today) > review_m:
        notes.append(f"table not reviewed in {-_months_until(reviewed, today):.0f}mo "
                     f"— versions may no longer match reality")
        status = CRITICAL if status == CRITICAL else WARNING

    if status == OK:
        return [CheckResult("EOL", OK,
                            f"{len(components)} components, none within {warn_m:.0f}mo")]
    return [CheckResult("EOL", status, " | ".join(notes))]
