"""Needs-restart check — services running code that has since been patched.

Security updates install daily via dnf-automatic (`upgrade_type = security`,
`apply_updates = yes`, `reboot = never`). Installing replaces the file on disk,
but a process that already mapped the old shared library keeps running the old
code until it restarts. So a box can be fully patched and still be running
unpatched code — for up to a month, until the scheduled reboot.

This check surfaces that gap: `dnf needs-restarting -s` lists the units whose
running processes reference replaced files.

**The kernel signal is deliberately ignored.** `dnf needs-restarting -r` reports
"reboot required — kernel" permanently on this fleet, because the servers boot
the LINODE kernel while dnf installs distro kernels that never become active. No
number of reboots clears it, so alerting on it would produce a permanently-red
signal that trains you to ignore the check. Only the service list (-s) is honest.

Severity is tied to the uptime bands so the report doesn't sit yellow for weeks:
stale services are EXPECTED shortly after any patch and are cleared by the
monthly reboot, so they only warrant a warning once that reboot is actually due.
"""
import subprocess

from watchtower.checks import CheckResult, OK, WARNING

# Units that are noise: restarted by their own timers/cron, or infrastructure
# whose staleness is cleared by the same reboot that clears everything else.
DEFAULT_IGNORE = {"tuned.service", "irqbalance.service", "polkit.service"}


def _uptime_days() -> float | None:
    try:
        with open("/proc/uptime") as f:
            return float(f.read().split()[0]) / 86400
    except (OSError, ValueError):
        return None


def _stale_services(timeout: int) -> list[str] | None:
    """Units running replaced code, or None if dnf can't answer."""
    try:
        out = subprocess.run(
            ["dnf", "needs-restarting", "-s"],
            capture_output=True, text=True, timeout=timeout,
        )
    except Exception:
        return None
    if out.returncode not in (0, 1):
        return None
    return sorted(
        line.strip() for line in out.stdout.splitlines()
        if line.strip().endswith(".service")
    )


def run(config: dict) -> list[CheckResult]:
    warn_days = config.get("warn_days", 25)
    timeout = config.get("timeout_secs", 60)
    ignore = set(config.get("ignore", [])) | DEFAULT_IGNORE

    services = _stale_services(timeout)
    if services is None:
        # Never fail the report over this — it is advisory, not a liveness signal.
        return [CheckResult("Needs restart", OK, "unavailable (dnf did not answer)")]

    stale = [s for s in services if s not in ignore]
    if not stale:
        return [CheckResult("Needs restart", OK, "all services running current code")]

    shown = ", ".join(s.removesuffix(".service") for s in stale[:6])
    if len(stale) > 6:
        shown += f", +{len(stale) - 6} more"

    days = _uptime_days()
    if days is not None and days >= warn_days:
        return [CheckResult(
            "Needs restart", WARNING,
            f"{len(stale)} service(s) on patched-but-unloaded libs, uptime {days:.1f}d "
            f"— reboot due: {shown}")]

    return [CheckResult(
        "Needs restart", OK,
        f"{len(stale)} service(s) on patched-but-unloaded libs "
        f"(cleared at next reboot): {shown}")]
