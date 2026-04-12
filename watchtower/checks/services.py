"""Service status check — verify systemd services are running, detect failed units."""
import subprocess

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def run(config: dict) -> list[CheckResult]:
    expected = config.get("expected", [])
    results = []

    # Check expected services
    if expected:
        running = []
        down = []
        for svc in expected:
            try:
                out = subprocess.run(
                    ["systemctl", "is-active", f"{svc}.service"],
                    capture_output=True, text=True, timeout=5,
                )
                if out.stdout.strip() == "active":
                    running.append(svc)
                else:
                    down.append(svc)
            except Exception:
                down.append(svc)

        if down:
            status = CRITICAL
            summary = f"{len(running)}/{len(expected)} running — DOWN: {', '.join(down)}"
        else:
            status = OK
            summary = f"{len(running)}/{len(expected)} running"
        results.append(CheckResult("Services", status, summary))

    # Check for any failed units
    try:
        out = subprocess.run(
            ["systemctl", "--failed", "--no-legend", "--plain"],
            capture_output=True, text=True, timeout=5,
        )
        failed = [line.split()[0] for line in out.stdout.strip().splitlines() if line.strip()]
    except Exception:
        failed = []

    if failed:
        results.append(CheckResult(
            "Failed units", WARNING,
            f"{len(failed)} failed: {', '.join(failed)}",
        ))
    elif not expected:
        results.append(CheckResult("Services", OK, "No failed units"))

    return results
