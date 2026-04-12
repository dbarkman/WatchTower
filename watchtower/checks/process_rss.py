"""Process RSS check — monitor memory usage of configured processes."""
import subprocess

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def _find_process_rss(name: str) -> int | None:
    """Find the RSS (in KB) of the largest process matching the name."""
    try:
        out = subprocess.run(
            ["pgrep", "-f", name],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0:
            return None

        pids = out.stdout.strip().splitlines()
        max_rss = 0
        for pid in pids:
            try:
                stat = subprocess.run(
                    ["ps", "-p", pid, "-o", "rss="],
                    capture_output=True, text=True, timeout=5,
                )
                rss = int(stat.stdout.strip())
                max_rss = max(max_rss, rss)
            except (ValueError, Exception):
                continue
        return max_rss if max_rss > 0 else None
    except Exception:
        return None


def run(config: dict) -> list[CheckResult]:
    processes = config.get("processes", [])
    if not processes:
        return []

    results = []
    for proc in processes:
        name = proc["name"]
        warn_mb = proc.get("warn_mb", 500)
        critical_mb = proc.get("critical_mb", 1000)

        rss_kb = _find_process_rss(name)
        if rss_kb is None:
            results.append(CheckResult(
                f"Process: {name}", WARNING, "not running",
            ))
            continue

        rss_mb = rss_kb // 1024

        if rss_mb >= critical_mb:
            status = CRITICAL
        elif rss_mb >= warn_mb:
            status = WARNING
        else:
            status = OK

        results.append(CheckResult(
            f"Process: {name}", status, f"{rss_mb} MB RSS",
        ))

    return results
