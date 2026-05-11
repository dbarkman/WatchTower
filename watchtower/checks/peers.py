"""Cross-server peer reachability check — verify each configured peer's /health endpoint responds."""
import requests

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def run(config: dict) -> list[CheckResult]:
    hosts = config.get("hosts", [])
    timeout = config.get("timeout_seconds", 5)

    if not hosts:
        return []

    up = []
    down = []
    details = []

    for host in hosts:
        name = host.get("name", host.get("url", "?"))
        url = host.get("url")
        if not url:
            down.append(name)
            details.append(f"{name}: no url configured")
            continue
        try:
            resp = requests.get(url, timeout=timeout)
            if resp.status_code == 200:
                up.append(name)
            else:
                down.append(name)
                details.append(f"{name}: HTTP {resp.status_code}")
        except requests.exceptions.Timeout:
            down.append(name)
            details.append(f"{name}: timeout after {timeout}s")
        except requests.exceptions.ConnectionError as e:
            down.append(name)
            details.append(f"{name}: connection refused / unreachable")
        except Exception as e:
            down.append(name)
            details.append(f"{name}: {type(e).__name__}")

    if down:
        summary = f"{len(up)}/{len(hosts)} reachable — DOWN: {', '.join(down)}"
        return [CheckResult("Peers", CRITICAL, summary, " | ".join(details) if details else None)]
    return [CheckResult("Peers", OK, f"{len(up)}/{len(hosts)} reachable")]
