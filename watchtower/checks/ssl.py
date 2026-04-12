"""SSL certificate check — warn when certs approach expiry."""
import subprocess
from datetime import datetime, timezone

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL


def _cert_expiry(cert_path: str) -> datetime | None:
    """Get expiry date from a PEM certificate file."""
    try:
        out = subprocess.run(
            ["sudo", "openssl", "x509", "-enddate", "-noout", "-in", cert_path],
            capture_output=True, text=True, timeout=5,
        )
        if out.returncode != 0:
            return None
        # Output: notAfter=May 21 06:53:20 2026 GMT
        date_str = out.stdout.strip().split("=", 1)[-1]
        return datetime.strptime(date_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    except Exception:
        return None


def run(config: dict) -> list[CheckResult]:
    certs = config.get("certs", [])
    warn_days = config.get("warn_days", 14)
    critical_days = config.get("critical_days", 7)

    if not certs:
        # Auto-discover from /etc/letsencrypt/live/ (requires sudo — root-owned dir)
        try:
            out = subprocess.run(
                ["sudo", "ls", "/etc/letsencrypt/live/"],
                capture_output=True, text=True, timeout=5,
            )
            if out.returncode == 0:
                for name in out.stdout.strip().splitlines():
                    if name != "README":
                        certs.append(f"/etc/letsencrypt/live/{name}/fullchain.pem")
        except Exception:
            pass

    if not certs:
        return [CheckResult("SSL", OK, "No certificates found")]

    now = datetime.now(timezone.utc)
    results_parts = []
    worst = OK

    for cert_path in certs:
        # Extract domain name from path
        parts = cert_path.split("/")
        domain = parts[4] if len(parts) > 4 else cert_path

        expiry = _cert_expiry(cert_path)
        if expiry is None:
            results_parts.append(f"{domain}: unable to read")
            worst = WARNING
            continue

        days_left = (expiry - now).days

        if days_left <= critical_days:
            status = CRITICAL
        elif days_left <= warn_days:
            status = WARNING
        else:
            status = OK

        if [OK, WARNING, CRITICAL].index(status) > [OK, WARNING, CRITICAL].index(worst):
            worst = status

        results_parts.append(f"{domain} expires in {days_left}d")

    return [CheckResult("SSL", worst, " | ".join(results_parts))]
