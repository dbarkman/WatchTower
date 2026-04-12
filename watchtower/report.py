#!/usr/bin/env python3
"""
Daily Health Report
===================
Runs all configured checks and sends a digest via Discord and/or ntfy.
Designed to run via cron (e.g., once or twice daily).

Usage:
  uv run python -m watchtower.report --config config/checks.yaml
"""
import argparse
import logging
import os
import socket
from datetime import datetime

import yaml
from dotenv import load_dotenv

from watchtower.checks import CheckResult, OK, WARNING, CRITICAL
from watchtower.checks import disk, memory, oom, services, auth, fail2ban, ssl, process_rss
from watchtower.alerts import send_discord, send_ntfy

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)

CHECK_MODULES = {
    "disk": disk,
    "memory": memory,
    "oom": oom,
    "services": services,
    "auth": auth,
    "fail2ban": fail2ban,
    "ssl": ssl,
    "process_rss": process_rss,
}


def run_checks(config: dict) -> list[CheckResult]:
    """Run all configured checks and collect results."""
    checks_config = config.get("checks", {})
    results = []

    for name, module in CHECK_MODULES.items():
        if name not in checks_config:
            continue
        check_conf = checks_config[name] or {}
        try:
            results.extend(module.run(check_conf))
        except Exception as e:
            logger.error(f"Check '{name}' crashed: {e}")
            results.append(CheckResult(name, WARNING, f"check failed: {e}"))

    return results


def format_digest(server_name: str, results: list[CheckResult]) -> str:
    """Format results into a readable digest."""
    date_str = datetime.now().strftime("%Y-%m-%d")

    # Sort: critical first, then warning, then ok
    priority = {CRITICAL: 0, WARNING: 1, OK: 2}
    results.sort(key=lambda r: priority.get(r.status, 3))

    counts = {OK: 0, WARNING: 0, CRITICAL: 0}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    lines = [f"Server Health — {server_name} ({date_str})", ""]
    for r in results:
        lines.append(f"{r.icon} {r.name}: {r.summary}")

    lines.append("")
    summary_parts = []
    if counts[CRITICAL]:
        summary_parts.append(f"{counts[CRITICAL]} critical")
    if counts[WARNING]:
        summary_parts.append(f"{counts[WARNING]} warnings")
    summary_parts.append(f"{counts[OK]} OK")
    lines.append(", ".join(summary_parts))

    if not counts[CRITICAL] and not counts[WARNING]:
        lines.append("No issues requiring attention.")

    return "\n".join(lines)


def send_digest(server_name: str, results: list[CheckResult], config: dict):
    """Send the digest via configured alert channels."""
    digest = format_digest(server_name, results)
    logger.info(f"\n{digest}")

    # Determine overall status for color/priority
    has_critical = any(r.status == CRITICAL for r in results)
    has_warning = any(r.status == WARNING for r in results)

    # Discord
    if has_critical:
        color = 0xFF0000
        title = f"\U0001f534 {server_name} — Issues Found"
    elif has_warning:
        color = 0xFFAA00
        title = f"\u26a0\ufe0f {server_name} — Warnings"
    else:
        color = 0x00FF00
        title = f"\u2705 {server_name} — All Clear"

    send_discord(title, digest, color=color)

    # ntfy — only send if there are issues (avoid daily noise for healthy servers)
    ntfy_topic = config.get("ntfy_topic")
    if ntfy_topic and (has_critical or has_warning):
        priority = "urgent" if has_critical else "high"
        send_ntfy(ntfy_topic, title, digest, priority=priority)
    elif ntfy_topic and config.get("ntfy_always", False):
        send_ntfy(ntfy_topic, title, digest, priority="low")


def main():
    parser = argparse.ArgumentParser(description="WatchTower — daily health report")
    parser.add_argument("--config", required=True, help="Path to checks.yaml")
    args = parser.parse_args()

    with open(args.config) as f:
        config = yaml.safe_load(f)

    server_name = config.get("server_name", socket.gethostname())
    results = run_checks(config)

    if not results:
        logger.warning("No checks configured or all checks skipped")
        return

    send_digest(server_name, results, config)


if __name__ == "__main__":
    main()
