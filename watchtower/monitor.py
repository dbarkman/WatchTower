#!/usr/bin/env python3
"""
Remote Health Monitor
=====================
Checks remote server health endpoints and alerts on consecutive failures.
Designed to run via cron (e.g., every minute).

Can operate in two modes:
  1. CLI args:  watchtower-monitor --url https://example.com/health --name "My Server" --ntfy-topic MY-Up
  2. Config file: watchtower-monitor --config config/targets.yaml  (checks all targets)

State is tracked in flat files under the state/ directory. Each target gets
a file tracking its consecutive failure count.
"""
import argparse
import json
import logging
import os
import sys

import requests
import yaml
from dotenv import load_dotenv

from watchtower.alerts import send_discord, send_ntfy

load_dotenv()

logger = logging.getLogger(__name__)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
)

STATE_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'state')
DEFAULT_FAILURE_THRESHOLD = 2
DEFAULT_TIMEOUT = 10


def _state_file(name: str) -> str:
    safe = name.replace(' ', '_').replace('/', '_').lower()
    return os.path.join(STATE_DIR, f'monitor_{safe}.state')


def _read_failure_count(name: str) -> int:
    try:
        with open(_state_file(name)) as f:
            return int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return 0


def _write_failure_count(name: str, count: int):
    os.makedirs(STATE_DIR, exist_ok=True)
    with open(_state_file(name), 'w') as f:
        f.write(str(count))


def check_health(url: str, timeout: int = DEFAULT_TIMEOUT) -> dict:
    """Hit a health endpoint and return structured result."""
    try:
        resp = requests.get(url, timeout=timeout)
        try:
            body = resp.json()
        except (json.JSONDecodeError, ValueError):
            body = {'raw': resp.text[:500]}
        return {
            'ok': resp.status_code == 200,
            'status_code': resp.status_code,
            'body': body,
        }
    except requests.ConnectionError:
        return {'ok': False, 'status_code': None, 'body': {'detail': 'Connection refused'}}
    except requests.Timeout:
        return {'ok': False, 'status_code': None, 'body': {'detail': f'Timeout after {timeout}s'}}
    except Exception as e:
        return {'ok': False, 'status_code': None, 'body': {'detail': str(e)}}


def check_target(url: str, name: str, ntfy_topic: str = None,
                 threshold: int = DEFAULT_FAILURE_THRESHOLD,
                 timeout: int = DEFAULT_TIMEOUT) -> bool:
    """Check one target and alert after consecutive failures."""
    result = check_health(url, timeout=timeout)

    if result['ok']:
        prev_failures = _read_failure_count(name)
        if prev_failures >= threshold:
            logger.info(f'✅ {name} recovered after {prev_failures} failures')
            send_discord(
                f'✅ {name} recovered',
                f'Health check passing again after {prev_failures} consecutive failures',
                color=0x00FF00,
            )
            send_ntfy(ntfy_topic, f'{name} recovered',
                      f'Back online after {prev_failures} consecutive failures')
        _write_failure_count(name, 0)

        status = result['body'].get('status', 'ok')
        age = result['body'].get('age_seconds')
        detail = f'status={status}'
        if age is not None:
            detail += f', heartbeat_age={age}s'
        logger.info(f'✅ {name}: {detail}')
        return True

    failures = _read_failure_count(name) + 1
    _write_failure_count(name, failures)

    detail = result['body'].get('detail', '') or result['body'].get('status', '')
    status_code = result['status_code']
    logger.warning(f'❌ {name}: failure {failures}/{threshold} (HTTP {status_code}, {detail})')

    if failures >= threshold:
        alert_detail = f'HTTP {status_code}\n{detail}' if status_code else detail
        send_discord(f'🚨 {name} is DOWN',
                     f'{failures} consecutive failures\nURL: {url}\n{alert_detail}')
        send_ntfy(ntfy_topic, f'{name} is DOWN',
                  f'{failures} consecutive failures\n{alert_detail}')

    return False


def run_config(config_path: str):
    """Load targets from YAML config and check each one."""
    with open(config_path) as f:
        config = yaml.safe_load(f)

    targets = config.get('targets', [])
    if not targets:
        logger.warning(f'No targets found in {config_path}')
        return

    for target in targets:
        check_target(
            url=target['url'],
            name=target['name'],
            ntfy_topic=target.get('ntfy_topic'),
            threshold=target.get('failure_threshold', DEFAULT_FAILURE_THRESHOLD),
            timeout=target.get('timeout', DEFAULT_TIMEOUT),
        )


def main():
    parser = argparse.ArgumentParser(description='WatchTower — remote health monitor')
    parser.add_argument('--url', help='Health endpoint URL (single target mode)')
    parser.add_argument('--name', help='Friendly name for alerts (single target mode)')
    parser.add_argument('--ntfy-topic', default=None, help='Ntfy topic for push notifications')
    parser.add_argument('--config', default=None, help='Path to targets.yaml (multi-target mode)')
    parser.add_argument('--threshold', type=int, default=DEFAULT_FAILURE_THRESHOLD,
                        help=f'Consecutive failures before alerting (default: {DEFAULT_FAILURE_THRESHOLD})')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT,
                        help=f'Request timeout in seconds (default: {DEFAULT_TIMEOUT})')
    args = parser.parse_args()

    if args.config:
        run_config(args.config)
    elif args.url and args.name:
        check_target(args.url, args.name, ntfy_topic=args.ntfy_topic,
                     threshold=args.threshold, timeout=args.timeout)
    else:
        parser.error('Either --config or both --url and --name are required')


if __name__ == '__main__':
    main()
