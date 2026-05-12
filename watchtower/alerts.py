"""
Alert Dispatchers
=================
Send notifications via Discord webhooks and ntfy push.
Self-contained — no external project dependencies.
"""
import logging
import os

import requests

logger = logging.getLogger(__name__)

REQUEST_TIMEOUT = 10


def send_discord(title: str, message: str, color: int = 0xFF0000):
    """Send an embed to Discord. Fails silently."""
    webhook_url = os.getenv('DISCORD_WEBHOOK_URL', '')
    if not webhook_url:
        return
    try:
        requests.post(
            webhook_url,
            json={'embeds': [{'title': title, 'description': message, 'color': color}]},
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as e:
        logger.warning(f'Discord alert failed: {e}')


def send_ntfy(topic: str, title: str, message: str, priority: str = 'high'):
    """Send a push notification via ntfy. Fails silently."""
    if not topic:
        return
    ntfy_url = os.getenv('NTFY_URL', 'https://ntfy.sh')
    try:
        requests.post(
            f'{ntfy_url}/{topic}',
            data=message.encode('utf-8'),
            headers={'Title': title, 'Priority': priority},
            timeout=REQUEST_TIMEOUT,
        )
    except Exception as e:
        logger.warning(f'Ntfy alert failed: {e}')
