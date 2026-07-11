"""OnFailure handler — instant alert when an OCT systemd unit gives up.

Invoked by systemd via oct-down-alert@.service when one of the OCT trading
units (oct, oct-web, one_cent_trader_ws) exhausts its restart limit and enters
the 'failed' state. Pushes ntfy + Discord on the shared WatchTower channel.

    python -m watchtower.oct_down_alert <unit-name>
"""
import os
import socket
import sys


def main():
    from dotenv import load_dotenv
    load_dotenv()
    from watchtower.alerts import send_ntfy, send_discord

    unit = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    host = socket.gethostname()
    topic = os.getenv("WT_NTFY_TOPIC", "WT-Health")
    msg = (f"\U0001f534 systemd unit '{unit}' entered FAILED state on {host} "
           f"(exhausted restart attempts). OCT trading for this unit is DOWN.")
    send_ntfy(topic, f"{host}: {unit} FAILED", msg, priority="urgent")
    send_discord(f"\U0001f534 {host} — {unit} FAILED", msg, color=0xFF0000)
    print(msg)


if __name__ == "__main__":
    main()
