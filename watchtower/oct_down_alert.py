"""OnFailure handler — records when an OCT systemd unit gives up.

Invoked by systemd via oct-down-alert@.service when one of the OCT trading
units (oct@<venue>, oct-web) exhausts its restart limit and enters the
'failed' state.

Log-only as of 2026-08-03: it writes to stdout, which systemd captures into
the journal (journalctl -u oct-down-alert@<unit>). Notification is UptimeRobot's
job — a failed unit makes the public /health/oct endpoint return 503 within the
restart grace window, and UptimeRobot pushes to the phone from there.

    python -m watchtower.oct_down_alert <unit-name>
"""
import socket
import sys


def main():
    unit = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    host = socket.gethostname()
    msg = (f"\U0001f534 systemd unit '{unit}' entered FAILED state on {host} "
           f"(exhausted restart attempts). OCT trading for this unit is DOWN.")
    print(msg)


if __name__ == "__main__":
    main()
