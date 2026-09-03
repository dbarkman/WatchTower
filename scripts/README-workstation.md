# Workstation posture reporting (macOS)

The laptop holds the SSH key to production, so its security posture is in scope
for the same vulnerability-management program as the servers. It cannot be
polled — it roams, it is behind NAT, and the server must never hold credentials
to a workstation — so the laptop **pushes** to the server.

⚠️ This is **patch and configuration posture verification, not vulnerability
scanning.** It asserts that disk encryption, the firewall and screen lock are
on and that updates are not piling up. Describing it as a scan would overstate
it.

## Install

1. On the server, the intake token lives in a root-only systemd drop-in:
   `/etc/systemd/system/watchtower-health.service.d/workstation.conf`
2. On the Mac:
   ```
   install -m 0755 scripts/workstation-posture.sh ~/.local/bin/
   umask 077; mkdir -p ~/.config/watchtower
   cat > ~/.config/watchtower/workstation.env <<EOF
   WT_WORKSTATION_URL=https://<host>/health/workstation
   WT_WORKSTATION_TOKEN=<token>
   EOF
   chmod 600 ~/.config/watchtower/workstation.env
   cp scripts/com.watchtower.workstation-posture.plist ~/Library/LaunchAgents/
   launchctl load ~/Library/LaunchAgents/com.watchtower.workstation-posture.plist
   ```

The token is never stored in this repo or in the script — only in the 0600 env
file and the root-only drop-in.

## Verify

```
launchctl list com.watchtower.workstation-posture   # LastExitStatus should be 0
```
A push older than `stale_days` (default 10) is itself a finding: "FileVault on"
from three weeks ago is not evidence of anything.
