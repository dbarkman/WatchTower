#!/bin/bash
# workstation-posture.sh — collect macOS security posture and push it to WatchTower.
#
# Runs weekly from launchd on David's Mac. Pushes to POST /health/workstation
# with a bearer token, because the laptop roams (so it cannot be pulled) and its
# SSH key now carries a passphrase that a launchd job cannot supply.
#
# Reads WT_WORKSTATION_TOKEN and WT_WORKSTATION_URL from the environment or
# ~/.config/watchtower/workstation.env — never hardcode the token here.
set -uo pipefail

CONF="${HOME}/.config/watchtower/workstation.env"
[ -f "$CONF" ] && . "$CONF"
: "${WT_WORKSTATION_URL:?set WT_WORKSTATION_URL}"
: "${WT_WORKSTATION_TOKEN:?set WT_WORKSTATION_TOKEN}"

bool() { [ "$1" = "yes" ] && echo true || echo false; }

# FileVault
fv=$(fdesetup status 2>/dev/null | grep -qi "FileVault is On" && echo yes || echo no)

# Application firewall
fw=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null \
      | grep -qi "enabled" && echo yes || echo no)

# Screen lock — askForPassword with a short grace counts as locking
sl=$(sysadminctl -screenLock status 2>&1 | grep -qi "screenLock is off" && echo no || echo yes)

# Software updates. `softwareupdate -l` lists pending; count security-labelled ones.
upd_raw=$(softwareupdate -l 2>/dev/null)
upd=$(printf '%s' "$upd_raw" | grep -c '^\*' || true)
sec=$(printf '%s' "$upd_raw" | grep -ciE 'security|safari|xprotect|mrt' || true)

os=$(sw_vers -productVersion 2>/dev/null)
host=$(scutil --get ComputerName 2>/dev/null || hostname -s)

payload=$(cat <<JSON
{"hostname":"${host}","os_version":"${os}","filevault":$(bool "$fv"),
 "firewall":$(bool "$fw"),"screen_lock":$(bool "$sl"),
 "updates_pending":${upd:-0},"security_updates_pending":${sec:-0}}
JSON
)

code=$(curl -s -o /tmp/wt-workstation.out -w '%{http_code}' \
  --max-time 30 \
  -H "Authorization: Bearer ${WT_WORKSTATION_TOKEN}" \
  -H 'Content-Type: application/json' \
  -X POST "$WT_WORKSTATION_URL" -d "$payload")

if [ "$code" = "200" ]; then
  echo "posture pushed: $payload"
  exit 0
fi
echo "push FAILED (HTTP $code): $(cat /tmp/wt-workstation.out 2>/dev/null)" >&2
exit 1
