#!/bin/bash
# Accept-queue overflow sampler. Runs every minute from root cron.
#
# When a listen queue fills, the kernel drops new connections without logging
# anything. The only trace is a cumulative counter. This script compares that
# counter to the previous minute's reading. When it moved, it writes one line
# naming the busiest clients of that minute, so a burst of drops can be traced
# to its source. A quiet minute writes nothing.
set -u
PATH=/usr/sbin:/usr/bin:/sbin:/bin

DIR=/var/www/html/WatchTower/logs
LAST=$DIR/.overflow_sampler.last
LOG=$DIR/overflow_sampler.log

# /proc/net/netstat holds TcpExt as a header line followed by a values line.
now=$(awk '/^TcpExt:/ { if (!seen) { split($0, keys); seen = 1 } else {
        for (i = 2; i <= NF; i++) if (keys[i] == "ListenOverflows") print $i } }' /proc/net/netstat)
prev=$(cat "$LAST" 2>/dev/null || echo "$now")
echo "$now" > "$LAST"

# The counter restarts at 0 on reboot.
[ "$now" -lt "$prev" ] && prev=0
drops=$((now - prev))
[ "$drops" -gt 0 ] || exit 0

# Busiest clients across every vhost during the minute that just ended.
minute=$(date -u -d '1 min ago' '+%d/%b/%Y:%H:%M')
top=$(for f in /var/log/httpd/*access_log /var/log/httpd/*access.log; do
        [ -f "$f" ] && tail -n 3000 "$f"
      done | grep -F "[$minute" | awk '{print $1}' | sort | uniq -c | sort -rn | head -3 |
      awk '{printf "%s=%s ", $2, $1}')
queues=$(ss -Htln | awk '$2 > 0 {printf "%s:%s/%s ", $4, $2, $3}')
# The overflow counter covers every port. Half-open connections grouped by local
# port show which listener the burst hit, e.g. SSH brute force on :22 vs web on :443.
synrecv=$(ss -Htn state syn-recv | awk '{n = split($3, a, ":"); print a[n]}' |
          sort | uniq -c | sort -rn | awk '{printf ":%s=%s ", $2, $1}')
load=$(cut -d' ' -f1 /proc/loadavg)

printf '%s drops=%s load=%s synrecv=[%s] queues=[%s] top=[%s]\n' \
    "$(date -u '+%Y-%m-%d %H:%M')" "$drops" "$load" "${synrecv% }" "${queues% }" "${top% }" >> "$LOG"
