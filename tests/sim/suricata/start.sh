#!/bin/bash
# Suricata IDS entrypoint (#131). Runs on the HOST network and captures
# the simnet bridge interface directly (docker bridges do not mirror
# cross-container unicast to promiscuous container ports on this host).
set -u
# find the sim bridge by its 172.29.0.0/16 address
IFACE=$(ip -4 -o addr show | awk '$4 ~ /^172\.29\./ { sub(/\/.*/,"",$4); print $2 }' | head -1)
[ -z "$IFACE" ] && { echo "no sim bridge found"; sleep 3600; exit 1; }
echo "[suricata] capturing $IFACE"
# clear stale root-owned outputs from previous runs
rm -f /var/log/suricata/eve.json 2>/dev/null
suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --set outputs.0.eve-log.filename=/var/log/suricata/eve.json >/var/log/suricata/suricata.log 2>&1
