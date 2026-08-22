#!/bin/bash
# Suricata IDS entrypoint (#131). Runs on the HOST network and captures
# the simnet bridge interface directly (docker bridges do not mirror
# cross-container unicast to promiscuous container ports on this host).
set -u
# find the sim bridge by its 172.29.0.0/16 address
IFACE=$(ip -4 -o addr show | awk '$4 ~ /^172\.29\./ { sub(/\/.*/,"",$4); print $2 }' | head -1)
# #326: fail fast — idling for an hour before exit leaves S8 silently
# running with no network IDS (and there is no restart policy to recover).
if [ -z "$IFACE" ]; then
    echo "FATAL: no sim bridge found — no interface carries a 172.29.x.x address; check compose network ordering / bridge names" >&2
    exit 1
fi
echo "[suricata] capturing $IFACE"
# clear stale root-owned outputs from previous runs
rm -f /var/log/suricata/eve.json 2>/dev/null
suricata -c /etc/suricata/suricata.yaml -i "$IFACE" --set outputs.0.eve-log.filename=/var/log/suricata/eve.json >/var/log/suricata/suricata.log 2>&1
