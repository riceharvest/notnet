#!/usr/bin/env bash
# notnet sim — router: stateful NAT between segments and c2net + per-posture iptables.
#
# Posture (SIM_POSTURE env): lax | standard | hardened
#   lax      - NAT only, no inspection, no segmentation policy
#   standard - NAT + drop cross-segment (iot->office/dmz, office->dmz) + log scans
#   hardened - standard + IPS block hook (/run/ips_blacklist) that DROPs sources
#
# Networks (fixed subnets from docker-compose.sim.yml):
#   c2net    172.28.0.0/24
#   iot      172.29.10.0/24
#   office   172.29.20.0/24
#   dmz      172.29.30.0/24
set -e

POSTURE="${SIM_POSTURE:-lax}"
echo "[router] posture=$POSTURE"

# Enable forwarding + NAT to c2net
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -A POSTROUTING -o eth-c2 -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -i eth-c2 -o eth-c2 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# Default: allow same-segment + egress to c2net
iptables -A FORWARD -i eth-iot -o eth-c2 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i eth-office -o eth-c2 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i eth-dmz -o eth-c2 -j ACCEPT 2>/dev/null || true

if [ "$POSTURE" = "lax" ]; then
    # flat: everything reaches everything
    iptables -A FORWARD -i eth-iot -o eth-office -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth-iot -o eth-dmz -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth-office -o eth-dmz -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth-office -o eth-iot -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth-dmz -o eth-iot -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth-dmz -o eth-office -j ACCEPT 2>/dev/null || true
elif [ "$POSTURE" = "standard" ] || [ "$POSTURE" = "hardened" ]; then
    # segmentation: iot is isolated (compromised IoT must not reach office/dmz),
    # office->dmz allowed (web servers reachable from LAN), dmz->office blocked.
    iptables -A FORWARD -i eth-iot -o eth-office -j DROP 2>/dev/null || true
    iptables -A FORWARD -i eth-iot -o eth-dmz -j DROP 2>/dev/null || true
    iptables -A FORWARD -i eth-office -o eth-dmz -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth-office -o eth-iot -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i eth-dmz -o eth-office -j DROP 2>/dev/null || true
    iptables -A FORWARD -i eth-dmz -o eth-iot -j DROP 2>/dev/null || true
fi

# IPS blacklist hook (hardened): /run/ips_blacklist holds "ip" per line.
# ids_monitor.py appends sources that triggered too many ALERTs.
if [ "$POSTURE" = "hardened" ]; then
    (
        while true; do
            if [ -f /run/ips_blacklist ]; then
                while read -r src; do
                    [ -z "$src" ] && continue
                    iptables -C INPUT -s "$src" -j DROP 2>/dev/null || \
                        iptables -A INPUT -s "$src" -j DROP 2>/dev/null || true
                    iptables -C FORWARD -s "$src" -j DROP 2>/dev/null || \
                        iptables -A FORWARD -s "$src" -j DROP 2>/dev/null || true
                done < /run/ips_blacklist
            fi
            sleep 5
        done
    ) &
fi

# keepalive: the container must stay up; print rules once for evidence
echo "[router] rules:"
iptables -S | head -30

# Sleep forever (background watcher may write /run/ips_blacklist)
while true; do sleep 60; done
