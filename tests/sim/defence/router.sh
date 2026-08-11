#!/usr/bin/env bash
# notnet sim — router: stateful firewall between segments and c2net.
#
# Posture (SIM_POSTURE env): lax | standard | hardened
#   lax      - NAT only, no inspection, no segmentation policy
#   standard - NAT + drop cross-segment (iot->office/dmz, dmz->office) + log
#   hardened - standard + IPS block hook (/run/ips_blacklist) DROPs sources
#
# Docker attaches one ethN per network in attach order; we detect the
# interface for each subnet by address, not by name.
set -e

POSTURE="${SIM_POSTURE:-lax}"
echo "[router] posture=$POSTURE"

# Subnets (must match docker-compose.sim.yml)
C2NET="172.29.0.0/24"
IOTNET="172.29.10.0/24"
OFFICENET="172.29.20.0/24"
DMZNET="172.29.30.0/24"

# Map subnet -> interface name by scanning addresses.
# The router holds the .1 (gateway) address on each segment, so match by
# /24 prefix, not a specific host IP.
iface_for() {
    local want="$1"   # e.g. "172.29.10"
    ip -o -4 addr show | awk -v w="$want" '{
        split($4,a,"/");
        split(a[1],oct,".");
        if (oct[1] "." oct[2] "." oct[3] == w) { print $2; exit }
    }'
}

ETH_C2="$(iface_for 172.29.0)"
ETH_IOT="$(iface_for 172.29.10)"
ETH_OFFICE="$(iface_for 172.29.20)"
ETH_DMZ="$(iface_for 172.29.30)"

echo "[router] ifaces: c2=$ETH_C2 iot=$ETH_IOT office=$ETH_OFFICE dmz=$ETH_DMZ"
[ -n "$ETH_C2" ] && [ -n "$ETH_IOT" ] && [ -n "$ETH_OFFICE" ] && [ -n "$ETH_DMZ" ] || {
    echo "[router] ERROR: could not map all segment interfaces"; exit 1;
}

# Enable forwarding + NAT to c2net
sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -A POSTROUTING -o "$ETH_C2" -j MASQUERADE 2>/dev/null || true
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null || true

# Default: allow same-segment + egress to c2net (per-segment interfaces)
iptables -A FORWARD -i "$ETH_IOT" -o "$ETH_C2" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i "$ETH_OFFICE" -o "$ETH_C2" -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i "$ETH_DMZ" -o "$ETH_C2" -j ACCEPT 2>/dev/null || true

if [ "$POSTURE" = "lax" ]; then
    # flat: everything reaches everything
    iptables -A FORWARD -i "$ETH_IOT" -o "$ETH_OFFICE" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_IOT" -o "$ETH_DMZ" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_OFFICE" -o "$ETH_DMZ" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_OFFICE" -o "$ETH_IOT" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_DMZ" -o "$ETH_IOT" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_DMZ" -o "$ETH_OFFICE" -j ACCEPT 2>/dev/null || true
elif [ "$POSTURE" = "standard" ] || [ "$POSTURE" = "hardened" ]; then
    # segmentation: IoT isolated (compromised IoT must not reach office/dmz),
    # office->dmz allowed (web servers reachable from LAN), dmz->office blocked.
    iptables -A FORWARD -i "$ETH_IOT" -o "$ETH_OFFICE" -j DROP 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_IOT" -o "$ETH_DMZ" -j DROP 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_OFFICE" -o "$ETH_DMZ" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_OFFICE" -o "$ETH_IOT" -j ACCEPT 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_DMZ" -o "$ETH_OFFICE" -j DROP 2>/dev/null || true
    iptables -A FORWARD -i "$ETH_DMZ" -o "$ETH_IOT" -j DROP 2>/dev/null || true
fi

# IPS blacklist hook (hardened): /run/ips_blacklist holds "ip" per line.
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

echo "[router] rules:"
iptables -S | head -30

while true; do sleep 60; done
