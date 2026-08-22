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

# Apply a rule idempotently (check first, append only when missing) and fail
# loudly (#338): with set -e, any real iptables failure — missing NET_ADMIN,
# absent nft backend, unloaded modules — aborts the script with non-zero
# status so the compose healthcheck fails instead of the sim silently
# reporting a segmentation posture that does not exist.
apply_rule() {
    if [ "$1" = "-t" ]; then
        iptables -t "$2" -C "${@:3}" 2>/dev/null || iptables -t "$2" -A "${@:3}"
    else
        iptables -C "$@" 2>/dev/null || iptables -A "$@"
    fi
}

apply_rule -t nat POSTROUTING -o "$ETH_C2" -j MASQUERADE
apply_rule FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# Default: allow same-segment + egress to c2net (per-segment interfaces)
apply_rule FORWARD -i "$ETH_IOT" -o "$ETH_C2" -j ACCEPT
apply_rule FORWARD -i "$ETH_OFFICE" -o "$ETH_C2" -j ACCEPT
apply_rule FORWARD -i "$ETH_DMZ" -o "$ETH_C2" -j ACCEPT

if [ "$POSTURE" = "lax" ]; then
    # flat: everything reaches everything
    apply_rule FORWARD -i "$ETH_IOT" -o "$ETH_OFFICE" -j ACCEPT
    apply_rule FORWARD -i "$ETH_IOT" -o "$ETH_DMZ" -j ACCEPT
    apply_rule FORWARD -i "$ETH_OFFICE" -o "$ETH_DMZ" -j ACCEPT
    apply_rule FORWARD -i "$ETH_OFFICE" -o "$ETH_IOT" -j ACCEPT
    apply_rule FORWARD -i "$ETH_DMZ" -o "$ETH_IOT" -j ACCEPT
    apply_rule FORWARD -i "$ETH_DMZ" -o "$ETH_OFFICE" -j ACCEPT
elif [ "$POSTURE" = "standard" ] || [ "$POSTURE" = "hardened" ]; then
    # segmentation: IoT isolated (compromised IoT must not reach office/dmz),
    # office->dmz allowed (web servers reachable from LAN), dmz->office blocked.
    apply_rule FORWARD -i "$ETH_IOT" -o "$ETH_OFFICE" -j DROP
    apply_rule FORWARD -i "$ETH_IOT" -o "$ETH_DMZ" -j DROP
    apply_rule FORWARD -i "$ETH_OFFICE" -o "$ETH_DMZ" -j ACCEPT
    apply_rule FORWARD -i "$ETH_OFFICE" -o "$ETH_IOT" -j ACCEPT
    apply_rule FORWARD -i "$ETH_DMZ" -o "$ETH_OFFICE" -j DROP
    apply_rule FORWARD -i "$ETH_DMZ" -o "$ETH_IOT" -j DROP
fi

# Default-deny catch-all (#340): set AFTER the explicit allows so everything
# above is in place first. Any path the script did not enumerate — c2net ->
# office/dmz, docker's default bridge attached later, a renamed veth after a
# restart — now fails closed instead of hitting the kernel ACCEPT default.
iptables -P FORWARD DROP

# Posture verification (#338): confirm the rules actually landed before the
# router reports healthy. ESTABLISHED + 3 egress + 6 posture rules = 10.
FORWARD_COUNT="$(iptables -S FORWARD 2>/dev/null | grep -c '^-A FORWARD' || true)"
if [ "$FORWARD_COUNT" -lt 10 ] || ! iptables -S FORWARD | grep -q '^-P FORWARD DROP'; then
    echo "[router] ERROR: expected >=10 FORWARD rules and policy DROP, got $FORWARD_COUNT rules — posture not applied"; exit 1;
fi

# IPS blacklist hook (hardened): /run/ips_blacklist holds "ip" per line.
if [ "$POSTURE" = "hardened" ]; then
    (
        while true; do
            for blfile in /run/ips_blacklist /run/contain_blacklist; do
                if [ -f "$blfile" ]; then
                    while read -r src; do
                        [ -z "$src" ] && continue
                        # Loud, non-fatal: the watcher must survive a transient
                        # failure, but a missed blacklist entry is logged (#338).
                        iptables -C INPUT -s "$src" -j DROP 2>/dev/null || \
                            iptables -A INPUT -s "$src" -j DROP 2>/dev/null || \
                            echo "[router] WARNING: failed to blacklist $src on INPUT" >&2
                        iptables -C FORWARD -s "$src" -j DROP 2>/dev/null || \
                            iptables -A FORWARD -s "$src" -j DROP 2>/dev/null || \
                            echo "[router] WARNING: failed to blacklist $src on FORWARD" >&2
                    done < "$blfile"
                fi
            done
            sleep 5
        done
    ) &
fi

echo "[router] rules:"
iptables -S | head -30

while true; do sleep 60; done
