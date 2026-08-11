#!/usr/bin/env bash
# notnet sim — host firewall (DOCKER-USER chain)
#
# Docker's FORWARD chain jumps into DOCKER-USER for ALL container traffic;
# rules there survive `docker compose` restarts and are the sanctioned place
# for user firewall policy. We enforce the sim's REAL-WORLD network posture
# here (this is the L3 enforcement the flat compose bridge can't express):
#
#   lax      — no rules (NAT only). Every container can reach every other.
#   standard — segmentation: IoT cannot reach Office/DMZ, DMZ cannot initiate
#              inward, all segments can reach the C2 control ports (heartbeat
#              + payload fetch + dead-drop DNS). The attacker bot (172.29.0.9)
#              keeps full reach — it is the threat model.
#   hardened — standard + fail2ban-style brute-force protection
#              (drop sources with > BRUTE_MAX_NEW new conns in a window) +
#              IPS blacklist enforcement (sources listed in the shared
#              evidence/ips_blacklist file are dropped).
#
# Rules are scoped to the sim subnet (172.29.0.0/16) so unrelated Docker
# traffic on this host is never touched.
#
# Usage:
#   host_firewall.sh install --posture lax|standard|hardened [--ips 1]
#   host_firewall.sh watch --evidence DIR            # run as background loop
#   host_firewall.sh remove                          # delete our rules

set -u

SIM_NET="172.29.0.0/16"
# segments inside the sim
NET_IOT="172.29.10.0/24"
NET_OFFICE="172.29.20.0/24"
NET_DMZ="172.29.30.0/24"
NET_C2="172.29.0.0/24"
# the attacker bot lives in the C2 segment — keep full reach
BOT_IP="172.29.0.9"
# C2 control ports every segment must reach (heartbeat/payload/dns)
C2_PORTS="8080,8081,8443,53"

BRUTE_MAX_NEW="15"
BRUTE_WINDOW="10"

MARK="notnet-sim"  # comment tag so we only ever touch our own rules

require_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "[host_firewall] need root (sudo) to manage DOCKER-USER" >&2
        exit 1
    fi
}

flush_ours() {
    # remove only rules we added (marked), by line number — reconstructing
    # the -D from `iptables -S` text breaks on `recent` module normalization.
    local n=0 line
    while IFS= read -r line; do
        n=$((n + 1))
        if echo "$line" | grep -q "$MARK"; then
            iptables -D DOCKER-USER "$n" 2>/dev/null
            n=$((n - 1))  # chain shrank by one
        fi
    done < <(iptables -S DOCKER-USER 2>/dev/null | tail -n +2)
}

has_rule() {
    iptables -C DOCKER-USER "$@" 2>/dev/null
}

add_rule() {
    if ! has_rule "$@"; then
        iptables -A DOCKER-USER "$@" -m comment --comment "$MARK" 2>/dev/null
    fi
}

install() {
    local posture="${1:-lax}" ips="${2:-0}"
    echo "[host_firewall] install posture=$posture ips=$ips"
    flush_ours

    if [ "$posture" = "lax" ]; then
        echo "[host_firewall] lax: no segmentation rules"
        return 0
    fi

    # stateful: allow replies to established/related flows
    add_rule -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # the attacker bot keeps full reach (threat model)
    add_rule -s "$BOT_IP" -j ACCEPT

    # all segments may reach the C2 control ports (heartbeats, payload, DNS)
    for seg in "$NET_IOT" "$NET_OFFICE" "$NET_DMZ"; do
        add_rule -s "$seg" -d "$NET_C2" -p tcp -m multiport --dports "$C2_PORTS" -j ACCEPT
        add_rule -s "$seg" -d "$NET_C2" -p udp --dport 53 -j ACCEPT
    done

    if [ "$posture" = "standard" ] || [ "$posture" = "hardened" ]; then
        # segmentation: IoT is untrusted, isolated from Office and DMZ
        add_rule -s "$NET_IOT" -d "$NET_OFFICE" -j DROP
        add_rule -s "$NET_IOT" -d "$NET_DMZ" -j DROP
        # DMZ servers never initiate inward
        add_rule -s "$NET_DMZ" -d "$NET_OFFICE" -j DROP
        add_rule -s "$NET_DMZ" -d "$NET_IOT" -j DROP
        # Office may reach DMZ services (normal internal->DMZ), and IoT admin
        add_rule -s "$NET_OFFICE" -d "$NET_DMZ" -j ACCEPT
        add_rule -s "$NET_OFFICE" -d "$NET_IOT" -j ACCEPT
    fi

    if [ "$posture" = "hardened" ]; then
        # fail2ban-style: drop sources opening > N new conns in a window
        add_rule -s "$SIM_NET" -m conntrack --ctstate NEW -m recent \
            --name notnet_brute --set
        add_rule -s "$SIM_NET" -m conntrack --ctstate NEW -m recent \
            --name notnet_brute --update --seconds "$BRUTE_WINDOW" \
            --hitcount "$BRUTE_MAX_NEW" -j DROP
    fi

    if [ "$ips" = "1" ] || [ "$posture" = "hardened" ]; then
        echo "[host_firewall] IPS mode on (blacklist consumed by watch)"
    fi

    echo "[host_firewall] rules installed:"
    iptables -S DOCKER-USER 2>/dev/null | grep -F "$MARK" | head -30
}

watch() {
    # tail the shared IPS blacklist and drop listed sources
    local ev="${1:-evidence}"
    local bl="$ev/ips_blacklist"
    mkdir -p "$ev"
    touch "$bl"
    echo "[host_firewall] watch $bl"
    tail -n +1 -F "$bl" 2>/dev/null | while read -r ip; do
        ip="$(echo "$ip" | tr -d '[:space:]')"
        [ -z "$ip" ] && continue
        case "$ip" in \#*) continue ;; esac
        if ! has_rule -s "$ip" -j DROP; then
            echo "[host_firewall] IPS: dropping blacklisted source $ip"
            iptables -I DOCKER-USER 1 -s "$ip" -j DROP -m comment --comment "$MARK-ips"
        fi
    done
}

remove() {
    echo "[host_firewall] removing rules"
    flush_ours
    # drop any IPS rules we added
    iptables -S DOCKER-USER 2>/dev/null | grep -F "$MARK-ips" | while read -r line; do
        local del="${line/-A /-D }"
        # shellcheck disable=SC2086
        iptables $del 2>/dev/null
    done
    echo "[host_firewall] done"
}

case "${1:-}" in
    install)
        require_root
        # parse --posture=... and --ips=... from remaining args
        posture="lax"; ips="0"
        for a in "$@"; do
            case "$a" in
                --posture=*) posture="${a#--posture=}" ;;
                --ips=*) ips="${a#--ips=}" ;;
            esac
        done
        install "$posture" "$ips"
        ;;
    watch)
        require_root
        ev="evidence"
        for a in "$@"; do
            case "$a" in
                --evidence=*) ev="${a#--evidence=}" ;;
            esac
        done
        watch "$ev"
        ;;
    remove)
        require_root
        remove
        ;;
    *)
        echo "usage: $0 install --posture=... [--ips=1] | watch --evidence=... | remove"
        exit 1
        ;;
esac
