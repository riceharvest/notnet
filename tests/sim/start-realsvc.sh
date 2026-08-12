#!/bin/bash
# Real-service device entrypoint (Tier 1, issue #123).
# Env:
#   DEVICE_SERVICES  comma list: ssh,redis,samba,telnet,http
#   DEVICE_TIER      legacy|modern   (drives auth posture)
#   DEVICE_CREDS     "user:pass"     (ssh/telnet/samba login)
#   SMB1_ENABLED     1|0
#   REDIS_AUTH       1|0  REDIS_PASSWORD
#   BOT_TAG          device tag the payload uses when this device is infected
#   C2_SERVER C2_PORT C2_SECRET   for /etc/notnet.conf
set -u
SERVICES="${DEVICE_SERVICES:-ssh}"
TIER="${DEVICE_TIER:-legacy}"
CREDS="${DEVICE_CREDS:-root:root}"
HOST="${DEVICE_HOSTNAME:-$(hostname)}"

# ── payload config: the REAL notnet binary reads this when executed ──
mkdir -p /etc
cat > /etc/notnet.conf <<EOF
http_server=${C2_SERVER:-c2}
http_port=${C2_PORT:-8080}
http_path=/api/v1/bot
c2_secret=${C2_SECRET:-mocksecret}
heartbeat_interval=2
scan_interval=1
persist_enabled=0
bot_tag=${BOT_TAG:-$HOST}
EOF
chmod 644 /etc/notnet.conf

# ── users ──
USERNAME="${CREDS%%:*}"
PASSWORD="${CREDS#*:}"
if ! id "$USERNAME" >/dev/null 2>&1; then
    useradd -m -s /bin/bash "$USERNAME" 2>/dev/null || useradd -m -s /bin/sh "$USERNAME"
fi
echo "$USERNAME:$PASSWORD" | chpasswd

case "$SERVICES" in *ssh*)
    # real OpenSSH
    [ -f /etc/ssh/ssh_host_rsa_key ] || ssh-keygen -q -t rsa -f /etc/ssh/ssh_host_rsa_key -N ''
    [ -f /etc/ssh/ssh_host_ed25519_key ] || ssh-keygen -q -t ed25519 -f /etc/ssh/ssh_host_ed25519_key -N ''
    if [ "$TIER" = "modern" ]; then
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication no/; s/^#*PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    else
        sed -i 's/^#*PasswordAuthentication.*/PasswordAuthentication yes/; s/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    fi
    /usr/sbin/sshd
;;
esac

case "$SERVICES" in *redis*)
    if [ "${REDIS_AUTH:-0}" = "1" ]; then
        redis-server --requirepass "${REDIS_PASSWORD:-changeme}" --protected-mode yes --daemonize yes
    else
        redis-server --protected-mode no --daemonize yes
    fi
;;
esac

case "$SERVICES" in *samba*)
    cat > /etc/samba/smb.conf <<EOF
[global]
   workgroup = WORKGROUP
   server role = standalone server
   map to guest = never
   security = user
   passdb backend = tdbsam
   smb ports = 445
   server min protocol = $([ "${SMB1_ENABLED:-0}" = "1" ] && echo NT1 || echo SMB2)
   log file = /var/log/samba/log.%m
   max log size = 1000
[share]
   path = /data/share
   browseable = yes
   writable = yes
   valid users = $USERNAME
EOF
    (echo "$PASSWORD"; echo "$PASSWORD") | smbpasswd -s -a "$USERNAME"
    smbd --foreground --no-process-group >/var/log/samba/smbd.log 2>&1 &
;;
esac

case "$SERVICES" in *telnet*)
    # real busybox telnetd on 23 (the IoT standard) + busybox login
    # (reads /etc/shadow directly, no PAM — like real embedded devices)
    busybox-iot telnetd -p 23 -l /bin/login >/var/log/telnetd.log 2>&1 &
;;
esac

case "$SERVICES" in *http*)
    nginx >/var/log/nginx/nginx.log 2>&1 &
;;
esac

# give the daemons a moment, then stay alive
sleep 2
tail -f /dev/null
