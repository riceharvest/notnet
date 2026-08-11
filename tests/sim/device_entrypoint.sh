#!/bin/sh
# Device entrypoint: render /etc/notnet.conf with the device's bot_tag,
# relaunch any persisted payload (S7 persistence test), then start the emulator.
set -e
DEVICE_ID="${DEVICE_ID:-device}"
sed "s/__DEVICE_ID__/$DEVICE_ID/g" /app/notnet.conf.tpl > /etc/notnet.conf
chmod 644 /etc/notnet.conf
echo "[device] $DEVICE_ID boot: notnet.conf rendered, starting emulator"

# S7 persistence across reboot: if a previous infection recorded a drop
# command (device.py writes /app/persist.sh when PERSIST=true), relaunch
# the payload now — models cron/systemd relaunching the bot after reboot.
if [ -f /app/persist.sh ]; then
  echo "[device] $DEVICE_ID boot: relaunching persisted payload"
  # Real devices mount /tmp as tmpfs — a reboot clears it, including the
  # single-instance lock the payload leaves behind. The sim container keeps
  # its filesystem across `docker restart`, so clear the stale lock here to
  # model the tmpfs wipe; otherwise the relaunched payload exits
  # immediately ("Another instance running").
  rm -f /tmp/notnet.lock
  (sh /app/persist.sh >/dev/null 2>&1 &)
fi

exec python3 /app/device.py
