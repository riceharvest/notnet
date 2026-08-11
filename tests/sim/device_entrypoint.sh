#!/bin/sh
# Device entrypoint: render /etc/notnet.conf with the device's bot_tag,
# then start the emulator.
set -e
DEVICE_ID="${DEVICE_ID:-device}"
sed "s/__DEVICE_ID__/$DEVICE_ID/g" /app/notnet.conf.tpl > /etc/notnet.conf
chmod 644 /etc/notnet.conf
echo "[device] $DEVICE_ID boot: notnet.conf rendered, starting emulator"
exec python3 /app/device.py
