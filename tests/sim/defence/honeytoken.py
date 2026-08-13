#!/usr/bin/env python3
"""notnet honeytoken tripwire (#148).

Deception layer for credential-driven attacks. The moment a SEEDED honey cred
lands in the bot's harvested credential buffer — or a honey relay token appears
in the relay VIA path — this watcher fires a zero-false-positive Canarytoken-style
alert.

What it watches (all real bot/sim evidence formats):
  1. evidence/cred_exfil.log  — the bot's drained cred-log buffer, one line per
     harvested credential in the exact shape src/spread.c spread_cred_record()
     writes:  proto|ip|port|user|pass   (README §Credential log).
  2. evidence/<device>.log     — victim device witness logs: "SSH <ip> AUTH OK
     user:pass" / "SMB <ip> AUTH OK account=user" when the bot cracks a device.
  3. relay VIA path            — any log line containing the honey relay token
     (a relay node the defender seeded; the bot's RELAY ... VIA ... wire format).

Why zero-FP: the honey set is real-format creds (e.g. user `deploy`, password
`password`) that exist ONLY on the honeypot devices and are NOT present on any
real fleet device, so a legitimate crack of a real device can never match.

Run (as a sim service, beside ids-monitor):
    python3 defence/honeytoken.py
Env:
    SIM_EVIDENCE   bot evidence dir (default /evidence)
    HONEY_FILE     honeytoken set (default tests/sim/conf/honeytokens.json)
    HONEY_ALERT    alert output (default /evidence/honeytoken_alerts.log)
"""
import json
import os
import re
import time
from datetime import datetime, timezone

EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence")
HONEY_FILE = os.environ.get("HONEY_FILE",
                  os.path.join(os.path.dirname(__file__), "..", "conf", "honeytokens.json"))
ALERT_FILE = os.environ.get("HONEY_ALERT", os.path.join(EVIDENCE, "honeytoken_alerts.log"))

# cred-log buffer line: proto|ip|port|user|pass   (README §Credential log)
CRED_RE = re.compile(r"^(?P<proto>[^|]+)\|(?P<ip>[^|]+)\|(?P<port>[^|]+)\|(?P<user>[^|]+)\|(?P<pass>[^|]+)\s*$")
# device witness: "SSH <ip> AUTH OK user:pass"  /  "SMB <ip> AUTH OK account=user"
AUTHOK_RE = re.compile(r"AUTH OK\s+(?P<user>[^\s:]+):?(?P<pass>[^\s:]*)")

honey = {"creds": set(), "relay_token": None}


def load_honey():
    try:
        with open(HONEY_FILE) as f:
            d = json.load(f)
    except OSError:
        return
    for c in d.get("creds", []):
        honey["creds"].add((c["user"], c["pass"]))
    honey["relay_token"] = d.get("relay_token")


def alert(kind, detail):
    os.makedirs(os.path.dirname(ALERT_FILE) or ".", exist_ok=True)
    line = f"{datetime.now(timezone.utc).isoformat()} HONEYTOKEN {kind}: {detail}"
    with open(ALERT_FILE, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def is_honey(user, password):
    return (user, password) in honey["creds"]


def scan_cred_buffer(path):
    """Watch the bot's drained cred-log buffer (proto|ip|port|user|pass)."""
    fired = 0
    try:
        with open(path, errors="replace") as f:
            for ln in f:
                m = CRED_RE.match(ln.strip())
                if not m:
                    continue
                if is_honey(m.group("user"), m.group("pass")):
                    alert("CREDLOG", f"{ln.strip()}")
                    fired += 1
    except OSError:
        pass
    return fired


def scan_device_logs():
    """Watch victim device AUTH OK witness lines for a honey cred."""
    fired = 0
    if not os.path.isdir(EVIDENCE):
        return 0
    for fn in os.listdir(EVIDENCE):
        if not fn.endswith(".log") or fn == os.path.basename(ALERT_FILE):
            continue
        if fn in ("ids_alerts.log", "honeytoken_alerts.log", "cred_exfil.log",
                  "telemetry_wazuh.log", "host_firewall.log"):
            continue
        try:
            with open(os.path.join(EVIDENCE, fn), errors="replace") as f:
                for ln in f:
                    if "AUTH OK" not in ln:
                        continue
                    m = AUTHOK_RE.search(ln)
                    if m and is_honey(m.group("user"), m.group("pass")):
                        alert("DEVICE", f"{fn}: {ln.strip()[:160]}")
                        fired += 1
        except OSError:
            pass
    return fired


def scan_relay_token():
    fired = 0
    if not honey["relay_token"] or not os.path.isdir(EVIDENCE):
        return 0
    tok = honey["relay_token"]
    for fn in os.listdir(EVIDENCE):
        if not fn.endswith(".log"):
            continue
        try:
            with open(os.path.join(EVIDENCE, fn), errors="replace") as f:
                for ln in f:
                    if tok in ln:
                        alert("RELAY", f"{fn}: honey relay token seen in VIA path")
                        fired += 1
        except OSError:
            pass
    return fired


def main():
    load_honey()
    open(ALERT_FILE, "a").close()
    print(f"{datetime.now(timezone.utc).isoformat()} honeytoken up: "
          f"{len(honey['creds'])} creds, relay_token={'set' if honey['relay_token'] else 'none'}")
    cred_log = os.path.join(EVIDENCE, "cred_exfil.log")
    positions = {}
    last_relay = 0
    while True:
        scan_cred_buffer(cred_log)
        scan_device_logs()
        # relay token scan is cheap but poll it less often
        if time.time() - last_relay > 2:
            scan_relay_token()
            last_relay = time.time()
        time.sleep(1)


if __name__ == "__main__":
    main()
