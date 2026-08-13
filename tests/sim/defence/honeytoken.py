#!/usr/bin/env python3
"""notnet honeytoken tripwire (#148).

Deception layer for credential-driven attacks. Reads the seeded honey-cred set
and the honey relay token (both written by gen_fleet.py into
tests/sim/conf/honeytokens.json), then tails the sim evidence directory for the
bot's harvested credential buffer (format `proto|ip|port|user|pass`) and the relay
command log. The moment a HONEY cred lands in a cred-log line — or a HONEY relay
token is used — it fires a deterministic, zero-false-positive Canarytoken-style
alert.

Why zero-FP: the honey set is real-format creds (e.g. user `honey-ssh`, password
`CANARY-...`) that no legitimate admin would ever configure, and the honey relay
token is a value never issued to the operator. Any hit is by definition a bot
touching a decoy, not a real login.

Usage (run inside the sim, as a watcher like ids_monitor.py):
    python3 defence/honeytoken.py
Env:
    SIM_EVIDENCE   evidence dir (default /evidence)
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
                            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                         "conf", "honeytokens.json"))
ALERT_FILE = os.environ.get("HONEY_ALERT", os.path.join(EVIDENCE, "honeytoken_alerts.log"))

# cred-log line: proto|ip|port|user|pass   (README §Credential log)
CRED_RE = re.compile(r"^(?P<proto>\w+)\|(?P<ip>[0-9.]+)\|(?P<port>\d+)\|(?P<user>[^|]*)\|(?P<pass>.*)$")

honey = {"creds": set(), "relay_token": None}


def load_honey():
    if not os.path.exists(HONEY_FILE):
        return
    with open(HONEY_FILE, encoding="utf-8") as f:
        data = json.load(f)
    for c in data.get("creds", []):
        # store lowercased user|pass for matching
        honey["creds"].add(f"{c['user'].lower()}|{c['pass']}")
    honey["relay_token"] = data.get("relay_token")


def now():
    return datetime.now(timezone.utc).isoformat()


def alert(kind, detail):
    os.makedirs(os.path.dirname(ALERT_FILE) or ".", exist_ok=True)
    line = f"{now()} HONEYTOKEN-{kind} {detail}"
    with open(ALERT_FILE, "a") as f:
        f.write(line + "\n")
    print(line, flush=True)


def process_line(fn, line):
    line = line.strip()
    if not line:
        return
    # cred-log match
    m = CRED_RE.match(line)
    if m and honey["creds"]:
        key = f"{m.group('user').lower()}|{m.group('pass')}"
        if key in honey["creds"]:
            alert("CRED", f"honey cred harvested proto={m.group('proto')} "
                           f"src={m.group('ip')}:{m.group('port')} "
                           f"user={m.group('user')} (zero-FP decoy hit)")
            return
    # relay honey token match
    if honey["relay_token"] and honey["relay_token"] in line:
        alert("RELAY", f"honey relay token traversed VIA chain: {line[:120]}")


def main():
    load_honey()
    open(ALERT_FILE, "a").close()
    print(f"{now()} honeytoken up: honey_creds={len(honey['creds'])} "
          f"relay_token={'set' if honey['relay_token'] else 'none'} "
          f"dir={EVIDENCE}")
    if not honey["creds"] and not honey["relay_token"]:
        print("WARNING: no honey tokens configured (gen_fleet.py did not seed any)")
    positions = {}
    while True:
        for fname in os.listdir(EVIDENCE) if os.path.isdir(EVIDENCE) else []:
            if not fname.endswith(".log"):
                continue
            if fname == os.path.basename(ALERT_FILE):
                continue
            path = os.path.join(EVIDENCE, fname)
            try:
                sz = os.path.getsize(path)
            except OSError:
                continue
            pos = positions.get(path, 0)
            if sz < pos:
                pos = 0
            if sz == pos:
                continue
            with open(path, "r", errors="replace") as f:
                f.seek(pos)
                for ln in f:
                    process_line(fname, ln)
                positions[path] = f.tell()
        time.sleep(1)


if __name__ == "__main__":
    main()
