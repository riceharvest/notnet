#!/usr/bin/env python3
"""IDS/IPS monitor for the notnet sim.

Tails the device evidence logs (mounted /evidence) and raises ALERT records
when it sees attacker behaviour. Optional IPS mode (SIM_IPS=1) writes offender
IPs to /run/ips_blacklist which the router consumes (hardened posture).

Signatures (mirror real-world detection of this exact malware family):
  SCAN-SWEEP    >SIM_SCAN_THRESH (default 20) distinct targets from one src in a window
  BRUTE-BURST   >SIM_BRUTE_THRESH (default 8) failed auths from one src in a window
  CVE-EXPLOIT   SOAPAction / formSysCmd / ___S_O_S_T_R_E_A_MAX___ / device.rsp
  PAYLOAD-DROP  "wget" in a device command + EXECUTING DROP marker
  EDR          EDR-ALERT marker from a PC device
  HONEYPOT     any contact with a honeypot device

Evidence files are per-device: /evidence/<device-id>.log (device.py format)
plus /evidence/http.log, /evidence/cowrie-*.log (Cowrie JSON lines).
"""
import glob
import os
import re
import time
from datetime import datetime, timezone

EVIDENCE_DIR = os.environ.get("SIM_EVIDENCE", "/evidence")
ALERT_FILE = os.environ.get("SIM_ALERT_FILE", "/evidence/ids_alerts.log")
IPS = os.environ.get("SIM_IPS", "0") == "1"
BLACKLIST = os.environ.get("SIM_BLACKLIST", "/run/ips_blacklist")
SCAN_THRESH = int(os.environ.get("SIM_SCAN_THRESH", "20"))
BRUTE_THRESH = int(os.environ.get("SIM_BRUTE_THRESH", "8"))
WINDOW = int(os.environ.get("SIM_IDS_WINDOW", "30"))

lock = threading_lock = None
import threading
lock = threading.Lock()

# src -> {target_set, time}  for scan detection
scan_state = {}
# src -> {fail_count, time}  for brute detection
brute_state = {}
blacklisted = set()


def now():
    return datetime.now(timezone.utc).isoformat()


def alert(sig, src, dst, detail):
    line = f"{now()} ALERT sig={sig} src={src} dst={dst} {detail}"
    with lock:
        with open(ALERT_FILE, "a") as f:
            f.write(line + "\n")
        print(line, flush=True)
    if IPS and sig in ("SCAN-SWEEP", "BRUTE-BURST", "CVE-EXPLOIT") and src not in blacklisted:
        blacklisted.add(src)
        with open(BLACKLIST, "a") as f:
            f.write(src + "\n")
        print(f"{now()} IPS: blacklisted {src}", flush=True)


def parse_device_line(line):
    """Extract (ts, src_ip, action, detail) from a device.py evidence line."""
    # format: <iso> <MESSAGE>
    m = re.match(r"^(\S+ \S+) (.*)$", line)
    if not m:
        return None, None, None, None
    ts, msg = m.group(1), m.group(2)
    src = None
    m2 = re.search(r"(\d+\.\d+\.\d+\.\d+)", msg)
    if m2:
        src = m2.group(1)
    return ts, src, msg, None


def process_line(fname, line):
    line = line.strip()
    if not line:
        return
    ts, src, msg, _ = parse_device_line(line)
    if msg is None:
        return
    if src is None:
        # try http.log format: SERVE/RESP/EXFIL/PAYLOAD lines carry addr
        m = re.search(r"from (\d+\.\d+\.\d+\.\d+)", line)
        if m:
            src = m.group(1)
    # Scan sweep: count distinct device names per src
    if "AUTH FAIL" in msg or "Login incorrect" in msg:
        if src:
            now_t = time.time()
            brute_state.setdefault(src, []).append(now_t)
            brute_state[src] = [t for t in brute_state[src] if now_t - t < WINDOW]
            if len(brute_state[src]) >= BRUTE_THRESH:
                alert("BRUTE-BURST", src, fname, f"{len(brute_state[src])} failures in {WINDOW}s")
                brute_state[src] = []
    if "SOAPAction" in msg or "formSysCmd" in msg or "___S_O_S_T_R_E_A_MAX___" in msg or "device.rsp" in msg:
        if src:
            alert("CVE-EXPLOIT", src, fname, msg[:120])
    if "EXECUTING DROP" in msg or "DROP received" in msg:
        if src:
            alert("PAYLOAD-DROP", src, fname, msg[:120])
    if "EDR-ALERT" in msg:
        if src:
            alert("EDR", src, fname, msg[:120])
    if "honeypot" in fname and src:
        alert("HONEYPOT", src, fname, msg[:120])
    # Scan sweep detection: any contact from one src against many devices
    if src:
        scan_state.setdefault(src, {})
        scan_state[src].setdefault("targets", set())
        scan_state[src].setdefault("t", time.time())
        scan_state[src]["targets"].add(fname)
        if time.time() - scan_state[src]["t"] > WINDOW:
            if len(scan_state[src]["targets"]) >= SCAN_THRESH:
                alert("SCAN-SWEEP", src, ",".join(list(scan_state[src]["targets"])[:5]),
                      f"{len(scan_state[src]['targets'])} distinct targets in {WINDOW}s")
            scan_state[src] = {"targets": set(), "t": time.time()}


def main():
    open(ALERT_FILE, "a").close()
    print(f"{now()} IDS up dir={EVIDENCE_DIR} ips={IPS} scan_thr={SCAN_THRESH} brute_thr={BRUTE_THRESH} window={WINDOW}", flush=True)
    # position map: fname -> current offset
    positions = {}
    while True:
        for fname in glob.glob(os.path.join(EVIDENCE_DIR, "*.log")):
            # never process our own alert output (feedback loop)
            if os.path.abspath(fname) == os.path.abspath(ALERT_FILE):
                continue
            try:
                sz = os.path.getsize(fname)
            except OSError:
                continue
            pos = positions.get(fname, 0)
            if sz < pos:
                pos = 0  # rotated
            if sz == pos:
                continue
            with open(fname, "r", errors="replace") as f:
                f.seek(pos)
                for line in f:
                    process_line(fname, line)
                positions[fname] = f.tell()
        time.sleep(1)


if __name__ == "__main__":
    main()
