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
  EDR           EDR-ALERT marker from a PC device
  HONEYPOT      any contact with a honeypot device

Behavioral detectors (issue #156) with confidence scoring:
  BEACONING         regular C2 heartbeat inter-arrivals (regularity >0.8,
                    mean interval <=10s); confidence = regularity
  LATERAL-MOVEMENT  internal src hitting the same port on >=3 internal dsts
                    within SIM_LATERAL_WINDOW; confidence = min(1, targets/5)
  CRED-STUFF        >=SIM_STUFF_THRESH (50) auth failures from one src in
                    SIM_STUFF_WINDOW (10s); confidence = min(1, fails/50)
  THREAT-SCORE      weighted max over active signal confidences, emitted to
                    ids_alerts.log when it crosses SIM_THREAT_SCORE_THRESH (0.5)

Evidence files are per-device: /evidence/<device-id>.log (device.py format)
plus /evidence/http.log, /evidence/cowrie-*.log (Cowrie JSON lines).
"""
import glob
import os
import re
import sys
import time
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import siem_emit  # noqa: E402  (SIEM fanout backends, issue #155)

EVIDENCE_DIR = os.environ.get("SIM_EVIDENCE", "/evidence")
ALERT_FILE = os.environ.get("SIM_ALERT_FILE", "/evidence/ids_alerts.log")
IPS = os.environ.get("SIM_IPS", "0") == "1"
BLACKLIST = os.environ.get("SIM_BLACKLIST", "/evidence/ips_blacklist")
SCAN_THRESH = int(os.environ.get("SIM_SCAN_THRESH", "20"))
BRUTE_THRESH = int(os.environ.get("SIM_BRUTE_THRESH", "8"))
WINDOW = int(os.environ.get("SIM_IDS_WINDOW", "30"))

# Behavioral detection (issue #156)
BEACON_MIN_INTERVALS = int(os.environ.get("SIM_BEACON_MIN_INTERVALS", "5"))
BEACON_REGULARITY = float(os.environ.get("SIM_BEACON_REGULARITY", "0.8"))
BEACON_MAX_INTERVAL = float(os.environ.get("SIM_BEACON_MAX_INTERVAL", "10"))
LATERAL_MIN_TARGETS = int(os.environ.get("SIM_LATERAL_MIN_TARGETS", "3"))
LATERAL_WINDOW = int(os.environ.get("SIM_LATERAL_WINDOW", str(WINDOW)))
LATERAL_CONF_DIVISOR = float(os.environ.get("SIM_LATERAL_CONF_DIVISOR", "5"))
STUFF_THRESH = int(os.environ.get("SIM_STUFF_THRESH", "50"))
STUFF_WINDOW = float(os.environ.get("SIM_STUFF_WINDOW", "10"))
STUFF_CONF_DIVISOR = float(os.environ.get("SIM_STUFF_CONF_DIVISOR", "50"))
THREAT_SCORE_THRESH = float(os.environ.get("SIM_THREAT_SCORE_THRESH", "0.5"))
INTERNAL_PREFIX = os.environ.get("SIM_INTERNAL_NET", "172.29.")
SIGNAL_WEIGHTS = {
    "BEACONING": float(os.environ.get("SIM_W_BEACONING", "1.0")),
    "LATERAL-MOVEMENT": float(os.environ.get("SIM_W_LATERAL", "0.9")),
    "CRED-STUFF": float(os.environ.get("SIM_W_CRED-STUFF", "0.85")),
}

lock = threading_lock = None
import threading
lock = threading.Lock()

# src -> {target_set, time}  for scan detection
scan_state = {}
# src -> {fail_count, time}  for brute detection
brute_state = {}
# --- behavioral state (issue #156) ---
# src -> [evidence ts, ...]  for beaconing
beacon_state = {}
# (src, port) -> [(ts, dst), ...]  for lateral movement
lateral_state = {}
# src -> [ts, ...]  for cred stuffing
stuff_state = {}
# src -> {sig: confidence}  active behavioral signals
threat_signals = {}
# src -> last emitted composite score
threat_emitted = {}
beacon_alerted = {}
stuff_alerted = {}
lateral_alerted = {}
blacklisted = set()


def is_internal(ip):
    return ip is not None and ip.startswith(INTERNAL_PREFIX)


SERVICE_PORTS = {"TELNET": 23, "SSH": 22, "SMB": 445, "REDIS": 6379, "HTTP": 80, "TBK": 80}


def service_port(msg):
    """Best-effort port for an evidence message; default HTTP/80."""
    for name, port in SERVICE_PORTS.items():
        if name in msg.upper():
            return port
    return 80


def parse_line_ts(line):
    """Epoch seconds from the leading ISO timestamp of an evidence line."""
    try:
        return datetime.fromisoformat(line.split(" ", 1)[0]).timestamp()
    except (ValueError, IndexError, OverflowError):
        return None


def _stdev(values):
    n = len(values)
    if n < 2:
        return 0.0
    mean = sum(values) / n
    return (sum((v - mean) ** 2 for v in values) / (n - 1)) ** 0.5


# ---------------------------------------------------------------------------
# Pure behavioral detectors (testable without file I/O).
# Each takes a list of (ts, src, dst[, port]) tuples with epoch-float ts and
# returns a list of hits: (src, confidence, detail).
# ---------------------------------------------------------------------------

def detect_beaconing(events):
    """Flag srcs whose inter-arrival times are highly regular and fast.

    regularity = 1.0 - stdev/mean over the last N>=BEACON_MIN_INTERVALS
    intervals; flag when regularity > BEACON_REGULARITY and mean interval
    <= BEACON_MAX_INTERVAL. Confidence = regularity clamped 0..1.
    """
    by_src = {}
    for ts, src, _dst in sorted(events):
        by_src.setdefault(src, []).append(ts)
    hits = []
    for src, times in by_src.items():
        intervals = [times[i] - times[i - 1] for i in range(1, len(times))]
        if len(intervals) < max(BEACON_MIN_INTERVALS, 5):
            continue
        recent = intervals[-max(BEACON_MIN_INTERVALS, 5):]
        mean = sum(recent) / len(recent)
        if mean <= 0:
            continue
        regularity = 1.0 - (_stdev(recent) / mean)
        regularity = max(0.0, min(1.0, regularity))
        if regularity > BEACON_REGULARITY and mean <= BEACON_MAX_INTERVAL:
            hits.append((src, regularity,
                         f"{len(recent)} intervals mean={mean:.2f}s regularity={regularity:.2f}"))
    return hits


def detect_lateral(events):
    """Flag an internal src hitting the same port across many internal dsts.

    events: (ts, src, dst, port). Flag when >= LATERAL_MIN_TARGETS distinct
    dst IPs are touched within LATERAL_WINDOW seconds. Confidence is
    min(1.0, targets / LATERAL_CONF_DIVISOR).
    """
    by_key = {}
    for ts, src, dst, port in sorted(events):
        by_key.setdefault((src, port), []).append((ts, dst))
    hits = []
    for (src, port), evs in by_key.items():
        left = 0
        counts = {}
        emitted = 0
        for right, (ts, dst) in enumerate(evs):
            counts[dst] = counts.get(dst, 0) + 1
            while ts - evs[left][0] > LATERAL_WINDOW:
                old = evs[left][1]
                counts[old] -= 1
                if counts[old] == 0:
                    del counts[old]
                left += 1
            distinct = len(counts)
            if distinct >= LATERAL_MIN_TARGETS and distinct > emitted:
                emitted = distinct
                conf = min(1.0, distinct / LATERAL_CONF_DIVISOR)
                hits.append((src, conf,
                             f"{distinct} internal targets on port {port} in {LATERAL_WINDOW}s"))
    return hits


def detect_cred_stuffing(events):
    """Flag high-rate auth-failure bursts from one src.

    events: (ts, src). Flag when >= STUFF_THRESH failures occur within
    STUFF_WINDOW seconds (high-rate variant of BRUTE-BURST). Confidence is
    min(1.0, failures / STUFF_CONF_DIVISOR).
    """
    by_src = {}
    for ts, src in events:
        by_src.setdefault(src, []).append(ts)
    hits = []
    for src, times in by_src.items():
        times.sort()
        left = 0
        emitted = 0
        for right, ts in enumerate(times):
            while ts - times[left] > STUFF_WINDOW:
                left += 1
            count = right - left + 1
            if count >= STUFF_THRESH and count > emitted:
                emitted = count
                conf = min(1.0, count / STUFF_CONF_DIVISOR)
                hits.append((src, conf, f"{count} auth failures in {STUFF_WINDOW}s"))
    return hits


def composite_threat_score(confidences):
    """Weighted max over active behavioral signals.

    confidences: {signal_name: confidence}. Returns the composite score.
    """
    return max((SIGNAL_WEIGHTS.get(sig, 1.0) * conf
                for sig, conf in confidences.items()), default=0.0)


def update_threat_score(src):
    """Emit a THREAT-SCORE line when the composite crosses the threshold."""
    confs = threat_signals.get(src)
    if not confs:
        return
    score = composite_threat_score(confs)
    if score < THREAT_SCORE_THRESH:
        return
    if score <= threat_emitted.get(src, 0.0):
        return
    threat_emitted[src] = score
    detail = " ".join(f"{sig}={conf:.2f}" for sig, conf in sorted(confs.items()))
    line = f"{now()} THREAT-SCORE src={src} score={score:.2f} {detail}"
    with lock:
        with open(ALERT_FILE, "a") as f:
            f.write(line + "\n")
        print(line, flush=True)


def now():
    return datetime.now(timezone.utc).isoformat()


def alert(sig, src, dst, detail):
    ts = now()
    line = f"{ts} ALERT sig={sig} src={src} dst={dst} {detail}"
    with lock:
        with open(ALERT_FILE, "a") as f:
            f.write(line + "\n")
        print(line, flush=True)
    # SIEM fanout (issue #155): no-op unless SIM_SIEM_* is configured.
    try:
        siem_emit.get_emitter().emit(sig, src, dst, detail, timestamp=ts)
    except Exception as exc:
        print(f"{ts} SIEM emit error: {exc}", file=sys.stderr, flush=True)
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
    # --- BEACONING: C2 heartbeat inter-arrival regularity per src ---
    # Uses the evidence line's own ISO timestamp: wall-clock tail lag would
    # inject poll-interval jitter and destroy the regularity signal.
    if os.path.basename(fname) == "http.log" and "C2 heartbeat from" in line and src:
        t = parse_line_ts(line)
        if t is not None:
            times = beacon_state.setdefault(src, [])
            times.append(t)
            del times[:-200]  # bound memory
            for hsrc, conf, detail in detect_beaconing([(x, src, fname) for x in times]):
                if hsrc != src:
                    continue
                prev = beacon_alerted.get(src, 0.0)
                if conf > prev:
                    beacon_alerted[src] = conf
                    alert("BEACONING", src, "c2", detail + f" confidence={conf:.2f}")
                    threat_signals.setdefault(src, {})["BEACONING"] = conf
                    update_threat_score(src)
    # Scan sweep: count distinct device names per src
    if "AUTH FAIL" in msg or "Login incorrect" in msg:
        if src:
            now_t = time.time()
            brute_state.setdefault(src, []).append(now_t)
            brute_state[src] = [t for t in brute_state[src] if now_t - t < WINDOW]
            if len(brute_state[src]) >= BRUTE_THRESH:
                alert("BRUTE-BURST", src, fname, f"{len(brute_state[src])} failures in {WINDOW}s")
                brute_state[src] = []
            # CRED-STUFF: high-rate variant (>STUFF_THRESH failures in STUFF_WINDOW s)
            stuff = stuff_state.setdefault(src, [])
            stuff.append(now_t)
            del stuff[:-500]
            stuff[:] = [x for x in stuff if now_t - x <= STUFF_WINDOW]
            for hsrc, conf, detail in detect_cred_stuffing([(x, src) for x in stuff]):
                if hsrc != src:
                    continue
                if src not in stuff_alerted or conf > stuff_alerted[src]:
                    stuff_alerted[src] = conf
                    alert("CRED-STUFF", src, fname, detail + f" confidence={conf:.2f}")
                    threat_signals.setdefault(src, {})["CRED-STUFF"] = conf
                    update_threat_score(src)
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
    # --- LATERAL-MOVEMENT: one internal src, same port, many internal dsts ---
    # dst is the evidence-owning device (its log we are tailing); port is
    # inferred from the service keyword. Matched on the raw line because
    # parse_device_line folds the leading service token into its timestamp.
    if is_internal(src):
        port = service_port(line)
        key = (src, port)
        events = lateral_state.setdefault(key, [])
        events.append((time.time(), os.path.basename(fname)))
        del events[:-500]
        cut = time.time() - LATERAL_WINDOW
        events[:] = [e for e in events if e[0] >= cut]
        for hsrc, conf, detail in detect_lateral([(ts, src, dst, port) for ts, dst in events]):
            if hsrc != src:
                continue
            if conf > lateral_alerted.get(key, 0.0):
                lateral_alerted[key] = conf
                alert("LATERAL-MOVEMENT", src, fname, detail + f" confidence={conf:.2f}")
                threat_signals.setdefault(src, {})["LATERAL-MOVEMENT"] = conf
                update_threat_score(src)


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
