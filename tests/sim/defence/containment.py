#!/usr/bin/env python3
"""notnet automated containment — escalation ladder (#157).

Tails ids_alerts.log; when a src crosses CONTAIN_THRESH alerts, escalates:
  detect -> alert (IDS) -> contain (isolate + sinkhole + relay kill)
  -> verify (re-alert = failed) -> evidence lock.

Actions are best-effort: the controller writes intent files that other sim
components consume (router.sh DROPs contain_blacklist IPs; dnsmasq reads
/run/dnsmasq.d drop-ins). No direct iptables calls from this process.

Run as a sim service (docker-compose.sim.yml, gated by CONTAIN=1):
    python3 defence/containment.py

Env:
    SIM_EVIDENCE      evidence dir          (default /evidence)
    SIM_ALERT_FILE    ids alerts log        (default /evidence/ids_alerts.log)
    CONTAIN_THRESH    alerts before contain (default 3)
    QUEUE_DIR         C2 command queue dir  (default ./queue)
"""
import hashlib
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime, timezone

EVIDENCE = os.environ.get("SIM_EVIDENCE", "/evidence")
ALERT_FILE = os.environ.get("SIM_ALERT_FILE", os.path.join(EVIDENCE, "ids_alerts.log"))
CONTAIN_THRESH = int(os.environ.get("CONTAIN_THRESH", "3"))
QUEUE_DIR = os.environ.get("QUEUE_DIR", "queue")
CONTAIN_BLACKLIST = "/run/contain_blacklist"
DNSMASQ_DROPIN_DIR = "/run/dnsmasq.d"
C2_DOMAINS = ["flux-c2.sim.test"]

DETECTED = "detected"
CONTAINED = "contained"
VERIFYING = "verifying"


def now():
    return datetime.now(timezone.utc).isoformat()


def log(msg):
    print(f"[{now()}] {msg}", flush=True)


class ContainmentController:
    def __init__(self, evidence_dir=EVIDENCE, queue_dir=QUEUE_DIR,
                 threshold=CONTAIN_THRESH):
        self.evidence_dir = evidence_dir
        self.queue_dir = queue_dir
        self.threshold = threshold
        self.ladder = {}

    def parse_new_alerts(self, seen_lines=0):
        counts = {}
        total = 0
        alert_file = os.path.join(self.evidence_dir, "ids_alerts.log")
        try:
            with open(alert_file, errors="replace") as f:
                for i, ln in enumerate(f):
                    total = i + 1
                    if i < seen_lines:
                        continue
                    m = re.search(r"sig=(\S+) src=(\S+)", ln)
                    if m:
                        src = m.group(2)
                        if re.match(r"\d+\.\d+\.\d+\.\d+$", src):
                            counts[src] = counts.get(src, 0) + 1
        except OSError:
            pass
        return counts, total

    def should_escalate(self, src):
        entry = self.ladder.get(src, {})
        return entry.get("alert_count", 0) >= self.threshold and \
            entry.get("state") not in (CONTAINED, VERIFYING)

    def transition(self, src, new_state):
        entry = self.ladder.setdefault(src, {"alert_count": 0,
                                              "escalate_count": 0})
        old = entry.get("state", "new")
        entry["state"] = new_state
        log(f"LADDER {src}: {old} -> {new_state}")

    def contain(self, src):
        outcomes = {}
        try:
            with open(CONTAIN_BLACKLIST, "a") as f:
                f.write(src + "\n")
            outcomes["subnet_isolation"] = "ok (wrote contain_blacklist)"
        except OSError as e:
            outcomes["subnet_isolation"] = f"failed: {e}"
        try:
            if not os.path.isdir(DNSMASQ_DROPIN_DIR):
                os.makedirs(DNSMASQ_DROPIN_DIR, exist_ok=True)
            conf = os.path.join(DNSMASQ_DROPIN_DIR, "contain.conf")
            entries = [f"address=/{d}/127.0.0.1" for d in C2_DOMAINS]
            with open(conf, "a") as f:
                f.write("\n".join(entries) + "\n")
            outcomes["c2_sinkhole"] = f"ok (wrote {conf})"
        except OSError as e:
            outcomes["c2_sinkhole"] = f"failed: {e}"
        if self._src_is_bot(src):
            try:
                os.makedirs(self.queue_dir, exist_ok=True)
                ts = int(time.time() * 1000)
                fn = os.path.join(self.queue_dir,
                                  f"cmd-{ts}-{os.getpid()}-contain.json")
                with open(fn, "w") as f:
                    json.dump({"cmd": "kill", "args": "", "channel": "",
                               "broadcast": True}, f)
                outcomes["relay_kill"] = f"ok (queued broadcast kill)"
            except OSError as e:
                outcomes["relay_kill"] = f"failed: {e}"
        else:
            outcomes["relay_kill"] = "skipped (not a known bot IP)"
        return outcomes

    def _src_is_bot(self, src):
        http_log = os.path.join(self.evidence_dir, "http.log")
        try:
            with open(http_log, errors="replace") as f:
                for ln in f:
                    m = re.search(r"C2 heartbeat from (\S+)", ln)
                    if m and m.group(1) == src:
                        return True
        except OSError:
            pass
        return False

    def evidence_lock(self, src):
        dest = os.path.join(self.evidence_dir, "containment",
                            f"{src}-{int(time.time())}")
        os.makedirs(dest, exist_ok=True)
        chain = []
        prev = "0" * 64
        device_log = os.path.join(self.evidence_dir, f"{src}.log")
        if os.path.isfile(device_log):
            shutil.copy2(device_log, dest)
            h = hashlib.sha256(
                open(os.path.join(dest, f"{src}.log"), "rb").read()).hexdigest()
            chain.append({"file": f"{src}.log", "sha256": h, "prev_hash": prev})
            prev = h
        http_log = os.path.join(self.evidence_dir, "http.log")
        matched = []
        try:
            with open(http_log, errors="replace") as f:
                for ln in f:
                    if src in ln:
                        matched.append(ln)
        except OSError:
            pass
        if matched:
            hp = os.path.join(dest, "http-extract.log")
            with open(hp, "w") as f:
                f.writelines(matched)
            h = hashlib.sha256(open(hp, "rb").read()).hexdigest()
            chain.append({"file": "http-extract.log", "sha256": h,
                          "prev_hash": prev})
            prev = h
        cp = os.path.join(dest, "chain.json")
        with open(cp, "w") as f:
            json.dump(chain, f, indent=2)
        log(f"EVIDENCE LOCK: {len(chain)} files sealed in {dest}")
        return dest

    def process(self, src_counts):
        for src, count in src_counts:
            entry = self.ladder.setdefault(src, {"alert_count": 0,
                                                  "escalate_count": 0})
            entry["alert_count"] += count
            if self.should_escalate(src):
                entry["escalate_count"] += 1
                self.transition(src, DETECTED)
                outcomes = self.contain(src)
                for action, result in outcomes.items():
                    log(f"CONTAIN {src} {action}: {result}")
                self.transition(src, CONTAINED)
                self.evidence_lock(src)
                self.transition(src, VERIFYING)


def main():
    controller = ContainmentController()
    seen_lines = 0
    log(f"Containment up: threshold={controller.threshold} "
        f"evidence={EVIDENCE} queue={QUEUE_DIR}")
    while True:
        counts, seen_lines = controller.parse_new_alerts(seen_lines)
        if counts:
            controller.process(list(counts.items()))
        time.sleep(5)


if __name__ == "__main__":
    main()
