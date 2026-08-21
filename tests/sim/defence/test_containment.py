#!/usr/bin/env python3
"""Tests for tests/sim/defence/containment.py (#157). Plain asserts."""
import json, os, sys, tempfile, shutil

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from containment import (ContainmentController, DETECTED, CONTAINED,
                         VERIFYING, CONTAIN_THRESH)

FAILS = []

def check(name, cond):
    if cond:
        print(f"  ok {name}")
    else:
        print(f"  FAIL {name}")
        FAILS.append(name)

def make_env(tmp, alerts, heartbeats=None):
    ev = os.path.join(tmp, "evidence")
    os.makedirs(ev, exist_ok=True)
    with open(os.path.join(ev, "ids_alerts.log"), "w") as f:
        f.write("\n".join(alerts))
    if heartbeats:
        with open(os.path.join(ev, "http.log"), "w") as f:
            f.write("\n".join(heartbeats))
    queue = os.path.join(tmp, "queue")
    os.makedirs(queue, exist_ok=True)
    return ev, queue

tmp = tempfile.mkdtemp()

print("== threshold: 3 alerts triggers ==")
ev, q = make_env(os.path.join(tmp, "t1"),
                 [f"2026-08-21T15:00:0{i}+00:00 ALERT sig=CVE-EXPLOIT src=10.0.0.1 dst=victim-{i} detail=x" for i in range(3)])
c = ContainmentController(evidence_dir=ev, queue_dir=q, threshold=3)
counts, total = c.parse_new_alerts(0)
check("parsed 3 alerts", sum(counts.values()) == 3)
check("src is 10.0.0.1", "10.0.0.1" in counts)
c.process(list(counts.items()))
entry = c.ladder["10.0.0.1"]
check("escalated at threshold=3", entry["alert_count"] >= 3)
check("state reached VERIFYING", entry["state"] == VERIFYING)

print("== below threshold: no escalation ==")
ev2, q2 = make_env(os.path.join(tmp, "t2"),
                   [f"2026-08-21T15:00:0{i}+00:00 ALERT sig=SCAN-SWEEP src=10.0.0.2 dst=victim detail=x" for i in range(2)])
c2 = ContainmentController(evidence_dir=ev2, queue_dir=q2, threshold=3)
counts2, _ = c2.parse_new_alerts(0)
c2.process(list(counts2.items()))
check("not escalated at 2 alerts", c2.ladder.get("10.0.0.2", {}).get("state") != VERIFYING)

print("== relay kill: bot IP gets broadcast kill queued ==")
hb = ["2026-08-21T15:00:00+00:00 C2 heartbeat from 10.0.0.5 body={\"tag\":\"bot-x\"}"]
ev3, q3 = make_env(os.path.join(tmp, "t3"), 
                   [f"2026-08-21T15:00:0{i}+00:00 ALERT sig=CVE-EXPLOIT src=10.0.0.5 dst=x detail=y" for i in range(3)],
                   hb)
c3 = ContainmentController(evidence_dir=ev3, queue_dir=q3, threshold=3)
counts3, _ = c3.parse_new_alerts(0)
c3.process(list(counts3.items()))
kill_files = [f for f in os.listdir(q3) if f.endswith(".json")]
check("broadcast kill queued for bot IP", len(kill_files) >= 1)
if kill_files:
    data = json.load(open(os.path.join(q3, kill_files[0])))
    check("kill command correct", data["cmd"] == "kill")

print("== evidence lock: files + chain created ==")
containment_dirs = [d for d in os.listdir(os.path.join(ev3, "containment"))] \
    if os.path.isdir(os.path.join(ev3, "containment")) else []
check("evidence dir created", len(containment_dirs) >= 1)
if containment_dirs:
    cd = os.path.join(ev3, "containment", containment_dirs[0])
    check("chain.json exists", os.path.isfile(os.path.join(cd, "chain.json")))
    chain = json.load(open(os.path.join(cd, "chain.json")))
    check("chain has entries", len(chain) >= 1)

print("== re-escalation after failed verify ==")
# simulate: after VERIFYING, feed 3 more alerts -> should re-escalate
c3.should_escalate.__self__.ladder["10.0.0.5"]["state"] = "contained_ok"
c3.ladder["10.0.0.5"]["alert_count"] = 0
more = [("2026-08-21T16:00:0%d+00:00 ALERT sig=CVE-EXPLOIT src=10.0.0.5 dst=x detail=z" % i) for i in range(3)]
with open(os.path.join(ev3, "ids_alerts.log"), "a") as f:
    f.write("\n" + "\n".join(more))
counts4, total4 = c3.parse_new_alerts(total4 := len([l for l in open(os.path.join(ev3, 'ids_alerts.log'))]) - 3) if False else c3.parse_new_alerts(3)
c3.process(list(counts4.items()))
check("re-escalated after new alerts", c3.ladder["10.0.0.5"].get("escalate_count", 0) >= 2)

shutil.rmtree(tmp)
print()
if FAILS:
    print(f"{len(FAILS)} FAILED: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL CONTAINMENT TESTS PASS")
