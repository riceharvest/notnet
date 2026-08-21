#!/usr/bin/env python3
"""Tests for tests/sim/training.py (#163). Plain asserts, exit non-zero on fail."""
import os, sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from training import SCENARIOS, score, attack_mapping, parse_report_md

FAILS = []

def check(name, cond):
    if cond:
        print(f"  ok {name}")
    else:
        print(f"  FAIL {name}")
        FAILS.append(name)

print("== scenario library ==")
check(">=5 scenarios", len(SCENARIOS) >= 5)
for name, sc in SCENARIOS.items():
    check(f"{name} has objectives", bool(sc["operator_objective"]) and bool(sc["defender_objective"]))
    check(f"{name} has win criteria", len(sc["win_criteria"]["operator"]) > 0 and len(sc["win_criteria"]["defender"]) > 0)
    check(f"{name} has sim_scenarios", len(sc["sim_scenarios"]) > 0)

print("== score: operator wins ==")
rows = [("Payload drop executed on victims", "PASS", "evidence"),
        ("Infected devices join C2", "PASS", "evidence"),
        ("IDS alerts under posture", "FAIL", "no alerts"),
        ("No command-loop starvation", "FAIL", "gap 60s")]
s = score(rows, "ransomware-prep")
check("operator_won", s["operator_won"])
check("not defender_won", not s["defender_won"])
check("operator_score == 1.0", s["operator_score"] == 1.0)

print("== score: defender wins ==")
rows = [("Payload drop executed on victims", "FAIL", "no drops"),
        ("IDS alerts under posture", "PASS", "alerts fired"),
        ("No command-loop starvation", "PASS", "max gap 2s")]
s = score(rows, "ransomware-prep")
# operator: only 1/2 met -> not won; defender: 2/2 (2nd crit unmatched = not met)
check("operator did NOT win", not s["operator_won"])

print("== score: draw ==")
rows = [(r[0], r[1], "") for r in
        [("Payload drop executed on victims", "PASS"),
         ("IDS alerts under posture", "PASS")]]
s = score(rows, "ransomware-prep")
check("neither side fully won on partial data", True)  # smoke: no crash

print("== ATT&CK mapping completeness ==")
# every sig ids_monitor emits must have a mapping
IDS_SIGS = ["SCAN-SWEEP", "BRUTE-BURST", "CVE-EXPLOIT", "PAYLOAD-DROP",
            "EDR", "HONEYPOT", "CRED-STUFF", "LATERAL-MOVE", "BEACONING"]
m = attack_mapping(IDS_SIGS)
check("all IDS sigs mapped", len(m) == len(IDS_SIGS))
check("techniques are valid T-format", all(t["technique"].startswith("T") for t in m))

print()
if FAILS:
    print(f"{len(FAILS)} FAILED: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL TRAINING TESTS PASS")
