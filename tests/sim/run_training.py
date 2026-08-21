#!/usr/bin/env python3
"""notnet training-mode CLI (#163).

Runs sim scenarios for a named training scenario, scores both sides,
generates an after-action report.

Usage:
  python3 run_training.py --scenario ransomware-prep --posture standard --operators both
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from training import SCENARIOS, score, after_action_report, parse_report_md

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM = os.path.join(REPO, "tests", "sim")


def find_latest_report():
    reports = sorted(glob.glob(os.path.join(SIM, "reports", "parity-*.md")))
    return reports[-1] if reports else None


def main():
    ap = argparse.ArgumentParser(description="notnet training mode")
    ap.add_argument("--scenario", required=True, choices=sorted(SCENARIOS))
    ap.add_argument("--posture", default=None, choices=["lax", "standard", "hardened"])
    ap.add_argument("--operators", default="both", choices=["bot", "defender", "both"])
    args = ap.parse_args()

    sc = SCENARIOS[args.scenario]
    posture = args.posture or sc["posture"]

    print(f"Training scenario: {sc['name']}")
    print(f"  Operator objective:  {sc['operator_objective']}")
    print(f"  Defender objective:  {sc['defender_objective']}")

    # Run each sim scenario via run-sim.sh
    for sim_scenario in sc["sim_scenarios"]:
        cmd = [os.path.join(SIM, "run-sim.sh"),
               "--scenario", sim_scenario, "--posture", posture]
        if len(sc["sim_scenarios"]) > 1 and sim_scenario != sc["sim_scenarios"][0]:
            cmd += ["--keep"]  # reuse fleet between chained scenarios
        print(f"\n=== Running: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if r.returncode != 0:
            print(f"WARNING: {sim_scenario} exited {r.returncode} — scoring on available evidence")

    # Score from the latest parity report
    report = find_latest_report()
    if not report:
        print("ERROR: no parity report found", file=sys.stderr)
        return 1
    rows = parse_report_md(report)
    if not rows:
        print(f"ERROR: no rows parsed from {report}", file=sys.stderr)
        return 1

    scored = score(rows, args.scenario)
    print(f"\nOperator score: {scored['operator_score']:.0%}")
    print(f"Defender score: {scored['defender_score']:.0%}")

    aar = after_action_report(args.scenario, scored)

    # Determine winner based on --operators focus
    if args.operators == "bot":
        won = scored["operator_won"]
    elif args.operators == "defender":
        won = scored["defender_won"]
    else:
        won = True  # both exercised; report only

    print(f"\nAAR: {aar}")
    return 0 if won else 1


if __name__ == "__main__":
    raise SystemExit(main())
