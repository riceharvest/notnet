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
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from training import SCENARIOS, score, after_action_report, parse_report_md

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SIM = os.path.join(REPO, "tests", "sim")


def session_reports(started_before=None, started_at=None):
    """All parity reports produced during this invocation (#334).

    Chained scenarios (e.g. ransomware-prep's c2-drive + autonomous) each
    write their own parity-<ts>.md; scoring only the newest one silently
    dropped every claim from the earlier runs. Collect every report with a
    mtime at/after the session start instead.
    """
    reports = sorted(glob.glob(os.path.join(SIM, "reports", "parity-*.md")))
    if started_at is not None:
        reports = [r for r in reports if os.path.getmtime(r) >= started_at - 1]
    if started_before is not None:
        reports = [r for r in reports if os.path.getmtime(r) <= started_before + 1]
    return reports


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

    session_start = time.time()
    scenarios = sc["sim_scenarios"]
    # Run each sim scenario via run-sim.sh.
    # --keep semantics (#335): --keep suppresses THAT run's own teardown, so
    # pass it on all but the LAST scenario — earlier runs leave the fleet up
    # for the next chained scenario to reuse (no full down/up per hop), and
    # the final run (without --keep) tears the whole stack down so nothing
    # leaks.
    for i, sim_scenario in enumerate(scenarios):
        cmd = [os.path.join(SIM, "run-sim.sh"),
               "--scenario", sim_scenario, "--posture", posture]
        if i < len(scenarios) - 1:
            cmd += ["--keep"]  # leave fleet up for the next chained scenario
        print(f"\n=== Running: {' '.join(cmd)}")
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
        if r.returncode != 0:
            print(f"WARNING: {sim_scenario} exited {r.returncode} — scoring on available evidence")

    # Score ALL parity reports from this session (#334), merged.
    reports = session_reports(started_at=session_start)
    if not reports:
        print("ERROR: no parity report produced during this training run",
              file=sys.stderr)
        return 1
    rows = []
    for rep in reports:
        rep_rows = parse_report_md(rep)
        if not rep_rows:
            print(f"WARNING: no rows parsed from {rep}", file=sys.stderr)
            continue
        rows.extend(rep_rows)
        print(f"  scored report: {os.path.basename(rep)} ({len(rep_rows)} claims)")
    if not rows:
        print("ERROR: no rows parsed from any session parity report", file=sys.stderr)
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
