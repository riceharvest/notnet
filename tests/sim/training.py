#!/usr/bin/env python3
"""notnet training mode — scenario library + scoring (#163).

Defender-vs-operator exercises: run sim scenarios, score both sides against
win criteria, generate an ATT&CK-mapped after-action report.

Usage:
  from training import SCENARIOS, score, after_action_report
  # or: python3 run_training.py --scenario ransomware-prep --posture standard
"""
import json
import os
import re
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPORTS = os.path.join(REPO, "tests", "sim", "reports")
EVIDENCE = os.path.join(REPO, "tests", "sim", "evidence")

# alert sig -> MITRE ATT&CK technique (must cover every sig ids_monitor emits)
SIG_TO_TECHNIQUE = {
    "SCAN-SWEEP":   ("T1046", "Network Service Scanning"),
    "BRUTE-BURST":  ("T1110", "Brute Force"),
    "CVE-EXPLOIT":  ("T1190", "Exploit Public-Facing Application"),
    "PAYLOAD-DROP": ("T1105", "Ingress Tool Transfer"),
    "EDR":          ("T1562", "Impair Defenses"),
    "HONEYPOT":     ("T1046", "Network Service Scanning"),
    "CRED-STUFF":   ("T1110", "Brute Force"),
    "LATERAL-MOVE": ("T1021", "Remote Services"),
    "BEACONING":    ("T1071", "Application Layer Protocol"),
    "THREAT-SCORE": ("T1059", "Command and Scripting Interpreter"),
}

SCENARIOS = {
    "ransomware-prep": {
        "name": "Ransomware Preparation",
        "description": "Operator spreads and persists; defender detects the "
                       "kill chain before persistence lands.",
        "operator_objective": "Achieve payload drop on >=2 devices with "
                              "persistence enabled.",
        "defender_objective": "Raise CVE-EXPLOIT or PAYLOAD-DROP alerts for "
                              "every infected device within the window.",
        "win_criteria": {
            "operator": ["Payload drop executed on victims",
                         "Infected devices join C2"],
            "defender": ["IDS alerts under posture",
                         "No command-loop starvation"],
        },
        "sim_scenarios": ["c2-drive", "autonomous"],
        "posture": "standard",
    },
    "cryptomining": {
        "name": "Cryptomining Beacon Detection",
        "description": "Operator maintains steady C2 check-ins; defender "
                       "flags beaconing regularity.",
        "operator_objective": "Sustain heartbeats across the window without "
                              "containment.",
        "defender_objective": "BEACONING detector fires with confidence >0.8.",
        "win_criteria": {
            "operator": ["Autonomous propagation delivers payloads"],
            "defender": ["No command-loop starvation",
                         "exfil_creds command dispatched"],
        },
        "sim_scenarios": ["autonomous", "monetization"],
        "posture": "lax",
    },
    "data-exfil": {
        "name": "Data Exfiltration",
        "description": "Operator harvests and exfiltrates credentials; "
                       "defender catches exfil traffic.",
        "operator_objective": "Complete exfil_creds cycle with non-empty "
                              "payload.",
        "defender_objective": "Sigma exfil_creds rule fires on the evidence.",
        "win_criteria": {
            "operator": ["exfil_creds command dispatched",
                         "Infected devices join C2"],
            "defender": ["IDS alerts under posture"],
        },
        "sim_scenarios": ["c2-drive", "monetization"],
        "posture": "standard",
    },
    "ddos-staging": {
        "name": "DDoS Staging via Relay/Proxy",
        "description": "Operator stages relay chains and SOCKS5 proxies; "
                       "defender maps the ORB infrastructure.",
        "operator_objective": "Establish proxy + relay on compromised hosts.",
        "defender_objective": "Suricata relay_via_chain + Sigma proxy_tunnel "
                              "both fire.",
        "win_criteria": {
            "operator": ["SOCKS5: target sees proxied request",
                         "Relay chain hop ACKs"],
            "defender": ["SOCKS5 traffic flows through bot",
                         "No command-loop starvation"],
        },
        "sim_scenarios": ["c2-drive", "remaining-parity"],
        "posture": "hardened",
    },
    "persistence-challenge": {
        "name": "Persistence Challenge",
        "description": "Operator installs persistence; defender proves it "
                       "survives reboot AND generates detection.",
        "operator_objective": "Persistence survives a container restart with "
                              "the same bot_tag.",
        "defender_objective": "Sigma persistence rule matches the systemd/cron "
                              "drop.",
        "win_criteria": {
            "operator": ["Persistence: device infected before reboot",
                         "Persistence: same tag after reboot"],
            "defender": ["IDS alerts under posture"],
        },
        "sim_scenarios": ["remaining-parity"],
        "posture": "standard",
    },
}


def score(rows, scenario_name):
    """Score parity-report rows against a scenario's win criteria.

    rows: list of (claim, result, evidence) tuples (run_sim Report.rows).
    Returns {scenario, operator_score, defender_score, operator_won,
             defender_won, per_criterion}.
    """
    sc = SCENARIOS[scenario_name]
    claims = {}
    for claim, result, evidence in rows:
        claims[claim] = (result, evidence)

    per_criterion = []
    op_met = df_met = 0
    op_total = df_total = 0
    for side in ("operator", "defender"):
        crits = sc["win_criteria"][side]
        met_count = 0
        for c in crits:
            matched_claim, result, evidence = None, None, ""
            for claim_key, (res, ev) in claims.items():
                if c.lower() in claim_key.lower() or claim_key.lower() in c.lower():
                    matched_claim, result, evidence = claim_key, res, ev
                    break
            met = result == "PASS" if result else False
            if met:
                met_count += 1
            per_criterion.append({"side": side, "criterion": c,
                                  "met": met,
                                  "evidence": evidence[:120] if evidence else
                                  (result or "not exercised")})
        if side == "operator":
            op_met = met_count
            op_total = len(crits)
        else:
            df_met = met_count
            df_total = len(crits)

    return {"scenario": scenario_name,
            "name": sc["name"],
            "operator_score": round(op_met / max(1, op_total), 2),
            "defender_score": round(df_met / max(1, df_total), 2),
            "operator_won": op_met == op_total,
            "defender_won": df_met == df_total,
            "per_criterion": per_criterion}


def parse_report_md(path):
    """Parse a parity report markdown table back into rows."""
    rows = []
    for ln in open(path, encoding="utf-8"):
        m = re.match(r"^\| (.+?) \| (PASS|FAIL|SKIP) \| (.+?) \|$", ln)
        if m and m.group(1) != "Claim":
            rows.append((m.group(1), m.group(2), m.group(3)))
    return rows


def attack_mapping(observed_sigs):
    """Map observed alert signatures to ATT&CK techniques."""
    out = []
    for sig in observed_sigs:
        t = SIG_TO_TECHNIQUE.get(sig)
        if t:
            out.append({"signature": sig, "technique": t[0], "name": t[1]})
    return out


def after_action_report(scenario_name, scored):
    """Generate an after-action markdown report."""
    sc = SCENARIOS[scenario_name]
    lines = [
        f"# After-Action Report — {sc['name']}",
        "",
        f"Scenario: `{scenario_name}` | Posture: `{sc['posture']}`",
        f"Generated: {datetime.now().isoformat()}",
        "",
        "## Objectives",
        f"- **Operator**: {sc['operator_objective']}",
        f"- **Defender**: {sc['defender_objective']}",
        "",
        "## Scores",
        f"- Operator: **{scored['operator_score']:.0%}**"
        f"{' WON' if scored['operator_won'] else ''}",
        f"- Defender: **{scored['defender_score']:.0%}**"
        f"{' WON' if scored['defender_won'] else ''}",
        "",
        "## Criteria",
        "| Side | Criterion | Met | Evidence |",
        "|---|---|---|---|",
    ]
    for pc in scored["per_criterion"]:
        lines.append(f"| {pc['side']} | {pc['criterion']} "
                     f"| {'Y' if pc['met'] else 'N'} | {pc['evidence']} |")

    # ATT&CK mapping from evidence alerts
    sigs_seen = set()
    alerts = os.path.join(EVIDENCE, "ids_alerts.log")
    if os.path.isfile(alerts):
        for ln in open(alerts, errors="replace"):
            m = re.search(r"sig=(\S+)", ln)
            if m:
                sigs_seen.add(m.group(1))
    techniques = attack_mapping(sorted(sigs_seen))
    lines += ["", "## ATT&CK Mapping", "", "| Signature | Technique | Name |",
              "|---|---|---|"]
    for t in techniques:
        lines.append(f"| {t['signature']} | {t['technique']} | {t['name']} |")
    if not techniques:
        lines.append("| (none) | - | no IDS alerts captured |")

    # Detection gaps
    gaps = [pc for pc in scored["per_criterion"] if not pc["met"]]
    lines += ["", "## Detection Gaps"]
    if gaps:
        for g in gaps:
            lines.append(f"- [{g['side']}] {g['criterion']}: {g['evidence']}")
    else:
        lines.append("- none — all criteria met")

    os.makedirs(REPORTS, exist_ok=True)
    out = os.path.join(REPORTS,
                       f"aar-{scenario_name}-{int(datetime.now().timestamp())}.md")
    with open(out, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"AAR written: {out}")
    return out
