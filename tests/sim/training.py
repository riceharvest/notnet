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
    "LATERAL-MOVEMENT": ("T1021", "Remote Services"),
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


def _norm(s):
    """Normalize a criterion/claim for matching: lowercase, punctuation folded
    to single spaces (#332)."""
    return re.sub(r"[^a-z0-9]+", " ", s.lower()).strip()


# Explicit aliases (#332): normalized criterion -> normalized claim fragment.
# Used when the report's claim wording legitimately differs from the win
# criterion's wording. One-way (criterion binds INTO claims) — never the
# reverse, so a short criterion can no longer bind to an unrelated longer
# claim that merely contains it.
CRITERION_ALIASES = {
    "persistence same tag after reboot":
        "persistence payload relaunches after device reboot",
    "persistence device infected before reboot":
        "persistence device infected before reboot baseline heartbeat",
    "relay chain hop acks":
        "relay on command dispatched listener starts",
    "socks5 traffic flows through bot":
        "socks5 client handshake connect through bot proxy",
}


def _bind_criterion(criterion, claims):
    """All report rows bound to a criterion: exact normalized match first,
    then alias, then one-way containment of the criterion in the claim."""
    cn = _norm(criterion)
    exact = [(k,) + claims[k] for k in claims if _norm(k) == cn]
    if exact:
        return exact
    an = _norm(CRITERION_ALIASES.get(cn, criterion))
    return [(k,) + claims[k] for k in claims if an in _norm(k)]


def score(rows, scenario_name):
    """Score parity-report rows against a scenario's win criteria.

    rows: list of (claim, result, evidence) tuples (run_sim Report.rows).
    Matching semantics (#332): criteria bind to claims by exact normalized
    match, then explicit alias, then ONE-WAY containment (criterion inside
    claim). A bound result of SKIP is excluded from the denominator (the
    check was legitimately inapplicable, e.g. IDS alerts under lax posture);
    an unbound criterion stays in the denominator as not met ("not
    exercised").
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
        total_count = 0
        for c in crits:
            hits = _bind_criterion(c, claims)
            # Priority across multiple bound rows: PASS > FAIL > SKIP/none.
            results = [res for _, res, _ in hits]
            if "PASS" in results:
                met, effective = True, "PASS"
            elif "FAIL" in results:
                met, effective = False, "FAIL"
            elif "SKIP" in results:
                met, effective = False, "SKIP"
            else:
                met, effective = False, None
            evidence = hits[0][2] if hits else ""
            if effective == "SKIP":
                # legitimately inapplicable — excluded from the denominator
                detail = "; ".join(h[1][:120] for h in hits[:1]) or "skipped"
                per_criterion.append({"side": side, "criterion": c,
                                      "met": False, "excluded": True,
                                      "evidence": f"SKIP (not counted): {detail}"})
                continue
            total_count += 1
            if met:
                met_count += 1
            per_criterion.append({"side": side, "criterion": c,
                                  "met": met,
                                  "evidence": evidence[:120] if evidence else
                                  (effective or "not exercised")})
        if side == "operator":
            op_met = met_count
            op_total = total_count
        else:
            df_met = met_count
            df_total = total_count

    return {"scenario": scenario_name,
            "name": sc["name"],
            "operator_score": round(op_met / max(1, op_total), 2),
            "defender_score": round(df_met / max(1, df_total), 2),
            "operator_won": op_total > 0 and op_met == op_total,
            "defender_won": df_total > 0 and df_met == df_total,
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

    # ATT&CK mapping from evidence alerts (#337): BOTH alert sources count —
    # ids_alerts.log (`sig=` lines from the log-watcher) and Suricata's
    # eve.json (`alert.signature` JSON fields), matching what run_sim S8
    # accepts as first-class IDS evidence.
    sigs_seen = set()
    alerts = os.path.join(EVIDENCE, "ids_alerts.log")
    if os.path.isfile(alerts):
        for ln in open(alerts, errors="replace"):
            m = re.search(r"sig=(\S+)", ln)
            if m:
                sigs_seen.add(m.group(1))
    eve = os.path.join(EVIDENCE, "eve.json")
    if os.path.isfile(eve):
        for ln in open(eve, errors="replace"):
            if '"alert"' not in ln:
                continue
            m = re.search(r'"signature"\s*:\s*"([^"]+)"', ln)
            # sim Suricata msgs embed the IDS sig name ("notnet CVE-EXPLOIT
            # HG532 ..."), so match known sig names inside the value
            sigval = m.group(1) if m else ln
            for known in SIG_TO_TECHNIQUE:
                if known in sigval:
                    sigs_seen.add(known)
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
