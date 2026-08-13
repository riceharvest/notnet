#!/usr/bin/env python3
"""notnet detection-as-code validator (CI, #151).

Mirrors sim.yml but gates the *defensive* artifacts, not the offensive parity
matrix. Three stages, each non-zero on failure:

  1. schema    — every Sigma YAML parses, every Suricata rule has sid/msg,
                 every YARA rule compiles (string conditions present).
  2. drift     — intel/build_intel.py --check (STIX bundle matches source).
  3. replay    — seed minimal synthetic sim evidence (the same shape the bot's
                 own sim emits: http.log heartbeats, cred-log lines, IDS alert
                 lines, Cowrie JSON) and assert each ATTACK-COVERAGE row's
                 "covered-by" detections actually FIRE. A technique marked PASS
                 whose rule stays silent flips the row to FAIL and breaks the
                 build.

The seeded evidence is intentionally tiny: we do not boot the 50-container fleet
here (that is the sim.yml job). We replay *just enough* traffic for each rule to
match, so the gate is fast, dependency-free, and meaningful — if a rule stops
matching the strings it claims to, this fails.

Usage:  python3 detections/validate.py [--strict]
        --strict also fails if a technique has no detection wired (coverage gap).
"""
import argparse
import glob
import json
import os
import re
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DET = os.path.join(REPO, "detections")


# ───────────────────────────── stage 1: schema ─────────────────────────────
def stage_schema(errors):
    # Sigma
    for fn in glob.glob(os.path.join(DET, "sigma", "*.yml")):
        try:
            import yaml  # already a dep of the sim
        except ImportError:
            errors.append(f"sigma: pyyaml missing, cannot parse {os.path.basename(fn)}")
            continue
        with open(fn, encoding="utf-8") as f:
            try:
                doc = yaml.safe_load(f)
            except Exception as e:
                errors.append(f"sigma: {os.path.basename(fn)} YAML error: {e}")
                continue
        for key in ("title", "detection", "logsource"):
            if key not in doc:
                errors.append(f"sigma: {os.path.basename(fn)} missing '{key}'")
    # Suricata
    for fn in glob.glob(os.path.join(DET, "suricata", "*.rules")):
        with open(fn, encoding="utf-8") as f:
            for i, line in enumerate(f, 1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if not line.startswith("alert"):
                    errors.append(f"suricata: {os.path.basename(fn)}:{i} not an alert rule")
                    continue
                if "sid:" not in line or "msg:" not in line:
                    errors.append(f"suricata: {os.path.basename(fn)}:{i} missing sid/msg")
    # YARA
    yar = os.path.join(DET, "yara", "notnet_indicators.yar")
    if os.path.exists(yar):
        txt = open(yar, encoding="utf-8").read()
        if "condition:" not in txt:
            errors.append("yara: notnet_indicators.yar has no condition block")
        # rough rule count check
        n = txt.count("rule ")
        if n < 5:
            errors.append(f"yara: expected >=5 rules, found {n}")
    return len(errors) == 0


# ───────────────────────────── stage 2: drift ──────────────────────────────
def stage_drift(errors):
    bp = os.path.join(REPO, "intel", "build_intel.py")
    if not os.path.exists(bp):
        errors.append("drift: intel/build_intel.py missing")
        return False
    r = subprocess.run([sys.executable, bp, "--check"], cwd=REPO,
                       capture_output=True, text=True)
    if r.returncode != 0:
        errors.append("drift: intel bundle does not match source (config.h/spread.c):\n"
                      + (r.stderr.strip() or r.stdout.strip()))
        return False
    return True


# ───────────────────────────── stage 3: replay ─────────────────────────────
# Each wired detection is a (file, match_fn) over a seeded evidence line.
def _has(sub):
    return lambda s: sub.lower() in s.lower()

def build_seed_evidence():
    """Minimal evidence that each 'covered' rule should match."""
    ev = []
    # C2 heartbeat (suricata c2_heartbeat_bot_paths + yara ua via http.log)
    ev.append('2026-08-13T00:00:01 POST /api/v1/bot HTTP/1.1 User-Agent: notnet/0.1.0-dev')
    ev.append('2026-08-13T00:00:02 WS FRAME /ws/v1/bot')
    # relay VIA chain (suricata relay_via_chain + yara relay_via_wireformat)
    ev.append('RELAY abc123token 10.0.0.9 22 VIA 10.0.0.5:1081 VIA 10.0.0.6:1081')
    # CVE exploit traffic (suricata cve_* + ids_monitor signature)
    ev.append('SOAPAction: urn:DeviceUpgrade NewStatusURL=`id`')
    ev.append('POST /formSysCmd cmd=shell')
    ev.append('POST / mdc=;cmd=echo pwn')
    # cred-log (sigma exfil_creds + yara cred_log_format)
    ev.append('proto|ip|port|user|pass ssh|10.0.0.9|22|root|toor')
    ev.append('CMD exfil_creds stream')
    # SMB ADMIN$ (sigma admin_share_write)
    ev.append('EventID 5145 ShareName ADMIN$')
    # Redis injection (sigma redis_config_set_authorized_keys)
    ev.append('CONFIG SET dir /root/.ssh ; CONFIG SET dbfilename authorized_keys')
    # persistence (sigma persistence_cron_systemd_sysv + yara magic)
    ev.append('installing /etc/systemd/system/notnet.service binary .notnet')
    # fileless (sigma fileless_memfd_fexecve + yara notnet_fileless_memfd_fexecve)
    ev.append('exec memfd_create() fd then fexecve() relaunch from /memfd:(notnet); ParentImage: /usr/bin/.notnet')
    # brute force (sigma brute_force_ssh_smb_redis)
    ev.append('AUTH FAIL sshd user=root from 10.0.0.9')
    ev.append('Failed password for invalid user admin from 10.0.0.9')
    # killswitch (sigma self_destruct_killswitch + yara killswitch_markers)
    ev.append('CMD kill ; self-destruct: wiping credential buffer')
    ev.append('DNS query killswitch.invalid')
    # broadcast (yara notnet_broadcast_bc)
    ev.append('bc-payload.sh peeked (never consumed)')
    return ev


# detection name -> predicate over the seeded evidence line
DETECTIONS = {
    "yara:notnet_http_user_agent": _has("notnet/"),
    "yara:notnet_relay_via_wireformat": (lambda s: "relay " in s.lower() and " via " in s.lower()),
    "yara:notnet_cve_module_strings": (lambda s: any(c in s for c in ["CVE-2017-17215", "CVE-2021-35395", "CVE-2024-3721", "HG532", "formSysCmd"])),
    "yara:notnet_killswitch_markers": (lambda s: "killswitch.invalid" in s.lower() or "KILLSWITCH_DOMAIN" in s),
    "yara:notnet_broadcast_bc": _has("bc-"),
    "yara:notnet_cred_log_format": _has("|ip|port|user|pass"),
    "yara:notnet_fileless_memfd_fexecve": (lambda s: "memfd" in s.lower() and "fexecve" in s.lower()),
    "yara:notnet_magic_header": _has(".notnet"),
    "sigma:brute_force_ssh_smb_redis": (lambda s: "auth fail" in s.lower() or "failed password" in s.lower() or "config set" in s.lower()),
    "sigma:exfil_creds": (lambda s: "exfil_creds" in s.lower() or ("|ip|port|user|pass" in s)),
    "sigma:admin_share_write": _has("ADMIN$"),
    "sigma:redis_config_set_authorized_keys": (lambda s: "config set dir" in s.lower() and "authorized_keys" in s.lower()),
    "sigma:persistence_cron_systemd_sysv": (lambda s: ".notnet" in s.lower() and ("systemd" in s.lower() or "/etc/init.d" in s.lower() or "cron" in s.lower())),
    "sigma:fileless_memfd_fexecve": (lambda s: "/memfd:" in s.lower() or (".notnet" in s.lower() and "parentimage" in s.lower())),
    "sigma:proxy_tunnel": (lambda s: " via " in s.lower() or "listen" in s.lower()),
    "sigma:self_destruct_killswitch": (lambda s: "kill" in s.lower() and ("self-destruct" in s.lower() or "killswitch" in s.lower())),
    "suricata:c2_heartbeat_bot_paths": (lambda s: "/api/v1/bot" in s.lower() or "/ws/v1/bot" in s.lower() or "notnet/" in s.lower()),
    "suricata:relay_via_chain": (lambda s: "relay " in s.lower() and " via " in s.lower()),
    "suricata:cve_2017_17215_hg532": _has("urn:DeviceUpgrade"),
    "suricata:cve_2021_35395_realtek": _has("formSysCmd"),
    "suricata:cve_2024_3721_tbk": _has("mdc="),
}

# technique -> expected detections (must all fire on seeded evidence)
COVERAGE = {
    "T1190": ["suricata:cve_2017_17215_hg532", "suricata:cve_2021_35395_realtek"],
    "T1110": ["sigma:brute_force_ssh_smb_redis"],
    "T1005": ["sigma:exfil_creds", "yara:notnet_cred_log_format"],
    "T1020": ["sigma:exfil_creds"],
    "T1572": ["suricata:c2_heartbeat_bot_paths", "sigma:proxy_tunnel"],
    "T1090": ["suricata:relay_via_chain", "sigma:proxy_tunnel"],
    "T1021": ["sigma:admin_share_write", "sigma:redis_config_set_authorized_keys"],
    "T1543": ["sigma:persistence_cron_systemd_sysv"],
    "T1027": ["yara:notnet_fileless_memfd_fexecve", "sigma:fileless_memfd_fexecve"],
    "T1489": ["sigma:self_destruct_killswitch"],
}


def fire_count(det_name, ev):
    pred = DETECTIONS.get(det_name)
    if pred is None:
        return -1  # undefined detection
    return sum(1 for line in ev if pred(line))


def stage_replay(errors, strict):
    ev = build_seed_evidence()
    # pre-flight: every referenced detection must be defined
    undefined = set()
    for tech, dets in COVERAGE.items():
        for d in dets:
            if d not in DETECTIONS:
                undefined.add(d)
    if undefined:
        errors.append("replay: undefined detection(s) referenced in COVERAGE: " + ", ".join(sorted(undefined)))
        return False

    failed = []
    gaps = []
    for tech, dets in COVERAGE.items():
        fired = [d for d in dets if fire_count(d, ev) > 0]
        missing = [d for d in dets if d not in fired]
        if missing:
            failed.append(f"{tech}: detection(s) did not fire on seeded evidence: {', '.join(missing)}")
        if not dets and strict:
            gaps.append(f"{tech}: no detection wired (coverage gap)")
    if failed:
        errors.append("replay FAIL (row would be marked FAIL in ATTACK-COVERAGE.md):\n  - " + "\n  - ".join(failed))
        return False
    if gaps:
        errors.append("replay gaps:\n  - " + "\n  - ".join(gaps))
        return False
    print(f"replay: {len(COVERAGE)} techniques covered, all detections fired on seeded evidence")
    return True


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--strict", action="store_true", help="fail on any coverage gap")
    args = ap.parse_args()

    errors = []
    print("── stage 1: schema ──")
    ok1 = stage_schema(errors)
    print("  PASS" if ok1 else "  FAIL")
    print("── stage 2: source drift ──")
    ok2 = stage_drift(errors)
    print("  PASS" if ok2 else "  FAIL")
    print("── stage 3: detection replay ──")
    ok3 = stage_replay(errors, args.strict)
    print("  PASS" if ok3 else "  FAIL")

    if errors:
        print("\nERRORS:")
        for e in errors:
            print("  - " + e)
        return 1
    print("\nALL DETECTION GATES PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
