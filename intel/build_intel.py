#!/usr/bin/env python3
"""notnet intel generator — the single source of truth for intel/intel-latest.json.

It re-extracts every IOC directly from include/config.h and src/spread.c so the
published bundle can never silently drift from the binary it describes. Run:

    python3 intel/build_intel.py            # (re)write intel/intel-latest.json
    python3 intel/build_intel.py --check    # assert the committed bundle matches
                                            #   source (used by CI, #152/#151)

The bundle is STIX 2.1. If the `stix2` package is importable it is also schema-
validated; otherwise a structural check (every object has type/id/spec_version
== 2.1) runs instead, so the repo needs no heavy dependency to stay honest.
"""
import argparse
import json
import os
import re
import sys
import uuid

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INTEL = os.path.join(REPO, "intel")
CFG = os.path.join(REPO, "include", "config.h")
SPREAD = os.path.join(REPO, "src", "spread.c")
OUT = os.path.join(INTEL, "intel-latest.json")
ATTACK_MAP_OUT = os.path.join(INTEL, "attack_mapping.json")
GENERATED = "2026-08-13T00:00:00.000Z"

ATTACK_TECHS = {
    "T1190": "Exploit Public-Facing Application",
    "T1110": "Brute Force",
    "T1005": "Data from Local System",
    "T1020": "Automated Exfiltration",
    "T1572": "Protocol Tunneling",
    "T1090": "Proxy",
    "T1021": "Remote Services",
    "T1543": "Create or Modify System Process",
    "T1027": "Obfuscated Files or Information",
    "T1489": "Service Stop",
    "T1071": "Application Layer Protocol",
    "T1105": "Ingress Tool Transfer",
}

# technique -> detections that cover it (#206 single source of truth).
# attack_mapping.json is GENERATED from this table and detections/validate.py
# replays it (stage 3), so adding a rule in one place can no longer silently
# diverge the mapping, the coverage matrix replay, or the published JSON.
TECH_COVERAGE = {
    "T1190": ["suricata:cve_2017_17215_hg532", "suricata:cve_2021_35395_realtek",
              "suricata:cve_2024_3721_tbk"],
    "T1110": ["sigma:brute_force_ssh_smb_redis"],
    "T1005": ["sigma:exfil_creds", "yara:notnet_cred_log_format"],
    "T1020": ["sigma:exfil_creds"],
    "T1572": ["suricata:c2_heartbeat_bot_paths", "sigma:proxy_tunnel"],
    "T1090": ["suricata:relay_via_chain", "sigma:proxy_tunnel"],
    "T1021": ["sigma:admin_share_write", "sigma:redis_config_set_authorized_keys"],
    "T1543": ["sigma:persistence_cron_systemd_sysv"],
    "T1027": ["yara:notnet_fileless_memfd_fexecve", "sigma:fileless_memfd_fexecve"],
    "T1489": ["sigma:self_destruct_killswitch"],
    "T1071": ["suricata:ara_llm_adapt", "sigma:ara_llm_adapt"],
    "T1105": ["suricata:ara_llm_adapt"],
}


def _detection_exists(name):
    """True if a covered_by name resolves to a real detection (#206 --check)."""
    kind, _, ident = name.partition(":")
    base = os.path.join(REPO, "detections")
    if kind == "suricata":
        return os.path.isfile(os.path.join(base, "suricata", ident + ".rules"))
    if kind == "sigma":
        return os.path.isfile(os.path.join(base, "sigma", ident + ".yml"))
    if kind == "yara":
        yar = os.path.join(base, "yara", "notnet_indicators.yar")
        try:
            return ("rule " + ident) in open(yar, encoding="utf-8").read()
        except OSError:
            return False
    return False


def build_attack_mapping():
    """attack_mapping.json content, generated from ATTACK_TECHS/TECH_COVERAGE."""
    return {
        "version": "0.1.0-dev",
        "generated": GENERATED,
        "techniques": [
            {"technique": t, "name": ATTACK_TECHS[t],
             "covered_by": TECH_COVERAGE[t]}
            for t in ATTACK_TECHS
        ],
    }


def _define(s, var):
    m = re.search(r'#define\s+' + re.escape(var) + r'\s+"([^"]+)"', s)
    return m.group(1) if m else None


def extract():
    cfg = open(CFG, encoding="utf-8").read()
    spread = open(SPREAD, encoding="utf-8", errors="replace").read()
    domains = {
        "irc": _define(cfg, "IRC_DEFAULT_SERVER"),
        "http": _define(cfg, "HTTP_DEFAULT_SERVER"),
        "ws": _define(cfg, "WS_DEFAULT_SERVER"),
        "peers": _define(cfg, "DNS_PEER_RESOLUTION"),
    }
    ks = _define(cfg, "KILLSWITCH_DOMAIN_DEFAULT")
    http_path = _define(cfg, "HTTP_DEFAULT_PATH")
    ws_path = _define(cfg, "WS_DEFAULT_PATH")
    cves = sorted(set(re.findall(r"CVE-\d{4}-\d{4,6}", spread)))
    return domains, ks, http_path, ws_path, cves


def build():
    domains, ks, http_path, ws_path, cves = extract()
    objs = []

    def iid(t):
        return "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, t))

    for key, dom in domains.items():
        if not dom:
            continue
        objs.append({
            "type": "indicator", "spec_version": "2.1",
            "id": iid(f"domain-{key}-{dom}"),
            "created": GENERATED, "modified": GENERATED,
            "name": f"notnet C2 domain {dom}",
            "pattern": f"[domain-name:value = '{dom}']",
            "pattern_type": "stix", "valid_from": GENERATED,
            "labels": ["malicious-activity"],
            "external_references": [{"source_name": "notnet",
                                     "url": "https://github.com/riceharvest/notnet"}],
        })

    if ks:
        objs.append({
            "type": "indicator", "spec_version": "2.1",
            "id": iid(f"killswitch-{ks}"),
            "created": GENERATED, "modified": GENERATED,
            "name": f"notnet killswitch domain {ks}",
            "description": ("Defender-sinkholeable author killswitch. Pointing this "
                            "domain at 127.0.0.1 disarms any STOCK-built leaked fleet "
                            "(#130)."),
            "pattern": f"[domain-name:value = '{ks}']",
            "pattern_type": "stix", "valid_from": GENERATED,
            "labels": ["malicious-activity", "kill-switch"],
            "external_references": [{"source_name": "notnet #130",
                                     "url": "https://github.com/riceharvest/notnet"}],
        })

    for cve in cves:
        objs.append({
            "type": "indicator", "spec_version": "2.1",
            "id": iid(f"cve-{cve}"),
            "created": GENERATED, "modified": GENERATED,
            "name": f"notnet CVE module {cve}",
            "pattern": f"[x-notnet:cve = '{cve}']",
            "pattern_type": "stix", "valid_from": GENERATED,
            "labels": ["malicious-activity", "exploit"],
            "external_references": [{"source_name": cve,
                                     "url": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve}"}],
        })

    for tag, pat, name in [
        # STIX 2.1 pattern operators are case-sensitive uppercase (MATCHES,
        # not matches — the lowercase form is a grammar error, caught by the
        # stix2 CI gate).
        (f"c2-http-{http_path}", f"[url:value MATCHES '.*{http_path}.*']", "notnet HTTP C2 path"),
        (f"c2-ws-{ws_path}", f"[url:value MATCHES '.*{ws_path}.*']", "notnet WS C2 path"),
        ("relay-via", "[network-traffic:extensions.'notnet-relay'.via MATCHES '.*VIA.*']",
         "notnet ORB relay VIA chain wire format"),
    ]:
        objs.append({
            "type": "indicator", "spec_version": "2.1",
            "id": iid(tag),
            "created": GENERATED, "modified": GENERATED, "name": name,
            "pattern": pat, "pattern_type": "stix", "valid_from": GENERATED,
            "labels": ["malicious-activity"],
            "external_references": [{"source_name": "notnet",
                                     "url": "https://github.com/riceharvest/notnet"}],
        })

    for t, name in ATTACK_TECHS.items():
        objs.append({
            "type": "attack-pattern", "spec_version": "2.1",
            "id": "attack-pattern--" + str(uuid.uuid5(uuid.NAMESPACE_URL, t)),
            "created": GENERATED, "modified": GENERATED, "name": name,
            "external_references": [{"source_name": "mitre-attack",
                                     "url": f"https://attack.mitre.org/techniques/{t}/",
                                     "external_id": t}],
        })

    # Deterministic bundle id (content-derived) so --check is stable across runs.
    bundle_id = "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps(objs, sort_keys=True)))
    return {"type": "bundle", "id": bundle_id, "objects": objs}


def validate(bundle):
    try:
        import stix2  # optional, heavy  # type: ignore
        stix2.parse(bundle, version="2.1")
        return "stix2-validate: OK"
    except ImportError:
        for o in bundle["objects"]:
            assert o.get("type") and o.get("id") and o.get("spec_version") == "2.1", o
        return "structural-check: OK (stix2 not installed)"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="assert the committed bundle matches source; exit non-zero on drift")
    args = ap.parse_args()

    bundle = build()
    print(validate(bundle))
    print(f"bundle objects: {len(bundle['objects'])}")

    if args.check:
        if not os.path.exists(OUT):
            print(f"ERROR: {OUT} missing", file=sys.stderr)
            return 1
        with open(OUT, encoding="utf-8") as f:
            committed = json.load(f)
        # Compare as normalized (sorted) JSON; ids are content-derived so stable.
        a = json.dumps(bundle, sort_keys=True)
        b = json.dumps(committed, sort_keys=True)
        if a != b:
            print("ERROR: intel bundle drifted from source (config.h/spread.c). "
                  "Re-run `python3 intel/build_intel.py` and commit.", file=sys.stderr)
            return 1
        print("drift-check: OK (bundle matches source)")

        # attack_mapping.json drift (#206): generated from ATTACK_TECHS /
        # TECH_COVERAGE above, and every covered_by name must resolve to a
        # real detection file/rule under detections/.
        if not os.path.exists(ATTACK_MAP_OUT):
            print(f"ERROR: {ATTACK_MAP_OUT} missing", file=sys.stderr)
            return 1
        with open(ATTACK_MAP_OUT, encoding="utf-8") as f:
            committed_map = json.load(f)
        amap = build_attack_mapping()
        if json.dumps(amap, sort_keys=True) != json.dumps(committed_map, sort_keys=True):
            print("ERROR: attack_mapping.json drifted from ATTACK_TECHS/TECH_COVERAGE "
                  "in build_intel.py. Re-run `python3 intel/build_intel.py` and commit.",
                  file=sys.stderr)
            return 1
        bad = [d for dets in TECH_COVERAGE.values() for d in dets
               if not _detection_exists(d)]
        if bad:
            print("ERROR: attack_mapping covered_by names not found under "
                  f"detections/: {', '.join(bad)}", file=sys.stderr)
            return 1
        print("drift-check: OK (attack_mapping.json matches source; "
              "all covered_by detections exist)")
        return 0

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
    print(f"wrote {OUT}")
    with open(ATTACK_MAP_OUT, "w", encoding="utf-8") as f:
        json.dump(build_attack_mapping(), f, indent=2)
        f.write("\n")
    print(f"wrote {ATTACK_MAP_OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
