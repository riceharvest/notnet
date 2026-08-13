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
        (f"c2-http-{http_path}", f"[url:value matches '.*{http_path}.*']", "notnet HTTP C2 path"),
        (f"c2-ws-{ws_path}", f"[url:value matches '.*{ws_path}.*']", "notnet WS C2 path"),
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
        return 0

    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
    print(f"wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
