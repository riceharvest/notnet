#!/usr/bin/env python3
"""notnet forensics — IOC extraction, attack timeline, evidence hash chain (#158).

Complements intel/build_intel.py: build_intel extracts IOCs from SOURCE (what
the malware IS); forensics extracts IOCs from a CAMPAIGN's evidence (what it
DID). Stdlib-only, same style.

Subcommands:
  iocs     --evidence DIR --out bundle.json   STIX 2.1 IOC bundle
  timeline --evidence DIR --out FILE          merged attack timeline (.json/.md)
  seal     --dir DIR --out chain.json          SHA-256 hash chain over files
  verify   --chain chain.json [--dir DIR]      verify chain (tamper position)

PCAP: live packet capture needs a tcpdump sidecar container (network_mode:
host, writing /evidence/capture.pcapng). Not implemented; when present,
timeline --include-pcap will reference it as an event source.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import uuid
from datetime import datetime

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CFG = os.path.join(REPO, "include", "config.h")
GENESIS = "0" * 64


# ────────────────────────── evidence parsing ──────────────────────────

def _read_evidence(evidence_dir):
    """Return {filename: [lines]} for all .log files."""
    out = {}
    for fn in sorted(os.listdir(evidence_dir)):
        if not fn.endswith(".log"):
            continue
        p = os.path.join(evidence_dir, fn)
        try:
            with open(p, encoding="utf-8", errors="replace") as f:
                out[fn] = f.readlines()
        except OSError:
            pass
    return out


def _domains_from_config():
    """C2 domains from include/config.h (same extraction as build_intel.py)."""
    try:
        cfg = open(CFG, encoding="utf-8").read()
    except OSError:
        return []
    doms = set()
    for var in ("IRC_DEFAULT_SERVER", "HTTP_DEFAULT_SERVER",
                "WS_DEFAULT_SERVER", "DNS_PEER_RESOLUTION",
                "KILLSWITCH_DOMAIN_DEFAULT"):
        m = re.search(r'#define\s+' + var + r'\s+"([^"]+)"', cfg)
        if m and "invalid" not in m.group(1):
            doms.add(m.group(1))
    return sorted(doms)


def _cves_from_alerts(lines):
    cves = set()
    for ln in lines:
        for m in re.finditer(r"CVE-\d{4}-\d{4,6}", ln):
            cves.add(m.group(0))
    return sorted(cves)


def _creds_from_lines(lines):
    """Cred-log format: proto|ip|port|user|pass"""
    creds = []
    for ln in lines:
        m = re.search(r"\b(ssh|telnet|smb|redis|rdp)\|([^|]+)\|(\d+)\|([^|]+)\|([^|\s]+)", ln)
        if m:
            creds.append({"proto": m.group(1), "ip": m.group(2),
                          "port": int(m.group(3)), "user": m.group(4),
                          "pass": m.group(5)})
    return creds


def _heartbeat_srcs(lines):
    srcs = {}
    for ln in lines:
        m = re.search(r"C2 heartbeat from (\d+\.\d+\.\d+\.\d+) .*\"tag\":\"([^\"]+)\"", ln)
        if m:
            srcs.setdefault(m.group(2), m.group(1))
    return srcs


# ────────────────────────── iocs ──────────────────────────

def cmd_iocs(args):
    ev = _read_evidence(args.evidence)
    http_lines = ev.get("http.log", [])
    alert_lines = ev.get("ids_alerts.log", [])
    all_lines = [l for lines in ev.values() for l in lines]

    objs = []

    def iid(seed):
        return "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, seed))

    GEN = datetime.now(datetime.now().astimezone().tzinfo).isoformat()

    # ipv4-addr: heartbeat sources
    tag_ip = _heartbeat_srcs(http_lines)
    for tag, ip in sorted(tag_ip.items()):
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": iid(f"ip-{tag}-{ip}"),
            "created": GEN, "modified": GEN,
            "name": f"notnet infected host {tag}",
            "pattern": f"[ipv4-addr:value = '{ip}']",
            "pattern_type": "stix", "valid_from": GEN,
            "labels": ["malicious-activity"],
        })

    # domain-name: C2 domains
    for dom in _domains_from_config():
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": iid(f"dom-{dom}"),
            "created": GEN, "modified": GEN,
            "name": f"notnet C2 domain {dom}",
            "pattern": f"[domain-name:value = '{dom}']",
            "pattern_type": "stix", "valid_from": GEN,
            "labels": ["malicious-activity", "c2"],
        })

    # file:hash — payload binary
    payload = os.path.join(REPO, "tests", "sim", "payload", "notnet")
    if os.path.isfile(payload):
        h = hashlib.sha256(open(payload, "rb").read()).hexdigest()
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": iid(f"sha-{h[:16]}"),
            "created": GEN, "modified": GEN,
            "name": "notnet payload binary",
            "pattern": f"[file:hashes.'SHA-256' = '{h}']",
            "pattern_type": "stix", "valid_from": GEN,
            "labels": ["malicious-activity", "payload"],
        })

    # url — C2 paths
    all_text = " ".join(l for lines in ev.values() for l in lines)
    for m in set(re.findall(r"(/(?:api|ws|bot)[a-z0-9/_v.-]*)", all_text)):
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": iid(f"url-{m}"),
            "created": GEN, "modified": GEN,
            "name": f"notnet C2 path {m}",
            "pattern": f"[url:value = '{m}']",
            "pattern_type": "stix", "valid_from": GEN,
            "labels": ["malicious-activity", "c2"],
        })

    # software — CVE modules observed
    for cve in _cves_from_alerts(all_lines):
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": iid(f"cve-{cve}"),
            "created": GEN, "modified": GEN,
            "name": f"notnet CVE module {cve}",
            "pattern": f"[software:name = '{cve}']",
            "pattern_type": "stix", "valid_from": GEN,
            "labels": ["malicious-activity", "exploit"],
        })

    # user-account — harvested creds
    for c in _creds_from_lines(all_lines):
        seed = f"cred-{c['user']}-{c['ip']}"
        objs.append({
            "type": "indicator", "spec_version": "2.1", "id": iid(seed),
            "created": GEN, "modified": GEN,
            "name": f"harvested credential {c['user']}@{c['ip']}",
            "pattern": f"[user-account:user_id = '{c['user']}']",
            "pattern_type": "stix", "valid_from": GEN,
            "labels": ["malicious-activity", "credential-harvest"],
        })

    types = {o["pattern"].split(":")[0].lstrip("[") for o in objs}
    bundle = {"type": "bundle", "id": "bundle--" + str(uuid.uuid5(
        uuid.NAMESPACE_URL, json.dumps(objs, sort_keys=True))), "objects": objs}
    with open(args.out, "w") as f:
        json.dump(bundle, f, indent=2, sort_keys=True)
    print(f"IOC bundle: {len(objs)} indicators, {len(types)} observable types "
          f"({', '.join(sorted(types))})")
    if len(types) < 5:
        print("WARNING: fewer than 5 observable types", file=sys.stderr)
    return 0


# ────────────────────────── timeline ──────────────────────────

_EVENT_PATTERNS = [
    (r"Local spread cycle|spawn_scan_threads", "scan"),
    (r"probe (hit|on)|GET / HTTP", "probe"),
    (r"CVE-EXPLOIT|verify passed", "exploit"),
    (r"DROP received|DROP spawned|wget.*notnet", "drop"),
    (r"EXECUTING DROP", "payload-exec"),
    (r"C2 heartbeat from", "c2-join"),
    (r"RELAY.*VIA|relay_via|SOCKS5", "lateral"),
    (r"exfil|EXFIL", "exfil"),
]


def _classify(msg):
    for pat, et in _EVENT_PATTERNS:
        if re.search(pat, msg, re.IGNORECASE):
            return et
    return None


def cmd_timeline(args):
    ev = _read_evidence(args.evidence)
    events = []
    for fn, lines in ev.items():
        device = fn.replace(".log", "")
        for ln in lines:
            ln = ln.strip()
            if not ln:
                continue
            m = re.match(r"^(\S+)\s+(.*)", ln)
            if not m:
                continue
            ts_s, msg = m.groups()
            et = _classify(msg)
            if not et:
                continue
            try:
                ts = datetime.fromisoformat(ts_s.replace("Z", "+00:00"))
            except ValueError:
                continue
            events.append({"ts": ts_s, "device": device, "event_type": et,
                           "detail": msg[:160]})
    events.sort(key=lambda e: e["ts"])

    # infection-chain linking: device A's DROP URL in device B's EXECUTING DROP
    chains = []
    drop_urls = {}  # url_fragment -> device that received the drop
    for e in events:
        if e["event_type"] == "drop":
            m = re.search(r"(http://\S+?bot/notnet\S*)", e["detail"])
            if m:
                drop_urls.setdefault(e["device"], m.group(1))
    for e in events:
        if e["event_type"] == "payload-exec":
            for parent, url in drop_urls.items():
                if parent != e["device"] and url.split("?")[0] in e["detail"]:
                    chains.append({"parent": parent, "child": e["device"]})

    if args.out.endswith(".md"):
        with open(args.out, "w") as f:
            f.write("# notnet attack timeline\n\n")
            f.write(f"{len(events)} events, {len(chains)} infection links\n\n")
            f.write("| ts | device | event | detail |\n|---|---|---|---|\n")
            for e in events:
                f.write(f"| {e['ts']} | {e['device']} | {e['event_type']} "
                        f"| {e['detail'][:80]} |\n")
            if chains:
                f.write("\n## Infection chains\n\n")
                for c in chains:
                    f.write(f"- {c['parent']} → {c['child']}\n")
    else:
        with open(args.out, "w") as f:
            json.dump({"events": events, "infection_chains": chains}, f,
                      indent=2)
    print(f"timeline: {len(events)} events, {len(chains)} infection links "
          f"→ {args.out}")
    return 0


# ────────────────────────── seal / verify ──────────────────────────

def _hash_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def cmd_seal(args):
    entries = []
    prev = GENESIS
    for fn in sorted(os.listdir(args.dir)):
        p = os.path.join(args.dir, fn)
        if not os.path.isfile(p):
            continue
        h = _hash_file(p)
        entries.append({"file": fn, "sha256": h, "prev_hash": prev})
        prev = h
    with open(args.out, "w") as f:
        json.dump(entries, f, indent=2)
    print(f"sealed {len(entries)} files → {args.out}")
    return 0


def cmd_verify(args):
    try:
        chain = json.load(open(args.chain))
    except (OSError, json.JSONDecodeError) as e:
        print(f"VERIFY FAIL: cannot read chain: {e}", file=sys.stderr)
        return 1
    base = args.dir or os.path.dirname(os.path.abspath(args.chain))
    prev = GENESIS
    for i, e in enumerate(chain):
        if e["prev_hash"] != prev:
            print(f"VERIFY FAIL at entry {i} ({e['file']}): chain break")
            return 1
        p = os.path.join(base, e["file"])
        if not os.path.isfile(p):
            print(f"VERIFY FAIL at entry {i}: missing file {e['file']}")
            return 1
        actual = _hash_file(p)
        if actual != e["sha256"]:
            print(f"VERIFY FAIL at entry {i} ({e['file']}): hash mismatch "
                  f"(expected {e['sha256'][:16]}..., got {actual[:16]}...) — "
                  f"file tampered")
            return 1
        prev = e["sha256"]
    print(f"VERIFY OK: {len(chain)} files, chain intact")
    return 0


# ────────────────────────── main ──────────────────────────

def main():
    ap = argparse.ArgumentParser(description="notnet forensics toolkit")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("iocs")
    p.add_argument("--evidence", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_iocs)

    p = sub.add_parser("timeline")
    p.add_argument("--evidence", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_timeline)

    p = sub.add_parser("seal")
    p.add_argument("--dir", required=True)
    p.add_argument("--out", required=True)
    p.set_defaults(fn=cmd_seal)

    p = sub.add_parser("verify")
    p.add_argument("--chain", required=True)
    p.add_argument("--dir", default=None)
    p.set_defaults(fn=cmd_verify)

    args = ap.parse_args()
    raise SystemExit(args.fn(args))


if __name__ == "__main__":
    main()
