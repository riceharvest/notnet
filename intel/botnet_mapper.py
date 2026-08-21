#!/usr/bin/env python3
"""notnet botnet mapper (#162) — map the fleet from the outside, without touching C2.

Reads simulated evidence (tests/sim/evidence layout):
  http.log       "<iso-ts> C2 heartbeat from <IP> body={\"tag\":\"...\",...}"
  ids_alerts.log "<iso> ALERT sig=SIG src=<IP> dst=<NAME> <detail>"

Produces an attribution report:
  - infected_count / device list (tag, ip, first_seen, last_seen)
  - network-segment breakdown (geo-by-segment): 172.29.10.* = iot,
    172.29.20.* = office, 172.29.30.* = dmz
  - CVE attribution: which exploit (from CVE-EXPLOIT IDS alerts) hit which
    device, i.e. the variant fingerprint.

Stdlib only. Usage:
    python3 intel/botnet_mapper.py --evidence tests/sim/evidence [--out report.json]
"""
import argparse
import json
import os
import re
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

HEARTBEAT_RE = re.compile(
    r"^(?P<ts>\S+)\s+C2 heartbeat from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})\s+body=(?P<body>\{.*\})"
)
TAG_RE = re.compile(r'"tag"\s*:\s*"([^"]+)"')
ALERT_RE = re.compile(
    r"^(?P<ts>\S+)\s+ALERT\s+sig=(?P<sig>\S+)\s+src=(?P<src>\S+)\s+dst=(?P<dst>\S+)\s+(?P<detail>.*)$"
)
CVE_RE = re.compile(r"CVE-\d{4}-\d{4,6}")

SEGMENTS = {"10": "iot", "20": "office", "30": "dmz"}


def parse_http_log(path):
    """Yield (timestamp, ip, tag) for every well-formed heartbeat line."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = HEARTBEAT_RE.match(line.strip())
            if not m:
                continue
            tm = TAG_RE.search(m.group("body"))
            if not tm:
                continue
            out.append((m.group("ts"), m.group("ip"), tm.group(1)))
    return out


def parse_ids_alerts(path):
    """Yield dicts for every ALERT line."""
    out = []
    if not os.path.exists(path):
        return out
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            m = ALERT_RE.match(line.strip())
            if m:
                out.append(m.groupdict())
    return out


def segment_of(ip):
    parts = ip.split(".")
    if len(parts) == 4:
        seg = SEGMENTS.get(parts[2])
        if seg:
            return seg
    return "unknown"


def map_botnet(evidence_dir):
    beats = parse_http_log(os.path.join(evidence_dir, "http.log"))
    alerts = parse_ids_alerts(os.path.join(evidence_dir, "ids_alerts.log"))

    devices = {}
    for ts, ip, tag in beats:
        d = devices.setdefault(tag, {"tag": tag, "ip": ip,
                                     "first_seen": ts, "last_seen": ts})
        if ts < d["first_seen"]:
            d["first_seen"] = ts
        if ts > d["last_seen"]:
            d["last_seen"] = ts

    dev_list = sorted(devices.values(), key=lambda d: d["tag"])
    for d in dev_list:
        d["segment"] = segment_of(d["ip"])

    segments = {"iot": 0, "office": 0, "dmz": 0}
    for d in dev_list:
        if d["segment"] in segments:
            segments[d["segment"]] += 1

    # Variant fingerprint: CVE exploits attributed to devices by name match.
    # An alert attributes its CVE to every device whose tag appears in the
    # dst name or the free-text detail (dst names embed the bot tag).
    cve_attribution = {}
    for a in alerts:
        if a["sig"] != "CVE-EXPLOIT":
            continue
        cves = CVE_RE.findall(a["detail"]) or CVE_RE.findall(a.get("dst", ""))
        haystack = (a.get("dst", "") + " " + a["detail"]).lower()
        for tag in devices:
            if tag.lower() in haystack:
                for cve in cves:
                    cve_attribution.setdefault(tag, set()).add(cve)

    return {
        "infected_count": len(dev_list),
        "devices": [
            {k: d[k] for k in ("tag", "ip", "first_seen", "last_seen")}
            | {"segment": d["segment"]}
            for d in dev_list
        ],
        "segments": segments,
        "cve_attribution": {t: sorted(c) for t, c in sorted(cve_attribution.items())},
    }


def main():
    ap = argparse.ArgumentParser(description="Map notnet-infected devices from external evidence")
    ap.add_argument("--evidence", required=True, help="directory containing http.log / ids_alerts.log")
    ap.add_argument("--out", help="write JSON report here (default: stdout)")
    args = ap.parse_args()

    if not os.path.isdir(args.evidence):
        print(f"ERROR: evidence dir not found: {args.evidence}", file=sys.stderr)
        return 1

    report = map_botnet(args.evidence)
    blob = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
        print(f"wrote {args.out} ({report['infected_count']} devices)")
    else:
        print(blob)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
