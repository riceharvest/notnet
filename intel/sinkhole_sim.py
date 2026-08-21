#!/usr/bin/env python3
"""notnet C2 sinkholing simulation (#162) — defender takes over the DGA domain.

Two modes:

1. DGA domain prediction (what the bots will resolve tomorrow):
       python3 intel/sinkhole_sim.py --generate-dga-seed --seed myseed --day 233
   The simulated DGA is: 8-hex = SHA-256(seed + str(day_of_year)).hexdigest()[:8],
   domain = hex + "." + tld (tld defaults to "sim.test").

2. Sinkhole capture report (who checked in while we held the domain):
       python3 intel/sinkhole_sim.py --domain <dga-domain> \
           --expected-tags cam-01,cam-02 [--evidence tests/sim/evidence]
   Counts the distinct bot tags that heartbeated to the sinkhole in http.log
   (lines that mention the sinkhole domain; if no line names it, the whole
   evidence window is treated as the sinkhole period) and reports captured /
   expected coverage.

Stdlib only.
"""
import argparse
import hashlib
import json
import os
import re
import sys

from botnet_mapper import parse_http_log  # same evidence parser, one source of truth

DEFAULT_TLD = "sim.test"


def dga_domain(seed, day, tld=DEFAULT_TLD):
    """8-hex label from SHA-256(seed + day_of_year), per the #162 DGA spec."""
    hex8 = hashlib.sha256((seed + str(day)).encode("utf-8")).hexdigest()[:8]
    return f"{hex8}.{tld}"


def sinkhole_report(domain, expected_tags, evidence_dir):
    # Heartbeats that reached the sinkhole: lines naming the domain if any do,
    # otherwise every heartbeat in the window (whole window was sinkholed).
    path = os.path.join(evidence_dir, "http.log")
    tag_re = re.compile(r'"tag"\s*:\s*"([^"]+)"')
    hits = set()
    saw_domain_ref = False
    if os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                if domain in line:
                    saw_domain_ref = True
                    m = tag_re.search(line)
                    if m:
                        hits.add(m.group(1))
        if not saw_domain_ref:
            hits = {tag for _, _, tag in parse_http_log(path)}

    expected = [t.strip() for t in expected_tags if t.strip()]
    captured = sorted(t for t in expected if t in hits)
    missing = sorted(t for t in expected if t not in hits)
    coverage = round(100.0 * len(captured) / len(expected), 2) if expected else 0.0
    return {
        "domain": domain,
        "expected_count": len(expected),
        "captured_count": len(captured),
        "captured_tags": captured,
        "missing_tags": missing,
        "unexpected_tags": sorted(hits - set(expected)),
        "coverage_pct": coverage,
    }


def main():
    ap = argparse.ArgumentParser(description="Simulate C2 sinkholing of the notnet DGA domain")
    ap.add_argument("--generate-dga-seed", action="store_true",
                    help="predict the DGA domain instead of reporting a capture")
    ap.add_argument("--seed", help="DGA seed (with --generate-dga-seed)")
    ap.add_argument("--day", type=int, help="day of year (with --generate-dga-seed)")
    ap.add_argument("--tld", default=DEFAULT_TLD, help=f"DGA tld (default {DEFAULT_TLD})")
    ap.add_argument("--domain", help="sinkholed DGA domain")
    ap.add_argument("--expected-tags", help="comma-separated bot tags expected to check in")
    ap.add_argument("--evidence", help="directory containing http.log")
    ap.add_argument("--out", help="write JSON report here (default: stdout)")
    args = ap.parse_args()

    if args.generate_dga_seed:
        if args.seed is None or args.day is None:
            print("ERROR: --generate-dga-seed needs --seed S --day N", file=sys.stderr)
            return 1
        print(dga_domain(args.seed, args.day, args.tld))
        return 0

    if not (args.domain and args.expected_tags and args.evidence):
        print("ERROR: need --domain D --expected-tags a,b,c --evidence DIR "
              "(or --generate-dga-seed --seed S --day N)", file=sys.stderr)
        return 1
    if not os.path.isdir(args.evidence):
        print(f"ERROR: evidence dir not found: {args.evidence}", file=sys.stderr)
        return 1

    report = sinkhole_report(args.domain,
                             args.expected_tags.split(","), args.evidence)
    blob = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
        print(f"wrote {args.out} ({report['captured_count']}/{report['expected_count']} tags)")
    else:
        print(blob)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
