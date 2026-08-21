#!/usr/bin/env python3
"""notnet replay defense (#162) — does the campaign-A IOC feed detect campaign B?

Loads a STIX 2.1 bundle of indicators (as produced by intel/build_intel.py or
the post-campaign feed generator), extracts the observables from each
indicator's pattern string, and scans the raw text of a second campaign's
evidence directory for matches.

Supported pattern types:
    [ipv4-addr:value = '...']
    [domain-name:value = '...']
    [url:value = '...' | url:value MATCHES '.*...*']
    [file:hashes.'SHA-256' = '...' | file:hashes.MD5 = ...]

Reports total_indicators, matched, detection_rate and false_negative_pct.
Exit code 0 always (this is a measurement, not a gate); use the JSON.

Stdlib only. Usage:
    python3 intel/replay_check.py --feed intel/intel-latest.json \
        --evidence tests/sim/evidence [--out replay_report.json]
"""
import argparse
import json
import os
import re
import sys

# One regex per supported STIX observable; group(1) is the literal to find.
PATTERNS = [
    re.compile(r"\[ipv4-addr:value\s*=\s*'([^']+)'\]"),
    re.compile(r"\[domain-name:value\s*=\s*'([^']+)'\]"),
    re.compile(r"\[url:value\s+(?:=\s*'([^']+)'|MATCHES\s+'[^']*([a-zA-Z0-9/._-]+)[^']*)'\]"),
    re.compile(r"\[file:hashes\.(?:'[A-Za-z0-9-]+'|\w+)\s*=\s*'([a-fA-F0-9]{8,64})'\]"),
]


def extract_indicators(bundle):
    """[(indicator_id, name, ioc_type, literal)] for every parseable indicator."""
    out = []
    for obj in bundle.get("objects", []):
        if obj.get("type") != "indicator":
            continue
        pattern = obj.get("pattern", "")
        for ioc_type, rx in zip(("ipv4-addr", "domain-name", "url", "file:hash"), PATTERNS):
            m = rx.search(pattern)
            if not m:
                continue
            literal = next(g for g in m.groups() if g)
            out.append((obj.get("id"), obj.get("name", ""), ioc_type, literal))
            break
    return out


def evidence_text(evidence_dir):
    chunks = []
    for root, _dirs, files in os.walk(evidence_dir):
        for fn in sorted(files):
            p = os.path.join(root, fn)
            try:
                with open(p, encoding="utf-8", errors="replace") as f:
                    chunks.append(f.read())
            except OSError:
                pass  # binary evidence files are skipped
    return "\n".join(chunks)


def replay_check(feed_path, evidence_dir):
    with open(feed_path, encoding="utf-8") as f:
        bundle = json.load(f)
    inds = extract_indicators(bundle)
    text = evidence_text(evidence_dir).lower()

    matched_ids = set()
    per_type = {}
    details = []
    for iid, name, ioc_type, literal in inds:
        hit = literal.lower() in text
        per_type.setdefault(ioc_type, [0, 0])
        per_type[ioc_type][1] += 1
        if hit:
            matched_ids.add(iid)
            per_type[ioc_type][0] += 1
        details.append({"id": iid, "name": name, "type": ioc_type,
                        "value": literal, "matched": hit})

    total = len(inds)
    matched = len(matched_ids)
    rate = round(100.0 * matched / total, 2) if total else 0.0
    return {
        "feed": feed_path,
        "evidence": evidence_dir,
        "total_indicators": total,
        "matched": matched,
        "detection_rate": rate,
        "false_negative_pct": round(100.0 - rate, 2),
        "by_type": {t: {"matched": m, "total": n} for t, (m, n) in sorted(per_type.items())},
        "indicators": details,
    }


def main():
    ap = argparse.ArgumentParser(description="Cross-campaign IOC replay validation")
    ap.add_argument("--feed", required=True, help="campaign-A STIX 2.1 bundle (JSON)")
    ap.add_argument("--evidence", required=True, help="campaign-B evidence directory")
    ap.add_argument("--out", help="write JSON report here (default: stdout)")
    args = ap.parse_args()

    if not os.path.isfile(args.feed):
        print(f"ERROR: feed not found: {args.feed}", file=sys.stderr)
        return 1
    if not os.path.isdir(args.evidence):
        print(f"ERROR: evidence dir not found: {args.evidence}", file=sys.stderr)
        return 1

    report = replay_check(args.feed, args.evidence)
    blob = json.dumps(report, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(blob + "\n")
        print(f"wrote {args.out} ({report['matched']}/{report['total_indicators']} "
              f"indicators, FN {report['false_negative_pct']}%)")
    else:
        print(blob)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
