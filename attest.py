#!/usr/bin/env python3
"""notnet build attestation (#154).

Records who produced which binary, from which commit, at what time, and the
binary's SHA-256 — so a leaked artifact is traceable. Wired into the Makefile
(`make attest`) and run by CI for release artifacts.

The "signer" is intentionally lightweight: a free-form string (CI runner / dev
host identity). Real signature verification of the binary is the signed-disarm
problem (#140); this file solves *attribution*, not *integrity*.

Usage:  python3 attest.py <binary> [--signer NAME] [--out BUILD-ATTESTATION.json]
"""
import argparse
import hashlib
import json
import os
import subprocess
import sys
import time


def git_commit():
    try:
        return subprocess.check_output(["git", "rev-parse", "HEAD"],
                                        stderr=subprocess.DEVNULL).decode().strip()
    except Exception:
        return "unknown"


def git_dirty():
    try:
        return subprocess.check_output(["git", "status", "--porcelain"],
                                       stderr=subprocess.DEVNULL).decode().strip() != ""
    except Exception:
        return False


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("binary", help="path to the built notnet binary")
    ap.add_argument("--signer", default=os.environ.get("NOTNET_BUILD_SIGNER", "unknown"))
    ap.add_argument("--out", default="BUILD-ATTESTATION.json")
    args = ap.parse_args()

    if not os.path.exists(args.binary):
        print(f"ERROR: binary not found: {args.binary}", file=sys.stderr)
        return 1

    commit = git_commit()
    rec = {
        "tool": "notnet",
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_commit": commit,
        "source_dirty": git_dirty(),
        "signer": args.signer,
        "build_host": os.uname().nodename,
        "artifact": os.path.basename(args.binary),
        "sha256": sha256(args.binary),
    }
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(rec, f, indent=2)
    print(f"wrote {args.out}: {args.binary} sha256={rec['sha256'][:16]}… signer={args.signer}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
