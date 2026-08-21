#!/usr/bin/env python3
"""End-to-end tests for the #162 attribution toolchain.

Synthesizes two tiny campaigns as temp dirs of fabricated evidence
(http.log + ids_alerts.log), builds a campaign-A STIX IOC bundle, then runs
botnet_mapper.py, sinkhole_sim.py and replay_check.py via subprocess and
asserts:

  - mapper finds every planted device, with correct segments and CVE hits
  - sinkhole coverage is exactly 100% on the synthetic pair
  - the campaign-A feed detects campaign-B traffic with false negatives < 10%

Stdlib only. Run: python3 intel/test_attribution.py
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)

MAPPER = os.path.join(HERE, "botnet_mapper.py")
SINKHOLE = os.path.join(HERE, "sinkhole_sim.py")
REPLAY = os.path.join(HERE, "replay_check.py")

SEED = "unit-test-seed"
DAY = 233

# Planted fleet: one device per segment.
FLEET = [
    ("cam-01", "172.29.10.11", "iot"),
    ("cam-02", "172.29.20.22", "office"),
    ("cam-03", "172.29.30.33", "dmz"),
]

DGA_DOMAIN_SEED = "unit-test-seed"
CVE = "CVE-2017-17215"
C2_PATH = "/api/v1/bot"
SHA256 = "a" * 64


def run(script, *args):
    r = subprocess.run([sys.executable, script, *args],
                       capture_output=True, text=True)
    if r.returncode != 0:
        raise AssertionError(f"{script} {' '.join(args)} failed:\n{r.stderr}")
    return r.stdout


def dga(day, tld="sim.test"):
    """Mirror of the sinkhole DGA spec — used to plant + predict domains."""
    import hashlib
    return hashlib.sha256((DGA_DOMAIN_SEED + str(day)).encode()).hexdigest()[:8] + "." + tld


def write_evidence(dirname, day, include_cve=True, extra_iocs=True, legacy_domains=()):
    """Fabricate http.log + ids_alerts.log for a tiny campaign."""
    dom = dga(day)
    beats = []
    for i, (tag, ip, _seg) in enumerate(FLEET):
        ts = f"2026-08-{10 + i:02d}T0{i}:00:00Z"
        body = json.dumps({"tag": tag, "host": dom, "path": C2_PATH,
                           "hash": SHA256 if extra_iocs else ""})
        beats.append(f"{ts} C2 heartbeat from {ip} body={body}")
    # Bots hardcode their last-known domains as fallback — older campaign
    # domains keep showing up in later runs' traffic (cross-campaign overlap).
    for j, legacy in enumerate(legacy_domains):
        tag, ip, _seg = FLEET[j % len(FLEET)]
        ts = f"2026-08-{13 + j:02d}T09:{j * 10:02d}:00Z"
        beats.append(f"{ts} C2 heartbeat from {ip} body="
                     + json.dumps({"tag": tag, "host": legacy,
                                   "fallback": "dns-cache"}))
    with open(os.path.join(dirname, "http.log"), "w") as f:
        f.write("\n".join(beats) + "\n")

    alerts = [
        f"2026-08-10T00:05:00Z ALERT sig=SCAN-SWEEP src=198.51.100.9 dst=lan-broadcast sweep",
        f"2026-08-10T00:09:00Z ALERT sig=BRUTE-BURST src=203.0.113.7 dst=admin-panel telnet burst",
    ]
    if include_cve:
        alerts.append(
            f"2026-08-10T00:07:00Z ALERT sig=CVE-EXPLOIT src=203.0.113.7 "
            f"dst=gw-cam-01 {CVE} exploit against HG532 gateway (cam-01)")
    with open(os.path.join(dirname, "ids_alerts.log"), "w") as f:
        f.write("\n".join(alerts) + "\n")
    return dom


def build_feed_a(path, dom):
    """STIX 2.1 bundle of campaign-A observables (build_intel.py style)."""
    import uuid
    def iid(t):
        return "indicator--" + str(uuid.uuid5(uuid.NAMESPACE_URL, t))
    def ind(name, pattern):
        return {"type": "indicator", "spec_version": "2.1", "id": iid(name),
                "name": name, "pattern": pattern, "pattern_type": "stix",
                "valid_from": "2026-08-10T00:00:00.000Z"}
    objs = [
        ind("c2-ip-1", f"[ipv4-addr:value = '{FLEET[0][1]}']"),
        ind("c2-ip-2", f"[ipv4-addr:value = '{FLEET[1][1]}']"),
        ind("c2-domain", f"[domain-name:value = '{dom}']"),
        ind("c2-url", f"[url:value MATCHES '.*{C2_PATH}.*']"),
        ind("payload-hash", f"[file:hashes.'SHA-256' = '{SHA256}']"),
    ]
    with open(path, "w") as f:
        json.dump({"type": "bundle",
                   "id": "bundle--" + str(uuid.uuid5(uuid.NAMESPACE_URL, "feed-a")),
                   "objects": objs}, f)


class TestAttribution(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="notnet-attrib-")
        cls.camp_a = os.path.join(cls.tmp, "campaign-a")
        cls.camp_b = os.path.join(cls.tmp, "campaign-b")
        os.makedirs(cls.camp_a)
        os.makedirs(cls.camp_b)
        cls.dom_a = write_evidence(cls.camp_a, DAY)
        # Campaign B: different DGA day but overlapping infrastructure —
        # the cross-campaign detection target.
        cls.dom_b = write_evidence(cls.camp_b, DAY + 1, include_cve=False,
                                   legacy_domains=(cls.dom_a,))
        cls.feed_a = os.path.join(cls.tmp, "feed-a.json")
        build_feed_a(cls.feed_a, cls.dom_a)

    def test_01_mapper_finds_all_planted_devices(self):
        out = run(MAPPER, "--evidence", self.camp_a)
        report = json.loads(out)
        self.assertEqual(report["infected_count"], len(FLEET))
        got = {d["tag"]: d for d in report["devices"]}
        for tag, ip, seg in FLEET:
            self.assertIn(tag, got)
            self.assertEqual(got[tag]["ip"], ip)
            self.assertEqual(got[tag]["segment"], seg)
        self.assertEqual(report["segments"], {"iot": 1, "office": 1, "dmz": 1})
        # Variant fingerprint: the planted CVE lands on cam-01.
        self.assertIn("cam-01", report["cve_attribution"])
        self.assertIn(CVE, report["cve_attribution"]["cam-01"])

    def test_02_dga_seed_matches_spec(self):
        out = run(SINKHOLE, "--generate-dga-seed", "--seed", DGA_DOMAIN_SEED,
                  "--day", str(DAY))
        self.assertEqual(out.strip(), self.dom_a)

    def test_03_sinkhole_coverage_is_100pct(self):
        expected = ",".join(tag for tag, _, _ in FLEET)
        out = run(SINKHOLE, "--domain", self.dom_a,
                  "--expected-tags", expected, "--evidence", self.camp_a)
        report = json.loads(out)
        self.assertEqual(report["expected_count"], len(FLEET))
        self.assertEqual(report["captured_count"], len(FLEET))
        self.assertEqual(report["coverage_pct"], 100.0)
        self.assertEqual(report["missing_tags"], [])

    def test_04_replay_false_negative_under_10pct(self):
        out = run(REPLAY, "--feed", self.feed_a, "--evidence", self.camp_b)
        report = json.loads(out)
        self.assertEqual(report["total_indicators"], 5)
        self.assertLess(report["false_negative_pct"], 10.0)
        self.assertEqual(report["matched"], 5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
