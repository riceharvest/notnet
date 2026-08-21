#!/usr/bin/env python3
"""Unit tests for siem_emit.py — plain asserts, no external deps.

Run:  python3 tests/sim/defence/test_siem_emit.py
"""
import json
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from siem_emit import (  # noqa: E402
    SIEMEmitter,
    format_cef,
    format_ecs,
    format_rfc5424,
    format_webhook,
    severity_for,
)

TS = "2026-08-21T10:00:00+00:00"

# ---------------------------------------------------------------- severity map
def test_severity_map():
    assert severity_for("CVE-EXPLOIT") == ("high", 132, 9)
    assert severity_for("PAYLOAD-DROP")[0] == "high"
    assert severity_for("SCAN-SWEEP") == ("medium", 130, 5)
    assert severity_for("BRUTE-BURST")[1] == 130
    assert severity_for("EDR")[0] == "info"
    assert severity_for("HONEYPOT")[2] == 3


# ------------------------------------------------------------------- RFC 5424
RFC5424_RE = re.compile(
    r"^<(?P<pri>\d{1,3})>1 "
    r"(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})) "
    r"(?P<host>\S+) (?P<app>\S+) (?P<proc>\S+) (?P<msgid>\S+) "
    r"(?P<sd>\[.+?\]) (?P<msg>.*)$"
)


def test_rfc5424_header():
    line = format_rfc5424("CVE-EXPLOIT", "10.0.0.9", "device-7", "SOAPAction hit", TS)
    m = RFC5424_RE.match(line)
    assert m, "RFC 5424 header does not match: %r" % line
    pri = int(m.group("pri"))  # type: ignore[union-attr]
    ts = m.group("ts")  # type: ignore[union-attr]
    msg = m.group("msg")  # type: ignore[union-attr]
    assert pri == 132
    assert ts == TS
    assert "SOAPAction hit" in msg


def test_rfc5424_pri_by_severity():
    for sig, pri in (("CVE-EXPLOIT", 132), ("PAYLOAD-DROP", 132),
                     ("SCAN-SWEEP", 130), ("BRUTE-BURST", 130),
                     ("EDR", 110), ("HONEYPOT", 110)):
        line = format_rfc5424(sig, "1.2.3.4", "d", "x", TS)
        m = RFC5424_RE.match(line)
        assert m
        got = int(m.group("pri"))
        assert got == pri, "%s: PRI %d != %d" % (sig, got, pri)


def test_rfc5424_structured_data():
    line = format_rfc5424("SCAN-SWEEP", "10.0.0.5", "cam-3", "sweep", TS)
    sd = RFC5424_RE.match(line).group("sd")
    assert sd.startswith("[notnet@")
    for field in ('sig="SCAN-SWEEP"', 'src="10.0.0.5"',
                  'dst="cam-3"', 'severity="medium"'):
        assert field in sd, "missing %s in SD %r" % (field, sd)
    # SD-ID is a single bracketed block; balanced brackets inside values are escaped-free here
    assert sd.count("[") == 1 and sd.count("]") == 1


# ------------------------------------------------------------------------ CEF
def test_cef_pipe_count_and_header():
    line = format_cef("CVE-EXPLOIT", "10.0.0.9", "device-7", "formSysCmd probe")
    # Header CEF:0|vendor|product|version|sigid|name|severity| => exactly 7 pipes
    assert line.count("|") == 7, "CEF pipe count != 7: %r" % line
    parts = line.split("|")
    assert parts[0] == "CEF:0"
    assert parts[1:4] == ["notnet", "ids", "1.0"]
    assert parts[4] == "CVE-EXPLOIT" and parts[5] == "CVE-EXPLOIT"
    sev = int(parts[6])
    assert 0 <= sev <= 10
    ext = parts[7]
    assert ext.startswith("src=10.0.0.9 dst=device-7 msg=formSysCmd probe")


def test_cef_severity_range_all_sigs():
    for sig in ("CVE-EXPLOIT", "PAYLOAD-DROP", "SCAN-SWEEP",
                "BRUTE-BURST", "EDR", "HONEYPOT"):
        sev = int(format_cef(sig, "a", "b", "c").split("|")[6])
        assert 0 <= sev <= 10, "%s CEF severity out of range: %d" % (sig, sev)


def test_cef_escapes_pipes_in_extensions():
    # detail containing '=' and newline must not break the extension parsing
    line = format_cef("EDR", "src", "dst", "weird=detail\nmore")
    ext = line.split("|", 7)[7]
    assert "\\=" in ext and "\\n" in ext
    assert line.count("|") == 7


# ------------------------------------------------------------------------ ECS
def test_ecs_required_fields():
    obj = json.loads(json.dumps(
        format_ecs("BRUTE-BURST", "10.0.0.8", "nas-1", "12 failures", TS)))
    assert obj["@timestamp"] == TS
    assert obj["ecs"]["version"] == "8.0.0"
    ev = obj["event"]
    assert ev["kind"] == "alert" and ev["module"] == "notnet-ids"
    assert isinstance(ev["severity"], int) and 0 <= ev["severity"] <= 10
    assert obj["source"]["ip"] == "10.0.0.8"
    assert obj["destination"]["ip"] == "nas-1"
    assert obj["message"] == "12 failures"
    assert obj["labels"]["signature"] == "BRUTE-BURST"


def test_ecs_json_lines_roundtrip():
    for sig in ("HONEYPOT", "PAYLOAD-DROP"):
        raw = json.dumps(format_ecs(sig, "1.1.1.1", "hp", "contact", TS))
        obj = json.loads(raw)  # one JSON object per line
        assert obj["labels"]["signature"] == sig
        assert obj["event"]["kind"] == "alert"


def test_webhook_payload():
    obj = format_webhook("HONEYPOT", "1.1.1.1", "hp", "contact", TS)
    assert obj["notnet"]["signature"] == "HONEYPOT"
    assert obj["notnet"]["severity"] == "info"
    assert obj["@timestamp"] == TS


# -------------------------------------------------------------------- emitter
def test_emitter_noop_when_unset():
    e = SIEMEmitter(env={})
    assert not e.enabled
    e.emit("EDR", "1.1.1.1", "pc", "x")  # must be a silent no-op


def _tmpfile(suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path


def test_emitter_fanout_to_two_files():
    cef_path = _tmpfile(".cef")
    ecs_path = _tmpfile(".json")
    try:
        e = SIEMEmitter(env={"SIM_SIEM_CEF": "file:" + cef_path,
                             "SIM_SIEM_ECS": "file:" + ecs_path})
        assert len(e.backends) == 2 and e.enabled
        e.emit("CVE-EXPLOIT", "10.0.0.9", "dev-7", "boom", TS)
        cef_lines = open(cef_path).read().strip().splitlines()
        ecs_lines = open(ecs_path).read().strip().splitlines()
        assert len(cef_lines) == 1 and len(ecs_lines) == 1
        assert cef_lines[0].count("|") == 7
        obj = json.loads(ecs_lines[0])
        assert obj["labels"]["signature"] == "CVE-EXPLOIT"
        assert obj["@timestamp"] == TS
    finally:
        os.unlink(cef_path)
        os.unlink(ecs_path)


def test_emitter_env_formats():
    e = SIEMEmitter(env={"SIM_SIEM_SYSLOG": "siem.local:514",
                         "SIM_SIEM_WEBHOOK": "https://x.example/hook"})
    kinds = sorted(b[0] for b in e.backends)
    assert kinds == ["syslog", "webhook"]
    syslog = [b for b in e.backends if b[0] == "syslog"][0]
    assert syslog[1] == "siem.local" and syslog[2] == 514


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for t in tests:
        try:
            t()
            print("PASS %s" % t.__name__)
        except AssertionError as exc:
            failed += 1
            print("FAIL %s: %s" % (t.__name__, exc))
    print("%d/%d passed" % (len(tests) - failed, len(tests)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
