#!/usr/bin/env python3
"""Unit tests for the behavioral detectors added by issue #156.

Feeds synthetic (ts, src, dst[, port]) event tuples into the pure detector
functions in ids_monitor.py -- no file I/O involved.
"""
import os
import random
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ids_monitor as ids


T0 = 1_750_000_000.0


def test_beaconing_sustained_2s_heartbeat_flags():
    """30 heartbeats at exactly 2s intervals over 60s -> flags, conf > 0.8."""
    events = [(T0 + i * 2.0, "203.0.113.7", "http.log") for i in range(31)]
    hits = ids.detect_beaconing(events)
    assert hits, "sustained 2s heartbeat must flag"
    src, conf, detail = hits[0]
    assert src == "203.0.113.7"
    assert conf > ids.BEACON_REGULARITY, f"confidence {conf} must exceed {ids.BEACON_REGULARITY}"
    assert 0.0 <= conf <= 1.0


def test_beaconing_irregular_jitter_does_not_flag():
    """Heavy jitter on a fast mean interval must NOT flag."""
    rng = random.Random(156)
    t = T0
    events = []
    for _ in range(60):
        events.append((t, "198.51.100.9", "http.log"))
        # mean ~5s but jitter uniform 0..10s -> stdev ~2.9s, regularity <0.8
        t += rng.uniform(0.0, 10.0)
    hits = ids.detect_beaconing(events)
    assert not hits, f"irregular jitter must not flag, got {hits}"


def test_beaconing_too_few_intervals_does_not_flag():
    """Fewer than 5 intervals is never enough evidence."""
    events = [(T0 + i * 2.0, "203.0.113.7", "http.log") for i in range(5)]  # 4 intervals
    assert not ids.detect_beaconing(events)


def test_beaconing_slow_mean_does_not_flag():
    """Regular but slow (>10s mean) check-ins are not beaconing per criteria."""
    events = [(T0 + i * 60.0, "203.0.113.7", "http.log") for i in range(30)]
    assert not ids.detect_beaconing(events)


def test_lateral_movement_horizontal_scan_flags():
    """/24 horizontal scan: same port, >=3 distinct internal dsts in window."""
    targets = [f"172.29.1.{i}" for i in range(2, 27)]  # scan 25 hosts
    events = [(T0 + i * 1.0, "172.29.0.50", dst, 23)
              for i, dst in enumerate(targets)]
    hits = ids.detect_lateral(events)
    assert hits, "horizontal scan must flag"
    src, conf, detail = hits[-1]
    assert src == "172.29.0.50"
    assert conf == min(1.0, len(targets) / ids.LATERAL_CONF_DIVISOR)
    assert conf == 1.0  # 25 targets saturates


def test_lateral_movement_minimum_threshold():
    """Exactly 3 distinct targets flags at conf 3/5; 2 does not flag."""
    ev3 = [(T0 + i, "172.29.0.9", f"172.29.2.{i}", 445) for i in range(3)]
    hits = ids.detect_lateral(ev3)
    assert hits and hits[0][1] == 3 / ids.LATERAL_CONF_DIVISOR
    ev2 = [(T0 + i, "172.29.0.9", f"172.29.2.{i}", 445) for i in range(2)]
    assert not ids.detect_lateral(ev2)


def test_lateral_movement_outside_window_does_not_flag():
    """Same 3 targets but spread beyond LATERAL_WINDOW stays quiet."""
    spread = ids.LATERAL_WINDOW + 10
    events = [(T0 + i * spread, "172.29.0.9", f"172.29.2.{i}", 445) for i in range(3)]
    assert not ids.detect_lateral(events)


def test_cred_stuffing_50_in_10s_flags():
    """50 auth failures inside 10s triggers with conf 1.0."""
    events = [(T0 + i * 0.15, "45.155.205.233") for i in range(50)]
    hits = ids.detect_cred_stuffing(events)
    assert hits, "50 failures in 10s must flag"
    src, conf, detail = hits[0]
    assert src == "45.155.205.233"
    assert conf == 1.0


def test_cred_stuffing_below_rate_does_not_flag():
    """Failures spread wider than STUFF_WINDOW stay below threshold."""
    # 49 failures in-window plus older ones outside the window
    events = [(T0 - 60.0, "45.155.205.233")] * 10
    events += [(T0 + i * 0.2, "45.155.205.233") for i in range(49)]
    assert not ids.detect_cred_stuffing(events)
    # slow drip: 1 failure every 5s never accumulates 50 in 10s
    drip = [(T0 + i * 5.0, "45.155.205.233") for i in range(200)]
    assert not ids.detect_cred_stuffing(drip)


def test_composite_threat_score_weighted_max():
    """Composite score is the weighted max of active signals."""
    score = ids.composite_threat_score({"BEACONING": 0.95})
    assert abs(score - ids.SIGNAL_WEIGHTS["BEACONING"] * 0.95) < 1e-9
    score = ids.composite_threat_score(
        {"BEACONING": 0.85, "LATERAL-MOVEMENT": 0.6, "CRED-STUFF": 1.0})
    expected = max(ids.SIGNAL_WEIGHTS[s] * c for s, c in
                   {"BEACONING": 0.85, "LATERAL-MOVEMENT": 0.6, "CRED-STUFF": 1.0}.items())
    assert abs(score - expected) < 1e-9
    assert ids.composite_threat_score({}) == 0.0


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    failed = 0
    for fn in tests:
        try:
            fn()
            print(f"  ok {fn.__name__}")
        except AssertionError as exc:
            failed += 1
            print(f"FAIL {fn.__name__}: {exc}")
    print(f"{len(tests) - failed}/{len(tests)} passed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
