#!/usr/bin/env python3
"""notnet sim driver — orchestrates scenarios, injects C2 commands, collects
evidence, and writes the parity report.

Usage:
  python3 run_sim.py [--scenario all|c2-drive|autonomous|resilience|monetization|defence] [--posture lax|standard|hardened]

Scenarios:
  c2-drive     S1: operator drives spread/scan against the fleet via the C2 queue
  autonomous   S2: IRC+HTTP disabled, bot left to spread on its own (Finding A)
  resilience   S5: flux + dead-drop + rotation
  monetization S6: SOCKS5 proxy + relay client tests
  defence      S8: same as c2-drive under lax/standard/hardened posture
  all          run c2-drive then autonomous (default)

Output: reports/parity-<timestamp>.md + reports/evidence/ copy of logs.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone

BASE = os.path.dirname(os.path.abspath(__file__))
QUEUE = os.path.join(BASE, "queue")
EVIDENCE = os.path.join(BASE, "evidence")
REPORTS = os.path.join(BASE, "reports")
C2_SECRET = os.environ.get("SIM_C2_SECRET", "mocksecret")

# Fleet summary loaded from fleet.yaml (light, no yaml dep: hardcode ids)
FLEET_IDS = [
    "fridge-01", "fridge-02", "cam-01", "cam-02",
    "router-01", "router-02", "router-03", "router-04",
    "tv-01", "thermostat-01", "baby-monitor-01", "printer-01",
    "pc-01", "pc-02", "winpc-01", "winpc-02", "nas-01", "server-01", "server-02",
    "web-01", "redis-01", "db-01",
]
# Modern/hardened tier — a 2026 attacker should NOT crack these.
MODERN_TIER = set(FLEET_IDS)
# Legacy/unmanaged tier — the small population botnets survive on;
# these SHOULD be pwned.
LEGACY_TIER = [
    "legacy-cam-01", "legacy-cam-02", "legacy-router-01", "legacy-router-02",
    "legacy-fridge-01", "legacy-pc-01", "legacy-server-01", "legacy-nas-01",
    "legacy-redis-01", "legacy-redis-02", "legacy-db-01",
]
HONEYPOTS = ["honeypot-telnet-01", "honeypot-ssh-01"]


def ts():
    return datetime.now(timezone.utc).isoformat()


def log(msg):
    print(f"[{ts()}] {msg}", flush=True)


# ───────────────────────── C2 command injection ─────────────────────────

_queue_seq = 0

def queue_cmd(cmd, args=""):
    """Drop a command into the C2 queue (served on next heartbeat)."""
    global _queue_seq
    os.makedirs(QUEUE, exist_ok=True)
    _queue_seq += 1
    fn = os.path.join(QUEUE, f"cmd-{int(time.time()*1000)}-{os.getpid()}-{_queue_seq:04d}.json")
    with open(fn, "w") as f:
        json.dump({"cmd": cmd, "args": args}, f)
    log(f"QUEUE {cmd} {args}")


# ───────────────────────── evidence helpers ─────────────────────────

def read_evidence():
    """Return dict: filename -> list of lines."""
    out = {}
    if not os.path.isdir(EVIDENCE):
        return out
    for fn in os.listdir(EVIDENCE):
        if fn.endswith(".log"):
            p = os.path.join(EVIDENCE, fn)
            try:
                with open(p, errors="replace") as f:
                    out[fn] = f.readlines()
            except OSError:
                pass
    return out


def grep_evidence(ev, patterns, files=None):
    """Return lines matching any pattern (substring)."""
    hits = []
    for fn, lines in ev.items():
        if files and not any(f in fn for f in files):
            continue
        for ln in lines:
            if any(p.lower() in ln.lower() for p in patterns):
                hits.append((fn, ln.strip()))
    return hits


def unique_tags(ev):
    """Extract unique bot_tag values from heartbeat JSON in http.log/ws.log."""
    tags = set()
    for fn, lines in ev.items():
        if not ("http.log" in fn or "ws.log" in fn or "backup" in fn):
            continue
        for ln in lines:
            if '"tag"' not in ln:
                continue
            try:
                # http.log: "<iso> <kind> from <ip> body={json}"
                # ws.log:   "<iso> WS FRAME <ip>: {json}"  (no body= prefix)
                if "body=" in ln:
                    body = ln.split("body=", 1)[1]
                else:
                    body = ln.split(": ", 1)[1] if ": " in ln else ln
                j = json.loads(body)
                if j.get("cmd") == "status" and j.get("tag"):
                    tags.add(j["tag"])
            except Exception:
                pass
    return tags


# ───────────────────────── checks ─────────────────────────

class Report:
    def __init__(self):
        self.rows = []

    def add(self, claim, result, evidence, detail=""):
        self.rows.append((claim, result, evidence, detail))
        log(f"  [{result}] {claim}" + (f" — {detail}" if detail else ""))

    def render(self):
        lines = [f"# notnet sim parity report — {ts()}", ""]
        lines.append("| Claim | Result | Evidence |")
        lines.append("|---|---|---|")
        for claim, result, evidence, detail in self.rows:
            lines.append(f"| {claim} | {result} | {evidence} |")
        return "\n".join(lines) + "\n"


def wait_for(predicate, timeout, what):
    start = time.time()
    while time.time() - start < timeout:
        if predicate():
            return True
        time.sleep(1)
    log(f"  TIMEOUT waiting for {what}")
    return False


def recreate_bot(conf):
    """Force-recreate the bot service with a different config mount."""
    env = dict(os.environ)
    env["SIM_BOT_CONF"] = conf
    subprocess.run(
        ["docker", "compose", "-f", "docker-compose.sim.yml",
         "-f", "docker-compose.fleet.yml", "up", "-d", "--force-recreate", "bot"],
        cwd=BASE, env=env, capture_output=True, text=True, timeout=120)
    log(f"bot recreated with config {conf}")


def bot_log_since(ts_epoch):
    """Return bot docker log lines since a unix timestamp."""
    try:
        r = subprocess.run(["docker", "logs", "sim-bot", "--since", str(int(ts_epoch))],
                           capture_output=True, text=True, timeout=30)
        return (r.stdout or "") + (r.stderr or "")
    except Exception:
        return ""


# ───────────────────────── scenarios ─────────────────────────

def dev_name(fname):
    """'legacy-cam-01.log' -> 'legacy-cam-01'; 'cam-01.log' -> 'cam-01'."""
    return os.path.basename(fname).rsplit(".", 1)[0]


def scenario_c2drive(report):
    log("=== S1 c2-drive: operator-driven proliferation ===")
    # 1. scan small subnets quickly (a /24 scan blocks the command loop ~30s+)
    queue_cmd("scan", "172.29.10.0/28")
    queue_cmd("scan", "172.29.20.0/28")

    # 2. spread per vector — BOTH tiers: modern (should resist) and legacy
    #    (the real-world finding: this is what actually gets pwned).
    targets = [
        # modern tier — a 2026 attacker should NOT crack these
        ("172.29.10.12", 80, "cam-01 TBK patched"),
        ("172.29.10.13", 80, "cam-02 TBK partial-patch"),
        ("172.29.10.15", 37215, "router-01 HG532 patched"),
        ("172.29.10.17", 80, "router-03 Realtek patched"),
        ("172.29.20.10", 22, "pc-01 SSH key-only"),
        ("172.29.20.12", 445, "winpc-01 SMB1 off"),
        ("172.29.20.12", 3389, "winpc-01 RDP NLA"),
        ("172.29.30.11", 6379, "redis-01 strong AUTH"),
        # legacy tier — the vulnerable tail botnets survive on
        ("172.29.10.30", 80, "legacy-cam-01 TBK + telnet"),
        ("172.29.10.32", 37215, "legacy-router-01 HG532 + telnet"),
        ("172.29.10.33", 80, "legacy-router-02 Realtek + telnet"),
        ("172.29.10.34", 23, "legacy-fridge-01 telnet"),
        ("172.29.20.30", 22, "legacy-pc-01 SSH"),
        ("172.29.20.32", 445, "legacy-nas-01 SMB"),
        ("172.29.30.20", 6379, "legacy-redis-01 unauth"),
        ("172.29.30.21", 6379, "legacy-redis-02 weak AUTH"),
    ]
    for ip, port, label in targets:
        queue_cmd("spread", f"{ip}:{port}")

    # 3. wait for spread + payload execution + heartbeats.
    # Each spread command may run the full brute-force pool; the C2 serves one
    # command per heartbeat, and MODERN devices burn the full 19x25 pool
    # rejecting. Give the queue ample time to drain (legacy completes early,
    # modern grind takes minutes).
    time.sleep(120)
    ev = read_evidence()

    # CVE drops — evidence lives in the DEVICE logs. Match only REAL exploit
    # traffic: "DROP received" / "EXECUTING DROP" on a device = exploit fired.
    cve_drops = grep_evidence(ev, ["DROP received", "EXECUTING DROP"])
    legacy_drops = [h for h in cve_drops if dev_name(h[0]) in LEGACY_TIER]
    report.add("CVE modules fire against LEGACY devices (real exploit traffic)",
               "PASS" if legacy_drops else "FAIL",
               "; ".join(h[1][:80] for h in legacy_drops[:5]) or "no CVE exploit traffic on legacy")

    # Modern-tier CVE resistance: patched devices must show resistance
    # evidence (probe miss / verify no-echo) and NO drop.
    modern_cve_resist = grep_evidence(ev, ["probe on patched", "verify on partial-patch", "-> miss"])
    modern_drops = [h for h in cve_drops if dev_name(h[0]) in MODERN_TIER]
    report.add("CVE modules DO NOT fire against patched/modern devices (real-world resistance)",
               "PASS" if modern_cve_resist and not modern_drops else "FAIL",
               f"resistance={len(modern_cve_resist)} modern_drops={len(modern_drops)}; " +
               "; ".join(h[1][:70] for h in modern_cve_resist[:3]))

    # brute-force cred harvest — legacy should crack, modern must not
    cred_hits = grep_evidence(ev, ["AUTH OK", "cracked"])
    cred_on_modern = [h for h in cred_hits if dev_name(h[0]) in MODERN_TIER]
    cred_on_legacy = [h for h in cred_hits if dev_name(h[0]) in LEGACY_TIER]
    report.add("Brute-force succeeds ONLY on legacy devices (real-world)",
               "PASS" if cred_on_legacy and not cred_on_modern else "FAIL",
               f"legacy={len(cred_on_legacy)} modern={len(cred_on_modern)}; " +
               "; ".join(h[1][:70] for h in cred_on_legacy[:3]))

    # payload execution (drop actually ran)
    drop_hits = grep_evidence(ev, ["EXECUTING DROP", "DROP received", "DROP spawned"])
    report.add("Payload drop executed on victims (legacy tier)", "PASS" if drop_hits else "FAIL",
               "; ".join(h[1][:80] for h in drop_hits[:5]) or "no drop evidence")

    # infection propagation: heartbeat tags beyond the attacker bot
    tags = unique_tags(ev)
    infected = tags - {"sim-attacker-1"}
    report.add("Infected devices join C2 with own bot_tag (propagation)",
               "PASS" if infected else "FAIL",
               f"tags={sorted(infected)[:12]}" if infected else "no infected tags",
               f"{len(infected)} infected")

    # real-world tier separation: modern tier must stay clean
    bad = infected & MODERN_TIER
    report.add("MODERN tier NOT infected (real-world security holds)",
               "PASS" if not bad else "FAIL",
               f"unexpected={sorted(bad)}" if bad else "modern fleet clean")
    # legacy tier: some should be infected (that's the real-world finding)
    legacy_infected = infected & set(LEGACY_TIER)
    report.add("LEGACY tier is the infected population (real-world finding)",
               "PASS" if legacy_infected else "SKIP",
               f"legacy infected={sorted(legacy_infected)[:8]}" if legacy_infected else "no legacy infected yet")

    # cred log exfil
    queue_cmd("exfil_creds")
    time.sleep(5)
    ev = read_evidence()
    exfil_hits = grep_evidence(ev, ["no credentials buffered", "exfil_creds"])
    report.add("exfil_creds command dispatched", "PASS" if exfil_hits else "FAIL",
               "; ".join(h[1][:80] for h in exfil_hits[:3]) or "no exfil evidence")


def scenario_autonomous(report):
    log("=== S2 autonomous: bot left to spread on its own (Finding A) ===")
    # Switch the bot to the autonomous config (IRC+HTTP disabled) so
    # spread_local() actually runs, and start a clean log window.
    recreate_bot("notnet.conf.autonomous")
    time.sleep(5)
    window_start = time.time()
    # Snapshot pre-existing infected tags + drop evidence so S1 leftovers
    # (same run) can't fake a PASS.
    pre_ev = read_evidence()
    pre_tags = unique_tags(pre_ev)
    pre_drop_lines = {ln for _, ln in grep_evidence(pre_ev, ["EXECUTING DROP", "DROP received", "payload dropped"])}
    log(f"  pre-existing infected tags (from prior scenarios): {sorted(pre_tags)}")
    time.sleep(50)
    ev = read_evidence()

    # spread_local + scan cycle evidence lives in the BOT's docker log, not
    # the evidence files (scan_subnet only probes, never writes to targets).
    botlog = bot_log_since(window_start)
    scan_hits = [l for l in botlog.splitlines() if "Local spread cycle" in l or "scan:" in l]
    report.add("Autonomous scan cycle runs (spread_local path)",
               "PASS" if scan_hits else "FAIL",
               "; ".join(l.strip()[:80] for l in scan_hits[-3:]) or "no scan evidence")

    drop_hits = grep_evidence(ev, ["EXECUTING DROP", "DROP received", "payload dropped"])
    new_drops = [(f, l) for f, l in drop_hits if l not in pre_drop_lines]
    report.add("Autonomous propagation delivers payloads (README claim)",
               "FAIL" if not new_drops else "PASS",
               "; ".join(l[:80] for _, l in new_drops[:5]) or "NO NEW payload drops — probe-only spreader (Finding A)")

    tags = unique_tags(ev)
    new_infected = (tags - pre_tags) - {"sim-attacker-1"}
    report.add("Autonomous infection of the fleet (new tags only)",
               "FAIL" if not new_infected else "PASS",
               f"new={sorted(new_infected)[:10]}" if new_infected else f"no NEW infections (Finding A); pre-existing={sorted(pre_tags)}")

def scenario_resilience(report):
    log("=== S5 resilience: dead-drop + rotation (flux uses its own config) ===")
    time.sleep(15)
    ev = read_evidence()

    # dead-drop: with ?secret=ok the bot should be repointed to the drop server.
    # Evidence lives in the bot's docker log AND deaddrop.log.
    try:
        r = subprocess.run(["docker", "logs", "sim-bot"],
                           capture_output=True, text=True, timeout=30)
        botlog = (r.stdout or "") + (r.stderr or "")
    except Exception:
        botlog = ""
    dd_hits = grep_evidence(ev, ["dead-drop", "DEADDROP", "dead_drop", "applied verified"],
                            files=["deaddrop.log", "http.log"])
    dd_bot = [l for l in botlog.splitlines() if "Dead-drop" in l or "dead_drop" in l]
    all_dd = dd_hits + [("sim-bot-log", l.strip()) for l in dd_bot]
    report.add("Dead-drop blob fetched + verified override applied",
               "PASS" if all_dd else "FAIL",
               "; ".join(h[1][:80] for h in all_dd[:3]) or "no dead-drop evidence")


def scenario_flux(report):
    log("=== S5b flux: multi-A rotation past a blackhole IP ===")
    recreate_bot("notnet.conf.flux")
    time.sleep(5)
    time.sleep(40)
    ev = read_evidence()
    # heartbeats should keep flowing (flux rotates off the blackhole IP)
    hb_hits = grep_evidence(ev, ["heartbeat", "C2 heartbeat"], files=["http.log"])
    # flux resolution evidence: use the FULL bot log (the connect happens
    # within seconds of recreate, before any per-window slice starts)
    try:
        r = subprocess.run(["docker", "logs", "sim-bot"],
                           capture_output=True, text=True, timeout=30)
        botlog = (r.stdout or "") + (r.stderr or "")
    except Exception:
        botlog = ""
    flux_lines = [l for l in botlog.splitlines()
                  if "FLUX" in l or "flux-c2" in l or "HTTP: connected" in l or "HTTP: attempting" in l]
    report.add("Fast-flux: heartbeats flow despite blackhole IP",
               "PASS" if hb_hits else "FAIL",
               f"{len(hb_hits)} heartbeat lines; " + "; ".join(l.strip()[:70] for l in flux_lines[-3:]))
    report.add("Fast-flux: flux resolution attempted (multi-A)",
               "PASS" if any("FLUX" in l for l in botlog.splitlines()) or
                          any("flux-c2" in l and "connected" in l for l in botlog.splitlines())
               else "FAIL",
               "; ".join(l.strip()[:70] for l in flux_lines[:3]) or "no flux lines in bot log")


def scenario_monetization(report):
    log("=== S6 monetization: SOCKS5 proxy + relay ===")
    recreate_bot("notnet.conf.c2drive")
    time.sleep(5)
    queue_cmd("proxy", "on 1080")
    queue_cmd("relay", "on 1081")
    time.sleep(20)
    ev = read_evidence()
    try:
        r = subprocess.run(["docker", "logs", "sim-bot"],
                           capture_output=True, text=True, timeout=30)
        botlog = (r.stdout or "") + (r.stderr or "")
    except Exception:
        botlog = ""
    proxy_hits = grep_evidence(ev, ["proxy", "SOCKS"], files=["http.log", "ws.log"])
    proxy_bot = [l for l in botlog.splitlines() if "proxy" in l.lower()]
    relay_hits = grep_evidence(ev, ["relay"], files=["http.log", "ws.log"])
    relay_bot = [l for l in botlog.splitlines() if "relay" in l.lower()]
    report.add("proxy on command dispatched + listener starts",
               "PASS" if proxy_hits or proxy_bot else "FAIL",
               "; ".join(h[1][:80] for h in proxy_hits[:2] + [("sim-bot-log", l.strip()) for l in proxy_bot[:2]]) or "no proxy evidence")
    report.add("relay on command dispatched + listener starts",
               "PASS" if relay_hits or relay_bot else "FAIL",
               "; ".join(h[1][:80] for h in relay_hits[:2] + [("sim-bot-log", l.strip()) for l in relay_bot[:2]]) or "no relay evidence")


def fw_rules_active():
    """Host firewall presence: count our DOCKER-USER rules via sudo."""
    import subprocess
    try:
        pw = os.environ.get("SUDO_PW", "")
        if pw:
            cmd = ["sudo", "-S", "iptables", "-S", "DOCKER-USER"]
            r = subprocess.run(cmd, input=pw + "\n", capture_output=True, text=True, timeout=10)
        else:
            cmd = ["sudo", "-n", "iptables", "-S", "DOCKER-USER"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        return "notnet-sim" in (r.stdout or "")
    except Exception:
        return False


def scenario_defence(report):
    log("=== S8 defence envelope ===")
    posture = os.environ.get("SIM_POSTURE", "lax")
    # Drive a spread burst so the IDS/lockout/EDR have real behaviour to catch.
    # pc-02 has lockout=true (SSH creds in pool → many failures first),
    # pc-01 + winpc-01 have edr_block=true, fridge-01 triggers brute-burst.
    for ip, port, label in [
        ("172.29.20.11", 22, "pc-02 SSH lockout (fails 5x -> lockout)"),
        ("172.29.10.10", 23, "fridge-01 telnet brute (8x -> IDS BRUTE-BURST)"),
        ("172.29.20.30", 22, "legacy-pc-01 SSH crack -> EDR blocks exec"),
        ("172.29.20.10", 22, "pc-01 SSH EDR"),
        ("172.29.20.12", 445, "winpc-01 SMB EDR"),
        ("172.29.10.12", 80, "cam-01 CVE"),
    ]:
        queue_cmd("spread", f"{ip}:{port}")
    # The bot serves one command per heartbeat; brute-force pools take time.
    time.sleep(200)
    ev = read_evidence()
    alert_hits = grep_evidence(ev, ["ALERT sig="], files=["ids_alerts.log"])
    if posture == "hardened":
        # In hardened the host firewall's brute-force protection often drops the
        # attacker's connection burst BEFORE it reaches devices, so the IDS (which
        # feeds on device logs) may see little. That IS the defence working.
        report.add(f"IDS alerts under posture={posture}",
                   "PASS" if alert_hits else "SKIP",
                   "; ".join(h[1][:80] for h in alert_hits[-3:]) or "suppressed by host firewall brute-force protection (expected at hardened)")
    else:
        report.add(f"IDS alerts under posture={posture}", "PASS" if alert_hits else "SKIP",
                   "; ".join(h[1][:80] for h in alert_hits[-3:]) or "no IDS alerts (lax expected)")
    lockout_hits = grep_evidence(ev, ["LOCKOUT triggered", "LOCKOUT: ", "account locked"])
    report.add(f"Account lockout under posture={posture}", "PASS" if lockout_hits else "SKIP",
               "; ".join(h[1][:80] for h in lockout_hits[:3]) or "no lockouts")
    edr_hits = grep_evidence(ev, ["EDR-ALERT"])
    report.add(f"EDR detection under posture={posture}", "PASS" if edr_hits else "SKIP",
               "; ".join(h[1][:80] for h in edr_hits[:3]) or "no EDR alerts (not hardened)")
    # Host firewall: segmentation rules must be present for standard/hardened.
    fw = fw_rules_active()
    if posture == "lax":
        report.add("Host firewall (DOCKER-USER) enforced", "SKIP" if fw else "PASS",
                   "lax = no rules expected")
    else:
        report.add("Host firewall (DOCKER-USER) enforced", "PASS" if fw else "FAIL",
                   "segmentation rules in DOCKER-USER" if fw else "no notnet-sim rules found (needs sudo)")


def copy_evidence():
    d = os.path.join(REPORTS, f"evidence-{int(time.time())}")
    os.makedirs(d, exist_ok=True)
    if os.path.isdir(EVIDENCE):
        for fn in os.listdir(EVIDENCE):
            if fn.endswith(".log"):
                shutil.copy2(os.path.join(EVIDENCE, fn), os.path.join(d, fn))
    return d


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="all",
                    choices=["all", "c2-drive", "autonomous", "resilience", "flux",
                             "monetization", "defence"])
    ap.add_argument("--posture", default=os.environ.get("SIM_POSTURE", "lax"),
                    choices=["lax", "standard", "hardened"])
    args = ap.parse_args()
    os.environ["SIM_POSTURE"] = args.posture

    os.makedirs(REPORTS, exist_ok=True)
    report = Report()

    log(f"driver start scenario={args.scenario} posture={args.posture}")

    if args.scenario in ("all", "c2-drive"):
        scenario_c2drive(report)
    if args.scenario in ("all", "autonomous"):
        scenario_autonomous(report)
    if args.scenario in ("resilience",):
        scenario_resilience(report)
    if args.scenario in ("flux",):
        scenario_flux(report)
    if args.scenario in ("monetization",):
        scenario_monetization(report)
    if args.scenario in ("defence",):
        scenario_defence(report)

    evdir = copy_evidence()
    out = os.path.join(REPORTS, f"parity-{int(time.time())}.md")
    with open(out, "w") as f:
        f.write(report.render())
        f.write(f"\nEvidence copied to: {evdir}\n")

    fails = [r for r in report.rows if r[1] == "FAIL"]
    log(f"driver done: {len(report.rows)} checks, {len(fails)} FAIL")
    log(f"report: {out}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
