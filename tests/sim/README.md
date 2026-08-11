# notnet sim — real-world attack simulation

The repo ships a **full network + host + target simulation** (`tests/sim/`) that
runs the real notnet binary against a heterogeneous fleet of emulated devices
(fridges, cameras, routers, TVs, PCs, NAS, Redis boxes, honeypots) exactly as a
malicious actor would: C2-driven proliferation, autonomous-propagation attempts,
payload execution on victims, credential harvesting, and an active defence layer
(IDS/IPS, lockout, EDR, honeypots, patched devices).

## What it validates

- **C2 channels**: HTTP + WebSocket (RFC 6455) + legacy IRC, shared-secret gate
- **Spreading**: CVE modules (TBK/HG532/Realtek), SSH/Telnet/SMB/Redis/RDP brute-force
- **Payload loop**: cracked devices actually execute the dropped binary and join
  the C2 as new bots (real propagation, measured by heartbeat bot_tag)
- **Autonomous propagation** (expected FAIL on shipped code — issue #95)
- **Resilience**: fast-flux, dead-drop, C2 rotation
- **Monetization**: SOCKS5 proxy, credential-log exfil, relay
- **Defence envelope**: same attack under lax/standard/hardened posture

## Usage

```sh
cd tests/sim
./run-sim.sh --scenario all --posture standard          # full run
./run-sim.sh --scenario c2-drive --posture lax          # operator-driven spread
./run-sim.sh --scenario autonomous                      # Finding A proof
./run-sim.sh --scenario defence --posture hardened      # IDS/lockout/EDR
./run-sim.sh --scenario resilience                      # dead-drop + rotation
./run-sim.sh --scenario flux                            # fast-flux multi-A
./run-sim.sh --scenario monetization                    # proxy + relay
```

Requires: Docker + Docker Compose, Python 3 with pyyaml. The bot image
compiles notnet in-container (`make clean && make`), validating the build.

## Output

- `reports/parity-<ts>.md` — auto-generated parity matrix (claim → PASS/FAIL → evidence)
- `reports/evidence-<ts>/` — per-service logs (device auths, CVE drops, heartbeats)
- `PARITY-MATRIX.md` — the spec (README claim → scenario → evidence grep)

## Topology

```
c2net-less flat simnet 172.29.0.0/16 (Docker bridge)
  c2:8080 (HTTP C2 + payload 8443 + src tar)   c2-ws:8081 (WS C2)
  c2-irc:6667 (legacy IRC)   c2-backup:8082    deaddrop:8090
  dnsmasq (flux-c2 multi-A)   ids-monitor (log IDS/IPS)
  bot (the attacker's payload, per-scenario config)
  30+ device containers (device.py emulator) + Cowrie honeypots
```

Segmentation is emulated by per-segment scan targeting (the bot only scans its
configured subnet range); a real iptables router is future work (needs
advanced Docker networking). The defence layer runs on evidence logs, so no
packet capture is required.
