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
- **Remaining parity (S7)**: the four README claims the sim previously never
  exercised end-to-end — IRC-only C2 channel (connect/auth/command/heartbeat
  over IRC), real SOCKS5 proxied traffic (RFC 1928/1929 client through the bot
  proxy to a target that sees the bot's source IP), persistence across reboot
  (device relaunches the payload after container restart), and payload
  pinning (valid SHA-256 pin accepted, tampered payload refused).

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
./run-sim.sh --scenario remaining-parity                # S7: IRC/SOCKS5/persistence/pinning
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

Segmentation is enforced TWO ways:
1. Per-segment scan targeting in the bot config (the bot only scans its configured
   subnet range) — this is what the ATTACKER sees.
2. **Host firewall (real L3)** — `defence/host_firewall.sh` programs Docker's
   DOCKER-USER chain so segments are actually isolated at the packet level
   (IoT cannot reach Office/DMZ, DMZ cannot initiate inward, C2 control ports
   stay reachable, hardened adds brute-force protection + IPS blacklist drops).
   Needs root: install the scoped NOPASSWD rule from `tests/sim/sudoers.example`,
   else the firewall is skipped with a warning and the sim runs with the
   log-layer defence only. The scripts use `sudo -n` only — never set or
   export a sudo password (no SUDO_PW; issue #339).

The defence layer also runs on evidence logs (no packet capture required).

## Defence: SIEM output (issue #155)

The IDS (`defence/ids_monitor.py`) can fan every detection out to real SOC
tooling. Backends are selected by environment variables — set any combination
for concurrent fanout, set none for the default local-only behaviour:

| Env var | Format | Transport |
|---|---|---|
| `SIM_SIEM_SYSLOG=host:port` | Syslog RFC 5424 (PRI 132 high / 130 medium / 110 info, `notnet@32473` structured data) | UDP datagrams |
| `SIM_SIEM_CEF=file:path` | ArcSight CEF v0 (`CEF:0\|notnet\|ids\|1.0\|<sig>\|<sig>\|<0-10>\|src=… dst=… msg=…`) | CEF-over-TCP line protocol; in the sim the identical newline-delimited records are appended to a file so a TCP collector or Filebeat file input can tail them unchanged |
| `SIM_SIEM_ECS=file:path` | Elastic Common Schema 8.x JSON lines (`@timestamp`, `event.kind=alert`, `source.ip`, `destination.ip`, `labels.signature`) | JSON-lines file |
| `SIM_SIEM_WEBHOOK=url` | Structured JSON (ECS body + `notnet` metadata) | HTTP POST |

Severity mapping: `CVE-EXPLOIT`/`PAYLOAD-DROP` → high, `SCAN-SWEEP`/
`BRUTE-BURST` → medium, `EDR`/`HONEYPOT` → info.

Example — fan out to syslog and both file formats from one detection stream:

```sh
export SIM_SIEM_SYSLOG=splunk.example.com:514
export SIM_SIEM_CEF=file:/var/log/notnet/ids-cef.log
export SIM_SIEM_ECS=file:/var/log/notnet/ids-ecs.json
```

Acceptance example — ingest the ECS JSON lines with Logstash:

```conf
input { file { path => "/var/log/notnet/ids-ecs.json" codec => json_lines } }
output { elasticsearch { hosts => ["https://es:9200"] index => "notnet-ids" } }
```

or with Filebeat (also works for the CEF file):

```yaml
filebeat.inputs:
  - type: filestream
    id: notnet-ids-ecs
    paths: [/var/log/notnet/ids-ecs.json]
    parsers: [{ndjson: {}}]
output.logstash:
  hosts: ["logstash:5044"]
```

Unit tests: `python3 tests/sim/defence/test_siem_emit.py` (validates the
RFC 5424 header regex, CEF pipe count = 7, ECS required fields; no deps).
