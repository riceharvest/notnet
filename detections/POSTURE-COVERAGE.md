# notnet — Posture-Indexed Coverage Cross-Table (#153)

This is the posture-indexed companion to `ATTACK-COVERAGE.md` (#147). It answers
the SOC question the sim was built to answer: **"if I patch my HG532es and disable
Telnet, which of notnet's paths survive?"**

Each named profile (defined in `tests/sim/defence/posture.yaml` and expanded by
`run-sim.sh --profile <name>`, #153) is a deterministic combination of **device
tier** + **network posture** + **host controls**. Run a profile through the sim
and assert the surviving/blocked set below.

## The profiles

| profile | device tier | posture | host controls | meaning |
|---|---|---|---|---|
| `legacy-unpatched` | legacy | lax | — | today's `legacy` tier: default creds, unpatched CVEs, telnet on |
| `patched-firmware` | modern | standard | segmentation | CVEs patched, SMB1 off, behind router segmentation |
| `edr-on` | modern | hardened | Wazuh+Sysmon+osquery (#150) | host telemetry layer catches fileless/LOTL Suricata misses |
| `credential-hygiene` | modern | standard | key-only SSH, no default creds | zeroes the SSH/Telnet brute rows |
| `segmented` | legacy | hardened | segmentation + IPS | IoT network isolated from office/dmz |

## Technique survival per profile

Legend: ✅ = technique lands (detection fires / device pwned) · ❌ = technique
blocked or dark (no detection needed, path dead) · 🟡 = caught host-side only
(network IDS blind — the #150 case).

| technique | legacy-unpatched | patched-firmware | edr-on | credential-hygiene | segmented |
|---|---|---|---|---|---|
| T1190 Exploit Pub-Facing | ✅ (CVEs fire) | ❌ (patched) | ❌ (patched) | ❌ (patched) | ✅ then ❌ (IPS drops) |
| T1110 Brute Force | ✅ | ❌ | ❌ | ❌ (key-only) | ✅ then ❌ (lockout/IPS) |
| T1005 Data from Local | ✅ | ❌ (no creds) | ❌ | ❌ | ✅ then ❌ |
| T1020 Automated Exfil | ✅ | ⚠️ (modern creds scarce) | ⚠️ | ⚠️ | ✅ then ❌ (segmentation) |
| T1572 Protocol Tunneling | ✅ | ✅ | ✅ | ✅ | ✅ (relay still works, but lateral blocked) |
| T1090 Proxy / T1021 Remote | ✅ | ✅ lateral | 🟡 host-caught | ✅ lateral | ✅ then ❌ (IoT→office DROP) |
| T1543 Persistence | ✅ | ❌ (EDR/modern) | ❌ (EDR block) | ❌ | ✅ then ❌ |
| T1027 Fileless (memfd) | 🟡 network-blind | 🟡 | ✅ caught (Sysmon/osquery) | 🟡 | 🟡 |
| T1489 Killswitch | ✅ (author only) | ✅ | ✅ | ✅ | ✅ |

## Key research findings (asserted by the sim)

- **`credential-hygiene` zeroes the SSH/Telnet brute rows.** With key-only SSH and
  no default creds, T1110 produces no harvest → T1005/T1020 have nothing to exfil.
  This is the single highest-leverage legacy mitigation.
- **`segmented` collapses lateral movement.** The `hardened` router policy (IoT
  DROP → office/dmz) means an IoT bot cannot reach the office segment, so T1021
  across segments is blocked even when the IoT device itself is pwned.
- **`edr-on` is the only profile that catches fileless/LOTL (T1027).** Suricata
  cannot see `memfd_create`→`fexecve`; Sysmon Event ID 1 (no on-disk image) +
  osquery `on_disk=0` do (#150). This is the coverage gap the host-telemetry layer
  exists to close.
- **T1572 (relay) survives every profile** because the relay is operator traffic
  through already-owned bots; segmentation blocks *lateral spread* but not the
  relay tunnel itself. The matching detection is `suricata:relay_via_chain` +
  `sigma:proxy_tunnel`, not a network block.

## Reproducing

```sh
cd tests/sim
./run-sim.sh --profile credential-hygiene --scenario all   # expect brute rows dark
./run-sim.sh --profile segmented          --scenario all   # expect lateral blocked
./run-sim.sh --profile edr-on             --scenario all   # expect fileless caught host-side
```

The detection CI (#151) replays the *detections*; this table is the *network/host*
half. Together they are the parameterized study a SOC can reason about.
