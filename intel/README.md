# notnet — STIX 2.1 / TAXII threat-intel publication (#152)

This directory turns notnet from "here's code" into "here's the threat you can
block today." It is the consumable, machine-readable half of the project.

## What's here

```
intel/
  build_intel.py    source of truth — re-extracts every IOC from include/config.h
                    and src/spread.c, writes intel-latest.json. Also --check mode
                    (CI, #151) to fail the build on drift.
  intel-latest.json STIX 2.1 bundle (indicators + attack-patterns)
  attack_mapping.json technique -> detection mapping (ties to ATTACK-COVERAGE.md, #147)
  taxii_server.py   dependency-free stdlib TAXII 2.1 server
  botnet_mapper.py  #162 — map the infected fleet from external evidence
  sinkhole_sim.py   #162 — DGA domain prediction + sinkhole capture report
  replay_check.py   #162 — cross-campaign IOC feed replay validation
  test_attribution.py #162 — end-to-end tests for the three tools above
  README.md         this file
```

## Attribution toolchain (#162)

Three tools that turn a finished sim run into outside-view threat intel:

### botnet_mapper.py — map the fleet without touching C2

```sh
python3 intel/botnet_mapper.py --evidence tests/sim/evidence --out mapper.json
```

Parses `http.log` C2 heartbeats (`<ts> C2 heartbeat from <IP> body={"tag":...}`)
and `ids_alerts.log` into an attribution report: `infected_count`, per-device
`{tag, ip, first_seen, last_seen}`, a segment breakdown (geo-by-segment:
`172.29.10.* = iot`, `.20.* = office`, `.30.* = dmz`) and a variant
fingerprint — which CVE each device was exploited through (from
`CVE-EXPLOIT` IDS alerts whose dst/detail names the device tag).

### sinkhole_sim.py — take over the DGA domain

```sh
# what will the bots resolve on day 233?
python3 intel/sinkhole_sim.py --generate-dga-seed --seed myseed --day 233
# -> 8-hex.sim.test   (SHA-256(seed + str(day)).hexdigest()[:8] + "." + tld)

# who checked in while we held the domain?
python3 intel/sinkhole_sim.py --domain <dga-domain> \
    --expected-tags cam-01,cam-02,cam-03 --evidence tests/sim/evidence
```

Reports captured vs expected bot tags with coverage % — the acceptance gate
is 100% of DGA-using bots captured by the sinkhole.

### replay_check.py — does the campaign-A feed still detect campaign B?

```sh
python3 intel/replay_check.py --feed intel/intel-latest.json \
    --evidence tests/sim/campaign-b --out replay.json
```

Extracts every observable from the STIX bundle's indicator patterns
(`ipv4-addr`, `domain-name`, `url`, `file:hashes.*`) and scans the raw text of
a second campaign's evidence for matches. Reports `total_indicators`,
`matched`, `detection_rate` and `false_negative_pct`; acceptance is FN < 10%.

### Tests

```sh
python3 intel/test_attribution.py    # synthesizes two tiny campaigns in temp dirs,
                                     # runs all three tools via subprocess
```

## IOCs published (all extracted from source — no hand-copied values)

- **C2 domains** (config.h:47/53/37 + 109): `api.notnet.net`, `ws.notnet.net`,
  `irc.notnet.net`, `peers.notnet.net`.
- **Killswitch domain** (config.h:146): `killswitch.invalid`. **This is itself a
  shareable IOC** — a defender can sinkhole it (point at `127.0.0.1`) to disarm
  any *stock-built* leaked fleet (#130). Publishing it turns the author's own
  safety mechanism into a defender tool.
- **CVE modules** (src/spread.c): `CVE-2017-17215` (HG532), `CVE-2021-35395`
  (Realtek), `CVE-2024-3721` (TBK DVR).
- **Wire fingerprints**: `/api/v1/bot` + `/ws/v1/bot` C2 paths, the
  `RELAY … VIA` multi-hop relay chain (src/relay.c).
- **ATT&CK mapping** on every bundle (ties to #147).

## Why a generator, not a checked-in file

`build_intel.py` reads the real `config.h` / `src/spread.c` every run. CI runs
`python3 intel/build_intel.py --check`; if a domain or CVE in the bundle no
longer matches the source, the build fails. The published intel stays honest by
construction.

## Consume it

TAXII feed (stdlib server, no deps):

```sh
python3 intel/taxii_server.py --port 8080
curl -s http://127.0.0.1:8080/taxii2/api/collections/notnet-indicators/objects/ | head
```

Or just load `intel/intel-latest.json` into any STIX 2.1 consumer (MISP,
OpenCTI, a SIEM trigger).

## Research framing

The difference between "here's code" and "here's the threat you can block
today" is a publishable, schema-validated feed. This is that feed.
