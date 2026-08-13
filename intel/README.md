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
  README.md         this file
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
