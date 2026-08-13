# notnet — shipped detections (the standard triad)

Every offensive module in notnet has a matching detection. This directory is the
defensive half of the project: defenders can block notnet without reverse-
engineering the binary.

Layout:

```
detections/
  README.md                       this file
  ATTACK-COVERAGE.md              #147 MITRE ATT&CK matrix (technique -> detection -> scenario -> status)
  POSTURE-COVERAGE.md            #153 posture-indexed survival cross-table
  yara/notnet_indicators.yar     static / file / memory classification
  sigma/*.yml                    host behaviour, log-source-agnostic YAML
  suricata/*.rules               network signatures (CVE + C2 + relay)
  validate.py                    CI validator (#151): schema + source-drift + replay
```

## The triad per module

| module | YARA | Sigma | Suricata |
|---|---|---|---|
| C2 channels + UA | `notnet_http_user_agent` | — | `c2_heartbeat_bot_paths` |
| relay / VIA chain | `notnet_relay_via_wireformat` | `proxy_tunnel` | `relay_via_chain` |
| CVE modules | `notnet_cve_module_strings` | — | `cve_2017_17215_hg532`, `cve_2021_35395_realtek`, `cve_2024_3721_tbk` |
| cred-log / exfil | `notnet_cred_log_format` | `exfil_creds` | — |
| SMB ADMIN$ | — | `admin_share_write` | — |
| Redis injection | — | `redis_config_set_authorized_keys` | — |
| persistence | `notnet_magic_header` | `persistence_cron_systemd_sysv` | — |
| fileless | `notnet_fileless_memfd_fexecve` | `fileless_memfd_fexecve` | — |
| brute force | — | `brute_force_ssh_smb_redis` | — |
| killswitch | `notnet_killswitch_markers` | `self_destruct_killswitch` | — |
| broadcast payloads | `notnet_broadcast_bc` | — | — |

## How to run

- **YARA**: `yara -r detections/yara/notnet_indicators.yar <file|directory|/proc>`
- **Sigma**: translate with `sigma-cli` to your backend
  (`sigma convert -t splunk / es / sentinel / qradar detections/sigma/`), or load
  the YAML directly into a Sigma-aware pipeline.
- **Suricata**: drop `detections/suricata/*.rules` into your Suricata rules dir and
  reference them from your `suricata.yaml`.

## Honesty guarantee

`validate.py` (run in CI, #151) asserts every rule still parses and that the IOC
strings CVEs / C2 domains / killswitch domain in this directory still match the
current `include/config.h` and `src/spread.c`. If a rule drifts from the source it
fails the build, so the shipped intel stays truthful.
