# notnet — MITRE ATT&CK Coverage Matrix

This matrix maps every notnet command/module to MITRE ATT&CK techniques,
the detection(s) that cover it (see `detections/`), the sim scenario that
exercises it, and the current pass/fail status.

**How `status` is derived.** The `status` column is *not* hand-maintained —
it is asserted by `.github/workflows/detections-ci.yml` (#151). That workflow
replays the bot's own traffic/logs through the rule set and marks a row PASS
only if every detection listed under `covered-by` fires against the matching
sim evidence. A rule that rots (stops firing) flips the row to FAIL and breaks
the build, so this matrix cannot drift from reality.

**Research framing.** Red Canary's annual technique-report structure: each row
is a citable claim about what the bot's behaviour looks like to a defender, not
a rule dump.

---

## Coverage matrix

| technique | name | covered-by (detection) | sim scenario | status |
|---|---|---|---|---|
| T1190 | Exploit Public-Facing Application | Suricata `cve_2017_17215_hg532.yml`, `cve_2021_35395_realtek.yml` (`src/spread.c`) | c2-drive / remaining-parity | PASS |
| T1110 | Brute Force | Sigma `brute_force_ssh_smb_redis.yml` | autonomous | PASS |
| T1005 | Data from Local System | Sigma `exfil_creds.yml` + YARA `notnet_indicators.yar` (cred-log `proto\|ip\|port\|user\|pass`) | monetization | PASS |
| T1020 | Automated Exfiltration | Sigma `exfil_creds.yml` | monetization | PASS |
| T1572 | Protocol Tunneling | Suricata `c2_heartbeat_bot_paths.yml` (proxy/relay), Sigma `proxy_tunnel.yml` | monetization | PASS |
| T1090 | Proxy | Suricata + Sigma `proxy_tunnel.yml` (RELAY `VIA` chain, `src/relay.c`) | monetization | PASS |
| T1021 | Remote Services | Sigma `admin_share_write.yml` (SMB `ADMIN$`), `redis_config_set_authorized_keys.yml` | c2-drive | PASS |
| T1543 | Create/Modify Service | Sigma `persistence_cron_systemd_sysv.yml` | remaining-parity | PASS |
| T1027 | Obfuscated/Fileless | YARA `notnet_indicators.yar` (`memfd`/`fexecve` memory), Sigma `fileless_memfd_fexecve.yml` | remaining-parity | PASS |
| T1489 | Service Stop (killswitch) | Sigma `self_destruct_killswitch.yml` | killswitch | PASS |

---

## Per-technique notes (source anchors)

### T1190 — Exploit Public-Facing Application
- **CVE-2017-17215** (Huawei HG532): TR-064/UPnP `DeviceUpgrade` SOAP injection on
  TCP 37215. Module + strings in `src/spread.c` (`cve_hg532_probe`/`_verify`/`_drop`,
  `HG532_PORT 37215`). Suricata rule matches the `urn:DeviceUpgrade` / `NewStatusURL`
  injection-shaped SOAP body.
- **CVE-2021-35395** (Realtek SDK / TOTOLINK): `formSysCmd` unauth OS command injection
  on TCP 80 (`cve_realtek_*`). Suricata rule matches the `formSysCmd` POST body.
- **CVE-2024-3721** (TBK DVR): `mdc=` OS command injection POST (`cve_tbk_*`).
  Listed in the same Suricata intel set; verify-shaped probe only.
- Offensive module table: README §Spreading; `cve_modules[]` in `src/spread.c`.

### T1110 — Brute Force
- SSH (22), Telnet (23), SMB (445), Redis (6379), RDP (3389). Burst pattern from one
  source IP. Sigma rule counts auth-failure bursts and flags `proto|ip|port|user|pass`
  harvest in the cred-log.

### T1005 / T1020 — Data from Local System / Automated Exfiltration
- Credential harvest buffer: one line per entry, format `proto|ip|port|user|pass`
  (`README` §Credential log, `CMD_EXFIL_CREDS` `exfil_creds` in `include/config.h:92`).
- `exfil_creds` streams the buffer to C2 in chunks then clears it. Sigma matches the
  `exfil_creds` C2 command + the chunked outbound stream; YARA matches the buffered
  `proto|ip|port|user|pass` memory layout.

### T1572 / T1090 / T1021 — Tunneling / Proxy / Remote Services
- ORB-style relay (`src/relay.c`): `RELAY <token> <target> <port> VIA <h1>:<p1> ...`,
  bounded to 8 hops, `include/config.h:181` (`#91`). Suricata matches the `RELAY … VIA`
  wire format on `/api/v1/bot` or the relay listener; Sigma matches the token-gated
  listener open + SOCKS5 `PROXY` (`proxy_tunnel.yml`).
- SMB `ADMIN$` write (`smb1_write_file`, `src/spread.c`) → `admin_share_write.yml`.
- Redis `CONFIG SET dir` + `authorized_keys` injection (`redis_ssh_key=`,
  `include/config.h` `CMD_EXFIL`) → `redis_config_set_authorized_keys.yml`.

### T1543 — Create/Modify Service
- Persistence installers detect init system and write systemd / cron / SysV
  (`README` §Persistence, `src/persist.c`). Sigma `persistence_cron_systemd_sysv.yml`
  matches the unit/job/script drops + the `.notnet` binary name
  (`PERSIST_BIN_NAME ".notnet"`, `include/config.h:81`).

### T1027 — Obfuscated / Fileless
- RAM-only mode (`persist_enabled=0`) relaunches via `memfd_create()` + `fexecve()`
  (`README` §RAM-only fileless mode). YARA matches the in-memory `memfd`/`fexecve`
  code path strings; Sigma `fileless_memfd_fexecve.yml` matches a process creation with
  no on-disk image (`on_disk=0`).

### T1489 — Service Stop (killswitch)
- Global DNS killswitch (#130, `include/config.h:121`): resolves
  `KILLSWITCH_DOMAIN_DEFAULT` (default `killswitch.invalid`, `config.h:146`) every
  `KILLSWITCH_INTERVAL_DEFAULT` (300s); on `127.0.0.1`/`0.0.0.0` it wipes creds, stops
  modules, removes persistence, exits 0. `kill` command is the operator-side equivalent.
- Sigma `self_destruct_killswitch.yml` matches the C2 `kill` command + the self-destruct
  log line; the killswitch *domain* is published as a sinkhole-able IOC in `intel/`
  (#152).

---

## Posture-indexed cross-table

Which techniques survive under which defensive profile is tracked separately in
`detections/POSTURE-COVERAGE.md` (#153). That file is generated by running each named
profile through the sim and asserting the surviving/blocked set, e.g.:

- `credential-hygiene` → SSH/Telnet brute rows go dark.
- `segmented` → lateral (T1021 across IoT→office) blocked by the router policy.
- `edr-on` → fileless (T1027) and LOTL caught host-side where Suricata is blind
  (#150).

See `detections/POSTURE-COVERAGE.md` for the live matrix.
