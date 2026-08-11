# notnet README parity matrix — sim spec

Every README claim, its sim scenario, the injection, and the evidence grep.
The driver's auto-generated `reports/parity-<ts>.md` mirrors this with results.

Legend: S1=c2-drive, S2=autonomous, S4=commands, S5=resilience, S6=monetization, S8=defence, S9=honeypot.

## C2 protocols

| Claim | Scenario | Inject | Evidence grep | Status |
|---|---|---|---|---|
| HTTP C2 + secret gate | S1 | heartbeat → queued cmd | http.log `SERVE cmd=` + bot log `HTTP: command:` | |
| WebSocket C2 (RFC 6455) | S1 | heartbeat → queued cmd | ws.log `WS SERVE` + bot log `WS:` | |
| IRC C2 (legacy, allowlist) | S1 | queue via c2-irc | irc.log `IRC SERVE` + bot log `IRC: command:` | |
| Shared secret fail-closed | S1 | response w/o secret | bot log `rejected` / `secret` | |
| Fast-flux (multi-A rotation) | S5 | flux-c2 hostname | http.log heartbeats continue w/ blackhole IP | |
| Dead-drop resolution | S5 | deaddrop blob ok/bad | deaddrop.log + http.log connect to drop | |
| C2 rotation (backup chain) | S5 | c2-backup | http-backup.log heartbeats | |
| `rotate` command | S5 | queue rotate | bot log `rotation` | |
| `kill` command | S4 | queue kill | bot exits, `kill: wiping state` | |

## Spreading vectors

| Claim | Scenario | Inject | Evidence grep | Status |
|---|---|---|---|---|
| CVE-2024-3721 TBK (port 80) | S1 | spread 172.29.10.12:80 | cam-01.log TBK DROP / bot log CVE-2024-3721 | |
| CVE-2017-17215 HG532 (37215) | S1 | spread 172.29.10.15:37215 | router-01.log HG532 | ✅ Fixed #98 (CL) + #97 (autonomous) |
| CVE-2021-35395 Realtek (80) | S1 | spread 172.29.10.17:80 | router-03.log Realtek | |
| CVE fail-safe (patched = no drop) | S1 | spread patched IPs | patched-*.log probe miss, no DROP | |
| SSH brute-force | S1 | spread 172.29.20.10:22 | pc-01.log SSH AUTH OK | |
| Telnet brute-force | S1 | spread 172.29.10.10:23 | fridge-01.log TELNET AUTH OK | |
| SMB brute-force | S1 | spread 172.29.20.12:445 | winpc-01.log SMB AUTH OK | |
| Redis unauth + AUTH | S1 | spread redis IPs:6379 | redis-*.log REDIS | ✅ Fixed #99 (recv loop) |
| RDP brute-force | S1 | spread 172.29.20.12:3389 | winpc-01.log RDP | |
| Autonomous spreading (README claim) | S2 | none (C2 disabled) | any DROP evidence = PASS; none = FAIL — **PASS since c511733 (#95)**: spread_local wires spawn_scan_threads, main loop gates on live connection state | ✅ Fixed #95 |

## Payload delivery

| Claim | Scenario | Inject | Evidence grep | Status |
|---|---|---|---|---|
| Direct binary download + SHA-256 pin | S4 | update http://c2:8443/bot/notnet (good pin) | payload.log + bot log `payload` | |
| Pin mismatch refused (fail-closed) | S4 | update (bad pin) | bot log `hash mismatch` / refused | |
| On-target compile fallback | S4 | compile config, broken binary | http.log `SRC-TAR` + bot log compile | |
| Source pin mismatch refused | S4 | wrong src pin | bot log compile refused | |

## Monetization + relay + plugins

| Claim | Scenario | Inject | Evidence grep | Status |
|---|---|---|---|---|
| SOCKS5 proxy on/off (token) | S6 | proxy on 1080 | bot log `proxy` + proxy bind | |
| Credential-log harvest + exfil_creds | S1 | exfil_creds | http.log EXFIL + bot log `cred_count` | |
| ORB relay on/off + RELAY wire | S6 | relay on 1081 | bot log `relay` + relay bind | |
| Plugin status/load/run/unload | S4 | plugin status | bot log `PLUGIN` | |
| byovd defensive scaffold refuses | S4 | plugin byovd load | bot log `byovd` refused | |

## Commands

| Command | Scenario | Inject | Evidence | Status |
|---|---|---|---|---|
| exec (allowlist) | S4 | exec uname -a | bot log `CMD: exec` + response | |
| exec (rejected) | S4 | exec rm -rf / | bot log `exec rejected` | |
| scan | S1 | scan subnet | http.log RESP `scan:` | |
| sleep | S4 | sleep 5 | bot log `sleep interval` | |
| config_set | S4 | config_set bot_tag=x | heartbeat tag changes | |
| download | S4 | download url path | bot log `download` | |
| upload | S4 | upload /etc/hostname | http.log upload/EXFIL | |
| exfil | S4 | exfil /etc/hostname | http.log EXFIL | |
| update | S4 | update url | payload.log + bot log | |
| reboot | S4 | reboot | bot log `reboot` | |
| status heartbeat fields | S1 | — | http.log heartbeat JSON fields | |

## Defence envelope (S8)

| Claim | Posture | Evidence | Status |
|---|---|---|---|
| IDS alert on scan/brute/CVE | standard | ids_alerts.log ALERT | |
| IPS blacklists offender | hardened | ids_alerts.log IPS + router drop | |
| Account lockout stalls brute | standard | device log LOCKOUT | |
| EDR blocks payload exec | hardened | device log EDR-ALERT | |
| Segmentation confines IoT | all | router iptables rules | |
| Honeypot captures attempt | S9 | cowrie log / honeypot evidence | |
