# notnet — Modern Mirai-Style Botnet

A research-purpose botnet written in pure C, designed to replicate across heterogeneous systems using a blend of classic and modern techniques.

## Design Goals

- **Pure C**: Compiles and runs on any system with a C compiler and network stack
- **Hybrid C2**: Multi-protocol C2 (IRC + HTTP + WebSocket) for maximum compatibility
- **Multi-vector spreading**: SSH, Telnet, SMB, Redis, RDP
- **Peer-to-peer daisychain**: (planned, not yet implemented) — peer DNS
  discovery exists, but no peer relay or C2 fallback through peers yet
- **On-target compilation**: supported as an update fallback — the bot can
  fetch a verified source bundle and compile locally (see Payload Delivery)
- **Modern + classic**: systemd persistence, IRC command channels, and brute-force spreading

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
| IRC       | Implemented | Nick allowlist (`irc_auth_nicks`) + optional `irc_pass` |
| HTTP      | Implemented | Shared secret echo (`c2_secret`) — commands rejected without it |
| WebSocket | Implemented (RFC 6455 handshake) | Shared secret echo (`c2_secret`) |

- IRC commands are accepted only from nicks in the `irc_auth_nicks` allowlist.
- HTTP and WebSocket commands are accepted only from responses that echo the
  configured `c2_secret`. With no secret configured, HTTP/WS commands are
  rejected (fail-closed).
- All three channels support TLS 1.2+ when built with `make TLS=1` and a
  certificate pin is configured (see Encryption).

## Spreading Vectors

| Target  | Method |
|---------|--------|
| SSH     | Password brute-force, post-exploitation payload deployment (banner-based; effective against legacy/test services, not modern key-exchange SSH) |
| Telnet  | Password brute-force, post-exploitation payload deployment (banner-based; effective against legacy/test services) |
| SMB     | Login brute-force (auth confirmation only) |
| Redis   | Unauthenticated write + authenticated brute-force, SSH key injection (`redis_ssh_key` required) |
| RDP     | Brute-force, credential reuse (auth confirmation only) |

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

## Commands

Commands are issued via the C2 channels (IRC PRIVMSG or HTTP/WS JSON with the
shared secret). The command queue is rate-limited to 10 commands/second.

| Command | Syntax | Status |
|---------|--------|--------|
| spread  | `spread <ip>:<port>` | Implemented — brute-force a single host:port (22/23/445/6379/3389) |
| scan    | `scan <subnet>` / `scan <ip>[:<port,...>]` | Implemented — port scan / service fingerprinting, results returned to C2 |
| exec    | `exec <command>` | Implemented — runs one of a strict allowlist (`uname`, `date`, `uptime`, `whoami`, `id`, `ls`, `ifconfig`, `hostname`, `netstat`, `ps`), no shell |
| download | `download <url> [path]` | Implemented — fetch URL to a local path |
| upload  | `upload <path> [remote_path]` | Implemented — upload a file to the C2 |
| exfil   | `exfil <path>` | Implemented — read a file and stream it to the C2 in chunks |
| update  | `update [url]` | Implemented — download + SHA-256 verify + install new binary |
| reboot  | `reboot` | Implemented — sync + reboot the target |
| sleep   | `sleep <seconds>` | Implemented — set scan interval (clamped 1–3600) |
| config_set | `config_set <key>=<value>` | Implemented — allowlisted runtime config keys |
| status  | — | Implemented — heartbeat reports version, hostname, uptime, scan count |

## Configuration

The bot loads config from `/etc/notnet.conf` (key=value format):

| Key | Default | Description |
||-----|---------|-------------|
|| `irc_server` | `irc.notnet.net` | IRC C2 server |
|| `irc_port` | `6697` | IRC C2 port |
|| `irc_channel` | `#notnet` | IRC channel to join |
|| `irc_pass` | *(none)* | IRC password (or `NOTNET_IRC_PASS` env var) |
|| `irc_auth_nicks` | *(none)* | Comma-separated authorized operator nicks |
|| `irc_enabled` | auto | 0/1 — explicitly enable/disable IRC C2 |
|| `http_server` | `api.notnet.net` | HTTP C2 server |
|| `http_port` | `443` | HTTP C2 port |
|| `http_path` | `/api/v1/bot` | HTTP C2 path |
|| `http_user_agent` | `notnet/<ver>` | HTTP User-Agent |
|| `http_enabled` | auto | 0/1 — explicitly enable/disable HTTP C2 |
|| `ws_server` | `ws.notnet.net` | WebSocket C2 server |
|| `ws_port` | `443` | WebSocket C2 port |
|| `ws_path` | `/ws/v1/bot` | WebSocket C2 path |
|| `ws_enabled` | auto | 0/1 — explicitly enable/disable WS C2 |
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
