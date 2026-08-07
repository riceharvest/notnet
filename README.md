# notnet — Modern Mirai-Style Botnet

A research-purpose botnet written in pure C, designed to replicate across heterogeneous systems using a blend of classic and modern techniques.

## Design Goals

- **Pure C**: Compiles and runs on any system with a C compiler and network stack
- **Hybrid C2**: Dual protocol support (IRC + HTTP/WebSocket) for maximum compatibility
- **Multi-vector spreading**: SSH, Telnet, SMB, Redis, RDP
- **Peer-to-peer daisychain**: C2 fallback via peer relay using DNS discovery
- **Modern + classic**: On-target compilation, systemd persistence, alongside IRC command channels and brute-force spreading

## Architectures

- x86_64
- ARM32 (armv7l, armv6l)
- ARM64 (aarch64)
- RISC-V (riscv64)
- MIPS/MIPS64 (best-effort)
- PowerPC (ppc64, ppc)

## C2 Protocols

| Protocol  | Use Case |
|-----------|----------|
| IRC       | Legacy, low-overhead, NAT traversal via nick routing |
| HTTP      | Modern, firewall-friendly, CDN-friendly (cleartext) |
| WebSocket | Text-based C2, browser-dashboard compatible (cleartext) |

## Spreading Vectors

| Target  | Method |
|---------|--------|
| SSH     | Password brute-force, post-exploitation payload deployment |
| Telnet  | Password brute-force, post-exploitation payload deployment |
| SMB     | Login brute-force (auth confirmation only) |
| Redis   | Unauthenticated write, SSH key injection |
| RDP     | Brute-force, credential reuse (auth confirmation only) |

## Payload Delivery

1. Direct binary download from C2 (preferred)
2. On-target compilation from embedded source tarball (fallback)

## Commands

- **spread** — Scan and replicate to vulnerable hosts
- **scan** — Port scan / service fingerprinting
- **exec** — Execute shell command on remote
- **download** — Download file from URL to target
- **upload** — Upload file to target (not yet implemented)
- **exfil** — Extract data from host (not yet implemented)
- **update** — Fetch new binary from C2
- **reboot** — Reboot target system
- **status** — Report bot status to C2

## Configuration

The bot loads config from `/etc/notnet.conf` (key=value format):

| Key | Default | Description |
||-----|---------|-------------|
|| `irc_server` | `irc.notnet.net` | IRC C2 server |
|| `irc_port` | `6697` | IRC C2 port |
|| `irc_channel` | `#notnet` | IRC channel to join |
|| `irc_pass` | *(none)* | IRC password (or `NOTNET_IRC_PASS` env var) |
|| `irc_auth_nicks` | *(none)* | Comma-separated authorized operator nicks |
|| `http_server` | `api.notnet.net` | HTTP C2 server |
|| `http_port` | `443` | HTTP C2 port |
|| `ws_server` | `ws.notnet.net` | WebSocket C2 server |
|| `ws_port` | `443` | WebSocket C2 port |
|| `scan_interval` | `30` | Seconds between scan cycles |
|| `ssh_enabled` | `1` | Enable SSH spreading |
|| `telnet_enabled` | `1` | Enable Telnet spreading |

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
|-----|---------|-------------|
| `scan_timeout_ms` | `500` | Connection timeout in ms per host |
| `scan_max_hosts` | `254` | Max hosts to scan per subnet |

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

## Encryption
- TLS 1.2+ support (planned — requires OpenSSL/mbedTLS linkage)
- Currently cleartext C2 (IRC, HTTP, WS)

## License

MIT

## Research Notice

> This botnet is designed for research purposes. Default configuration uses a 30-second
> sleep between scans to avoid aggressive network behavior. It is not intended for
> unsanctioned deployment on third-party systems.
