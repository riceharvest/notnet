# notnet — Modern Mirai-Style Botnet

A research-purpose botnet written in pure C, designed to replicate across heterogeneous systems using a blend of classic and modern techniques.

## Design Goals

- **Pure C**: Compiles and runs on any system with a C compiler and network stack
- **Hybrid C2**: Dual protocol support (IRC + HTTP/WebSocket) for maximum compatibility
- **Multi-vector spreading**: SSH, Telnet, SMB, Redis, RDP
- **Peer-to-peer daisychain**: C2 fallback via peer relay using DNS discovery
- **Modern + classic**: TLS encryption, on-target compilation, systemd persistence, alongside IRC command channels and brute-force spreading

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
| HTTP/S    | Modern, firewall-friendly, CDN-friendly |
| WebSocket | Encrypted C2, browser-dashboard compatible |

## Spreading Vectors

| Target  | Method |
|---------|--------|
| SSH     | Password brute-force, key injection |
| Telnet  | Login brute-force |
| SMB     | EternalBlue-style (MS17-010), login brute-force |
| Redis   | Unauthenticated write, SSH key injection |
| RDP     | Brute-force, credential reuse |

## Payload Delivery

1. Direct binary download from C2 (preferred)
2. On-target compilation from embedded source tarball (fallback)

## Commands

- **spread** — Scan and replicate to vulnerable hosts
- **scan** — Port scan / service fingerprinting
- **exec** — Execute shell command on remote
- **download** / **upload** — File transfer
- **exfil** — Extract data from host
- **update** — Fetch new binary from C2
- **reboot** — Reboot target system
- **status** — Report bot status to C2

## Persistence

Automatically detects init system and installs:
- systemd service
- cron job
- SysV init script

## Encryption

- TLS 1.2+ with cert pinning (default)
- Plain text fallback (IRC, HTTP)

## License

MIT

## Research Notice

> This botnet is designed for research purposes. Default configuration uses a 30-second
> sleep between scans to avoid aggressive network behavior. It is not intended for
> unsanctioned deployment on third-party systems.
