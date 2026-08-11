# Real-World Viability — which notnet features actually work in 2026?

Verdict produced by running the sim against a REAL-WORLD fleet: ~2/3 of
targets are modern/hardened (unique creds, patched firmware, SSH key-only,
SMB1 off, EDR, lockout, protected-mode Redis), ~1/3 are the legacy
unmanaged tail botnets survive on. Evidence: `reports/parity-*.md` +
`reports/evidence-*/`.

## Verdict per feature

| Feature | Against MODERN fleet | Against LEGACY tail | Real-world conclusion |
|---|---|---|---|
| SSH password brute-force | **FAIL** — key-only auth, every attempt rejected (495 rejections on pc-01) | **WORKS** — pi:raspberry / root:toor cracked | Works ONLY on the legacy/unmanaged population. Modern Linux is key-only. |
| Telnet default-cred brute | **FAIL** — modern devices removed telnet (no port) | **WORKS** — root:123456 cracked, payload dropped | Dead on modern IoT. Legacy devices still ship telnet + default creds. |
| SMB1 brute-force | **FAIL** — SMB1 disabled, negotiate returns STATUS_NOT_SUPPORTED | **WORKS** — admin:admin session setup | Dead on modern Windows (SMB1 removed). The bot speaks ONLY SMB1, so modern SMB2/3 networks are unreachable. |
| RDP brute-force | **FAIL** — NLA + creds not in pool | Partial (auth-confirm only) | RDP is auth-confirmation-only per README; against NLA it fails. |
| Redis unauth write | **FAIL** — protected-mode / requirepass strong | **WORKS** — legacy unauth Redis exploited | Works on legacy misconfigured Redis. Protected-mode (default since 3.2) blocks it. |
| Redis AUTH brute | **FAIL** — strong password (500 AUTH failures) | **WORKS** — "password" cracked + exploited | Works only on weak-password Redis. Modern default is random strong password. |
| CVE-2024-3721 TBK | **FAIL** — patched (probe miss) / partial (verify fail) | **WORKS** — probe→verify→drop | Works on unpatched TBK DVRs. Patched firmware blocks it. |
| CVE-2017-17215 HG532 | **FAIL** — TR-064 patched | **WORKS** — probe→verify→drop | Works on unpatched routers. TR-064 disabled by default on modern firmware. |
| CVE-2021-35395 Realtek | **FAIL** — patched | **WORKS** — probe→verify→drop | Works on unpatched Realtek-SDK devices. |
| EDR / payload execution | **FAIL** — EDR blocks payload exec on PCs | **WORKS** — no EDR on legacy | Modern endpoint protection stops the drop. Legacy IoT has no EDR. |
| Account lockout | **FAIL** — lockout stalls the brute (60s) | **WORKS** — no lockout on legacy | Modern sshd/IDP lockouts stall the 475-combo pool. |
| Autonomous spreading (fixed #95) | Runs but pwns nothing modern | **WORKS** — worms through the legacy tail | The worm works, but its blast radius is the legacy population only. |
| Credential-log harvest | Works on whatever it cracks | Works | The log is mostly legacy/default creds — low-value in a modern world. |

## The honest big picture

notnet's techniques are **real but legacy-focused**. They are the same
vectors that 2026 Mirai variants actually use — because botnets survive on
exactly the legacy tail this fleet models. Against a modern defended fleet:

- SSH brute-force: dead (key-only)
- Telnet: dead (removed)
- SMB1: dead (removed)
- Redis unauth: dead (protected-mode)
- All three CVEs: dead (patched)

What still works in the real world: the framework's C2 resilience
(fast-flux, dead-drop, rotation — tested separately), autonomous
propagation mechanics, and the entire attack chain against **unmanaged
devices** (cheap IoT, abandoned routers, default-creds servers). That is
precisely how real 2026 botnets persist: not by defeating modern security,
but by harvesting the devices modern security never reached.

## Sim limitations to note

- The flat Docker network means no real L3 segmentation/firewall between
  targets (router emulation is future work; the IDS/IPS runs on logs).
- Cowrie honeypots log attempts but cannot execute payloads (by design).
- Brute-force pool timing: one C2 command per heartbeat + full 19×25 pool
  per target makes large modern-fleet sweeps slow (~minutes per host).
