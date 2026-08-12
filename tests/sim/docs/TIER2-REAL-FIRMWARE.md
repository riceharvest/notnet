# Tier 2 — Real CVE Endpoints: Deep Research

Goal: host the bot's three CVE targets as REAL vulnerable devices — actual
vendor firmware binaries answering the probes — instead of the verified
Python emulators. Research date: 2026-08-12.

## 1. The wire contracts that must be real

From `src/spread.c` (the exact exchanges the bot performs):

| Module | CVE | Endpoint | Probe marker | Verify | Drop |
|---|---|---|---|---|---|
| TBK DVR | CVE-2024-3721 (public: CVE-2020-10381 family) | HTTP :80, GET / → page contains TBK/DVR/NVR | body marker | POST `/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=<enc>` + `Cookie: uid=1` → token echoed | same + wget payload |
| HG532 | CVE-2017-17215 | TR-064 SOAP :37215, POST `/ctrlt/DeviceUpgrade_1`, SOAPAction `...WANPPPConnection:1#DeviceUpgrade` | response contains `HUAWEIUPNP` | injection via `NewStatusURL/NewDownloadURL` `;echo <tok>;` → 200 + HUAWEIUPNP envelope | same + `;wget...;` |
| Realtek | CVE-2021-35395 | HTTP :80, GET / → Server contains Boa/Realtek/httpd | header marker | POST `/boafrm/formSysCmd` `sysCmd=echo <tok>` → output echoed | same + `sysCmd=wget...` |

So a "real" endpoint must be a device that (a) runs the REAL vulnerable
web daemon (HG532's ctrlt SOAP daemon, Realtek's Boa httpd with
formSysCmd, the DVR's device.rsp CGI) and (b) actually executes the
injected command. A stock patched server is NOT enough — it must be
vulnerable firmware.

## 2. Verified state of the art (2026)

- **FirmAE** (pr0v3rbs/FirmAE) — the standard for full-firmware emulation.
  QEMU system emulation; 79% boot success across 1,124 vendor images
  (vs Firmadyne's 16%). Actively maintained (commits June 2026, dockerized
  analysis container, firmware database). Requires a root/QEMU host with
  tap networking + a MySQL image DB — it is NOT a Docker service and is
  not CI-friendly. The emulated device boots its OWN kernel (MIPS/ARM)
  with the real init + all services.
- **qemu-user-static** (multiarch/qemu-user-static) — the standard way to
  run foreign-arch binaries inside Docker containers. This is the key
  enabler for a CI-able "real endpoint" tier: run the REAL httpd binary
  from an extracted firmware rootfs under `qemu-mips-static -L <rootfs>`.
- **No ready-made "vulnerable real firmware" Docker images** exist on
  GitHub for these three CVEs (searched; only exploit POCs).
- **Firmware acquisition**: vendor sites purge old firmware, but images
  survive on router forums, archive.org, GitHub firmware collections, and
  Chinese mirrors. FirmAE ships example images (e.g. DIR-868L) proving the
  pipeline works.

## 3. Reality options per endpoint

### Option A — qemu-user-static container (RECOMMENDED, CI-able)

Run the REAL vulnerable daemon binary under a static QEMU user emulator in
a Docker container on the sim network.

```
rootfs/            <- binwalk-extracted firmware filesystem (MIPS/ARM)
Dockerfile:        FROM multiarch/qemu-user-static (or debian + qemu-mips-static)
                   COPY rootfs /firmware
                   COPY libnvram-stub.so /firmware/lib/   (if needed)
                   CMD ["/usr/bin/qemu-mips-static", "-L", "/firmware", "/firmware/usr/sbin/ctrlt"]
```

- The bot's probe hits the REAL vulnerable binary over real sockets. The
  injected `wget` executes under emulation (MIPS binaries run fine under
  qemu-user; the payload wget is issued BY the firmware's busybox).
- Networking: the daemon binds a port inside the container; map it into
  the sim bridge (standard container networking, static IPs as today).
- CI-able: vendor the (small, 5–20 MB) firmware rootfs or build the image
  from a pinned download in CI.
- The classic blocker: **nvram**. Embedded web daemons call
  `nvram_get("...")` for state. Mitigations: (1) LD_PRELOAD a fake
  libnvram returning defaults (pattern: zcutlip/nvram-faker, Firmadyne's
  libnvram); (2) if the daemon tolerates missing nvram, no stub needed.
  Realtek Boa + HG532 ctrlt both need a stub in most builds.
- Other gotchas: daemons that bind a hardcoded LAN IP (patch the binary or
  use `-E` / run with a fake lo; usually they bind 0.0.0.0 fine); ioctls
  (SIOCGIFADDR etc.) mostly pass through qemu-user on Linux; DNS lookups
  work via the container's resolver.

### Option B — FirmAE full system emulation (MAX fidelity, local lab)

Boot the ENTIRE firmware (real kernel, real init, ALL services) on a QEMU
VM via FirmAE. Best possible realism; also exercises the device's other
services (telnet, UPnP, admin UI) and its real boot behavior.

- Not CI-able: needs a root host, tap interfaces, minutes-per-boot, per-
  image kernel config. Runs on the lab box (the 5950X handles MIPS QEMU
  easily; KVM not required).
- Integration: bridge FirmAE's tap network into the sim's Docker bridge
  (macvlan or a small router hop) so the bot on the sim network can reach
  the emulated device's IP.
- FirmAE does the nvram arbitration automatically (its main advantage).

### Option C — keep the verified emulator (fallback)

If a firmware image for a specific device can't be found (most likely for
the white-label DVR), keep the byte-accurate emulator for THAT device and
go real for the other two. The emulators are already verified against the
bot's real exploit traffic; the gap is behavioral fidelity, not protocol
accuracy.

## 4. Firmware acquisition plan

| Target | Device family | Arch | Sources (in order) | Feasibility |
|---|---|---|---|---|
| HG532 | Huawei HG532e/s/d/n | MIPS (RTL8196? / BCM) | router forums, archive.org, GitHub firmware collections, Huawei EU support archive captures; Satori writeups name the exact model | HIGH — widely mirrored |
| Realtek | Any Realtek Jungle SDK router (Netis WF2411/WF2414, Tenda W316R-era, many white-labels) | MIPS | the same archives; hundreds of SKUs share the SDK's Boa+formSysCmd | HIGH — the SDK is everywhere |
| TBK DVR | TBK DVR-4104/4216 white-label DVRs | ARM/MIPS | vendor mirrors (tbkvision), Chinese mirror sites, exploit-db references | MEDIUM-LOW — obscure white-label |

Extraction: binwalk -e; find the web daemon + libs (ldd under
qemu-mips-static -L to resolve); identify nvram dependency.

## 5. Sim integration

- Replace the emulated device entries in `docker-compose.fleet.yml` with
  the real-firmware containers at the SAME static IPs (the bot's scan
  targets and the driver's expectations stay valid).
- Evidence handling: real devices do NOT write the sim's evidence log
  files. The driver's checks that grep device logs (e.g. "CVE-EXPLOIT"
  drops) must switch to verifying via the C2's perspective (the victim
  joins as a bot → C2 inventory) + the real device's own logs (journald/
  files inside the container, collected like the emulators').
- IDS: with real traffic the log-watcher still works off the C2/bot logs;
  a Suricata capture (Tier 3) becomes even more valuable.
- Defense posture: patched variants = real firmware with the vulnerable
  daemon DISABLED or a patched build (or the same firmware with a firewall
  rule blocking the port) — keeps the modern/legacy tier split honest.

## 6. Recommendation

1. Do a 1-day spike: acquire HG532 firmware + one Realtek-SDK firmware,
   extract, get the real httpd/ctrlt running under qemu-mips-static in a
   container, and point the bot at it. This validates Option A end-to-end
   (the nvram stub is the main risk).
2. If the spike passes: vendor the rootfs images, add the three real
   containers to the fleet (HG532 + Realtek now; TBK DVR if firmware is
   found), adapt the driver's evidence checks, wire into CI as a
   `--real-firmware` mode.
3. Keep FirmAE (Option B) as a documented local-lab extension for
   full-fidelity runs — the same firmware images feed both paths, so the
   spike work carries over.
