# Real Boa bring-up — TOTOLINK N300RT (issue #126)

## ACQUIRED (2026-08-12) — real Realtek-SDK firmware

- Firmware: `N300RT`-family .web images from the LIVE totolink.net via the
  Wayback Machine (the current N300 series is still sold; the firmware
  served in 2025-26 captures):
  - 790bc26de0a5457cbe257c5fbf8028fe.web  (3.39 MB)
  - b65038ea765fdb96197d5dd0bfccacdd.web  (3.39 MB)
  - Wayback: https://web.archive.org/web/20260218121937id_/https://www.totolink.net/data/upload/20250430/<hash>.web
- Device class: TOTOLINK N300RT / N300RH family — Realtek RTL8196C
  (Lexra MIPS), the Realtek Jungle SDK. The OpenWrt page confirms the
  serial bootlog: "boa: server version Boa/0.94.14rc21" + "MiniIGD
  v1.09.1" — the exact vulnerable web stack the bot's Realtek module
  targets (CVE-2021-35395, /boafrm/formSysCmd).

## EXTRACTED

- The .web format: [uboot][LZMA kernel][little-endian squashfs at
  0x13D022]. `sasquatch` (the LZMA-patched unsquashfs, built from
  devttys0/sasquatch) extracts the rootfs.
- Full rootfs at ~/firmae-lab/fw-totolink/fullroot/ (uClibc 0.9.33, the
  Realtek libs: libapmib.so, libmtdapi.so, libcjson.so, libmystdlib.so,
  busybox; 92-file /web UI; bin/boa).

## RUNNING UNDER QEMU (qemu-mips-static, big-endian MIPS-I)

Working:
- chroot + qemu-mips-static runs the REAL Boa/0.94.14rc21.
- The apmib flash reads: /dev/mtdblock0 is a regular file (the .web's
  flash area); the MIB lives at flash offset 0x6000 with a
  COMPRESS_MIB_HEADER_T (6-byte signature + compRate + compLen).
- Signature reverse-engineered from the libapmib rodata: the hw-setting
  signature is "Hf" (ver=0, len=16) — the "Hf"/"Hu" constants sit next
  to "Invalid hw setting signature" / "Expect [sig=%s, ver=%d, len=%d]".
- LD_PRELOAD shim (apmib_shim.c, cross-compiled mips-linux-gnu-gcc)
  satisfies apmib_init/apmib_get/flash_read_raw_mib; the boa passes the
  user/group checks (root in /var/passwd + /var/group — /etc/passwd is a
  symlink to /var/passwd) and BINDS port 80:
  "boa: server version Boa/0.94.14rc21 ... starting server pid=11, port 80"

REMAINING BLOCKER:
- The boa SIGSEGVs shortly after binding ("caught SIGSEGV, dumping core
  in /tmp"). asp_init() still logs "Initialize AP MIB failed!" (the
  apmib_get shim returns zero-filled buffers; the asp layer dereferences
  string MIB codes). Next step: the shim must return REAL values for the
  asp's MIB string codes (model name, sys version, wan info — the
  MIB_* enum values from the Realtek SDK headers) so the asp init
  succeeds and the CGI/form handler survives the first request.

## Repo artifacts

- tests/sim/docs/REAL-BOA-TOTOLINK.md (this file)
- ~/firmae-lab/fw-totolink/apmib_shim.c, boa.conf, Dockerfile.boa
- ~/firmae-lab/fw-totolink/fullroot/ (the extracted rootfs)

## Status update (later same day)

- The boa RUNS + binds port 80 under qemu-mips-static and ACCEPTS
  connections. The crash triggers on the FIRST REQUEST: the asp request
  handler dereferences the uninitialized MIB state ("Initialize AP MIB
  failed!asp_init:1001" → SIGSEGV on the first accept).
- The remaining work: provide a REAL MIB flash image at 0x6000 — the
  LZSS-compressed config blob (COMPRESS_MIB_HEADER_T sig=Hf ver=0 len=N
  + the LZSS data). The decode.cpp from chuangshizhiqiang/
  apmibConfigFileDecode documents the format; a minimal valid MIB (model
  name, sys version, wan ip) would let asp_init succeed and the request
  handler survive.
- Alternative: patch the libapmib so apmib_get falls back to
  apmib_getDef (the compiled-in SDK defaults) — the asp would use the
  defaults instead of the empty flash values.
- LD_PRELOAD shim note: the uClibc loader silently ignores LD_PRELOAD
  for a -nostdlib MIPS-I shim; the flash-file approach (a real MIB at
  /dev/mtdblock0) avoids the loader entirely.

## MIB construction progress (final session note)

- The Realtek MIB flash format is fully understood: COMPRESS_MIB_HEADER_T
  (6-byte sig + compRate:be16 + compLen:be32) + LZSS (Okumura N=4096
  F=18) data at flash 0x6000. build_mib.py builds a minimal MIB (2041
  bytes -> 588 LZSS) + apmib_decode.cpp verifies the round-trip.
- The boa reads the MIB (sig=Hf/Hu echoed back) but the hw-setting
  signature CHECK still fails: the expected 2-char constant is neither
  "Hf" nor "Hu" (those are the current/default setting sigs). The
  stripped libapmib needs a proper MIPS disassembler (radare2/Ghidra) to
  extract the comparison constant from the sig-check function — objdump
  cannot handle the no-section-header ELF, capstone pip install fails on
  this image's old pip.
- Everything else is proven: real firmware, real Boa binds port 80,
  accepts connections, MIB format + LZSS round-trip. The asp layer will
  initialize once the sig constant lands.

## Final state (MIB decompress wall)

Disassembly (radare2 + raw MIPS decode) shows the "Invalid hw setting
signature" error is actually the **LZSS decompress failure** — there is NO
signature constant. Flow: mtd_read(6 bytes @ 0x6000) → decompress(src=
buf+2, dst=buf+0xd14, 0x24, 1) → if result != 1 → "Invalid hw setting
signature". The lib's LZSS variant differs from the decode-repo's classic
Okumura (N=4096/F=18/TH=2): the a2=0x24 arg hints at different ring
params. Fix: reverse the lib's decompress parameters (src/dst/size/flag
layout at the 0x8028 gp offsets) or obtain a real config.dat from a
TOTOLINK device.
