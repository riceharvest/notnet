# Realtek Firmware Hunt — 11 formSysCmd HITs (#126)

Bulk acquisition from the wayback TOTOLINK download center. Filter:
`/home/dario/firmae-lab/tools/check_formsyscmd.sh <fw>` — binwalk →
squashfs → extract boa/cgibin/webs → grep formSysCmd. 20 router
firmwares downloaded (the old totolink.net download.asp snapshots via
`web.archive.org/web/<ts>/http://www.totolink.net/include/download.asp?path=...&file=...`
— the plain fetch returns the real RAR; `id_` returns an interstitial).

## HITS (Boa/0.94.14rc21, MIPS BE, formSysCmd present)

| Firmware | IID | Boot |
|---|---|---|
| TOTOLINK-A3002RU-V1.1.0-B20180416.1741 | 4 | extract missing (getArch fail) |
| TOTOLINK-A702R-V1.1.2-B20171114.1556 | 5 | boots, boa SEGV (apmib) |
| TOTOLINK-N100RE-V3.2.0-B20180330.1733 | 6 | boots, boa SEGV |
| TOTOLINK-N150RH-V3.0.0-B20171227.1756 | 7 | boots, boa SEGV |
| TOTOLINK-N150RT-V2.2.4-B20180330.1635 | 8 | boots, boa SEGV |
| TOTOLINK-N151RT-V2.2.0-B20180226.1703 | 9 | boots, boa SEGV |
| TOTOLINK-N200RE-V3.2.0-B20180330.1757 | 10 | boots, boa SEGV |
| TOTOLINK-N300RT-V2.2.4-B20180330.1621 | 11 | boots, boa SEGV |
| TOTOLINK-N301RT-V2.2.0-B20180226.1639 | 12 | boots, boa SEGV |
| TOTOLINK-N301RT-V3.0.4-B20171210.1909 | 13 | boots, boa SEGV |
| TOTOLINK-N302R-Plus-V3.1.6-B20180201.1450 | 14 | boots, boa SEGV |

All 2017-2018 builds: the kernel + userspace boot, rcS starts boa, but
boa SEGVs at startup — the apmib (flash config) init. The 2025 N300RT
build's apmib tolerates a missing flash; these older builds crash.

## Realtek SDK flash format (decoded from rtl819x-toolchain GPL source)

The apmib reads THREE sections (offsets per apmib.h):
- HW setting  at 0x6000: sig `H6` (8196C/E) or `h6` (8196B), ver `01`,
  u16 BE len, data + 2's-complement checksum (bytes sum to 0).
  The FORCE tag `Hf`/`Df`/`Cf` is only accepted on the upgrade path, NOT
  the init path — "Invalid hw setting signature" on a `Hf` flash.
- Default cfg at 0x8000: sig `6G` (HOME_GATEWAY) / `6A` (AP) + ver,
  u16 len, data+checksum. TOTOLINK N300RT expects ver=3, len=34436
  (sizeof(APMIB_T)+1 for this build) — "Expect [sig=6G, ver=3,
  len=34436]" from the binary.
- Current cfg  at 0xc000: sig `6g`/`6a` + ver, u16 len, data+checksum.

Builder: `/home/dario/firmae-lab/fw-totolink/build_flash_sdk.py` →
4MB flash with the three checksummed sections (space-filled structs —
no NULL string fields, avoiding strlen(NULL) crashes).

## Remaining wall (2026-08-12 late)

With the correct flash the apmib passes hw + default parsing, then dies
on `apmib_shm_calloc`: `/var/DSCONF shmget() failed [Invalid argument]`.
The apmib is built with CONFIG_APMIB_SHARED_MEMORY — it ftok()s /var and
shmget()s the 34436-byte config. Under qemu-user (chroot test) the
shmget fails (qemu-user SysV IPC limitation); the full-system boot (real
kernel) should handle it — the last IID 11 boot attempt was interrupted
before the result came back. Next step: boot IID 11 with the corrected
flash and check for `boa: starting server` / port 80.

## Boot recipe notes (bulk)

- boot-one.sh: per-IID run.sh from scratch/3 template (rdinit= fix,
  unique tap + host IP 192.168.1.<2+iid>), strips the `-netdev socket`
  listeners (ports 2001+ collide across concurrent qemu instances).
- makeImage's final e2fsck races udisks auto-mount — non-fatal (image
  is built); dirty fs later mounts RO, run e2fsck once before boot.
- Image edits: prefer debugfs over losetup+mount (udisks auto-mounts
  every `losetup -Pf` partition and blocks detach).
