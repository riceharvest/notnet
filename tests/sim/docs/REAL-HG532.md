# Real HG532 firmware (#125) — ACQUIRED

## The firmware

- Source: `reb311ion/Huawei_Router_HG532` (GitHub), `firmware.bin`
- SHA-256: `4010ef8b42011ad873d91c5e5792ad3885952d5f839551361b602636f5e98247`
- Layout (binwalk): LZMA kernel @ 0x2258, LZMA @ 0x11180, Squashfs v3.0
  big-endian lzma @ 0xEF080 (2.7MB, 197 inodes, created 2014-04-17 —
  the vulnerable era).
- Extracted with sasquatch. Rootfs: MIPS32 rel2 / uClibc (same runtime
  as the TOTOLINK Boa).

## The vulnerable service

- `/bin/upnp` contains the exact CVE-2017-17215 code:
  - `urn:www-huawei-com:service:DeviceUpgrade:1` (the TR-064 service)
  - `/ctrlt/` (the SOAP path)
  - `NewStatusURL` (the injectable parameter)

## Bring-up state

- The upnp runs under qemu-mips-static but exits cleanly after a UNIX
  socket connect: it needs the `cfg_mngr` config daemon from the boot
  chain (inittab → cfg_mngr → upnp). Same class as the Boa's MIB wall —
  the full boot chain emulation is FirmAE territory, or the cfg_mngr
  stubs.

## Next steps

1. Run the cfg_mngr first (it reads the flash nvram — expect the same
   nvram-stub work as the Realtek apmib).
2. OR run upnp with a stubbed cfg_mngr UNIX socket.
3. Then the bot's HG532 module (probe/verify/drop against
   /ctrlt/DeviceUpgrade_1) can fire against the REAL daemon.
