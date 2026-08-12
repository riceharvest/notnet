# FirmAE Lab (#124)

Goal: boot REAL IoT firmware (HG532 / Realtek SDK / TBK DVR) under QEMU
so the bot's CVE modules fire against the actual vulnerable services.

## Status: EXTRACTION + FULL-SYSTEM BOOT SOLVED (2026-08-12 evening)

The extractor wall is dead. Both acquired firmwares extract on the HOST
and boot full-system under QEMU. One boots completely (web reachable);
the other boots but the CVE injection needs the vendor HAL chain.

## Extractor: root cause + fix

- Silent exit 0: extractor.py:782 only runs with `-d` OR a passing
  psql_check() — a failed DB check exits 0 silently. Always run with `-d`.
- "Skipping: completed!" with no files written: the outputs WERE written
  — into the ephemeral container. Output arg `1` is relative to the
  container cwd `/firmadyne` (abspath in Extractor.__init__), and
  `docker run --rm` destroys the container on exit. The mounted volume
  is `/lab`; the output dir must be under it.
- Host chain works: binwalk 2.3.4 (PYTHONPATH=/usr/lib/python3.14/site-packages)
  + sasquatch (host build) extracts both D-Link DLOB and HG532 LZMA squashfs.
- DB: extractor connects to database `firmware` user `firmadyne` /
  `firmadyne` on 127.0.0.1:5432 (assist-all-postgres). Schema loaded from
  FirmAE/database/schema. Host run: `sudo env PYTHONPATH=... python3
  sources/extractor/extractor.py -b <brand> -sql 127.0.0.1 -np -nk/-nf <fw> images`

## DIR-868L — FULL SUCCESS (live web endpoint)

`sudo ./run.sh -c dlink`-equivalent host flow: extract (images/1.tar.gz +
1.kernel) → getArch=armel → tar2db → makeImage → makeNetwork → check.
Result: ping:true, web:true, ip 192.168.0.1. The REAL D-Link firmware
boots under qemu-system-arm (kernel 2.6.36.4brcmarm+, userspace xmldbc/
updatewifistats/gpiod) and its web server answers on port 80. This is a
live real-firmware endpoint the bot can target.

Key steps for the host (Fedora) run:
- qemu-system-arm installed via dnf (missing by default).
- tunctl wrapper at /usr/local/sbin/tunctl (ip tuntap based; Fedora has
  no uml-utilities). FirmAE run.sh scripts call `sudo tunctl -t/-d`.
- busybox + bash-static copied from the firmae-lab container to
  /usr/local/bin (makeImage.sh needs them on PATH).
- binaries/ copied from the container (download.sh output: vmlinux*,
  busybox.*, console.*, libnvram.*, gdb*).

## HG532 — BOOTS, TR-064 LIVE, injection blocked by vendor HAL

- Host extraction: images/2.tar.gz + 2.kernel (IID=2, mipseb). Rootfs has
  /bin/upnp (CVE-2017-17215 daemon), /bin/web, /bin/mic (config agent),
  /bin/cms, telnetd.
- Full-system boot works with the DEFAULT init path: the run.sh template
  must use `rdinit=` NOT `init=` for the kernel cmdline. `init=` triggers
  the FirmAE console-wrapper path whose console.mipseb exits 0 → kernel
  panic "Attempted to kill init". With `rdinit=/firmadyne/preInit.sh`
  and no initrd, the kernel falls back to the firmware's own /sbin/init
  (busybox) → /etc/inittab → rcS → userspace. (This is why the inference
  boot always worked and the check boot panicked.)
- /proc was empty until rcS gained `mount -t proc proc /proc` etc.
  (preInit.sh never runs on the default-init path).
- Interactive shell: inittab per-tty entries are ignored by this busybox;
  rcS line `(/bin/sh < /dev/ttyS1 > /dev/ttyS1 2>&1) &` puts a shell on
  the second serial (unix socket /tmp/qemu.2.S1, chmod 666, socat in).
- Service chain: /bin/mic (inetd-app framework) spawns upnp/cms/dns/
  dhcps. Real TR-064 server LIVE on 192.168.0.1:37215 (digest auth realm
  HuaweiHomeGateway, creds dslf-config:admin — the reb311ion exploit's
  creds). Canonical payload: POST /ctrlt/DeviceUpgrade_1 with
  `<NewStatusURL>$(cmd)</NewStatusURL><NewDownloadURL>$(echo HUAWEIUPNP)
  </NewDownloadURL>`; output read via `--path-as-is
  http://IP:37215/icon/../../../tmp/ccmd`.
- BLOCKER: every SOAP action returns UPnPError 401 Invalid Action — the
  service dispatch table is empty because mic never writes /var/curcfg.xml
  (its config generation fails; defaultcfg.xml is encrypted, and the
  TrendChip HAL /dev/bhal c 255 0 has no driver in the generic FirmAE
  kernel — mknod alone does not help). Daemons log "Unable to open device
  /dev/bhal". This is the classic SoC-specific-firmware limit: the
  TC3162U HAL (tc3162_dmt.ko, built for kernel 2.6.21) cannot run on the
  FirmAE 4.1 kernel. The injection does NOT execute on this build.

Next steps for the HG532 CVE: (a) locate the full HG532 firmware with the
untrimmed rcS + a matching HAL emulation (FirmAE device-specific kernel),
or (b) switch the live-target goal to a firmware whose SoC is supported
by the FirmAE kernel (Broadcom/RT chipsets — DIR-868L already proves that
class), or (c) run the upnp daemon + mic chain under qemu-mips-static with
a bhal shim module. The DIR-868L endpoint already satisfies "boot real
firmware, reach a live endpoint"; the CVE tier (#125/#128) needs one more
iteration on the HAL.

## Lab hygiene notes

- udisks auto-mounts every `losetup -Pf` partition at
  /run/media/dario/<uuid> — unmount before `losetup -d`, else detach
  fails with EBUSY.
- Killing qemu via the monitor: NEVER send `quit` (it exits qemu); use
  `info chardev` etc. only.
- Background sudo needs a TTY for the password: use
  `echo '<pw>' | sudo -S <cmd>` (foreground sudo works with the cached
  ticket; background does not).
