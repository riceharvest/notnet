# FirmAE Lab (#124)

Goal: boot REAL IoT firmware (HG532 / Realtek SDK / TBK DVR) under QEMU
so the bot's CVE modules fire against the actual vulnerable services.

## What is verified working (2026-08-12)

- `firmae-lab` Docker image (~2.9GB): Ubuntu 20.04 + QEMU (arm/mips/x86),
  PostgreSQL with the FirmAE schema, binwalk 2.3.3 (built from source —
  the Ubuntu-packaged 2.2.0 General module is broken), the FirmAE
  prebuilt kernels/busybox/libnvram (download.sh), the FirmAE scripts.
- Run: `docker run --rm --privileged -v /dev/kvm:/dev/kvm \
  --cap-add NET_ADMIN --cap-add SYS_ADMIN -e USER=root \
  -v ~/firmae-lab:/lab -w /firmadyne firmae-lab \
  sh -c 'PSQL_IP=127.0.0.1 ./run.sh -c <brand> /lab/<fw>.zip'`
- Verified with the FirmAE example DIR-868L: extraction completes
  (binwalk), architecture detection completes ("get architecture done"),
  the emulation starts.

## Blocker

The full QEMU boot hangs at the image-creation step when run inside the
Docker container (the scratch WORK_DIR is never populated and run.sh sits
in a child wait with no QEMU process). FirmAE is designed for a real
Ubuntu 20.04 host; the container path needs deeper debugging (scratch
dir handling, child process management under the container runtime).

## Reliable path (recommended)

Run FirmAE on a real Ubuntu 20.04 host/VM (the 5950X box) per the FirmAE
README (download.sh + install.sh + init.sh + `sudo ./run.sh -c`). The
same firmware images then feed issue #125 (HG532), #126 (Realtek), #127
(TBK DVR), and #128 bridges the emulated device into the sim network.

## qemu-user fallback (proven pipeline, 2026-08-12)

The qemu-user-static path works: the DIR-868L rootfs was extracted
(binwalk → squashfs → unsquashfs) and its REAL /sbin/httpd (ARM) runs
under qemu-arm-static in a chroot. The D-Link httpd exits without its
nvram store (the documented qemu-user blocker) — the bot's actual
targets (HG532 ctrlt, Realtek Boa) are simpler daemons that more often
survive with a libnvram stub. Firmware extraction recipe (in the
firmae-lab image):

    unzip -o DIR-868L_fw.zip -d z
    binwalk z/<inner>.bin            # find the SquashFS offset+size
    dd if=z/<inner>.bin of=root.squashfs bs=1 skip=<off> count=<sz>
    unsquashfs -f -d rootfs root.squashfs
    cp /usr/bin/qemu-arm-static rootfs/usr/bin/
    chroot rootfs /usr/bin/qemu-arm-static /sbin/httpd
