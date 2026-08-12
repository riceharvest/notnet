# Real-Firmware Live Endpoints — Bot CVE Modules Fire (#124/#125/#128)

Status: the bot's CVE probes now run against REAL firmware booted under
FirmAE on the host tap network. First confirmed live hit 2026-08-12.

## Verified live endpoints (FirmAE full-system boot, host)

| Device | IP (tap) | Service | Status |
|---|---|---|---|
| D-Link DIR-868L (ARM) | 192.168.0.1:80 | real web server | boot OK, web:true |
| Huawei HG532 (MIPS be) | 192.168.0.1:37215 | real TR-064/UPnP | boot OK, digest auth, SOAP dispatch empty (HAL wall) |
| TOTOLINK N300RT (MIPS be, Realtek SDK) | 192.168.1.1:80 | real Boa/0.94.14rc21 | boot OK, serving |

## Bot vs live firmware — observed behavior (notnet binary, local spread)

The bot scans its local /24 (the tap network) and runs the CVE modules
against the live devices:

```
CVE: CVE-2021-35395 probe hit on 192.168.1.1:80 (Realtek Jungle SDK (router/NVR)) — HTTP/1.0 200 OK
Server: Boa/0.94.14rc21
CVE: CVE-2021-35395 verify failed on 192.168.1.1:80 — no payload drop
```

- Probe tier FIRES: the real Boa header matches cve_realtek_probe.
- Verify tier honestly fails: this TOTOLINK build's boa has NO
  /boafrm/formSysCmd handler (the pages reference it, the binary's form
  table doesn't) — so CVE-2021-35395 does not apply to this build.
  Real-world-correct: fingerprint fires, exploit doesn't land.
- HG532: CVE-2017-17215 probe would need the HUAWEIUPNP envelope; the
  emulated upnp returns UPnPError 401 Invalid Action for every action
  (service table empty — mic never writes /var/curcfg.xml; TrendChip
  /dev/bhal c 255 0 has no driver in the FirmAE 4.1 kernel). Canonical
  payload (reb311ion exploit, dslf-config:admin, `$()` injection,
  /icon/../../../tmp/ccmd read) does NOT execute.
- DIR-868L: real D-Link web answers on 80; no bot CVE targets its
  handler set (D-Link HNAP tier not in the module list).

## How to reproduce

1. Boot a firmware (see FIRMAE-LAB.md): scratch/<iid>/run.sh (rdinit=
   patched, tunctl wrapper, /proc mounts in rcS for HG532).
2. Host-side tap IP aligned to the guest LAN (TOTOLINK: 192.168.1.2/24
   on tap3_0; DIR-868L/HG532: 192.168.0.2/24 on tap1_0/tap2_0).
3. Run the bot (local spread scans the tap /24):
   `rm -f /tmp/notnet.lock; NOTNET_C2_SECRET=notnet-v1 ./notnet`
   (hosts entry api.notnet.net -> 127.0.0.1 + local C2 on 8080 optional;
   the local spread cycle runs without a reachable C2).
4. Watch the bot log: `CVE-2021-35395 probe hit on 192.168.1.1:80`.

## What would make verify/drop fire on real firmware

- Realtek: a firmware build that still ships the /boafrm/formSysCmd
  handler (older Jungle SDK v2/v3.4.x builds; the N300RT 2025 build
  removed it). Same boot recipe applies.
- HG532: a HAL shim for the TrendChip tc3162 (bhal device) or a
  device-specific FirmAE kernel; alternatively an HG532 build whose
  config chain works without the HAL (needs /var/curcfg.xml generation).

## Issue mapping

- #124 FirmAE extraction + host boot: SOLVED (both firmwares + D-Link).
- #125 HG532 real CVE endpoint: TR-064 live; injection blocked by HAL.
- #126 Realtek SDK: live Boa + bot probe HIT; verify needs older build.
- #128 bridge emulated devices into sim: the tap-network live endpoints
  are reachable by the bot's local spread; the fleet target IPs
  (172.29.10.x) still map to the dockerized emulators.
