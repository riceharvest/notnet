# Sim profiles (#132) — emulator default stays green, real tiers opt-in

The verified Python emulator fleet is the DEFAULT and must stay green in
CI. The real tiers are opt-in profiles; no real-tier change may break the
emulator profile.

## Matrix (2026-08-12)

| Profile | What runs | CI | Last verified |
|---|---|---|---|
| **emulator** (default) | all 52 devices via device.py + mock C2 | yes (smoke, full, real-C2 jobs) | 21/21 full, 9/9 c2-drive |
| **real-services** (Tier 1, #123) | 6 legacy devices run real OpenSSH/Redis/Samba/busybox telnetd (fleet.yaml `real:` field), rest emulated | yes (same jobs; CI builds notnet-sim-realsvc) | 9/9 c2-drive with the mixed fleet |
| **real-firmware** (Tier 2, #124-#128) | FirmAE-booted real IoT firmware (HG532/Realtek/DVR) | NO — local lab only | in progress (#124 infra built) |
| **real-topology** (Tier 3, #130) | segment IPs + host DOCKER-USER policy on the flat bridge | yes (defence scenario) | L2-bridge split reverted (blocker #130) |
| **suricata** (Tier 3, #131) | real packet-capture IDS replacing the log-watcher | planned | not started |

## Rules

- `run-sim.sh` defaults to the emulator profile; `--c2 real` selects the
  production C2 (CI job c2-real); the real-services devices are always in
  the fleet (they pass the checks).
- CI 4/4 (smoke, full, full-real-C2, TLS) must stay green on every push.
- The real-firmware tier is lab-only: FirmAE runs on the 5950X host
  (~/firmae-lab), never in CI.
- Any profile that fails must fail LOUDLY (non-zero driver RC + a FAIL row
  in the parity report), never a silent pass.
