# BYOVD — defense-neutralization research note (#94)

**Status: research scaffold, defensive-only. notnet ships NO
driver-loading code.** This note documents the pattern so defenders and
researchers can recognize it; the plugin of the same name registers in
the built-in registry (#92) and refuses every operation.

## What BYOVD is

Bring-Your-Own-Vulnerable-Driver (BYOVD) is the commodity successor to
custom kernel rootkits. Instead of writing (or stealing) a signed
kernel driver of your own — a losing bet since platform hardening
(signature enforcement, Secure Boot, HVCI/Memory Integrity, PatchGuard)
closed that door — an attacker carries a **legitimately signed but
vulnerable** third-party driver (typically an old anti-cheat, game,
hardware, or security product driver) and abuses its known bug to get
kernel-level code execution: usually by exploiting a vulnerable
IOCTL/routine exposed by the signed driver to read/write kernel memory,
disable callbacks, or neutralize security tooling.

Classic abuse chain (for recognition, not implementation):

1. Copy a known-vulnerable **signed** driver from a local pool to disk.
2. Load it through the standard driver-loading path (Windows-only;
   requires administrative privileges — which is why the technique is
   almost always combined with privilege escalation or social
   engineering to reach admin first).
3. Exploit the driver's documented vulnerability (e.g. an arbitrary
   kernel read/write IOCTL) to kill/disable EDR and other security
   tooling.
4. Unload the driver and remove artifacts, leaving no custom rootkit.

Attackers never need to write kernel code; the vulnerable driver
already carries Microsoft's signature, so it passes signature checks
that would reject an unsigned custom driver.

## Ecosystem (2026 picture)

- ESET's research catalogued **~90 EDR killers**, of which **54 abuse
  a shared pool of ~35 legitimately signed vulnerable drivers** — the
  same small driver set reused across the entire ecosystem (a driver
  abused by one tool is quickly adopted by others).
- The pattern has gone mainstream: ransomware groups (e.g. the
  BlackCat/ALPHV affiliates) and info-stealer operators deploy BYOVD
  "EDR killers" as a standard pre-encryption/pre-exfiltration step.
- The defense is now winning some rounds: in a 2026 case the
  vulnerable-driver blocklist **quarantined a dropped vulnerable driver
  127 ms after it hit disk** — the cat-and-mouse game has moved to
  speed and evasion (unpacking, delayed drops, LOLBin-adjacent driver
  staging), not technique novelty.

## Defensive checklist

For defenders on Windows endpoints:

1. **Enable the Microsoft vulnerable-driver blocklist** (Windows
   Security → Device security → Core isolation → Microsoft Vulnerable
   Driver Blocklist; also deployed via the WDAC/MDAT policy surface).
   This is the single most effective control — it blocks the ~35
   shared abused drivers by name/hash at load time.
2. **Enable HVCI / Memory Integrity** (Core isolation). Blocks
   kernel-mode injection and makes driver exploitation harder even when
   a vulnerable driver slips through.
3. **Apply WDAC / App Control for Business** (or MDAC/ASR equivalents)
   with a driver rule policy that only allows known-good signed
   drivers; complement with `ci.dll` driver-signing enforcement and
   attestation (WHQL + attestation signing) so only attested drivers
   load.
4. **Keep Secure Boot + UEFI Secure Boot enforcement on** so the boot
   chain cannot be replaced (defense-in-depth against bootkit-style
   persistence).
5. **Monitor driver loads** (Event ID 7045, Sysmon Event ID 6, driver
   load telemetry) for unusual/known-vulnerable driver names and
   unexpected `.sys` files appearing in `%TEMP%`, `C:\Windows\Temp`,
   or adjacent to the payload.
6. **Watch the admin boundary**: BYOVD requires administrative
   privileges to load drivers — LAPS, least-privilege, and credential
   theft defenses (the repo's own cred-log module is a reminder of how
   cheaply admin creds are harvested) are the upstream choke point.
7. **Quarantine fast**: the 127 ms blocklist case shows drop-to-load
   is detectable — EDR/AV quarantine policies should key on the
   known-bad driver hashes and the classic IOCTL abuse offsets.

## notnet's stance

- **This repo ships no driver-loading code.** The technique is
  Windows-only, requires admin, is heavily signature-flagged, and the
  repo's 2026 judgment is that kernel-level defense neutralization is a
  losing bet for the same reason custom rootkits were: platform
  hardening moves faster than the abuse (blocklist quarantines in
  ~100 ms). Implementing it would be weaponized code with no research
  upside the documentation does not already cover.
- The `byovd` plugin in the built-in registry (#92) is a **defensive
  research scaffold**: every operation (load/run/unload) is refused
  with a clear log so the C2 sees an explicit refusal, never a silent
  success.
- The `byovd_guard` config flag (default 0, settable via `byovd_guard=`
  in `/etc/notnet.conf` or the `config_set byovd_guard=1` C2 command)
  is the defensive posture toggle: when set, the plugin's load callback
  reports that BYOVD-style driver abuse is **blocked**. It controls
  reporting only — there is no driver-loading capability to enable.
- Detection beats deployment: the defensive checklist above is the
  actionable output of this issue.
