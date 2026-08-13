# Security Policy — notnet

notnet is a **research-purpose** botnet framework. It is published so defenders
can study, detect, and block this class of malware — and so the offensive
capabilities are matched, in the same repository, by shipped detections,
intel, and guardrails.

## Intended use

- Security research on systems you own or are explicitly authorized to test.
- Building/validating the detection artifacts in `detections/` and `intel/`.
- Cyber-range / detection-engineering exercises with the `tests/sim` harness.

notnet is **not** intended for unsanctioned deployment on third-party systems.
Doing so is unauthorized access and is illegal in most jurisdictions.

## Responsible disclosure

If you find a defect in the **defensive** tooling — a detection that fails to
fire, an intel IOC that has drifted, or a guardrail that does not hold — please
open an issue or a private advisory. Detection gaps are the highest-priority
reports because they weaken the repo's stated purpose.

Contact: **security@riceharvest.github.io** (PGP optional; subject
`notnet disclosure`).

## Reporting abuse of leaked builds

A stock notnet binary cannot be disarmed by its operator (#130): the
author killswitch domain is baked in at build time. If a build with your
author domain leaks:

1. Point `KILLSWITCH_DOMAIN_DEFAULT` (the domain you built with) at `127.0.0.1`
   or `0.0.0.0`. Every stock-built instance resolves it and self-destructs.
2. The killswitch domain is published as a sinkhole-able IOC in `intel/`
   (#152) — defenders can also sinkhole it to neuter leaked stock fleets.

Signed-disarm (a cryptographically signed stay-alive beacon; see #140) makes a
leak *recoverable*: a fork that strips the check also strips signature
verification, so the binary will not accept operator commands.

## Build attestation

Every release binary should carry a `BUILD-ATTESTATION.json` (see
`attest.py`) recording the build host, git commit, signer, and the binary's
SHA-256. A leaked artifact is traceable to who produced it. CI generates this
for CI-produced artifacts.

## Scope note (GitHub AUP)

This repository ships an operational bot **and** the defenses against it. The
defenses — `detections/`, `intel/`, and this policy — are the argument that the
repo is research tooling, not malware for deployment. Keep them in lockstep:
do not ship an offensive change without its detection, and do not weaken a
guardrail without opening an issue first.
