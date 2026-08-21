# 2026-08-21 full-repo audit — wave 8 (post-#163 sweep)

Baseline: `make` clean build (13 warnings, all -Wunused-result on system()/fread in persist.c), tests/run-tests.sh PASS (killswitch armed + inert, 5/5 scenarios). Findings below were each verified by reading the cited lines.

Filed:
- #164 c2.py /upload: no secret, no size cap (CWE-306/434)
- #165 c2.py recv_http unbounded buffer (CWE-770)
- #166 c2.py ws_read_frame unbounded plen (CWE-409)
- #167 c2.py responses accepted with no secret → state/evidence injection (CWE-306)
- #168 c2.py console token `==` compare + ?token= in URL (CWE-208/598)
- #169 protocol.c exfil chunk memcpy rlen-only guard — latent stack overflow (CWE-120)
- #170 mesh.c cmd_queue write vs protocol.c unlocked read — data race (CWE-362)
- #171 spread.c strcat append relies on distant reserve constant (CWE-120 latent)
- #172 c2.py hardcoded default secret "notnet-v1" (CWE-798)
- #173 c2.py payload + src tarball unauthenticated on 0.0.0.0 (CWE-306)
- #174 protocol.c IRC nick-prefix trust + authenticated-by-any-366/376 (CWE-290)
- #175 protocol.c secret-echo gate is whole-body substring scan (CWE-345)
- #176 payload.c tar_extract_safe skips checksum/magic, warn-skips longname (CWE-347 latent)
- #177 c2.py console innerHTML with bot-supplied fields — stored XSS (CWE-79)
- #178 protocol.c download/upload metachar check ≠ path scoping (CWE-22 framing)
- #179 protocol.c exec allowlist via PATH + silent extra-arg drop (CWE-426)
- #180 spread.c subnet host_ip+i wraps near top of IPv4 space (CWE-190, correctness)
- #181 protocol.c three hand-rolled JSON scanners desync on escapes (CWE-436)
- #182 protocol.c ws_read oversized-frame remainder re-parsed as next header (CWE-436)
- #183 c2.py upload filename from raw URL path, no charset validation (CWE-20)
- #184 protocol.c queued commands after kill still execute same tick
- #187 c2.py unbounded thread-per-connection on all listeners (CWE-400)
- #188 protocol.c sleep freezes whole C2 loop incl. killswitch/heartbeat (CWE-400)
- #189 protocol.c IRC authenticated flag not reset on reconnect (CWE-287)

Filed then withdrawn after verification (auditor error, closed with explanation):
- #185 sleep/scan_interval "dead knob" — wrong, scan_interval is the main-loop sleep (notnet.c:484). Superseded by #188 (the real problem).
- #186 secret charset divergence bot vs C2 — wrong, the alphanumeric check at protocol.c:3857 is inside load_config(); config_set doesn't even allow c2_secret.

Not filed (checked, clean): getaddrinfo used everywhere (no gethostbyname/inet_addr), no strcpy/sprintf, persist.c system() calls are all fixed strings or validated paths (#41-43), proxy/relay have const-time token compare + conn caps, plugin fetch is SHA-256-pin fail-closed, payload update is pin fail-closed with mkstemp+rename, killswitch compile-time-only, .gitignore covers all artifacts, no secrets in git tree.

Build hygiene (minor, no issue filed): 13 -Wunused-result warnings in persist.c; `make TLS=1` untested this pass (CI covers it).
