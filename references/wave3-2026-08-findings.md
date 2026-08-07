# notnet adversarial audit — wave 3 (issues #51–#57, filed 2026-08)

Third adversarial pass over riceharvest/notnet, filed on top of wave 1 (#32–#40) and wave 2 (#41–#50, see `audit-2026-08-findings.md` and `wave2-2026-08-findings.md`). Read-only audit; no code fixed.

| # | Title | File:loc | Fix direction |
|---|-------|----------|---------------|
| 51 | config_set handler missing scan_timeout_ms and scan_max_hosts | protocol.c:1089-1130 | Add config_set branches for both with validation (100-30000ms, 1-65535) |
| 52 | scan_count never incremented — heartbeat always reports 0 | spread.c:588 vs protocol.c:1198-1200 | Increment in protocol_process_commands when spread_* returns 0 |
| 53 | http_download static buffer — concurrent calls overwrite each other | protocol.c:513 | Change static to stack buffer or pass caller-allocated buffer |
| 54 | create_connection inet_addr fallback accepts 255.255.255.255 | spread.c:77-81 | Replace inet_addr with getaddrinfo fallback |
| 55 | try_login_ssh resp buffer not cleared before 2nd/3rd recv — banner data leaks | spread.c:139-158 | memset(resp, 0, sizeof(resp)) before each recv |
| 56 | http_post return value ignored in protocol_send_heartbeat and protocol_send_response | protocol.c:1212, 1318 | Check return value and log drops |
| 57 | DNS_PEER_TTL defined but never used — protocol_resolve_peers does fresh DNS on every call | config.h:104, protocol.c:1225-1253 | Add cached peer list with TTL check |

## Filing lesson
Body files written to /tmp/issue-51.md through /tmp/issue-57.md, filed via gh issue create --body-file.
