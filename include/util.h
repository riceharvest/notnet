/*
 * notnet - Modern Mirai-Style Botnet
 * util.h - Logging, random, string helpers
 */
#ifndef NOTNET_UTIL_H
#define NOTNET_UTIL_H

#include "config.h"
#include <stdint.h>
#include <time.h>
#include <stdarg.h>

/* ── Logging ────────────────────────────────────────────────── */
void log_init(void);
void log_close(void);
void log_flush(void);
void log_info(const char *fmt, ...);
void log_warn(const char *fmt, ...);
void log_error(const char *fmt, ...);
void log_debug(const char *fmt, ...);

/* Best-effort memory wipe the optimizer cannot elide. Shared by the
 * C2 `kill` path (protocol.c) and the global killswitch (killswitch.c). */
void wipe_volatile(volatile char *p, size_t n);

/* ── Random Helpers ─────────────────────────────────────────────── */
uint32_t random_uint32(void);
void random_string(char *buf, int len);
/* Fill buf with len cryptographically-random bytes (getrandom).
 * Returns 0 on success, -1 on failure. Security-relevant randomness
 * (WS masks, handshake keys) must use this, not rand(). */
int random_bytes(void *buf, size_t len);

/* ── String Helpers ─────────────────────────────────────────────── */

/* ── Crypto Helpers ─────────────────────────────────────────────── */
/* Compute SHA-256 of data and write it as a lowercase hex string to
 * out (must hold 65 bytes: 64 hex chars + NUL). Returns 0 on success,
 * -1 on invalid args. Used for payload integrity verification (#81). */
int sha256_hex(const unsigned char *data, size_t len, char out[65]);

/* ── Network Helpers ─────────────────────────────────────────── */

/* ── File Helpers ─────────────────────────────────────────────── */

/* Read entire file into dynamically allocated buffer. Caller must free().
 * Returns bytes read, or -1 on error. Capped at PAYLOAD_MAX_SIZE. */
int file_read(const char *path, unsigned char **out_buf);

/* Read entire file with an explicit size cap. Caller must free().
 * Returns bytes read, or -1 on error. Used for files larger than
 * PAYLOAD_MAX_SIZE (e.g. the on-target compilation source bundle). */
int file_read_max(const char *path, unsigned char **out_buf, size_t max_size);

/* ── Timing Helpers ─────────────────────────────────────── */
uint64_t get_timestamp_ms(void);

#endif /* NOTNET_UTIL_H */
