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

/* ── Random Helpers ─────────────────────────────────────────────── */
uint32_t random_uint32(void);
uint16_t random_uint16(void);
void random_string(char *buf, int len);
/* Fill buf with len cryptographically-random bytes (getrandom).
 * Returns 0 on success, -1 on failure. Security-relevant randomness
 * (WS masks, handshake keys) must use this, not rand(). */
int random_bytes(void *buf, size_t len);

/* ── String Helpers ─────────────────────────────────────────────── */
char *str_replace(char *str, const char *old, const char *new);

/* ── Crypto Helpers ─────────────────────────────────────────────── */
/* Compute SHA-256 of data and write it as a lowercase hex string to
 * out (must hold 65 bytes: 64 hex chars + NUL). Returns 0 on success,
 * -1 on invalid args. Used for payload integrity verification (#81). */
int sha256_hex(const unsigned char *data, size_t len, char out[65]);

/* ── Network Helpers ─────────────────────────────────────────── */
uint32_t generate_random_ip(void);
char *format_ip(uint32_t ip);

/* ── File Helpers ─────────────────────────────────────────────── */
int file_exists(const char *path);
int file_size(const char *path);

/* Read entire file into dynamically allocated buffer. Caller must free().
 * Returns bytes read, or -1 on error. */
int file_read(const char *path, unsigned char **out_buf);

/* ── Timing Helpers ─────────────────────────────────────── */
uint64_t get_timestamp_ms(void);
int time_since(time_t t);

#endif /* NOTNET_UTIL_H */
