/*
 * notnet - Modern Mirai-Style Botnet
 * util.c - Logging, random, string helpers
 */
#include "util.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/random.h>
#include <fcntl.h>
#include <unistd.h>

/* ── Logging ────────────────────────────────────────────────── */
static FILE *log_file = NULL;
static int log_initialized = 0;

void log_init(void) {
    /* Always use stderr for stdout (Docker/container compatibility) */
    log_file = stderr;
    
    log_initialized = 1;
    log_info("Log initialized");
}

void log_close(void) {
    if (log_initialized && log_file != stderr) {
        fflush(log_file);
        fclose(log_file);
    }
    log_initialized = 0;
}

void log_flush(void) {
    if (log_initialized && log_file) {
        fflush(log_file);
    }
}

void log_info(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char msg[512];
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    char timebuf[64];
    time_t t = time(NULL);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    
    if (log_initialized && log_file) {
        fprintf(log_file, "[%s] [INFO] %s\n", timebuf, msg);
        fflush(log_file);
    }
}

void log_warn(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char msg[512];
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    char timebuf[64];
    time_t t = time(NULL);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    
    if (log_initialized && log_file) {
        fprintf(log_file, "[%s] [WARN] %s\n", timebuf, msg);
        fflush(log_file);
    }
}

void log_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char msg[512];
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    char timebuf[64];
    time_t t = time(NULL);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    
    if (log_initialized && log_file) {
        fprintf(log_file, "[%s] [ERROR] %s\n", timebuf, msg);
        fflush(log_file);
    }
    
    /* Always print errors to stderr */
    fprintf(stderr, "[%s] [ERROR] %s\n", timebuf, msg);
}

void log_debug(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char msg[512];
    vsnprintf(msg, sizeof(msg), fmt, args);
    va_end(args);
    
    /* Debug logging only when not compiled out */
    #ifndef NDEBUG
    char timebuf[64];
    time_t t = time(NULL);
    struct tm tm_buf;
    localtime_r(&t, &tm_buf);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", &tm_buf);
    
    if (log_initialized && log_file) {
        fprintf(log_file, "[%s] [DEBUG] %s\n", timebuf, msg);
        fflush(log_file);
    }
    #endif
}

/* ── Random Helpers ─────────────────────────────────────────────── */
uint32_t random_uint32(void) {
    /* SECURITY FIX (#26): Mask rand() output to avoid signed integer
     * overflow when shifting. On glibc, rand() returns int in [0, 2^31-1).
     * SECURITY FIX (#37): Draw from getrandom() instead of rand() — the
     * linear congruential generator seeded with time(NULL) is guessable. */
    uint32_t v;
    if (random_bytes(&v, sizeof(v)) == 0) return v;
    /* Fallback only if the OS RNG is unavailable */
    return ((rand() & 0x7FFF) << 16) | (rand() & 0xFFFF);
}
void random_string(char *buf, int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    if (!buf || len <= 0) return;
    /* SECURITY FIX (#37): Fill a random buffer once and map bytes into the
     * charset (with modulo bias avoided via rejection sampling) instead of
     * calling rand() per character. */
    unsigned char raw[512];
    if (len - 1 > (int)sizeof(raw)) len = (int)sizeof(raw) + 1;
    if (random_bytes(raw, (size_t)(len - 1)) != 0) {
        /* Fallback: rand()-based (still bounded, but not cryptographic) */
        for (int i = 0; i < len - 1; i++) {
            buf[i] = charset[rand() % (sizeof(charset) - 1)];
        }
        buf[len - 1] = '\0';
        return;
    }
    size_t cmax = (256 / (sizeof(charset) - 1)) * (sizeof(charset) - 1);
    int out = 0;
    for (int i = 0; i < len - 1 && out < len - 1; i++) {
        unsigned char c = raw[i];
        if (c >= cmax) continue;  /* rejection sampling */
        buf[out++] = charset[c % (sizeof(charset) - 1)];
    }
    while (out < len - 1) {
        /* Extremely unlikely; fill remainder from fresh bytes */
        unsigned char c;
        if (random_bytes(&c, 1) != 0) break;
        if (c < cmax) buf[out++] = charset[c % (sizeof(charset) - 1)];
    }
    buf[len - 1] = '\0';
}

int random_bytes(void *buf, size_t len) {
    if (!buf || len == 0) return -1;
#ifdef __linux__
    ssize_t got = getrandom(buf, len, 0);
    if (got == (ssize_t)len) return 0;
#endif
    /* Fallback: /dev/urandom (works everywhere, still cryptographic) */
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t total = 0;
    unsigned char *p = (unsigned char *)buf;
    while (total < len) {
        ssize_t n = read(fd, p + total, len - total);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        total += (size_t)n;
    }
    close(fd);
    return 0;
}

/* ── Crypto Helpers ─────────────────────────────────────────────── */
/* Compact SHA-256 (FIPS 180-4). Pure C, no external deps — keeps the
 * static build self-contained. Used for payload integrity (#81). */
typedef struct {
    uint32_t h[8];
    uint64_t len;
    uint8_t buf[64];
    size_t buflen;
} sha256_ctx;

static uint32_t sha256_rotr(uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }

static void sha256_init(sha256_ctx *c) {
    c->h[0] = 0x6a09e667; c->h[1] = 0xbb67ae85; c->h[2] = 0x3c6ef372; c->h[3] = 0xa54ff53a;
    c->h[4] = 0x510e527f; c->h[5] = 0x9b05688c; c->h[6] = 0x1f83d9ab; c->h[7] = 0x5be0cd19;
    c->len = 0; c->buflen = 0;
}

static void sha256_block(sha256_ctx *c, const uint8_t *p) {
    static const uint32_t K[64] = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
    uint32_t w[64];
    for (int i = 0; i < 16; i++) {
        w[i] = ((uint32_t)p[i * 4] << 24) | ((uint32_t)p[i * 4 + 1] << 16) |
               ((uint32_t)p[i * 4 + 2] << 8) | p[i * 4 + 3];
    }
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = sha256_rotr(w[i - 15], 7) ^ sha256_rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
        uint32_t s1 = sha256_rotr(w[i - 2], 17) ^ sha256_rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }
    uint32_t a = c->h[0], b = c->h[1], cc = c->h[2], d = c->h[3];
    uint32_t e = c->h[4], f = c->h[5], g = c->h[6], h = c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = sha256_rotr(e, 6) ^ sha256_rotr(e, 11) ^ sha256_rotr(e, 25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t t1 = h + S1 + ch + K[i] + w[i];
        uint32_t S0 = sha256_rotr(a, 2) ^ sha256_rotr(a, 13) ^ sha256_rotr(a, 22);
        uint32_t maj = (a & b) ^ (a & cc) ^ (b & cc);
        uint32_t t2 = S0 + maj;
        h = g; g = f; f = e; e = d + t1;
        d = cc; cc = b; b = a; a = t1 + t2;
    }
    c->h[0] += a; c->h[1] += b; c->h[2] += cc; c->h[3] += d;
    c->h[4] += e; c->h[5] += f; c->h[6] += g; c->h[7] += h;
}

static void sha256_update(sha256_ctx *c, const uint8_t *data, size_t len) {
    c->len += len;
    while (len > 0) {
        size_t take = 64 - c->buflen;
        if (take > len) take = len;
        memcpy(c->buf + c->buflen, data, take);
        c->buflen += take;
        data += take;
        len -= take;
        if (c->buflen == 64) { sha256_block(c, c->buf); c->buflen = 0; }
    }
}

static void sha256_final(sha256_ctx *c, uint8_t out[32]) {
    uint64_t bits = c->len * 8;
    uint8_t pad = 0x80;
    sha256_update(c, &pad, 1);
    uint8_t zero = 0;
    while (c->buflen != 56) sha256_update(c, &zero, 1);
    uint8_t lenb[8];
    for (int i = 0; i < 8; i++) lenb[i] = (bits >> (56 - i * 8)) & 0xFF;
    sha256_update(c, lenb, 8);
    for (int i = 0; i < 8; i++) {
        out[i * 4]     = (c->h[i] >> 24) & 0xFF;
        out[i * 4 + 1] = (c->h[i] >> 16) & 0xFF;
        out[i * 4 + 2] = (c->h[i] >> 8) & 0xFF;
        out[i * 4 + 3] = c->h[i] & 0xFF;
    }
}

int sha256_hex(const unsigned char *data, size_t len, char out[65]) {
    if (!data || !out) return -1;
    sha256_ctx c;
    sha256_init(&c);
    sha256_update(&c, data, len);
    uint8_t digest[32];
    sha256_final(&c, digest);
    static const char hexd[] = "0123456789abcdef";
    for (int i = 0; i < 32; i++) {
        out[i * 2]     = hexd[digest[i] >> 4];
        out[i * 2 + 1] = hexd[digest[i] & 0x0F];
    }
    out[64] = '\0';
    return 0;
}

/* ── String Helpers ───────────────────────────────────────────── */
/* ── Network Helpers ─────────────────────────────────────────── */
/* ── File Helpers ─────────────────────────────────────────────── */
/* Read entire file into dynamically allocated buffer. Caller must free().
 * Returns bytes read, or -1 on error. */
int file_read(const char *path, unsigned char **out_buf) {
    return file_read_max(path, out_buf, PAYLOAD_MAX_SIZE);
}

/* Read entire file with an explicit size cap. */
int file_read_max(const char *path, unsigned char **out_buf, size_t max_size) {
    if (!path || !out_buf) return -1;

    /* Validate path */
    const char *bad = strpbrk(path, ";|&`$(){}[]<>!");
    if (bad) {
        log_error("file_read: dangerous char in path: %s", path);
        return -1;
    }

    FILE *f = fopen(path, "rb");
    if (!f) {
        log_error("file_read: cannot open %s: %s", path, strerror(errno));
        return -1;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || (size_t)fsize > max_size) {
        log_error("file_read: invalid size %ld for %s (max %zu)", fsize, path, max_size);
        fclose(f);
        return -1;
    }

    *out_buf = (unsigned char *)malloc(fsize);
    if (!*out_buf) {
        log_error("file_read: malloc failed for %ld bytes", fsize);
        fclose(f);
        return -1;
    }

    size_t nread = fread(*out_buf, 1, fsize, f);
    fclose(f);

    if ((long)nread != fsize) {
        log_error("file_read: short read (%zu of %ld) for %s", nread, fsize, path);
        free(*out_buf);
        *out_buf = NULL;
        return -1;
    }

    return (int)nread;
}

/* ── Timing Helpers ─────────────────────────────────────── */
uint64_t get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}