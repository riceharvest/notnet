/*
 * notnet - Modern Mirai-Style Botnet
 * util.c - Logging, random, string helpers
 */
#include "util.h"
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

/* ── Logging ────────────────────────────────────────────────── */
static FILE *log_file = NULL;
static char log_buffer[LOG_BUFFER_SIZE];
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
    struct tm *tm_info = localtime(&t);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
    
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
    struct tm *tm_info = localtime(&t);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
    
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
    struct tm *tm_info = localtime(&t);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
    
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
    struct tm *tm_info = localtime(&t);
    strftime(timebuf, sizeof(timebuf), "%Y-%m-%d %H:%M:%S", tm_info);
    
    if (log_initialized && log_file) {
        fprintf(log_file, "[%s] [DEBUG] %s\n", timebuf, msg);
        fflush(log_file);
    }
    #endif
}

/* ── Random Helpers ─────────────────────────────────────────────── */
uint32_t random_uint32(void) {
    /* SECURITY FIX (#26): Mask rand() output to avoid signed integer
     * overflow when shifting. On glibc, rand() returns int in [0, 2^31-1). */
    return ((rand() & 0x7FFF) << 16) | (rand() & 0xFFFF);
}

uint16_t random_uint16(void) {
    return rand() & 0xFFFF;
}

void random_string(char *buf, int len) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    for (int i = 0; i < len - 1; i++) {
        buf[i] = charset[rand() % (sizeof(charset) - 1)];
    }
    buf[len - 1] = '\0';
}

/* ── String Helpers ───────────────────────────────────────────── */
char *str_replace(char *str, const char *old, const char *new) {
    /* Simple string replacement */
    char *newstr = strdup(str);
    if (!newstr) return NULL;
    
    char *found = strstr(newstr, old);
    if (!found) {
        free(newstr);
        return str;
    }
    
    /* Replace first occurrence */
    int old_len = strlen(old);
    int new_len = strlen(new);
    
    memmove(found + new_len, found + old_len, strlen(found + old_len) + 1);
    memcpy(found, new, new_len);
    
    return newstr;
}

/* ── Network Helpers ─────────────────────────────────────────── */
uint32_t generate_random_ip(void) {
    return (random_uint32() & 0xFFFFFF00) | (random_uint32() & 0xFF);
}

char *format_ip(uint32_t ip) {
    static char buf[16];
    snprintf(buf, sizeof(buf), "%d.%d.%d.%d",
             (ip >> 24) & 0xFF,
             (ip >> 16) & 0xFF,
             (ip >> 8) & 0xFF,
             ip & 0xFF);
    return buf;
}

/* ── File Helpers ─────────────────────────────────────────────── */
int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

int file_size(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    return st.st_size;
}

/* ── Timing Helpers ─────────────────────────────────────── */
uint64_t get_timestamp_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + tv.tv_usec / 1000;
}

int time_since(time_t t) {
    return time(NULL) - t;
}
