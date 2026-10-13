/*
 * notnet — host test for the distributed-inference sharding (#402).
 *
 * Single-process, CI-safe, no network: exercises the shard capacity
 * probe, the assignment store, the fail-closed weight fetch, and the
 * activation-forward gating. Proves the coordination/transport layer
 * behaves before any real shard runner is dropped in.
 *
 * What it proves:
 *   1. capacity probe reads RAM from /proc/meminfo and derives a
 *      feasible shard-layer count from the per-layer footprint
 *   2. shard_set/get_assignment round-trips (model, layers, idx, peers)
 *   3. shard_fetch fails closed with no SHA pin, and with a pin but a
 *      dead URL (partial file unlinked)
 *   4. shard_forward refuses on the LAST pipeline peer (runs LM head)
 *      and refuses with no relay token (fail-closed)
 *   5. shard_forward returns -1 (not crash) when unbound/edge inputs
 *   6. shard_status_render emits the heartbeat field; empty when off
 *   7. fleet tps estimate sums peer capacity (x100)
 *
 * Build + run:
 *   make
 *   gcc -I include -o /tmp/shard_test tests/host/shard_test.c src/*.o -lpthread
 *   /tmp/shard_test
 *
 * Research purposes only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "protocol.h"
#include "shard.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS  %s\n", msg); } \
    else { printf("  FAIL  %s\n", msg); g_fail = 1; } \
} while (0)

int main(void) {
    printf("── shard capacity probe ──\n");
    shard_capacity_t cap;
    /* 30-layer model, 64MB/layer -> a box with >=192MB usable holds some layers */
    shard_probe_capacity(&cap, 64, 30);
    CHECK(cap.ram_mb > 0, "capacity: RAM read from /proc/meminfo (>0 on Linux)");
    if (cap.ram_mb > 192) {
        CHECK(cap.shard_layers > 0, "capacity: derived shard_layers > 0 when RAM suffices");
        CHECK(cap.shard_layers <= 30, "capacity: shard_layers capped at model total");
    } else {
        CHECK(cap.shard_layers == 0, "capacity: 0 layers when RAM too small (no overcommit)");
    }
    /* layer_mb==0 (unconfigured) must not divide by zero or overcommit */
    shard_capacity_t cap0;
    shard_probe_capacity(&cap0, 0, 30);
    CHECK(cap0.shard_layers == 0, "capacity: layer_mb=0 -> 0 layers (no plan, no crash)");

    printf("── assignment store ──\n");
    shard_assignment_t asg;
    memset(&asg, 0, sizeof(asg));
    snprintf(asg.model, sizeof(asg.model), "gemma4-26b-a4b");
    asg.layer_start = 8;
    asg.layer_count = 4;
    asg.my_index = 1;
    snprintf(asg.peers[0], 256, "10.0.0.5:1082");
    snprintf(asg.peers[1], 256, "10.0.0.6:1082");
    snprintf(asg.peers[2], 256, "10.0.0.7:1082");
    asg.peer_count = 3;
    shard_set_assignment(&asg);

    shard_assignment_t got;
    CHECK(shard_get_assignment(&got) == 0, "assign: stored assignment retrievable");
    CHECK(got.layer_start == 8 && got.layer_count == 4, "assign: layer range round-trips");
    CHECK(got.my_index == 1 && got.peer_count == 3, "assign: index + peer count round-trip");
    CHECK(strcmp(got.peers[2], "10.0.0.7:1082") == 0, "assign: peer list round-trips");
    CHECK(shard_have_assignment() == 1, "assign: have_assignment true after set");

    printf("── shard_fetch fail-closed ──\n");
    notnet_bot_t bot;
    memset(&bot, 0, sizeof(bot));
    shard_cfg_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.enabled = 1;
    snprintf(cfg.shard_url, sizeof(cfg.shard_url), "http://127.0.0.1:1/shards");
    snprintf(cfg.shard_dir, sizeof(cfg.shard_dir), "/tmp/shard_test_%d", (int)getpid());

    /* no pin -> refuse */
    cfg.shard_sha[0] = '\0';
    CHECK(shard_fetch(&bot, &cfg, &asg) == -1, "fetch: no SHA pin -> fail-closed");

    /* bad pin length -> refuse */
    snprintf(cfg.shard_sha, sizeof(cfg.shard_sha), "abc");
    CHECK(shard_fetch(&bot, &cfg, &asg) == -1, "fetch: short SHA pin -> fail-closed");

    /* valid pin but dead URL -> download fails, partial unlinked */
    snprintf(cfg.shard_sha, sizeof(cfg.shard_sha),
             "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    CHECK(shard_fetch(&bot, &cfg, &asg) == -1, "fetch: dead URL -> fail-closed");
    /* the partial file must be gone */
    char dest[320];
    snprintf(dest, sizeof(dest), "%s/%s.layers%u-%u.bin",
             cfg.shard_dir, asg.model, asg.layer_start,
             (unsigned)asg.layer_start + asg.layer_count - 1);
    CHECK(access(dest, F_OK) != 0, "fetch: partial shard file unlinked after failure");

    /* disabled module -> refuse */
    shard_cfg_t off;
    memset(&off, 0, sizeof(off));
    CHECK(shard_fetch(&bot, &off, &asg) == -1, "fetch: disabled module -> fail-closed");

    printf("── shard_forward gating ──\n");
    /* unbound bot (no relay token) -> refuse, not crash */
    CHECK(shard_forward(&asg, "abcd", 4) == -1, "forward: unbound bot -> fail-closed");

    /* bind a bot but no relay token -> still refuse */
    notnet_bot_t fbot;
    memset(&fbot, 0, sizeof(fbot));
    shard_bind_bot(&fbot);
    CHECK(shard_forward(&asg, "abcd", 4) == -1, "forward: no relay token -> fail-closed");

    /* last peer (idx == peer_count-1) runs the LM head -> nothing to forward */
    shard_assignment_t last;
    memcpy(&last, &asg, sizeof(last));
    last.my_index = last.peer_count - 1;   /* 2 == last of 3 */
    CHECK(shard_forward(&last, "abcd", 4) == -1, "forward: last peer runs LM head (no forward)");

    /* empty frame -> refuse */
    CHECK(shard_forward(&asg, "abcd", 0) == -1, "forward: empty frame -> fail-closed");

    printf("── telemetry ──\n");
    shard_cfg_t tcfg;
    memset(&tcfg, 0, sizeof(tcfg));
    tcfg.enabled = 1;
    snprintf(tcfg.model, sizeof(tcfg.model), "gemma4-26b-a4b");
    tcfg.total_layers = 32;
    tcfg.tok_per_sec = 39;   /* 0.39 tok/s, the paper's TV-box rate, x100 */
    char st[160];
    shard_status_render(&tcfg, &asg, &cap, st, sizeof(st));
    CHECK(strstr(st, "model=gemma4-26b-a4b") != NULL, "telemetry: model in status");
    CHECK(strstr(st, "layers=8+4") != NULL, "telemetry: layer range in status");
    CHECK(strstr(st, "idx=1/3") != NULL, "telemetry: pipeline position in status");
    CHECK(strstr(st, "tok=0.39") != NULL, "telemetry: tok/s rendered from x100");

    /* disabled -> empty status field (heartbeat stays clean) */
    shard_cfg_t dcfg;
    memset(&dcfg, 0, sizeof(dcfg));
    char st2[160];
    shard_status_render(&dcfg, &asg, &cap, st2, sizeof(st2));
    CHECK(st2[0] == '\0', "telemetry: disabled module -> empty heartbeat field");

    printf("── fleet throughput ──\n");
    shard_update_fleet_tps(15, 39);   /* 15 boxes @ 0.39 tok/s */
    CHECK(shard_fleet_tps_x100() == 15 * 39, "fleet: tps sums peer capacity (x100)");
    shard_update_fleet_tps(0, 39);
    CHECK(shard_fleet_tps_x100() == 0, "fleet: no peers -> 0");

    /* cleanup */
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", cfg.shard_dir);
    if (system(cmd) != 0) { /* best effort */ }

    printf("\n%s\n", g_fail ? "SHARD TEST FAILED" : "SHARD TEST PASSED");
    return g_fail ? 1 : 0;
}
