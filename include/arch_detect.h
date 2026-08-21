/*
 * notnet - Modern Mirai-Style Botnet
 * arch_detect.h - Target architecture fingerprinting (#160)
 *
 * Before a CVE module fires, the bot identifies the target's likely CPU
 * architecture. Two independent signals, combined in arch_detect():
 *
 *   1. HTTP banner markers — the Server header and body of a passive
 *      GET / fingerprint. Boa/Realtek SDK httpd almost always ships on
 *      MIPS (big-endian) firmware; uClinux-style banners ("uClinux",
 *      "ARM9", GoAhead-on-ARM builds) indicate ARM9-class cores;
 *      nginx/Apache answer for generic x86/64 hosts (arch UNKNOWN from
 *      HTTP alone — those are servers, not the embedded targets this
 *      kit cares about).
 *
 *   2. TCP/IP initial-TTL heuristic via a raw probe socket: consumer
 *     embedded stacks ship initial TTL 64 (MIPS-ish, observed <65),
 *     Windows/x86 desktop stacks 128 (<129). The raw socket sniffs the
 *     SYN-ACK of a connect we initiate ourselves; without CAP_NET_RAW
 *     it fails soft and the header signal stands alone.
 *
 * Results are memoized in a small fixed cache keyed by target IP.
 *
 * Research purposes only.
 */
#ifndef NOTNET_ARCH_DETECT_H
#define NOTNET_ARCH_DETECT_H

#include <stddef.h>
#include <stdint.h>

/* Architecture labels reported by arch_detect(). Kept as plain strings
 * so they render directly into C2 responses and heartbeat telemetry. */
#define ARCH_MIPS     "mips"
#define ARCH_ARM9     "arm9"
#define ARCH_X86      "x86"
#define ARCH_UNKNOWN  "unknown"

/* Fingerprint `ip` (HTTP probe against `port`, TTL heuristic fallback)
 * and return the architecture label. Result is cached per IP; repeat
 * lookups cost one table scan. out (if non-NULL) receives
 * "<arch> ttl=<n|-> src=<header|ttl|cache|none>" bounded to out_len.
 * Always returns a non-NULL label (ARCH_UNKNOWN when nothing matched). */
const char *arch_detect(const char *ip, uint16_t port,
                        char *out, size_t out_len);

/* Drop all cached fingerprints (used before a fresh scan cycle). */
void arch_cache_reset(void);

#endif /* NOTNET_ARCH_DETECT_H */
