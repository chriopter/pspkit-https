/* Emulator-only real-library download audit. No entropy waiver in production.
   ms0:/PSP/GAME/corpus/jobs.tsv: numeric id, size, SHA-256, HTTPS URL,
   separated by tabs. Writes id.zip, results.jsonl, library.log and DONE.
   Every instance needs its own memory stick. This tests transfers, not
   installation layouts; no downloaded program is executed. */
#include <pspkernel.h>
#include <pspdebug.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include "pspkit-https/https.h"
#include "pspkit-https/entropy.h"

PSP_MODULE_INFO("HTTPS corpus audit", 0, 1, 0);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER);
PSP_HEAP_SIZE_KB(12 * 1024);
#define BASE "ms0:/PSP/GAME/corpus/"
static SceUID log_lock;
static unsigned current_id;
static unsigned long long started, last_progress;
static unsigned long long now_ms(void) { return sceKernelGetSystemTimeWide() / 1000; }
static void json_string(FILE *f, const char *s) {
    fputc('"', f);
    for (; *s; ++s) {
        unsigned char c = (unsigned char)*s;
        if (c == '"' || c == '\\') {
            fputc('\\', f);
            fputc(c, f);
        } else if (c < 32)
            fprintf(f, "\\u%04x", c);
        else
            fputc(c, f);
    }
    fputc('"', f);
}
static void log_line(const char *s) {
    sceKernelWaitSema(log_lock, 1, NULL);
    FILE *f = fopen(BASE "library.log", "a");
    if (f) {
        fprintf(f, "%06u %llu %s\n", current_id, now_ms(), s);
        fclose(f);
    }
    sceKernelSignalSema(log_lock, 1);
}
static void progress(void *ctx, size_t done, size_t total) {
    (void)ctx;
    unsigned long long now = now_ms();
    if (now - last_progress < 5000) return;
    last_progress = now;
    FILE *f = fopen(BASE "results.jsonl", "a");
    if (!f) {
        https_abort();
        return;
    }
    fprintf(f,
            "{\"event\":\"progress\",\"id\":%u,\"size\":%lu,\"total\":%lu,\"elapsed_ms\":%llu,"
            "\"phase\":",
            current_id, (unsigned long)done, (unsigned long)total, now - started);
    json_string(f, https_get_phase());
    fputs("}\n", f);
    fclose(f);
}
struct body {
    FILE *f;
    wc_Sha256 sha;
    size_t accepted, limit;
    int error;
};
static int sink(void *ctx, const void *data, size_t len) {
    struct body *b = ctx;
    if (len > b->limit - b->accepted) {
        b->error = -1001;
        return -1;
    }
    if (fwrite(data, 1, len, b->f) != len) {
        b->error = errno ? errno : -1002;
        return -1;
    }
    if (wc_Sha256Update(&b->sha, data, (word32)len)) {
        b->error = -1003;
        return -1;
    }
    b->accepted += len;
    return 0;
}
static void hex(char *out, const unsigned char *in) {
    static const char digits[] = "0123456789abcdef";
    unsigned i;
    for (i = 0; i < 32; i++) {
        out[i * 2] = digits[in[i] >> 4];
        out[i * 2 + 1] = digits[in[i] & 15];
    }
    out[64] = 0;
}
int main(void) {
    pspDebugScreenInit();
    log_lock = sceKernelCreateSema("corpus log", 0, 1, 1, NULL);
    if (log_lock < 0) goto stopped;
    https_set_log(log_line);
    entropy_init();
    entropy_allow_unswept();
    https_set_user_agent("PSPDX corpus-test/1");
    https_set_accept_gzip(0);
    int connected = https_net_connect() == 0;
    FILE *jobs = fopen(BASE "jobs.tsv", "r");
    if (!jobs) {
        log_line("cannot open jobs.tsv");
        goto stopped;
    }
    static char line[8192];
    while (fgets(line, sizeof(line), jobs)) {
        char *a = strchr(line, '\t');
        if (!a) continue;
        *a++ = 0;
        char *b = strchr(a, '\t');
        if (!b) continue;
        *b++ = 0;
        char *url = strchr(b, '\t');
        if (!url) continue;
        *url++ = 0;
        url[strcspn(url, "\r\n")] = 0;
        current_id = (unsigned)strtoul(line, NULL, 10);
        unsigned long expected = strtoul(a, NULL, 10);
        started = last_progress = now_ms();
        FILE *f = fopen(BASE "results.jsonl", "a");
        if (!f) break;
        fprintf(f, "{\"event\":\"start\",\"id\":%u,\"expected_size\":%lu,\"url\":", current_id,
                expected);
        json_string(f, url);
        fputs("}\n", f);
        fclose(f);
        char path[128];
        snprintf(path, sizeof(path), BASE "%06u.zip", current_id);
        struct body body;
        memset(&body, 0, sizeof(body));
        body.limit = (size_t)expected + 1024 * 1024;
        body.f = fopen(path, "wb");
        int hash_ready = wc_InitSha256(&body.sha) == 0;
        if (!body.f) body.error = errno ? errno : -1004;
        if (!hash_ready) body.error = -1005;
        /* Archive storage can sustain only tens of KiB/s. Keep the stall
           detector, but allow a live slow transfer time to finish. */
        unsigned timeout = expected / 25000 + 120;
        if (timeout < 900) timeout = 900;
        https_set_time_limit(timeout);
        struct https_result r;
        memset(&r, 0, sizeof(r));
        int rc = HTTPS_FAILED;
        if (!connected) connected = https_net_connect() == 0;
        if (connected && body.f && hash_ready) rc = https_get(url, sink, &body, progress, NULL, &r);
        unsigned char digest[32];
        char digest_hex[65] = "";
        if (hash_ready) {
            if (!wc_Sha256Final(&body.sha, digest))
                hex(digest_hex, digest);
            else
                body.error = -1006;
            wc_Sha256Free(&body.sha);
        }
        if (body.f && fclose(body.f)) body.error = errno ? errno : -1007;
        char doubt_host[128];
        int doubt = https_doubt_take(doubt_host, sizeof(doubt_host));
        f = fopen(BASE "results.jsonl", "a");
        if (!f) break;
        fprintf(f,
                "{\"event\":\"result\",\"id\":%u,\"rc\":%d,\"status\":%ld,\"size\":%lu,\"expected_"
                "size\":%lu,\"sha256\":",
                current_id, rc, r.status, (unsigned long)body.accepted, expected);
        json_string(f, digest_hex);
        fputs(",\"expected_sha256\":", f);
        json_string(f, b);
        fprintf(f, ",\"elapsed_ms\":%llu,\"redirects\":%d,\"host\":", now_ms() - started,
                r.redirects);
        json_string(f, r.host);
        fprintf(f, ",\"handshake_ms\":%u,\"encoding\":", r.handshake_ms);
        json_string(f, r.content_encoding);
        fprintf(f, ",\"sink_error\":%d,\"doubt\":%d,\"doubt_host\":", body.error, doubt);
        json_string(f, doubt_host);
        fprintf(f, ",\"ok\":%s}\n",
                rc == HTTPS_COMPLETE && r.status == 200 && body.accepted == expected &&
                        !strcmp(digest_hex, b) && !body.error
                    ? "true"
                    : "false");
        fclose(f);
        pspDebugScreenPrintf("%06u rc=%d HTTP=%ld %lu bytes\n", current_id, rc, r.status,
                             (unsigned long)body.accepted);
    }
    fclose(jobs);
    https_net_disconnect();
    FILE *done = fopen(BASE "DONE", "w");
    if (done) {
        fputs("DONE\n", done);
        fclose(done);
    }
stopped:
    for (;;)
        sceKernelDelayThread(1000000);
    return 0;
}
