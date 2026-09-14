/* Throughput test against a server on the host: the same five megabytes
   over a bare socket, then over TLS 1.3 with each cipher suite preferred.
   Loopback is faster than any radio, so what this measures is the cost of
   the stack and the cipher on the CPU, with nothing else in the way.

   Runs in PPSSPP through tests/nettest/run, which also starts the servers
   and reads the numbers back out of the log. */

#include <pspkernel.h>
#include <pspiofilemgr.h>
#include <pspnet_inet.h>
#include <psprtc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

#include "pspkit-https/entropy.h"
#include "pspkit-https/https.h"

PSP_MODULE_INFO("nettest", 0, 1, 0);
PSP_MAIN_THREAD_ATTR(THREAD_ATTR_USER);
PSP_HEAP_SIZE_KB(8 * 1024);

#define HOST "127.0.0.1"
#define RAW_PORT 8080
#define TLS_URL "https://127.0.0.1:8443/5MB.bin"
#define LOG_FILE "ms0:/PSP/GAME/nettest/nettest.log"

static unsigned char g_buf[256 * 1024];
static SceUID g_log = -1;
static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;

/* A line at a time, straight to the file: run watches it. */
static void log_text(const char *text) {
    if (g_log < 0) return;
    pthread_mutex_lock(&g_log_lock);
    sceIoWrite(g_log, text, strlen(text));
    sceIoWrite(g_log, "\n", 1);
    pthread_mutex_unlock(&g_log_lock);
}

static void logline(const char *fmt, ...) {
    char line[160];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    log_text(line);
}

static u64 tick(void) {
    u64 t = 0;
    sceRtcGetCurrentTick(&t);
    return t;
}

static unsigned now_ms(void) { return (unsigned)(tick() / 1000); }
static unsigned now_us(void) { return (unsigned)tick(); }
static int expired(unsigned start, unsigned budget_ms) { return (now_ms() - start) > budget_ms; }

static unsigned kbps(unsigned bytes, unsigned us) {
    return us ? (unsigned)((unsigned long long)bytes * 1000 / us) : 0;
}

static void raw(void) {
    int sock = sceNetInetSocket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { logline("raw: no socket"); return; }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(RAW_PORT);
    sa.sin_addr.s_addr = inet_addr(HOST);
    unsigned start = now_ms();
    if (sceNetInetConnect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = sceNetInetGetErrno();
        if (e != EINPROGRESS && e != EALREADY && e != EWOULDBLOCK) { logline("raw: connect errno %d", e); sceNetInetClose(sock); return; }
    }
    const char *req = "GET /5MB.bin HTTP/1.1\r\nHost: " HOST "\r\nUser-Agent: nettest\r\nConnection: close\r\n\r\n";
    size_t sent = 0, len = strlen(req);
    while (sent < len) {
        int n = (int)sceNetInetSend(sock, req + sent, len - sent, 0);
        if (n > 0) { sent += (size_t)n; continue; }
        int e = sceNetInetGetErrno();
        if (e != EAGAIN && e != EWOULDBLOCK && e != EINTR && e != ENOTCONN && e != EINPROGRESS) { logline("raw: send errno %d", e); sceNetInetClose(sock); return; }
        if (expired(start, 10000)) { logline("raw: connect timed out"); sceNetInetClose(sock); return; }
        sceKernelDelayThread(5 * 1000);
    }
    unsigned t0 = now_us(), idle = now_ms();
    unsigned total = 0;
    for (;;) {
        int n = (int)sceNetInetRecv(sock, g_buf, sizeof(g_buf), 0);
        if (n > 0) { total += (unsigned)n; idle = now_ms(); continue; }
        if (n == 0) break;
        int e = sceNetInetGetErrno();
        if (e != EAGAIN && e != EWOULDBLOCK && e != EINTR) { logline("raw: recv errno %d", e); break; }
        if (expired(idle, 20000)) { logline("raw: stalled"); break; }
        sceKernelDelayThread(500);
    }
    unsigned us = now_us() - t0;
    sceNetInetClose(sock);
    logline("raw http: %u KB in %u ms: %u KB/s", total / 1024, us / 1000, kbps(total, us));
}

static unsigned g_got;
static int count(void *ctx, const void *data, size_t len) {
    (void)ctx; (void)data;
    g_got += (unsigned)len;
    return 0;
}

static void tls(const char *suites, const char *label) {
    https_set_cipher_suites(suites);
    struct https_result r;
    g_got = 0;
    unsigned t0 = now_us();
    if (https_get(TLS_URL, count, 0, 0, 0, &r) != 0) { logline("%s: failed", label); return; }
    unsigned us = now_us() - t0;
    logline("%s: %u KB in %u ms (handshake %u ms): %u KB/s", label, g_got / 1024,
            us / 1000, r.handshake_ms, kbps(g_got, us));
}

int main(void) {
    g_log = sceIoOpen(LOG_FILE, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
    https_set_log(log_text);
    /* wolfSSL draws its randomness from the pool, which refuses until it
       has been full once; jitter is enough for a test whose keys protect
       nothing, and the test says so. */
    entropy_init();
    entropy_allow_unswept();
    if (https_net_connect() < 0) {
        logline("no network");
    } else {
        for (int i = 0; i < 2; i++) {
            raw();
            tls("TLS13-AES128-GCM-SHA256", "tls aes-128-gcm");
            tls("TLS13-CHACHA20-POLY1305-SHA256", "tls chacha20-poly1305");
        }
    }
    https_net_disconnect();
    logline("done");
    sceIoClose(g_log);
    sceKernelExitGame();
    return 0;
}
