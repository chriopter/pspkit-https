/* The HTTP half of src/https.c on the host. wolfSSL is a pipe here: what
   the library writes is the request, and what a test puts in answers[] is
   read back as the server's response, one answer per request. Connecting,
   the handshake and the roots all succeed without doing anything. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pspkit-https/https.h"
#include "psp.h"
#include "wolfssl/ssl.h"

static int failures;
#define CHECK(c)                                                                 \
    do {                                                                         \
        if (!(c)) {                                                              \
            fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #c);              \
            failures++;                                                          \
        }                                                                        \
    } while (0)

/* ---------------------------------------------------------- the server */

static char requests[8192];          /* every request of one get, in order */
static const char *answers[4];
static size_t answer_at;
static int answer;
static char body[256];
static size_t body_len;
static unsigned chunk_seed;          /* nonzero: reads end at random points */
static unsigned trickle_ms;          /* nonzero: a byte a read, this far apart */
static int trickle_waiting;
static SceInt64 clock_us = 1000000;  /* the PSP's clock; each look moves it 1 ms */

int wolfSSL_write(WOLFSSL *ssl, const void *data, int size) {
    size_t have = strlen(requests);
    if (have + (size_t)size < sizeof(requests)) {
        memcpy(requests + have, data, (size_t)size);
        requests[have + (size_t)size] = '\0';
    }
    return size;
}

/* Whole answer in one read, the head and its body together, as a server
   on a fast link delivers them. Nothing left reads as a clean close. */
int wolfSSL_read(WOLFSSL *ssl, void *data, int size) {
    const char *a = answer < 4 ? answers[answer] : NULL;
    if (!a) return 0;
    /* A slow server: nothing yet while the time passes, then one byte. */
    if (trickle_ms && (trickle_waiting = !trickle_waiting)) {
        clock_us += trickle_ms * 1000;
        return -1;
    }
    size_t n = strlen(a) - answer_at;
    if (n > (size_t)size) n = (size_t)size;
    if (trickle_ms) n = 1;
    if (chunk_seed) {
        chunk_seed = chunk_seed * 1103515245u + 12345u;
        size_t cut = 1 + (chunk_seed >> 16) % 61;
        if (n > cut) n = cut;
    }
    memcpy(data, a + answer_at, n);
    answer_at += n;
    if (!a[answer_at]) { answer++; answer_at = 0; }
    return (int)n;
}

int wolfSSL_get_error(WOLFSSL *ssl, int ret) {
    return ret < 0 ? WOLFSSL_ERROR_WANT_READ : WOLFSSL_ERROR_ZERO_RETURN;
}

static int sink(void *ctx, const void *data, size_t len) {
    if (body_len + len > sizeof(body)) return 1;
    memcpy(body + body_len, data, len);
    body_len += len;
    return 0;
}

static enum https_outcome get(const char *url, struct https_result *r, const char *first,
                              const char *second) {
    requests[0] = '\0';
    answers[0] = first;
    answers[1] = second;
    answers[2] = NULL;
    answer = 0;
    answer_at = 0;
    body_len = 0;
    trickle_waiting = 0;
    return https_get(url, sink, NULL, NULL, NULL, r);
}

static int count(const char *text, const char *needle) {
    int n = 0;
    for (const char *p = strstr(text, needle); p; p = strstr(p + 1, needle)) n++;
    return n;
}

static void print_log(const char *line) {
    if (getenv("VERBOSE")) fprintf(stderr, "  %s\n", line);
}

int main(void) {
    struct https_result r;
    https_set_log(print_log);
    CHECK(https_net_connect() == 0);

    /* Not asked, nothing asked for; an encoding the server sends anyway is
       named, and the body arrives as it was sent. */
    CHECK(get("https://example.org/a", &r,
              "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8b\x08\x01",
              NULL) == HTTPS_COMPLETE);
    CHECK(!strstr(requests, "Accept-Encoding"));
    CHECK(!strcmp(r.content_encoding, "gzip"));
    CHECK(body_len == 4 && !memcmp(body, "\x1f\x8b\x08\x01", 4));

    /* Asked: once per request. A plain answer names nothing. */
    https_set_accept_gzip(1);
    CHECK(get("https://example.org/b", &r, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}", NULL) ==
          HTTPS_COMPLETE);
    CHECK(count(requests, "\r\nAccept-Encoding: gzip\r\n") == 1);
    CHECK(r.content_encoding[0] == '\0');
    CHECK(body_len == 2);

    /* Through a redirect: the header goes to both hosts, and what the result
       names is the final response's, not the redirect's. */
    CHECK(get("https://example.org/c", &r,
              "HTTP/1.1 302 Found\r\nContent-Encoding: gzip\r\nLocation: https://example.com/d\r\n"
              "Content-Length: 0\r\n\r\n",
              "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n[]") == HTTPS_COMPLETE);
    CHECK(r.redirects == 1);
    CHECK(count(requests, "\r\nAccept-Encoding: gzip\r\n") == 2);
    CHECK(r.content_encoding[0] == '\0');

    /* Blanks before the line's end are not the value; a long one is cut. */
    CHECK(get("https://example.org/e", &r,
              "HTTP/1.1 200 OK\r\ncontent-encoding:  GZIP \t\r\nContent-Length: 0\r\n\r\n", NULL) ==
          HTTPS_COMPLETE);
    CHECK(!strcmp(r.content_encoding, "GZIP"));
    CHECK(get("https://example.org/f", &r,
              "HTTP/1.1 200 OK\r\nContent-Encoding: x-something-long, gzip\r\nContent-Length: 0\r\n\r\n",
              NULL) == HTTPS_COMPLETE);
    CHECK(!strcmp(r.content_encoding, "x-something-lon"));

    /* Off again, and a failed request leaves the field empty. */
    https_set_accept_gzip(0);
    CHECK(get("https://example.org/g", &r, "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", NULL) ==
          HTTPS_COMPLETE);
    CHECK(!strstr(requests, "Accept-Encoding"));
    strcpy(r.content_encoding, "stale");
    CHECK(get("http://example.org/h", &r, NULL, NULL) == HTTPS_FAILED);
    CHECK(r.content_encoding[0] == '\0');

    /* A bare CR or LF in the head is refused, not copied into a value. */
    CHECK(get("https://example.org/i", &r,
              "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r'\nX: y\r\nContent-Length: 0\r\n\r\n",
              NULL) == HTTPS_FAILED);
    CHECK(r.content_encoding[0] == '\0');
    CHECK(get("https://example.org/j", &r, "HTTP/1.1 200 OK\nContent-Length: 1\n\r\n\r\nx", NULL) ==
          HTTPS_FAILED);
    /* A 204 announces no body, whatever length it names. */
    CHECK(get("https://example.org/k", &r, "HTTP/1.1 204 No Content\r\nContent-Length: 10\r\n\r\n",
              NULL) == HTTPS_COMPLETE);
    CHECK(r.content_length == 0 && r.body_len == 0);
    /* Blanks after a Location are not part of it. */
    CHECK(get("https://example.org/l", &r,
              "HTTP/1.1 302 Found\r\nLocation: https://example.com/m \t\r\nContent-Length: 0\r\n\r\n",
              "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok") == HTTPS_COMPLETE);
    CHECK(r.redirects == 1 && !strcmp(r.host, "example.com"));

    /* A head that trickles in has 30 s in all, not 30 s a byte: at a byte a
       second this one would take more than a minute. */
    static const char slow[] = "HTTP/1.1 200 OK\r\nX-Pad: a head that takes its time\r\n"
                               "Content-Length: 80\r\n\r\n"
                               "eighty bytes of body, sent at the pace of the head before it, "
                               "and not any faster";
    CHECK(strlen(strstr(slow, "\r\n\r\n") + 4) == 80);
    https_close_idle();
    trickle_ms = 1000;
    SceInt64 began = clock_us;
    CHECK(get("https://example.org/s", &r, slow, NULL) == HTTPS_FAILED);
    CHECK(r.status == 0 && r.body_len == 0);
    CHECK(clock_us - began < 32 * 1000000);
    /* At half a second a byte the head takes 35 s and fails as well, but at
       a quarter it takes 18 s; the body then goes on for 20 s more, with
       no gap of 30 s in it, and is not cut off. */
    trickle_ms = 500;
    CHECK(get("https://example.org/t", &r, slow, NULL) == HTTPS_FAILED);
    trickle_ms = 250;
    began = clock_us;
    CHECK(get("https://example.org/u", &r, slow, NULL) == HTTPS_COMPLETE);
    CHECK(r.status == 200 && r.body_len == 80 && body_len == 80);
    CHECK(clock_us - began > 30 * 1000000);
    /* A time limit bounds the whole get: the body is cut once it is up. */
    https_close_idle();
    https_set_time_limit(25);
    began = clock_us;
    CHECK(get("https://example.org/v", &r, slow, NULL) == HTTPS_TRUNCATED);
    CHECK(r.status == 200 && r.truncated && r.body_len > 0 && r.body_len < 80);
    CHECK(clock_us - began < 26 * 1000000);
    /* Run out before the body, and the get fails. */
    https_set_time_limit(5);
    CHECK(get("https://example.org/w", &r, slow, NULL) == HTTPS_FAILED);
    CHECK(r.status == 0);
    trickle_ms = 0;
    https_set_time_limit(0);

    /* The same answers cut at random points read the same as whole. */
    static const char *const script[][2] = {
        { "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nContent-Encoding: gzip\r\n\r\n\x1f\x8b\x08\x01", NULL },
        { "HTTP/1.1 302 Found\r\nLocation: /next?x=1\r\nContent-Length: 3\r\n\r\nabc",
          "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nhello world" },
        { "HTTP/1.0 200 OK\r\nContent-Encoding:  x-something-long, gzip\r\n\r\nuntil the close", NULL },
        { "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhelloEXTRA", NULL },
        { "HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nshort", NULL },
        { "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", NULL },
        { "HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx", NULL },
    };
    for (unsigned c = 0; c < sizeof(script) / sizeof(*script); c++) {
        struct https_result whole, cut;
        char whole_body[256];
        chunk_seed = 0;
        enum https_outcome want = get("https://example.org/r", &whole, script[c][0], script[c][1]);
        size_t whole_len = body_len;
        memcpy(whole_body, body, body_len);
        for (unsigned seed = 1; seed <= 3000; seed++) {
            https_close_idle();
            chunk_seed = seed;
            enum https_outcome got = get("https://example.org/r", &cut, script[c][0], script[c][1]);
            if (got != want || cut.status != whole.status || cut.body_len != whole.body_len ||
                cut.content_length != whole.content_length || cut.redirects != whole.redirects ||
                strcmp(cut.content_encoding, whole.content_encoding) || body_len != whole_len ||
                memcmp(body, whole_body, body_len)) {
                fprintf(stderr, "script %u differs when cut with seed %u\n", c, seed);
                failures++;
                break;
            }
        }
        chunk_seed = 0;
    }

    https_net_disconnect();
    printf("request: %s\n", failures ? "FAILED" : "ok");
    return failures != 0;
}

/* ---------------------------------------------------- the rest, inert */

static struct { int unused; } dummy;
int sceKernelDelayThread(unsigned usec) { return 0; }
SceInt64 sceKernelGetSystemTimeWide(void) { return clock_us += 1000; }
SceUID sceKernelCreateThread(const char *name, int (*entry)(SceSize, void *), int priority,
                             int stack, unsigned attr, void *option) {
    return -1;                    /* no roots thread: they load on first use */
}
int sceKernelStartThread(SceUID thread, SceSize args, void *argp) { return -1; }
int sceKernelDeleteThread(SceUID thread) { return 0; }
int sceKernelWaitThreadEnd(SceUID thread, unsigned *timeout) { return 0; }
int sceUtilityLoadNetModule(int module) { return 0; }
int sceUtilityUnloadNetModule(int module) { return 0; }
int sceNetInit(int pool, int a, int b, int c, int d) { return 0; }
int sceNetTerm(void) { return 0; }
int sceNetInetInit(void) { return 0; }
int sceNetInetTerm(void) { return 0; }
int sceNetInetSocket(int domain, int type, int protocol) { return 3; }
int sceNetInetConnect(int s, const struct sockaddr *addr, socklen_t len) { return 0; }
size_t sceNetInetRecv(int s, void *buf, size_t len, int flags) { return (size_t)-1; }
size_t sceNetInetSend(int s, const void *buf, size_t len, int flags) { return (size_t)-1; }
int sceNetInetClose(int s) { return 0; }
int sceNetInetGetErrno(void) { return 0; }
int sceNetResolverInit(void) { return 0; }
int sceNetResolverTerm(void) { return 0; }
int sceNetResolverCreate(int *rid, void *buf, SceSize len) { *rid = 1; return 0; }
int sceNetResolverDelete(int rid) { return 0; }
int sceNetResolverStartNtoA(int rid, const char *host, struct in_addr *addr, unsigned timeout,
                            int retry) {
    addr->s_addr = htonl(0x7f000001);
    return 0;
}
int sceNetApctlInit(int stack, int priority) { return 0; }
int sceNetApctlTerm(void) { return 0; }
int sceNetApctlConnect(int index) { return 0; }
int sceNetApctlDisconnect(void) { return 0; }
int sceNetApctlGetState(int *state) { *state = 4; return 0; }
int scePowerGetBatteryVolt(void) { return 0; }
int scePowerGetBatteryElec(void) { return 0; }
int scePowerGetBatteryTemp(void) { return 0; }
int scePowerGetBatteryLifeTime(void) { return 0; }
void entropy_stir(const void *data, size_t len) {}

int wolfSSL_Init(void) { return WOLFSSL_SUCCESS; }
int wolfSSL_Cleanup(void) { return WOLFSSL_SUCCESS; }
const char *wolfSSL_lib_version(void) { return "stub"; }
WOLFSSL_METHOD *wolfTLSv1_3_client_method(void) { return (WOLFSSL_METHOD *)&dummy; }
WOLFSSL_CTX *wolfSSL_CTX_new(WOLFSSL_METHOD *method) { return (WOLFSSL_CTX *)&dummy; }
void wolfSSL_CTX_free(WOLFSSL_CTX *ctx) {}
int wolfSSL_CTX_load_verify_buffer_ex(WOLFSSL_CTX *ctx, const unsigned char *in, long len,
                                      int format, int user_chain, unsigned flags) {
    return WOLFSSL_SUCCESS;
}
void wolfSSL_CTX_set_verify(WOLFSSL_CTX *ctx, int mode, VerifyCallback verify) {}
void wolfSSL_CTX_SetIORecv(WOLFSSL_CTX *ctx, CallbackIORecv recv) {}
void wolfSSL_CTX_SetIOSend(WOLFSSL_CTX *ctx, CallbackIOSend send) {}
int wolfSSL_CTX_set_groups(WOLFSSL_CTX *ctx, int *groups, int count) { return WOLFSSL_SUCCESS; }
WOLFSSL *wolfSSL_new(WOLFSSL_CTX *ctx) { return (WOLFSSL *)&dummy; }
/* A session that ends takes what it had not read with it: the next request
   is on a connection of its own and starts at the next answer. */
void wolfSSL_free(WOLFSSL *ssl) {
    if (answer_at) { answer++; answer_at = 0; }
}
int wolfSSL_shutdown(WOLFSSL *ssl) { return WOLFSSL_SUCCESS; }
int wolfSSL_set_cipher_list(WOLFSSL *ssl, const char *list) { return WOLFSSL_SUCCESS; }
void wolfSSL_SetIOReadCtx(WOLFSSL *ssl, void *ctx) {}
void wolfSSL_SetIOWriteCtx(WOLFSSL *ssl, void *ctx) {}
int wolfSSL_UseSNI(WOLFSSL *ssl, unsigned char type, const void *data, unsigned short size) {
    return WOLFSSL_SUCCESS;
}
int wolfSSL_check_domain_name(WOLFSSL *ssl, const char *name) { return WOLFSSL_SUCCESS; }
int wolfSSL_check_ip_address(WOLFSSL *ssl, const char *address) { return WOLFSSL_SUCCESS; }
int wolfSSL_UseKeyShare(WOLFSSL *ssl, unsigned short group) { return WOLFSSL_SUCCESS; }
int wolfSSL_connect(WOLFSSL *ssl) { return WOLFSSL_SUCCESS; }
char *wolfSSL_ERR_error_string(unsigned long error, char *out) { return strcpy(out, "stub"); }
const char *wolfSSL_get_curve_name(WOLFSSL *ssl) { return "X25519"; }
const char *wolfSSL_get_cipher(WOLFSSL *ssl) { return "stub"; }
WOLFSSL_X509 *wolfSSL_X509_STORE_CTX_get_current_cert(WOLFSSL_X509_STORE_CTX *store) { return NULL; }
WOLFSSL_ASN1_TIME *wolfSSL_X509_get_notAfter(WOLFSSL_X509 *cert) { return NULL; }
int wolfSSL_ASN1_TIME_to_tm(const WOLFSSL_ASN1_TIME *t, struct tm *tm) { return 0; }
char *wolfSSL_X509_get_subjectCN(WOLFSSL_X509 *cert) { return NULL; }
WOLFSSL_X509_NAME *wolfSSL_X509_get_issuer_name(WOLFSSL_X509 *cert) { return NULL; }
char *wolfSSL_X509_NAME_oneline(WOLFSSL_X509_NAME *name, char *out, int size) { return out; }
