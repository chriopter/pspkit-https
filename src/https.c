/*
 * HTTPS on the PSP: sceNetInet sockets under wolfSSL, and just enough HTTP/1.1
 * to stream one body of any size into a sink. Short-lived connections are
 * reused per host when the response has an unambiguous Content-Length.
 *
 * The four traps in this file each cost an afternoon and none is documented:
 * the BSD socket wrappers return garbage, sceNetInetSelect hangs, SO_NONBLOCK
 * and SO_ERROR do not exist in the headers, and retrying EINTR inside an IO
 * callback spins forever inside the handshake.
 */

#include <pspkernel.h>
#include <psputility.h>
#include <psputility_netmodules.h>
#include <pspnet.h>
#include <pspnet_apctl.h>
#include <pspnet_inet.h>
#include <pspnet_resolver.h>
#include <psppower.h>
#include <psprtc.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wolfssl/options.h>
#include <wolfssl/ssl.h>

#include "ca_bundle.h"
#include "pspkit-https/entropy.h"
#include "pspkit-https/https.h"

/* ------------------------------------------------------------ the host */

static pthread_mutex_t g_log_lock = PTHREAD_MUTEX_INITIALIZER;
static void (*g_log)(const char *text);
void https_set_log(void (*line)(const char *text)) {
    pthread_mutex_lock(&g_log_lock);
    g_log = line;
    pthread_mutex_unlock(&g_log_lock);
}

static void logline(const char *fmt, ...) {
    pthread_mutex_lock(&g_log_lock);
    void (*logger)(const char *) = g_log;
    pthread_mutex_unlock(&g_log_lock);
    if (!logger) return;
    char line[100];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    logger(line);
}

#define DEFAULT_AGENT "pspkit-https"
static const char *g_agent = DEFAULT_AGENT;
void https_set_user_agent(const char *agent) { g_agent = agent ? agent : DEFAULT_AGENT; }

/* Off unless asked: a sink that does not expect gzip would store it as the
   file, and a ZIP gains nothing from being compressed again. */
static int g_accept_gzip;
void https_set_accept_gzip(int on) { g_accept_gzip = on != 0; }

static unsigned now_ms(void) {
    return (unsigned)(sceKernelGetSystemTimeWide() / 1000);
}

static int expired(unsigned start, unsigned budget_ms) {
    return (now_ms() - start) > budget_ms;
}

/* A bound on a whole get, for a caller that would rather give up than wait
   out a slow server; zero, the default, leaves only the per-step timeouts. */
static unsigned g_time_limit_s;
static unsigned g_get_start;
void https_set_time_limit(unsigned seconds) { g_time_limit_s = seconds; }
static int over_time(void) {
    if (!g_time_limit_s || (now_ms() - g_get_start) / 1000u < g_time_limit_s) return 0;
    logline("https: time limit of %u s reached", g_time_limit_s);
    return 1;
}

#define PORT 443
#define MAX_REDIRECTS 5
#define HEAD_MAX (8 * 1024)

#define CONNECT_TIMEOUT_MS   10000
#define HANDSHAKE_TIMEOUT_MS 20000
/* For the body per read, not per body: a 42 MB download over 802.11b takes
   minutes and must not be cut off for being slow, only for being stuck. The
   head is a few hundred bytes and has it in all. */
#define STALL_TIMEOUT_MS     30000

/* ChaCha20-Poly1305 first: on a core with no AES instructions it moves
   bytes at two and a half times the rate of AES-GCM through this stack,
   which is the difference between a download that costs a third of the
   CPU and one that costs an eighth. AES stays for a server without it. */
#define DEFAULT_SUITES "TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES128-GCM-SHA256"

static const char *g_suites = DEFAULT_SUITES;
static void close_idle(void);
static int g_wolf_ready;

/* The state more than one thread reaches: the idle connections, the context
   and the thread that fills it, the hosts trusted on the person's word. An
   application's network thread makes the requests while its main thread may
   close the idle connections or answer a certificate question; the lock is
   never held across the network. Initialised statically, so there is no
   first call to race. */
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
static WOLFSSL_CTX *roots_ready(void);
static void roots_start(void);
static void roots_release(void);

/* What the stack is doing right now, for a status line: a literal, set by
   the thread doing the work and read by whoever draws. */
static const char *g_phase = "";
static int g_abort;
static void phase(const char *p) {
    pthread_mutex_lock(&g_lock);
    g_phase = p;
    pthread_mutex_unlock(&g_lock);
}
static void abort_clear(void) {
    pthread_mutex_lock(&g_lock);
    g_abort = 0;
    pthread_mutex_unlock(&g_lock);
}
static int aborted(void) {
    pthread_mutex_lock(&g_lock);
    int value = g_abort;
    pthread_mutex_unlock(&g_lock);
    return value;
}
void https_abort(void) {
    pthread_mutex_lock(&g_lock);
    g_abort = 1;
    pthread_mutex_unlock(&g_lock);
}
const char *https_get_phase(void) {
    pthread_mutex_lock(&g_lock);
    const char *value = g_phase;
    pthread_mutex_unlock(&g_lock);
    return value;
}

void https_set_cipher_suites(const char *suites) {
    close_idle();
    g_suites = suites ? suites : DEFAULT_SUITES;
}

/* What the last handshake settled on. Written by whichever thread made it and
   read by the one that draws. Both copy the whole snapshot under the lock
   so strings and timing always belong to the same connection. */
static struct https_info g_last;

/* The doubt the verify callback left for the main thread, and the host it
   was about; the callback does not know the host, so the request writes
   it down before the handshake. taken last, so a reader that sees the
   kind sees the host it goes with. */
static char g_verify_host[128];
static char g_doubt_host[128];
static enum https_doubt g_doubt;

/* The hosts the person has said to connect to anyway. An answer about one
   host's certificate is not a blank cheque for every host the run reaches
   afterwards, so it is kept per host: the one https_doubt_take last handed
   out, which is the one the person was asked about. */
#define TRUSTED_MAX 8
static char g_asked_host[128];
static char g_trusted[TRUSTED_MAX][128];
static unsigned g_trusted_next;

static int trusted(const char *host) {
    int found = 0;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < TRUSTED_MAX && !found; i++)
        found = g_trusted[i][0] && !strcmp(g_trusted[i], host);
    pthread_mutex_unlock(&g_lock);
    return found;
}

enum https_doubt https_doubt_take(char *host, size_t size) {
    pthread_mutex_lock(&g_lock);
    enum https_doubt d = g_doubt;
    if (host && size) host[0] = '\0';
    if (d != HTTPS_DOUBT_NONE) {
        if (host && size) snprintf(host, size, "%s", g_doubt_host);
        snprintf(g_asked_host, sizeof(g_asked_host), "%s", g_doubt_host);
        g_doubt = HTTPS_DOUBT_NONE;
    }
    pthread_mutex_unlock(&g_lock);
    return d;
}

void https_doubt_accept(void) {
    pthread_mutex_lock(&g_lock);
    int known = 0;
    for (int i = 0; i < TRUSTED_MAX && !known; i++)
        known = g_trusted[i][0] && !strcmp(g_trusted[i], g_asked_host);
    if (g_asked_host[0] && !known)
        snprintf(g_trusted[g_trusted_next++ % TRUSTED_MAX], sizeof(g_trusted[0]), "%s", g_asked_host);
    g_asked_host[0] = '\0';
    pthread_mutex_unlock(&g_lock);
}
void https_get_last_info(struct https_info *out) {
    pthread_mutex_lock(&g_lock);
    *out = g_last;
    pthread_mutex_unlock(&g_lock);
}

/* ------------------------------------------------------------------- net */

static struct {
    int common_module, inet_module;
    int net, inet, resolver, apctl, connected;
} g_net;

/* The radio and the stack, and nothing of TLS: a failed or repeated
   https_net_connect takes the link down but keeps the roots it has parsed. */
static void link_down(void) {
    if (g_net.connected) { sceNetApctlDisconnect(); g_net.connected = 0; }
    if (g_net.apctl)     { sceNetApctlTerm();       g_net.apctl = 0; }
    if (g_net.resolver)  { sceNetResolverTerm();    g_net.resolver = 0; }
    if (g_net.inet)      { sceNetInetTerm();        g_net.inet = 0; }
    if (g_net.net)       { sceNetTerm();            g_net.net = 0; }
    if (g_net.inet_module) { sceUtilityUnloadNetModule(PSP_NET_MODULE_INET); g_net.inet_module = 0; }
    if (g_net.common_module) { sceUtilityUnloadNetModule(PSP_NET_MODULE_COMMON); g_net.common_module = 0; }
}

void https_net_disconnect(void) {
    close_idle();
    roots_release();
    if (g_wolf_ready) { wolfSSL_Cleanup(); g_wolf_ready = 0; }
    link_down();
    pthread_mutex_lock(&g_lock);
    memset(g_trusted, 0, sizeof(g_trusted));
    g_trusted_next = 0;
    g_doubt = HTTPS_DOUBT_NONE;
    g_asked_host[0] = '\0';
    pthread_mutex_unlock(&g_lock);
    phase("");
}

#ifdef DEBUG_WOLFSSL
/* Development only: wolfSSL's own trace, into the log. It is the only way to
   see which step of a chain check failed. */
static void wolf_log(const int level, const char *const msg) {
    (void)level;
    logline("wolf: %s", msg);
}
#endif

int https_net_connect(void) {
    abort_clear();
#ifdef DEBUG_WOLFSSL
    wolfSSL_SetLoggingCb(wolf_log);
    wolfSSL_Debugging_ON();
#endif
    /* The roots are parsed while the radio looks for the access point. */
    roots_start();

    /* Asked again with the link already up -- a retry after the catalog
       failed, not the wifi -- there is nothing to bring up. */
    if (g_net.connected) {
        int state = 0;
        if (sceNetApctlGetState(&state) >= 0 && state == 4) { phase(""); return 0; }
        close_idle();
        link_down();
    }
    phase("wifi");
    if (sceUtilityLoadNetModule(PSP_NET_MODULE_COMMON) < 0) goto fail;
    g_net.common_module = 1;
    if (sceUtilityLoadNetModule(PSP_NET_MODULE_INET) < 0) goto fail;
    g_net.inet_module = 1;

    if (sceNetInit(128 * 1024, 42, 4 * 1024, 42, 4 * 1024) < 0) goto fail;
    g_net.net = 1;
    if (sceNetInetInit() < 0) goto fail;
    g_net.inet = 1;
    if (sceNetResolverInit() < 0) goto fail;
    g_net.resolver = 1;
    if (sceNetApctlInit(0x1600, 42) < 0) goto fail;
    g_net.apctl = 1;

    /* Connection profile 1, the first one configured on the console. */
    phase("access point");
    if (sceNetApctlConnect(1) < 0) goto fail;
    g_net.connected = 1;

    unsigned start = now_ms();
    for (;;) {
        int state = 0;
        if (sceNetApctlGetState(&state) < 0) goto fail;
        if (state == 4) { phase(""); return 0; }   /* got an IP */
        if (aborted() || expired(start, CONNECT_TIMEOUT_MS)) goto fail;
        sceKernelDelayThread(50 * 1000);
    }

fail:
    link_down();
    phase("");
    return -1;
}

/* The PSP resolver rather than getaddrinfo: newlib's lookup path yields
   "Trying 0.0.0.0" here, so it is not to be trusted. */
static int resolve(const char *host, struct in_addr *out) {
    static char buf[1024];
    int rid = -1;
    if (sceNetResolverCreate(&rid, buf, sizeof(buf)) < 0) return -1;
    int rc = sceNetResolverStartNtoA(rid, host, out, 2 * 1000 * 1000, 5);
    sceNetResolverDelete(rid);
    return rc < 0 ? -2 : 0;
}

/* PSPSDK declares these as returning size_t even though they report failure as
   a negative value, so the cast back to int is deliberate and load-bearing. */
static int psp_recv(int fd, void *buf, int len) {
    return (int)sceNetInetRecv(fd, buf, (size_t)len, 0);
}

static int psp_send(int fd, const void *buf, int len) {
    return (int)sceNetInetSend(fd, buf, (size_t)len, 0);
}

/* sceNetInetSelect hangs on this stack, so waiting is a short sleep. */
static void wait_socket(int ms) {
    sceKernelDelayThread((unsigned)ms * 1000);
}

/* Read once per connection, just before wolfSSL builds this session's RNG, so
   that what goes in reaches this handshake and not merely the next. The
   current draw moves with whatever the CPU and the radio are doing and has a
   noisy converter beneath it; voltage and temperature drift slowly and are
   worth a good deal less. How long the connect took is the network's answer,
   not ours. None of it is counted -- see entropy_stir. */
static void stir_power(unsigned connect_ms) {
    struct {
        int volt, elec, temp, life;
        unsigned connect_ms;
    } p;
    p.volt = scePowerGetBatteryVolt();
    p.elec = scePowerGetBatteryElec();
    p.temp = scePowerGetBatteryTemp();
    p.life = scePowerGetBatteryLifeTime();
    p.connect_ms = connect_ms;
    entropy_stir(&p, sizeof(p));
}

/* ---------------------------------------------------------------- pacing */

/* The clamp is on arriving bytes rather than on the socket, so it shapes
   every fetch alike. */
static unsigned g_paced_kbps;           /* 0: no limit */
static u64 g_pace_since, g_pace_bytes;

void https_set_rate_limit(unsigned kbps) { g_paced_kbps = kbps; }

static void pace_begin(void) {
    g_pace_since = sceKernelGetSystemTimeWide() / 1000;
    g_pace_bytes = 0;
}

static void pace(int n) {
    if (!g_paced_kbps || n <= 0) return;
    g_pace_bytes += (unsigned)n;
    u64 due = g_pace_bytes / g_paced_kbps;
    for (;;) {
        u64 spent = sceKernelGetSystemTimeWide() / 1000 - g_pace_since;
        if (due <= spent || aborted()) break;
        unsigned wait = due - spent > 20 ? 20 : (unsigned)(due - spent);
        sceKernelDelayThread(wait * 1000);
    }
}

/* ------------------------------------------------------------------- tls */

static int io_recv(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    if (sz <= 0) return 0;
    int fd = *(int *)ctx;

    int n = psp_recv(fd, buf, sz);
    if (n > 0) {
        pace(n);
        /* When a packet lands is decided by the radio, the access point's
           scheduling and the path across the internet, none of which this
           device has a say in. wait_socket polls on a fixed sleep, which
           coarsens the arrival time, so this is worth about a bit; the
           timestamp is folded in by entropy_stir itself. */
        entropy_stir(&n, sizeof(n));
        return n;
    }
    if (n == 0) return WOLFSSL_CBIO_ERR_CONN_CLOSE;

    int e = sceNetInetGetErrno();
    if (e == ECONNRESET) return WOLFSSL_CBIO_ERR_CONN_RST;
    if (e == ETIMEDOUT) return WOLFSSL_CBIO_ERR_TIMEOUT;
    /* EINTR is documented to map to CBIO_ERR_ISR, but returning WANT_READ hands
       control back to the caller, where a deadline governs the retry. Retrying
       inside the callback has no bound and hangs the handshake. */
    if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
        return WOLFSSL_CBIO_ERR_WANT_READ;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

static int io_send(WOLFSSL *ssl, char *buf, int sz, void *ctx) {
    (void)ssl;
    if (sz <= 0) return 0;
    int fd = *(int *)ctx;

    int n = psp_send(fd, buf, sz);
    if (n >= 0) return n;

    int e = sceNetInetGetErrno();
    if (e == EPIPE || e == ECONNRESET) return WOLFSSL_CBIO_ERR_CONN_RST;
    if (e == EAGAIN || e == EWOULDBLOCK || e == EINTR)
        return WOLFSSL_CBIO_ERR_WANT_WRITE;
    return WOLFSSL_CBIO_ERR_GENERAL;
}

/* PSP newlib has no memmem. */
static const char *mem_find(const char *hay, size_t hlen,
                            const char *needle, size_t nlen) {
    if (nlen == 0 || hlen < nlen) return NULL;
    for (size_t i = 0; i + nlen <= hlen; i++) {
        if (hay[i] == needle[0] && memcmp(hay + i, needle, nlen) == 0)
            return hay + i;
    }
    return NULL;
}

/* Case-insensitive header lookup within the head. Returns the value start. */
static const char *header(const char *head, size_t len, const char *name) {
    size_t nlen = strlen(name);
    const char *p = head, *end = head + len;
    while (p < end) {
        const char *eol = mem_find(p, (size_t)(end - p), "\r\n", 2);
        if (!eol) eol = end;
        if ((size_t)(eol - p) > nlen && p[nlen] == ':' &&
            strncasecmp(p, name, nlen) == 0) {
            const char *v = p + nlen + 1;
            while (v < eol && (*v == ' ' || *v == '\t')) v++;
            return v;
        }
        if (eol == end) break;
        p = eol + 2;
    }
    return NULL;
}

static int connection_closes(const char *value, const char *end) {
    if (!value || !end) return 0;
    for (const char *p = value; p + 5 <= end; p++)
        if (!strncasecmp(p, "close", 5) &&
            (p == value || p[-1] == ' ' || p[-1] == ',') &&
            (p + 5 == end || p[5] == ' ' || p[5] == ','))
            return 1;
    return 0;
}

/* A head is lines of printable bytes and tabs, each ended by CRLF. A bare CR
   or LF, or another control byte, would let one header's value run into the
   next line: a Content-Encoding of "gzip\r\nLocation..." was copied whole. */
static int head_clean(const char *head, size_t len) {
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)head[i];
        if (c == '\r') {
            if (i + 1 >= len || head[i + 1] != '\n') return 0;
            i++;
        } else if ((c < 32 && c != '\t') || c == 127) {
            return 0;
        }
    }
    return 1;
}

/* ------------------------------------------------------------------- url */

/* A GitHub release download redirects to a signed URL well over 512 bytes. */
struct url { char host[128]; char path[1600]; unsigned short port; };

static int url_parse(const char *s, struct url *u) {
    if (strncmp(s, "https://", 8) != 0) return -1;
    /* Literal controls and spaces would become request delimiters. */
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        if (*p <= 32 || *p == 127) return -1;
    s += 8;
    const char *path = s + strcspn(s, "/?#");
    size_t hl = (size_t)(path - s);
    if (hl == 0 || hl >= sizeof(u->host)) return -1;
    memcpy(u->host, s, hl);
    u->host[hl] = '\0';
    u->port = PORT;
    char *colon = strchr(u->host, ':');
    if (colon) {
        *colon = '\0';
        unsigned port = 0;
        const char *p = colon + 1;
        if (!*p) return -1;
        for (; *p; p++) {
            if (*p < '0' || *p > '9') return -1;
            port = port * 10 + (unsigned)(*p - '0');
            if (port > 65535) return -1;
        }
        if (!port) return -1;
        u->port = (unsigned short)port;
    }
    if (!u->host[0]) return -1;
    for (const unsigned char *p = (const unsigned char *)u->host; *p; p++)
        if (!((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
              (*p >= '0' && *p <= '9') || *p == '.' || *p == '-')) return -1;
    /* Queries without a slash still target '/', and fragments stay local. */
    size_t len = strcspn(path, "#");
    size_t prefix = *path != '/';
    if (prefix + len >= sizeof(u->path)) return -1;
    if (prefix) u->path[0] = '/';
    memcpy(u->path + prefix, path, len);
    u->path[prefix + len] = '\0';
    return 0;
}

/* Location may be absolute or a path on the same host. */
static int url_resolve(const struct url *base, const char *loc, size_t loclen,
                       struct url *out) {
    char tmp[1800], absolute[2000], authority[140], path[sizeof(base->path)];
    if (loclen >= sizeof(tmp)) return -1;
    memcpy(tmp, loc, loclen);
    tmp[loclen] = '\0';
    if (memchr(tmp, '\0', loclen)) return -1;
    int n;
    if (!strncmp(tmp, "//", 2)) {
        n = snprintf(absolute, sizeof(absolute), "https:%s", tmp);
    } else if (strchr(tmp, ':') && (size_t)(strchr(tmp, ':') - tmp) < strcspn(tmp, "/?#")) {
        return url_parse(tmp, out);
    } else {
        if (base->port == PORT) snprintf(authority, sizeof(authority), "%s", base->host);
        else snprintf(authority, sizeof(authority), "%s:%u", base->host, base->port);
        snprintf(path, sizeof(path), "%s", base->path);
        if (tmp[0] == '/') path[0] = '\0';
        else if (tmp[0] == '?') path[strcspn(path, "?")] = '\0';
        else if (tmp[0] && tmp[0] != '#') {
            path[strcspn(path, "?")] = '\0';
            char *slash = strrchr(path, '/');
            if (slash) slash[1] = '\0';
        }
        n = snprintf(absolute, sizeof(absolute), "https://%s%s%s", authority, path, tmp);
    }
    return n < 0 || n >= (int)sizeof(absolute) ? -1 : url_parse(absolute, out);
}

/* The day this file was compiled, as yyyymmdd, from the "Mmm dd yyyy" the
   compiler hands out. It is the one date the client knows to be in the past
   whatever the console's clock says. */
static long build_day(void) {
    static const char months[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    const char *d = __DATE__;
    long mon = 0;
    for (int i = 0; i < 12; i++)
        if (!strncmp(d, months + i * 3, 3)) mon = i + 1;
    long day = (d[4] == ' ' ? 0 : (d[4] - '0') * 10) + (d[5] - '0');
    return atol(d + 7) * 10000 + mon * 100 + day;
}

/* True when the certificate's notAfter lies before the build: it had run out
   before this client existed, and no clock can make it current again. An
   unreadable date counts as run out -- the waiver below is for a clock the
   client distrusts, not for a date it cannot read. */
static int expired_before_build(WOLFSSL_X509_STORE_CTX *store) {
    WOLFSSL_X509 *c = wolfSSL_X509_STORE_CTX_get_current_cert(store);
    WOLFSSL_ASN1_TIME *t = c ? wolfSSL_X509_get_notAfter(c) : NULL;
    struct tm tm;
    if (!t || wolfSSL_ASN1_TIME_to_tm(t, &tm) != WOLFSSL_SUCCESS) {
        logline("cert notAfter unreadable at depth %d", store->error_depth);
        return 1;
    }
    long after = (tm.tm_year + 1900L) * 10000 + (tm.tm_mon + 1) * 100 + tm.tm_mday;
    if (after >= build_day()) return 0;
    logline("cert at depth %d ran out %ld, before this build (%ld)",
            store->error_depth, after, build_day());
    return 1;
}

/* The one check that has to be waived: the console's clock. The PSP's RTC is
   user-settable and resets to 2000 when the battery dies, so a correct chain
   would be rejected as not-yet-valid on a large share of real consoles. Every
   other verification failure -- unknown issuer, bad signature, wrong host --
   still fails the handshake. This trades expiry for the ability to run at all;
   revocation was never checked on a device with no clock anyway.

   The waiver has a floor. A certificate that had already run out on the day
   the client was built is refused whichever way the clock is wrong: without
   that, a key leaked from any certificate ever issued would open every
   console for ever, and a client this old is due an update anyway. */
/* A doubt is not a refusal: the chain is turned down this once and the
   person asked, since a console that has lain in a drawer for years meets
   run-out certificates and issuers it never heard of, and must still work.
   Once they have said so, such chains pass for the rest of the run. What
   never passes is a chain that is wrong rather than old or unfamiliar: a
   bad signature, another host's name. */
static int doubt(WOLFSSL_X509_STORE_CTX *store, enum https_doubt kind) {
    if (trusted(g_verify_host)) {
        logline("cert %d at depth %d for %.40s taken on the person's word", store->error,
                store->error_depth, g_verify_host);
        return 1;
    }
    pthread_mutex_lock(&g_lock);
    snprintf(g_doubt_host, sizeof(g_doubt_host), "%s", g_verify_host);
    g_doubt = kind;
    pthread_mutex_unlock(&g_lock);
    return 0;
}

static int verify_ignoring_dates(int preverify, WOLFSSL_X509_STORE_CTX *store) {
    if (preverify) return 1;
    if (store->error == ASN_BEFORE_DATE_E || store->error == ASN_AFTER_DATE_E) {
        if (expired_before_build(store)) return doubt(store, HTTPS_DOUBT_EXPIRED);
        logline("cert date ignored: the console clock is not trustworthy");
        return 1;
    }
    if (store->error == ASN_NO_SIGNER_E || store->error == ASN_SELF_SIGNED_E) {
        logline("cert at depth %d from an issuer this client does not carry", store->error_depth);
        return doubt(store, HTTPS_DOUBT_ISSUER);
    }
    {
        WOLFSSL_X509 *c = wolfSSL_X509_STORE_CTX_get_current_cert(store);
        char *sub = c ? wolfSSL_X509_get_subjectCN(c) : NULL;
        char iss[48] = "?";
        if (c) wolfSSL_X509_NAME_oneline(wolfSSL_X509_get_issuer_name(c), iss, sizeof(iss));
        /* ASN_NO_SIGNER_E means a CA we do not carry, not an attack: rebuild
           the bundle with make-ca-bundle.py and this host works again. */
        logline("cert %d at depth %d: %.14s from %.24s", store->error,
                store->error_depth, sub ? sub : "?", iss);
    }
    return 0;
}

/* ------------------------------------------------------------------ roots */

/* One context for the whole run, with Mozilla's roots parsed into it once; a
   context per connection parsed every root again on every handshake. The
   parsing runs on a thread of its own that https_net_connect starts, so it happens
   while the radio is still looking for the access point rather than after.
   The parsed roots are not kept between runs: wolfSSL 5.9.2's saved
   certificate cache does not bring every signer back whole -- restored, the
   chain behind raw.githubusercontent.com fails at ISRG Root YR with a path
   length error that the freshly parsed roots pass.

   The roots are the only thing standing between a hostile access point and
   whatever it would like to answer in the server's place. They are compiled
   in -- Sony's store is from 2007 and expired long ago. */
static WOLFSSL_CTX *g_ctx;
static SceUID g_roots_thread = -1;
/* A test build forces in a header of its own that defines ca_bundle.h's
   guard, PSPKIT_HTTPS_TEST_CA, and one CA as PEM in PSPKIT_HTTPS_CA_PEM:
   that CA is all it trusts. */

static int roots_parse(WOLFSSL_CTX *ctx) {
#ifdef PSPKIT_HTTPS_TEST_CA
    return wolfSSL_CTX_load_verify_buffer_ex(ctx, (const unsigned char *)PSPKIT_HTTPS_CA_PEM,
                                             (long)sizeof(PSPKIT_HTTPS_CA_PEM) - 1,
                                             WOLFSSL_FILETYPE_PEM, 0,
                                             WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) == WOLFSSL_SUCCESS;
#else
    int loaded = 0;
    for (int i = 0; i < PSPKIT_HTTPS_CA_COUNT; i++) {
        const unsigned char *der = PSPKIT_HTTPS_CA_DER + PSPKIT_HTTPS_CA_OFFSETS[i];
        long len = (long)(PSPKIT_HTTPS_CA_OFFSETS[i + 1] - PSPKIT_HTTPS_CA_OFFSETS[i]);
        /* A root's dates are not held against it here: the console's clock
           cannot tell, and the verify callback decides that per chain. */
        if (wolfSSL_CTX_load_verify_buffer_ex(ctx, der, len, WOLFSSL_FILETYPE_ASN1, 0,
                                              WOLFSSL_LOAD_FLAG_DATE_ERR_OKAY) == WOLFSSL_SUCCESS)
            loaded++;
        else
            logline("root %d refused", i);
    }
    return loaded;
#endif
}

static WOLFSSL_CTX *roots_load(void) {
    unsigned start = now_ms();
    if (!g_wolf_ready) {
        int irc = wolfSSL_Init();
        if (irc != WOLFSSL_SUCCESS) {
            logline("wolfssl %s init=%d", wolfSSL_lib_version(), irc);
            return NULL;
        }
        g_wolf_ready = 1;
    }
    WOLFSSL_CTX *ctx = wolfSSL_CTX_new(wolfTLSv1_3_client_method());
    if (!ctx) { logline("no TLS 1.3 in this build"); return NULL; }

    int loaded = roots_parse(ctx);
    if (loaded <= 0) {
        logline("roots: none loaded");
        wolfSSL_CTX_free(ctx);
        return NULL;
    }
    logline("roots: %d parsed in %u ms", loaded, now_ms() - start);

    wolfSSL_CTX_set_verify(ctx, WOLFSSL_VERIFY_PEER, verify_ignoring_dates);
    wolfSSL_CTX_SetIORecv(ctx, io_recv);
    wolfSSL_CTX_SetIOSend(ctx, io_send);
    /* X25519 costs a fraction of P-256 on a core with no crypto hardware, and
       offering its key share up front avoids a HelloRetryRequest, which would
       be an entire extra round trip. */
    static int groups[] = { WOLFSSL_ECC_X25519, WOLFSSL_ECC_SECP256R1 };
    if (wolfSSL_CTX_set_groups(ctx, groups, 2) != WOLFSSL_SUCCESS)
        logline("x25519 unavailable, using default groups");
    return ctx;
}

/* Publishes a context made outside the lock, unless another caller got
   there first; then this one is not needed and goes. */
static WOLFSSL_CTX *roots_publish(WOLFSSL_CTX *ctx) {
    pthread_mutex_lock(&g_lock);
    if (!g_ctx) {
        g_ctx = ctx;
        ctx = NULL;
    }
    WOLFSSL_CTX *current = g_ctx;
    pthread_mutex_unlock(&g_lock);
    if (ctx) wolfSSL_CTX_free(ctx);
    return current;
}

static int roots_thread(SceSize args, void *argp) {
    (void)args; (void)argp;
    WOLFSSL_CTX *ctx = roots_load();
    if (ctx) roots_publish(ctx);
    return 0;
}

static void roots_start(void) {
    pthread_mutex_lock(&g_lock);
    int wanted = !g_ctx && g_roots_thread < 0;
    if (wanted) {
        /* Below the caller's priority: an application's frames come first. */
        g_roots_thread = sceKernelCreateThread("pspkit_https_roots", roots_thread, 0x28,
                                               128 * 1024, PSP_THREAD_ATTR_USER, NULL);
        if (g_roots_thread >= 0 && sceKernelStartThread(g_roots_thread, 0, NULL) < 0) {
            sceKernelDeleteThread(g_roots_thread);
            g_roots_thread = -1;
        }
    }
    pthread_mutex_unlock(&g_lock);
}

/* Waits for the roots thread if one was started. The handle is taken under
   the lock so that only one caller joins it; the waiting is not. */
static void roots_join(void) {
    pthread_mutex_lock(&g_lock);
    SceUID thread = g_roots_thread;
    g_roots_thread = -1;
    pthread_mutex_unlock(&g_lock);
    if (thread < 0) return;
    sceKernelWaitThreadEnd(thread, NULL);
    sceKernelDeleteThread(thread);
}

/* The context once the roots are in it: waits for the thread when one is at
   work, and loads them here when none was started. NULL when they could not
   be loaded; the next request tries again. Nothing that can call back into
   the application -- the parsing logs -- runs under the lock. */
static WOLFSSL_CTX *roots_ready(void) {
    roots_join();
    pthread_mutex_lock(&g_lock);
    WOLFSSL_CTX *ctx = g_ctx;
    pthread_mutex_unlock(&g_lock);
    if (ctx) return ctx;
    ctx = roots_load();
    return ctx ? roots_publish(ctx) : NULL;
}

static void roots_release(void) {
    roots_join();
    pthread_mutex_lock(&g_lock);
    WOLFSSL_CTX *ctx = g_ctx;
    g_ctx = NULL;
    pthread_mutex_unlock(&g_lock);
    if (ctx) wolfSSL_CTX_free(ctx);
}

/* ---------------------------------------------------------------- request */

/* An application that alternates two hosts -- raw.githubusercontent.com and
   api.github.com, say -- would close the first connection each time it
   reached the second with one idle slot. The lock also protects slots from
   the screen closing idle connections while a request is active. */
#define IDLE_SLOTS 3
#define IDLE_MS 30000
struct connection {
    int sock;
    WOLFSSL *ssl;
    char host[128];
    unsigned short port;
    unsigned idle_at;
};
static struct connection *g_idle[IDLE_SLOTS];

static void close_connection(struct connection *c, int graceful) {
    if (!c) return;
    if (c->ssl) {
        if (graceful) wolfSSL_shutdown(c->ssl);
        wolfSSL_free(c->ssl);
    }
    if (c->sock >= 0) sceNetInetClose(c->sock);
    free(c);
}

static void close_idle(void) {
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < IDLE_SLOTS; i++) {
        close_connection(g_idle[i], 0);
        g_idle[i] = NULL;
    }
    /* A handshake may still use the context. Its certificates are released
       at disconnect, after the worker has stopped using them. */
    pthread_mutex_unlock(&g_lock);
}

void https_close_idle(void) { close_idle(); }

static struct connection *take_idle(const struct url *u) {
    struct connection *found = NULL;
    pthread_mutex_lock(&g_lock);
    for (int i = 0; i < IDLE_SLOTS; i++) {
        struct connection *c = g_idle[i];
        if (!c) continue;
        if (expired(c->idle_at, IDLE_MS)) {
            close_connection(c, 0);
            g_idle[i] = NULL;
        } else if (c->port == u->port && !strcmp(c->host, u->host)) {
            g_idle[i] = NULL;
            found = c;
            break;
        }
    }
    pthread_mutex_unlock(&g_lock);
    return found;
}

static void save_idle(struct connection *c) {
    pthread_mutex_lock(&g_lock);
    int slot = -1;
    for (int i = 0; i < IDLE_SLOTS; i++)
        if (!g_idle[i]) { slot = i; break; }
    if (slot < 0) {
        slot = 0;
        for (int i = 1; i < IDLE_SLOTS; i++)
            if ((unsigned)(now_ms() - g_idle[i]->idle_at) >
                (unsigned)(now_ms() - g_idle[slot]->idle_at))
                slot = i;
        close_connection(g_idle[slot], 0);
    }
    c->idle_at = now_ms();
    g_idle[slot] = c;
    pthread_mutex_unlock(&g_lock);
}

/* One HTTP request, possibly over an idle connection. Fills head[] and streams
   the body. Returns: 0 complete, 1 truncated, <0 failed before the body.
   On a 3xx with Location, *redirect is filled and 2 is returned. */
static int one_request(const struct url *u, https_sink sink, void *sink_ctx,
                       https_progress progress, void *progress_ctx,
                       struct https_result *res, struct url *redirect, int *stale) {
    int sock = -1, rc, ret = -1;
    WOLFSSL *ssl = NULL;
    int can_keep = 0;
    static char buf[16 * 1024];
    static char head[HEAD_MAX + 1];
    size_t headlen = 0;

    *stale = 0;
    res->handshake_ms = 0;
    res->status = 0;
    res->body_len = 0;
    res->content_length = 0;
    res->truncated = 0;
    res->content_encoding[0] = '\0';          /* a redirect's is not the body's */
    if (over_time()) return -1;               /* before a redirect or a retry */
    struct connection *conn = take_idle(u);
    int reused = conn != NULL;
    if (conn) {
        sock = conn->sock;
        ssl = conn->ssl;
        res->handshake_ms = 0;
        logline("https: reuse %s", u->host);
        goto request;
    }
    struct in_addr ip;
    phase("dns");
    if (resolve(u->host, &ip) < 0) { logline("dns failed: %s", u->host); return -1; }
    phase("connect");

    conn = calloc(1, sizeof(*conn));
    if (!conn) return -1;
    conn->sock = -1;
    snprintf(conn->host, sizeof(conn->host), "%s", u->host);
    conn->port = u->port;

    sock = sceNetInetSocket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { logline("socket failed"); ret = -2; goto out; }
    conn->sock = sock;

    /* No portable O_NONBLOCK here, and SO_NONBLOCK / SO_ERROR are not in the
       headers -- using them picks up constants from elsewhere and configures
       the wrong option. The stack behaves as non-blocking (recv reports
       EAGAIN), which is what the IO callbacks are written for. */
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(u->port);
    sa.sin_addr = ip;

    /* A non-blocking connect returns at once with EINPROGRESS. With no
       SO_ERROR and no usable select, the way to learn that it finished is
       to ask again: the stack answers EALREADY while it is still at it and
       EISCONN (or 0) once the connection stands. */
    unsigned start = now_ms();
    if (sceNetInetConnect(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        int e = sceNetInetGetErrno();
        if (e != EINPROGRESS && e != EALREADY && e != EWOULDBLOCK) {
            logline("connect failed errno=%d", e);
            goto out;
        }
        for (;;) {
            sceKernelDelayThread(20 * 1000);
            if (sceNetInetConnect(sock, (struct sockaddr *)&sa, sizeof(sa)) == 0) break;
            e = sceNetInetGetErrno();
            if (e == EISCONN) break;
            if (e != EINPROGRESS && e != EALREADY && e != EWOULDBLOCK) {
                logline("connect failed errno=%d", e);
                goto out;
            }
            if (aborted()) { logline("https: aborted while connecting"); goto out; }
            if (over_time()) goto out;
            if (expired(start, CONNECT_TIMEOUT_MS)) { logline("connect timeout"); goto out; }
        }
    }
    stir_power(now_ms() - start);

    WOLFSSL_CTX *ctx = roots_ready();
    if (!ctx) goto out;

    ssl = wolfSSL_new(ctx);
    conn->ssl = ssl;
    if (!ssl) { logline("wolfSSL_new failed"); goto out; }
    if (g_suites && wolfSSL_set_cipher_list(ssl, g_suites) != WOLFSSL_SUCCESS) {
        logline("cipher list rejected: %s", g_suites);
        goto out;
    }
    wolfSSL_SetIOReadCtx(ssl, &conn->sock);
    wolfSSL_SetIOWriteCtx(ssl, &conn->sock);
    if (wolfSSL_UseSNI(ssl, WOLFSSL_SNI_HOST_NAME, u->host,
                       (unsigned short)strlen(u->host)) != WOLFSSL_SUCCESS)
        logline("SNI rejected");
    /* Without this a valid certificate for any other host would pass. An
       address is matched against the certificate's IP entries instead:
       wolfSSL takes only a proper host name as a domain name. */
    struct in_addr literal;
    int pinned = inet_aton(u->host, &literal)
                     ? wolfSSL_check_ip_address(ssl, u->host)
                     : wolfSSL_check_domain_name(ssl, u->host);
    if (pinned != WOLFSSL_SUCCESS) {
        logline("cannot pin %s", u->host);
        goto out;
    }
    if (wolfSSL_UseKeyShare(ssl, WOLFSSL_ECC_X25519) != WOLFSSL_SUCCESS)
        logline("x25519 key share unavailable");

    phase("tls handshake");
    snprintf(g_verify_host, sizeof(g_verify_host), "%s", u->host);
    start = now_ms();
    while ((rc = wolfSSL_connect(ssl)) != WOLFSSL_SUCCESS) {
        int e = wolfSSL_get_error(ssl, rc);
        if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) {
            char msg[80];
            wolfSSL_ERR_error_string((unsigned long)e, msg);
            logline("handshake failed %d: %s", e, msg);
            goto out;
        }
        if (aborted()) { logline("https: aborted in the handshake"); goto out; }
        if (over_time()) goto out;
        if (expired(start, HANDSHAKE_TIMEOUT_MS)) { logline("handshake timeout"); goto out; }
        wait_socket(1);
    }
    res->handshake_ms = now_ms() - start;
    {
        const char *group = wolfSSL_get_curve_name(ssl);
        const char *cipher = wolfSSL_get_cipher(ssl);
        logline("%s %s %s %u ms", u->host, cipher,
                group ? group : "?", res->handshake_ms);
        /* The same four facts the log gets, kept for the info panel: what
           was negotiated is only knowable here, while the session is open. */
        pthread_mutex_lock(&g_lock);
        snprintf(g_last.host, sizeof(g_last.host), "%s", u->host);
        snprintf(g_last.cipher, sizeof(g_last.cipher), "%s", cipher ? cipher : "?");
        snprintf(g_last.group, sizeof(g_last.group), "%s", group ? group : "?");
        g_last.handshake_ms = res->handshake_ms;
        pthread_mutex_unlock(&g_lock);
    }

request:
    phase("request");
    pace_begin();
    char authority[140];
    if (u->port == PORT) snprintf(authority, sizeof(authority), "%s", u->host);
    else snprintf(authority, sizeof(authority), "%s:%u", u->host, u->port);
    int reqlen = snprintf(buf, sizeof(buf),
                          "GET %s HTTP/1.1\r\n"
                          "Host: %s\r\n"
                          "User-Agent: %s\r\n"
                          "%s"
                          "Connection: keep-alive\r\n\r\n", u->path, authority, g_agent,
                          g_accept_gzip ? "Accept-Encoding: gzip\r\n" : "");
    if (reqlen <= 0 || reqlen >= (int)sizeof(buf)) { logline("request too long"); goto out; }

    start = now_ms();
    for (int sent = 0; sent < reqlen; ) {
        rc = wolfSSL_write(ssl, buf + sent, reqlen - sent);
        if (rc > 0) { sent += rc; continue; }
        int e = wolfSSL_get_error(ssl, rc);
        if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) {
            logline("write failed %d", e);
            if (reused) *stale = 1;
            goto out;
        }
        if (aborted()) { logline("https: aborted while sending"); goto out; }
        if (over_time()) goto out;
        if (expired(start, STALL_TIMEOUT_MS)) { logline("write timeout"); goto out; }
        wait_socket(1);
    }

    /* Read until the head is complete, then hand the rest to the sink. */
    const char *body_start = NULL;
    const char *leftover = NULL;
    size_t leftover_len = 0;
    size_t want = 0;
    int have_length = 0, chunked = 0;
    start = now_ms();
    for (;;) {
        /* The head has STALL_TIMEOUT_MS in all from the request: a server
           that sends it a byte now and then must not hold the request for
           as long as it likes. The body's clock starts over with each read. */
        if (expired(start, STALL_TIMEOUT_MS)) {
            logline(body_start ? "read stalled" : "http: no complete head in time");
            goto out;
        }
        if (over_time()) goto out;
        rc = wolfSSL_read(ssl, buf, (int)sizeof(buf));
        if (rc > 0) {
            if (body_start) start = now_ms();
            const char *data = buf;
            size_t len = (size_t)rc;

            if (!body_start) {
                /* Only what fits is copied; a read that carries the head plus
                   megabytes of body is normal and must not be refused. */
                size_t room = HEAD_MAX - headlen;
                size_t take = len < room ? len : room;
                memcpy(head + headlen, data, take);
                headlen += take;
                head[headlen] = '\0';
                const char *sep = mem_find(head, headlen, "\r\n\r\n", 4);
                if (!sep) {
                    if (headlen == HEAD_MAX) { logline("http: head too large"); goto out; }
                    continue;
                }
                leftover = data + take;
                leftover_len = len - take;

                size_t hl = (size_t)(sep - head) + 4;
                if (hl < 16 || (memcmp(head, "HTTP/1.1 ", 9) && memcmp(head, "HTTP/1.0 ", 9)) ||
                    head[9] < '1' || head[9] > '5' || head[10] < '0' || head[10] > '9' ||
                    head[11] < '0' || head[11] > '9' || (head[12] != ' ' && head[12] != '\r') ||
                    !head_clean(head, hl)) {
                    logline("http: bad status line");
                    goto out;
                }
                res->status = (head[9] - '0') * 100 + (head[10] - '0') * 10 + head[11] - '0';
                if (res->status < 200) { logline("http: informational response unsupported"); goto out; }
                const char *cl = header(head, hl, "Content-Length");
                if (cl) {
                    const char *end = cl;
                    if (*end < '0' || *end > '9') goto out;
                    for (; *end >= '0' && *end <= '9'; end++) {
                        unsigned digit = (unsigned)(*end - '0');
                        if (want > ((size_t)-1 - digit) / 10) goto out;
                        want = want * 10 + digit;
                    }
                    while (*end == ' ' || *end == '\t') end++;
                    if (end[0] != '\r' || end[1] != '\n') goto out;
                    const char *next = end + 2;
                    if (header(next, (size_t)(head + hl - next), "Content-Length")) goto out;
                    have_length = 1;
                }
                res->content_length = want;
                /* Named, not decoded: the caller asked for it and knows what
                   to do with it. Blanks before the line's end are not part of it. */
                const char *ce = header(head, hl, "Content-Encoding");
                if (ce) {
                    size_t n = (size_t)(mem_find(ce, (size_t)(head + hl - ce), "\r\n", 2) - ce);
                    while (n && (ce[n - 1] == ' ' || ce[n - 1] == '\t')) n--;
                    if (n >= sizeof(res->content_encoding)) n = sizeof(res->content_encoding) - 1;
                    memcpy(res->content_encoding, ce, n);
                    res->content_encoding[n] = '\0';
                }
                const char *te = header(head, hl, "Transfer-Encoding");
                if (te) chunked = 1;
                const char *connection = header(head, hl, "Connection");
                const char *connection_end = connection
                    ? mem_find(connection, (size_t)(head + hl - connection), "\r\n", 2) : NULL;
                can_keep = have_length && !chunked &&
                    !strncmp(head, "HTTP/1.1 ", 9) &&
                    !connection_closes(connection, connection_end);

                if (res->status >= 300 && res->status < 400) {
                    const char *loc = header(head, hl, "Location");
                    if (loc) {
                        const char *eol = mem_find(loc, (size_t)(head + hl - loc), "\r\n", 2);
                        /* Blanks before the line's end are not the value. */
                        while (eol && eol > loc && (eol[-1] == ' ' || eol[-1] == '\t')) eol--;
                        if (eol && url_resolve(u, loc, (size_t)(eol - loc), redirect) == 0) {
                            logline("http %ld -> %s", res->status, redirect->host);
                            ret = 2;
                            goto out;
                        }
                        logline("http: invalid redirect");
                        goto out;
                    }
                }
                if (chunked) {
                    /* GitHub serves everything we ask for with a length;
                       a chunk decoder is not worth its bytes until it is not. */
                    logline("http: transfer-encoding not supported");
                    goto out;
                }
                /* These statuses have no message body even when metadata
                   announces the length of the corresponding representation. */
                if (res->status == 204 || res->status == 304) {
                    want = 0;
                    have_length = 1;
                    res->content_length = 0;
                }
                logline("http %ld, %lu bytes announced", res->status, (unsigned long)want);
                phase("download");
                if (progress) progress(progress_ctx, 0, want);

                /* Whatever followed the head in this read is body. */
                body_start = head + hl;
                start = now_ms();
                data = body_start;
                len = headlen - hl;
                ret = 1;                                 /* body has begun */
                if (aborted()) goto out;
                if (len == 0 && leftover_len == 0) {
                    if (have_length && want == 0) { ret = 0; goto out; }
                    continue;
                }
            }

            /* Two pieces on the read that completed the head: the tail of the
               buffer it was copied into, then what did not fit. */
            for (int piece = 0; piece < 2; piece++) {
                if (piece == 1) {
                    if (leftover_len == 0) break;
                    data = leftover;
                    len = leftover_len;
                    leftover_len = 0;
                }
                if (len == 0) continue;

                /* Anything past Content-Length is not part of this message. */
                if (have_length && len > want - res->body_len) {
                    logline("http: %lu bytes past content-length, ignored",
                            (unsigned long)(len - (want - res->body_len)));
                    can_keep = 0;
                    len = want - res->body_len;
                }
                if (len && sink && sink(sink_ctx, data, len) != 0) {
                    logline("sink aborted");
                    goto out;
                }
                if (len > (size_t)-1 - res->body_len) goto out;
                res->body_len += len;
                if (progress) progress(progress_ctx, res->body_len, want);
                if (aborted()) { logline("http: aborted"); goto out; }
                if (have_length && res->body_len >= want) { ret = 0; goto out; }
            }
            continue;
        }

        int e = wolfSSL_get_error(ssl, rc);
        if (e == WOLFSSL_ERROR_NONE || e == WOLFSSL_ERROR_ZERO_RETURN) {
            /* Clean close: complete unless a length says otherwise. */
            if (body_start && (!have_length || res->body_len >= want)) ret = 0;
            else if (!body_start) {
                logline("http: closed before head");
                if (reused) *stale = 1;
            }
            goto out;
        }
        if (e != WOLFSSL_ERROR_WANT_READ && e != WOLFSSL_ERROR_WANT_WRITE) {
            /* A reset after the body has arrived is common enough to tolerate,
               but it must not be reported as a clean read. */
            logline("read error %d after %lu bytes", e, (unsigned long)res->body_len);
            if (body_start && have_length && res->body_len >= want) ret = 0;
            goto out;
        }
        if (aborted()) { logline("http: aborted while waiting"); goto out; }
        wait_socket(1);
    }

out:
    if (ret == 1) res->truncated = 1;
    if (reused && ret < 0 && !res->body_len && !headlen)
        *stale = 1;
    if (ret == 0 && can_keep) save_idle(conn);
    else close_connection(conn, ret == 0 || ret == 2);
    return ret;
}

enum https_outcome https_get(const char *url, https_sink sink, void *sink_ctx,
              https_progress progress, void *progress_ctx,
              struct https_result *out) {
    struct url u, next;
    struct https_result res;
    memset(&res, 0, sizeof(res));
    if (out) *out = res;                      /* callers log it either way */
    abort_clear();
    g_get_start = now_ms();
    phase("");
    if (!url || !g_net.connected || strpbrk(g_agent, "\r\n") || url_parse(url, &u) < 0)
        return HTTPS_FAILED;

    for (res.redirects = 0; ; res.redirects++) {
        int stale = 0;
        int rc = one_request(&u, sink, sink_ctx, progress, progress_ctx, &res, &next, &stale);
        if (stale && !res.body_len) {
            /* A server may close an idle connection just before our next GET.
               Retrying is safe only before any response body reached the sink. */
            rc = one_request(&u, sink, sink_ctx, progress, progress_ctx, &res, &next, &stale);
        }
        if (rc != 2) {
            snprintf(res.host, sizeof(res.host), "%s", u.host);
            if (out) *out = res;
            phase("");
            return rc == 0 ? HTTPS_COMPLETE : rc == 1 ? HTTPS_TRUNCATED : HTTPS_FAILED;
        }
        if (res.redirects >= MAX_REDIRECTS) {
            logline("too many redirects");
            snprintf(res.host, sizeof(res.host), "%s", u.host);
            if (out) *out = res;
            phase("");
            return HTTPS_FAILED;
        }
        u = next;
    }
}
