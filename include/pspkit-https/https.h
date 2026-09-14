#ifndef PSPKIT_HTTPS_H
#define PSPKIT_HTTPS_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* TLS 1.3 HTTPS on the PSP. Configure logging, initialise entropy, set its
   seed path and load a seed or complete a sweep before connecting. Requests
   fail closed until entropy is ready. One worker owns connect, disconnect,
   get and the request settings; callers must serialise these operations.
   Callbacks must not reenter them. Other functions explicitly allow any
   thread. No public header requires PSP SDK types. */

/* Any thread: replace the logger, or disable it with NULL. Lines have no
   newline and are borrowed for the callback only. Callbacks may overlap on
   the worker and roots thread, so the logger must be thread-safe. An old
   callback may still be running when this setter returns. Log callbacks
   must not call library functions. */
void https_set_log(void (*line)(const char *text));

/* Worker, between requests: set the User-Agent, or NULL for the default.
   The string is kept, not copied, and must remain valid until replaced.
   CR and LF are invalid; a request using such an agent fails. */
void https_set_user_agent(const char *agent);

/* Worker, between requests: cap received data in decimal kilobytes per
   second; zero removes the limit. */
void https_set_rate_limit(unsigned kbps);

/* Worker, between requests: wolfSSL cipher list, or NULL for the default.
   The string is kept, not copied, until replaced. Closes idle connections
   so the next handshake uses the setting. An invalid list fails the request. */
void https_set_cipher_suites(const char *suites);

/* Worker: initialise the stack and connect to profile 1; return 0 with an
   IP, -1 on failure or abort. Repeated calls reuse a live link. Starts roots
   parsing in the background. Clears a previous abort when the call starts. */
int https_net_connect(void);

/* Worker, with no request running: join roots parsing, close connections
   and release TLS and network resources. Repeated calls are harmless. */
void https_net_disconnect(void);

/* Called on the request worker. data is borrowed until return; return zero
   to accept all len bytes, any nonzero value to stop the transfer. A NULL
   sink discards the body. Callbacks may call https_abort. */
typedef int (*https_sink)(void *ctx, const void *data, size_t len);

/* Called on the request worker after headers and accepted body pieces.
   total is zero for an unknown or empty body. A NULL callback is allowed. */
typedef void (*https_progress)(void *ctx, size_t done, size_t total);

struct https_result {
    long status;                 /* Final HTTP status, or zero without headers. */
    size_t body_len;              /* Bytes accepted by the sink or discarded. */
    size_t content_length;        /* Announced bytes; zero if absent or empty. */
    int truncated;               /* One exactly when HTTPS_TRUNCATED is returned. */
    unsigned handshake_ms;       /* Final handshake duration; zero for reuse. */
    int redirects;               /* Redirects followed, from zero to five. */
    char host[128];               /* Final host, or empty before URL parsing. */
};

struct https_info {
    char host[128];
    char cipher[48];
    char group[24];
    unsigned handshake_ms;
};

/* Any thread: copy the last successful handshake into non-NULL out.
   Strings are terminated, use wolfSSL spelling, and are empty before the
   first handshake. The caller owns the snapshot. */
void https_get_last_info(struct https_info *out);

/* Any thread: return a static phase string for display. It stays valid
   forever; an empty string means no network operation is active. */
const char *https_get_phase(void);

/* Any thread or callback: stop the active connect or GET at its next wait
   or body piece. DNS already in progress may take ten seconds to return.
   A later connect or GET clears the flag, so this is not a queued cancel. */
void https_abort(void);

/* Any thread: close connections currently idle. An active request may put
   its connection back afterwards; call with the worker quiescent when every
   subsequent request must perform a new handshake. */
void https_close_idle(void);

enum https_doubt { HTTPS_DOUBT_NONE, HTTPS_DOUBT_EXPIRED, HTTPS_DOUBT_ISSUER };

/* Any thread, with one owner for certificate questions: consume a pending
   doubt and remember its host for acceptance. Copies a terminated host,
   empty for NONE, when host is non-NULL and size is nonzero. A small buffer
   truncates the display only; acceptance still uses the full host. */
enum https_doubt https_doubt_take(char *host, size_t size);

/* The question owner: accept the host from the last non-NONE take once.
   Without a pending answer this does nothing. Exceptions cover date/issuer
   doubts only; up to eight hosts are retained, with the oldest evicted.
   Acceptance lasts until eviction or disconnect. */
void https_doubt_accept(void);

enum https_outcome { HTTPS_FAILED = -1, HTTPS_COMPLETE = 0, HTTPS_TRUNCATED = 1 };

/* Worker after a successful connect: GET a non-NULL https:// URL, following
   up to five redirects. HTTP downgrades and transfer encodings are refused.
   Hosts are DNS names or IPv4 literals; IPv6 and URL userinfo are unsupported.
   COMPLETE means a whole body, regardless of HTTP status; inspect status
   for 4xx/5xx. TRUNCATED means headers were accepted but the body stopped,
   including sink cancellation before its first byte. FAILED means URL,
   connection, header or redirect failure. The private redirect code never
   escapes. out may be NULL; otherwise it is initialised even on failure.
   URL and callback contexts are borrowed until return. */
enum https_outcome https_get(const char *url, https_sink sink, void *sink_ctx,
                             https_progress progress, void *progress_ctx,
                             struct https_result *out);

#ifdef __cplusplus
}
#endif

#endif
