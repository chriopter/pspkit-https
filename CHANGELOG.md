# Changelog

## 0.2.12

- `https_load_roots(ctx)`: Mozilla's roots, the ones this library trusts and keeps current every week, parsed into a wolfSSL context of the caller's, so a library with TLS connections of its own (pspkit-tunnel's relays) trusts the same and is kept current with it

## 0.2.11

- `https_set_transport(host, transport)`: a host reached through something other than the console's own sockets -- a tunnel such as [pspkit-tunnel](https://github.com/chriopter/pspkit-tunnel). TLS, the certificate check, HTTP and Basic stay as they are; only the bytes travel another way. A kept connection that went the old way is closed instead of reused when a host's way changes
- An address written out (`http://192.168.1.10/`) no longer goes to the console's resolver, which refuses one on real hardware: every source given by IP failed there with "dns failed", while an emulator's resolver let it pass

## 0.2.10

- `https_set_basic(host, user, password)`: HTTP Basic for one host, for a catalog somebody keeps behind a password. Sent with every request to that host and to no other, a redirect's included; a user name or password with a line break is refused

## 0.2.9

- `http://` URLs, for servers people host themselves: a plain socket, port 80 by default, and everything else as for `https://`, from the head to chunked bodies, redirects and idle connections, which are kept apart from TLS ones. A redirect from `https://` down to `http://` is still refused; one from `http://` up to `https://` is followed

## 0.2.8

- `https_doubt_trust(host)`: a host the player accepted on an earlier run is accepted again, as `https_doubt_accept()` would, so an app that keeps its answers asks once, not every run. Same eight places, date and issuer doubts only; a forged signature or the wrong name still fails

## 0.2.7

- Mozilla's roots as of Tue Oct 20 13:32:40 2026 GMT. Removed: emSign ECC Root CA - C3; emSign ECC Root CA - G3; emSign Root CA - C1. The CA generator accepts curl's fingerprint comments.

## 0.2.6

- Stream HTTP chunked responses, including Archive.org metadata used for download recovery. Fragmented chunks and bounded trailers are decoded before the sink; malformed or incomplete framing and ambiguous transfer lengths are refused.

- Downloads from Archive.org work again: accept legacy certificate serial numbers of zero, including the redundant Go Daddy Class 2 root its servers send. wolfSSL 5.9.2 otherwise ends the handshake with `ASN_PARSE_E` (-140). Signature, issuer and hostname checks remain in force. Rebuild wolfSSL when updating; `tests/certificates` covers the chain and rejects forged, untrusted and wrong-host certificates.

## 0.2.5

- A console whose clock is not set downloads like any other. wolfSSL read a time of 0 as a failed clock and ended the connection with `GETTIME_ERROR` (-337) at the first TLS 1.3 session ticket, so every request to a server that sends tickets, `raw.githubusercontent.com` among them, failed after the handshake
- wolfSSL no longer reads the console's clock at all: its timers count from boot, and its date is the build day. `tools/build-wolfssl` refuses a library that still refers to `time` or `gettimeofday`. Build wolfSSL again when updating
- `tests/clock`: wolfSSL with the PSP's options against a server that sends session tickets, on a clock that reads 0

## 0.2.4

- Requests may run on two threads at once: the request and head buffers are per request, one TLS handshake runs at a time, and transfers run in parallel
- Six idle connections are kept for sixty seconds
- Non-ASCII bytes in a URL path go out percent-encoded
- Mozilla's roots as of Fri Sep 25 03:12:01 2026 GMT, the same roots as before

## 0.2.3

- `https_net_init()` initializes the network stack for the PSP system connection dialog. Requests adopt that connection without silently selecting profile 1 after cancellation.
- Explicit non-blocking sockets keep receive timeouts and cancellation reachable when WLAN drops. Failed socket configuration rejects the connection.
- Progress callbacks continue during response waits, allowing cancellation even when no new bytes arrive.
- Scripted request tests cover stalled responses, cancellation and socket setup failures.

## 0.2.2

- A response head has 30 seconds in all from the request. The 30-second stall timeout started over with every byte, so a server sending a byte a second held a request without end
- `https_set_time_limit()` bounds a whole `https_get`, redirects included; off by default, so a slow body is still only cut off after 30 seconds without a byte
- `tests/request` plays a server that trickles, for the head, the body and the limit

## 0.2.1

- A bare CR or LF, or another control byte, in a response head is refused instead of joining one header's value to the next line
- A 204 or 304 reports a `content_length` of 0, whatever length its head names, since it has no body
- Blanks after a `Location` value are trimmed, so the redirect is followed

## 0.2.0

- `https_set_accept_gzip()` asks for `Accept-Encoding: gzip`; off by default. The library still does not inflate
- `struct https_result` names the final response's `Content-Encoding` in `content_encoding`
- `tests/request`: `src/https.c` on the PC against a scripted server, stubs in place of the PSP and wolfSSL

## 0.1.0

- HTTPS, the entropy pool and the sweep taken out of PSPDX
- Mozilla's whole root store instead of a hand-picked few, parsed once a run on a thread of its own; a weekly workflow opens a pull request when it changes
- wolfSSL as a submodule, built by `tools/build-wolfssl`
- Certificate dates held against the build day, documented, and no network time
- The sweep counts only what nobody could predict: turns by direction and moment, and button presses
- `https_abort()` stops a request at every wait, not only between pieces of body
- An accepted certificate doubt covers its host only
- A cleaned-up API: `https_net_connect`/`https_net_disconnect`, `https_set_cipher_suites`, `https_set_rate_limit`, `https_doubt_accept`, getters named `*_get_*`, `sweep_step` taking the buttons; every declaration says which thread may call it
- `demo/`: an ASCII sweep that shows its turns and presses, and a fetch that can be cancelled
- Released as a zip with prebuilt libraries: headers, `libpspkit-https.a`, `libwolfssl.a` and a `module.mk`
- `tests/nettest`, `tools/entropy-sim`

## 0.0.1

- The repository exists, nothing in it yet
