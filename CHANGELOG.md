# Changelog

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
