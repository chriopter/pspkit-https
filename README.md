# pspkit-https

**HTTPS for PSP homebrew** — download over TLS 1.3 from a PSP, with the
certificate checks and the randomness a PSP does not bring by itself.
**[→ Download](https://github.com/chriopter/pspkit-https/releases/latest)**

<img width="480" alt="The sweep screen of the demo" src="assets/demo-sweep.png" />

*Stick and buttons make the seed for wolfSSL's random number generator.*

## What it does

- **Secure downloads:** HTTPS with TLS 1.3, built on wolfSSL
- **Trusts what Firefox trusts:** Mozilla's list of root certificates, checked for updates every week
- **Copes with a wrong clock:** a PSP's date is usually off, so certificates are checked against the day the library was built; an expired or unknown one asks the player instead of failing
- **Makes its own randomness:** once, the player steers the stick or smashes buttons for about 18 seconds; the result is saved, later starts skip it

Tested in PPSSPP so far. [`demo/`](demo/) is a complete example.

## How to use

**1. Download** the zip from the
[latest release](https://github.com/chriopter/pspkit-https/releases/latest)
and unpack it into your homebrew, say into `lib/`. It holds the headers and
the prebuilt libraries, wolfSSL included.

**2. Include it** in your Makefile, before `build.mak`:

```make
include lib/pspkit-https-0.1.0/module.mk
```

**3. Make a seed, then download.** The first start shows the sweep; every
later start loads the saved seed.

```c
#include "pspkit-https/entropy.h"
#include "pspkit-https/https.h"
#include "pspkit-https/sweep.h"

/* Called with each piece of the download. */
static int on_data(void *ctx, const void *data, size_t len) {
    return 0;                                 /* 0 = keep going */
}

int main(void) {
    entropy_set_seed_file("ms0:/PSP/GAME/MYAPP/seed.bin");
    entropy_init();
    if (!entropy_load())
        sweep_ascii_run();                    /* the screen above */
    entropy_save(0);

    struct https_result result;
    https_net_connect();                      /* Wi-Fi profile 1 */
    https_get("https://example.org/", on_data, NULL, NULL, NULL, &result);
}
```

## Details

<details>
<summary><b>Connections</b> · speed, requests, limits</summary>

- ChaCha20-Poly1305 is used first: the PSP has no AES hardware, and 5 MB take 1.3 s with ChaCha against 4.8 s with AES-GCM
- X25519 for the key exchange, about seven times faster than P-256 on a PSP
- Redirects are followed (up to 5), but never from `https://` down to `http://`
- Connections to the same server are reused for 30 seconds
- `https_abort()` stops a download from any thread
- Not supported: chunked responses, POST, IPv6, two downloads at once

</details>

<details>
<summary><b>Certificates</b> · roots, dates, asking the player</summary>

- 121 root certificates from Mozilla, taken from curl; a workflow checks for a newer list every Monday and opens a pull request
- Server name and certificate chain are always checked; a forged signature or the wrong name always fails
- **Dates:** a PSP's clock resets to 2000 when the battery runs flat. So a certificate only counts as expired if it had already expired on the day the library was built. Anything that expired later still passes; only updating the app closes that gap
- Why not ask the internet for the time? A hostile Wi-Fi can fake the answer, and setting the PSP's clock needs a kernel module
- **Asking the player:** after a refused connection, `https_doubt_take()` tells you the server and why (expired or unknown issuer); if the player agrees, call `https_doubt_accept()` and try again

</details>

<details>
<summary><b>The seed</b> · why a sweep, what counts</summary>

- A PSP has no random number generator an app can use, and TLS needs 128 bits nobody can guess. So the player makes them
- Only what nobody could predict counts: a turn in a new direction at an unexpected moment, a button nobody expected. Circles, turbo buttons, holding a button count nothing
- Honest players need about 18 seconds, by stick or by buttons
- The seed is saved in a 32-byte file and replaced on every start
- Your own sweep screen: call `sweep_step()` every frame with the pad, draw `struct sweep`, show `sweep_get_percent()`; PSPDX draws water with it

</details>

<details>
<summary><b>Threads</b> · who may call what</summary>

- Downloads: `https_net_connect`, `https_get` and the settings from one thread at a time
- Anytime, from anywhere: `https_abort`, `https_get_phase`, `https_get_last_info`
- The sweep and `entropy_init` from your main thread
- Every function in `include/pspkit-https/` says this at its declaration

</details>

<details>
<summary><b>From source</b> · submodule, own wolfSSL build</summary>

To change the library or build it yourself, pin a release tag as a submodule
instead of the zip:

```sh
git submodule add https://github.com/chriopter/pspkit-https lib/pspkit-https
git -C lib/pspkit-https checkout v0.1.0
git submodule update --init --recursive
cd lib/pspkit-https
docker run --rm -v "$PWD:/src" -w /src \
    pspdev/pspdev:latest sh tools/build-wolfssl
```

```make
include lib/pspkit-https/module.mk
```

Updating is `git -C lib/pspkit-https checkout v0.2.0` and a commit; build
wolfSSL again when its version changed.

</details>

<details>
<summary><b>Development</b> · build, demo, tests</summary>

| Command | What it does |
|---|---|
| `tools/build-wolfssl` | Builds wolfSSL 5.9.2 for the PSP |
| `tools/package/build VERSION` | Builds the release zip; a `v*` tag does it on GitHub |
| `demo/run` | Builds the demo and starts it in PPSSPP (`--fresh` starts with a sweep) |
| `tests/nettest/run` | Measures download speed over a local connection |
| `ca/update` | Fetches the newest root certificates |
| `tools/entropy-sim` | Tests the seed counting against lazy input on the PC |

</details>

<details>
<summary><b>Credits</b></summary>

- [wolfSSL](https://github.com/wolfSSL/wolfssl), GPL-2.0; its PSP build started from pspdev's [psp-packages](https://github.com/pspdev/psp-packages)
- Root certificates: Mozilla, via [curl](https://curl.se/docs/caextract.html)
- pspkit-https is GPL-2.0

</details>
