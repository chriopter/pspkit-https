# pspkit-https

**Modern HTTPS for PSP homebrew** — TLS 1.3, all of Mozilla's roots, and a
seed made by the player's hands. Taken out of
[PSPDX](https://github.com/chriopter/pspdx). **[→ Demo](demo/)**

## How to use

Add it, build wolfSSL once, include it, fetch.

```sh
git submodule add https://github.com/chriopter/pspkit-https lib/pspkit-https
git submodule update --init --recursive
docker run --rm -v "$PWD/lib/pspkit-https:/src" -w /src pspdev/pspdev:latest sh tools/build-wolfssl
```

In the Makefile, before `build.mak`:

```make
include lib/pspkit-https/module.mk
```

```c
#include "pspkit-https/entropy.h"
#include "pspkit-https/https.h"
#include "pspkit-https/sweep.h"

entropy_set_seed_file("ms0:/PSP/GAME/MYAPP/seed.bin");
entropy_init();
if (!entropy_load()) sweep_ascii_run();     /* the first start sweeps */
entropy_save(0);

https_net_connect();                        /* also starts parsing the roots */
https_get("https://example.org/", sink, ctx, NULL, NULL, &result);
```

[`demo/`](demo/) is exactly that on one screen. Tested in PPSSPP so far.

## How it works

**HTTPS**

- wolfSSL, TLS 1.3 only, X25519, ChaCha20-Poly1305 first
- GET with redirects, keep-alive per host, bodies of any size into a callback,
  progress, abort from any thread

**Trust**

- All of Mozilla's roots, pinned, checked for updates every week
- Chain and hostname always checked
- Dates only against the day the library was built, because a PSP's clock is
  usually wrong
- An expired certificate, or one from an unknown issuer, asks the player
  instead of failing

**The seed**

- A PSP has no random generator an app can reach, so the player makes one:
  steer the analog stick, smash buttons
- Only what nobody could have predicted counts; 128 bits take about 18 seconds
- Kept in a file afterwards, so later starts skip the sweep

Not a perfect TLS 1.3, on purpose: a PSP has no trustworthy clock, no root
store, no way to update either, and may have sat in a drawer for years. The
goal is that it still connects.

## Under the hood

<details>
<summary><b>TLS</b> · suites, requests, limits</summary>

#### Suites

- `TLS13-CHACHA20-POLY1305-SHA256`, then `TLS13-AES128-GCM-SHA256` for a server
  without ChaCha
- The PSP's CPU has no AES instructions: 5 MB take 1.3 s with ChaCha and 4.8 s
  with AES-GCM (PPSSPP)
- X25519 key share sent up front: five exchanges take 154 ms against 1032 ms
  for P-256, and no extra round trip
- `https_set_cipher_suites()` changes the order

#### Requests

```text
https_net_connect  ->  Wi-Fi profile 1  ->  IP
                   ->  meanwhile, the roots are parsed on a thread
https_get          ->  DNS -> connect -> TLS 1.3 -> GET -> body into the sink
                   ->  3xx: up to five redirects, never down to http://
```

- Up to three idle connections kept for 30 s, reused per host
- `https_abort()` from any thread stops at the next wait: connecting, the
  handshake, sending or the next piece of body
- `https_get_phase()` says what is happening, for a status line
- `https_set_rate_limit()` holds downloads to a PSP radio's speed in an emulator

#### Not supported

- `Transfer-Encoding: chunked`, POST, IPv6, plain `http://`
- More than one request at a time
- Roots of your own

</details>

<details>
<summary><b>Certificates</b> · roots, dates, questions</summary>

#### Roots

```text
ca/update    ->  cacert.pem from curl  ->  checked against curl's SHA-256
             ->  which roots came and went  ->  src/ca_bundle.h
ca/generate  ->  the DER table from the pinned file, refusing a file that does not match its pin
```

- Mozilla's store as curl publishes it, taken whole: 121 roots
- Every Monday a workflow runs `ca/update`; when the roots changed it opens a
  pull request, or refreshes the one still open
- One wolfSSL context for the run; the roots are parsed once, on a thread
  `https_net_connect` starts (38 ms in PPSSPP)
- Not cached between runs: wolfSSL 5.9.2's saved certificate cache did not
  restore every signer whole, and a restored store failed a chain the parsed
  one passed
- Intermediates a verified chain brought stay until `https_net_disconnect()`

#### Dates

- A PSP's clock is set by hand and resets to 2000 when the battery dies, so
  certificate dates cannot be held against it
- The floor is the day the library was built: a certificate that had already
  expired then is a question for the player; one that expired later passes
- That gap grows with the age of the build, and only an update closes it
- No network time: NTP and a server's Date header can be forged by the access
  point, Roughtime can be dropped by it, and setting the PSP's clock needs a
  kernel module

#### Questions

```text
handshake refused  ->  https_doubt_take(host)  ->  EXPIRED or ISSUER
                   ->  ask the player  ->  https_doubt_accept()  ->  request again
```

- Accepted per host, up to eight hosts, until `https_net_disconnect()`
- What always fails: a bad signature, the wrong hostname

</details>

<details>
<summary><b>Seed</b> · sweep, buttons, pool, file</summary>

#### Sweep

```c
struct sweep s = SWEEP_START;
for (;;) {
    sceCtrlReadBufferPositive(&pad, 1);
    unsigned events = sweep_step(&s, pad.Lx, pad.Ly, pad.Buttons);  /* every frame */
    draw_source(s.x, s.z, s.moving);          /* whatever the picture is */
    if (events & SWEEP_PRESSED) celebrate(events & SWEEP_PRESS_PAID);
    draw_bar(sweep_get_percent());            /* 100 once there are 128 bits */
}
```

- `sweep_ascii_run()` is the plainest screen: dots, the source, cells a press
  flips, a bar, and the last turns and presses with what they paid
- PSPDX draws water and falling stars with the same calls
- `entropy_get_last_turn()` and `entropy_get_last_press()` say what the count
  made of each one
- START ends a full sweep, SELECT leaves a second one

#### What counts

- **Turns:** a heading held for three samples, at least 15° off the last one,
  still held a sixth of a second later. Predictors guess its direction and its
  moment; each part nobody guessed pays up to 3 bits. Walls, flicks and
  circles pay nothing
- **Presses:** a button going down. Predictors guess which and when; up to 2
  bits each. Chords, presses under five frames apart and held buttons pay
  nothing; at most 11.25 bits a second
- START, SELECT and HOME never count
- Honest hands, simulated: stick 18.6 s, buttons 17.3 s (median)
- A heuristic lower bound against lazy hands, not proof: a script that plays
  randomly cannot be told from a player

#### Pool and file

- A SHA-256 pool; wolfSSL gets no seed until it has been full once
- `entropy_save()` writes a 32-byte seed derived from the pool;
  `entropy_load()` takes it and writes a successor at once, so a crashed run
  does not leave the next one starting from the same seed
- Packet timing, battery readings and every sample are stirred in, uncounted
- Whoever holds the Memory Stick holds the seed: nothing an app can reach on
  a PSP keeps a secret from them
- Not used: the PSP's KIRK chip. Its random numbers need a kernel module and
  come from a deterministic generator seeded once at boot

</details>

<details>
<summary><b>Threads</b> · who calls what</summary>

- **One network worker:** `https_net_connect`, `https_net_disconnect`,
  `https_get` and the setters, never at the same time
- **Any thread:** `https_abort`, `https_close_idle`, `https_get_phase`,
  `https_get_last_info`, the doubt calls (one owner for the questions)
- **The entropy owner:** `entropy_init`, `entropy_stash`, `entropy_restore`,
  `entropy_forget`, `sweep_step`
- **Any thread after init:** the entropy getters, `entropy_stir`,
  `entropy_load`, `entropy_save`
- The log callback may run on two threads at once and must not call the library

Every declaration in [`include/pspkit-https/`](include/pspkit-https/) says
what it may be called from and what it returns.

</details>

## Development

<details>
<summary><b>Build and run</b> · Docker, PPSSPP</summary>

#### Build

```sh
git submodule update --init
docker run --rm -v "$PWD:/src" -w /src pspdev/pspdev:latest sh tools/build-wolfssl
```

- wolfSSL 5.9.2 from the `wolfssl/` submodule into `build/wolfssl`
- Build flags on top of upstream: the seed hook, alternative chains, 4096-bit
  RSA, the library's own socket IO
- Another wolfSSL: `git -C wolfssl fetch --depth 1 origin tag vX.Y.Z-stable`,
  check it out, build again

#### Run in the emulator

```text
demo/run            ->  build  ->  PPSSPP  ->  seed from the stick if there is one
demo/run --fresh    ->  the same, sweep first
tests/nettest/run   ->  loopback servers  ->  5 MB plain and over both suites
```

- Needs Docker and the PPSSPP Flatpak, and no other PPSSPP running

</details>

<details>
<summary><b>Code layout</b> · include, src, ca, tools</summary>

| Location | Responsibility |
|---|---|
| `include/pspkit-https/` | The three headers an app includes: `https.h`, `entropy.h`, `sweep.h` |
| `src/https.c` | Sockets, TLS, redirects, roots and certificate questions |
| `src/entropy.c`, `src/entropy_internal.h` | The pool, the seed file, and how turns and presses are counted |
| `src/sweep.c`, `src/sweep_ascii.c` | Stick and buttons into the pool, and the plainest sweep screen |
| `src/ca_bundle.h` | Generated by `ca/generate` |
| `ca/` | The pinned root store and the scripts around it |
| `wolfssl/` | wolfSSL, a submodule pinned to a release tag |
| `tools/build-wolfssl` | Builds wolfSSL for the PSP |
| `tools/entropy-sim/` | The counting on the host: attacks, simulated hands, a report |
| `module.mk` | What an app's Makefile includes |
| `demo/` | Sweep, fetch, the handshake on screen |
| `tests/nettest/` | Loopback throughput with a throwaway CA |
| `.github/workflows/` | The weekly trust-store check |

</details>

<details>
<summary><b>Entropy simulation</b> · attacks, hands, report</summary>

```sh
cd tools/entropy-sim && make && ./sim selftest
python3 report.py compute WORK ../../../pspdx/dev/testdata
python3 report.py render WORK entropy-report.html
```

- The selftest: a pool never full gives no seed, circles and turbo buttons stay
  short, seed files rotate
- The report: every lazy pattern and simulated hand through the counting, and
  what wolfSSL would get as bitmaps and statistics

</details>

## Credits

- [wolfSSL](https://github.com/wolfSSL/wolfssl), GPL-2.0
- The wolfSSL build started from the `wolfssl` PSPBUILD in pspdev's
  [psp-packages](https://github.com/pspdev/psp-packages): the same toolchain
  file and cmake options
- The roots: Mozilla, as extracted by [curl](https://curl.se/docs/caextract.html)

GPL-2.0, like wolfSSL.
