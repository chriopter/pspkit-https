/* Drives the library's own entropy.c and sweep.c -- compiled unchanged
   against the stubs -- with recorded or simulated traces of the stick and
   the buttons. Built against a sweep.h without button flags (the hardened copy)
   it plays the stick alone.

   sim run TRACE [--broken]
       One sweep, the whole trace. JSON on stdout: the frame of every paid
       turn with the bits after it, the frame the bar filled, and the path of
       the source (every second frame) for the pictures.
   sim seeds LIST [--broken] [--draws K]
       For every trace named in LIST: forget, init, sweep until the bar is
       full, then K draws of 64 bytes as wolfSSL would take them and the seed
       file a save writes. One line per sweep: frames, the draws in hex, the
       file in hex.
   sim selftest
       The pool's promises, checked: no draw before full, the stash keeps the
       draw, no save before full, load rolls the file forward, a 20-byte file
       is refused, stir takes every byte; and the cheap patterns -- a
       circling stick, two headings swapped every six frames, a stroke along
       22.5 degrees trembling by a count -- do not fill the bar in half a
       minute, well past what an honest hand needs (about eighteen seconds);
       nor do the cheap ways with buttons: turbo at 10, 12, 15 and 30 Hz, two
       buttons swapped, all ten in a round, a chord hammered, a button held,
       a circling stick with turbo on top; while a hand pressing buttons at
       random does fill it. That the broken pool is
       deterministic is checked by report.py, across two processes: the draw
       counter deliberately survives entropy_forget. */
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "pspkit-https/entropy.h"
#include "pspkit-https/sweep.h"
#include "sim.h"
#include "wolfssl_seed.h"

/* The frozen comparison keeps its original API. */
#ifndef SWEEP_PRESSED
#define entropy_set_seed_file entropy_seed_file
#define entropy_get_bits entropy_bits
#define entropy_get_stashed entropy_stashed
#endif

static void stick_frame(struct sweep *s, unsigned char lx, unsigned char ly) {
#ifdef SWEEP_PRESSED
    sweep_step(s, lx, ly, 0);
#else
    sweep_step(s, lx, ly);
#endif
}

static unsigned char *load(const char *path, long *frames) {
    FILE *f = fopen(path, "rb");
    if (!f) { perror(path); exit(1); }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    unsigned char *buf = malloc((size_t)n + 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { perror(path); exit(1); }
    fclose(f);
    *frames = n / 4;
    return buf;
}

static char seed_path[256];

/* One frame of a trace through whatever the sweep takes; what it did. */
static int frame(struct sweep *s, const unsigned char *t) {
#ifdef SWEEP_PRESSED
    return sweep_step(s, t[0], t[1], (unsigned)t[2] | (unsigned)t[3] << 8);
#else
    sweep_step(s, t[0], t[1]);
    return 0;
#endif
}

static void hex(const unsigned char *b, int n) {
    for (int i = 0; i < n; i++) printf("%02x", b[i]);
}

static int run(const char *path) {
    long frames;
    unsigned char *t = load(path, &frames);
    struct sweep s = SWEEP_START;
    entropy_forget();
    entropy_init();
    printf("{\"frames\":%ld,\"credits\":[", frames);
    long full = -1;
    int first = 1;
    for (long i = 0; i < frames; i++) {
        sim_frame();
        int before = entropy_get_bits();
        int what = frame(&s, t + 4 * i);
        int after = entropy_get_bits();
        if (after != before) {
            /* The last field: 1 the stick paid, 2 a press did, 3 both. */
            int kind = (what & 4 ? 2 : 0) | (what & 4 ? (what & 1) : 1);
            printf("%s[%ld,%d,%.4f,%.4f,%d]", first ? "" : ",", i, after, s.x, s.z, kind);
            first = 0;
        }
        if (full < 0 && after >= ENTROPY_BITS) full = i;
    }
    printf("],\"full\":%ld,\"bits\":%d,\"path\":[", full, entropy_get_bits());
    struct sweep p = SWEEP_START;
    /* The path again, without the pool: sweep_step's geometry only. */
    entropy_forget();
    entropy_init();
    for (long i = 0; i < frames; i++) {
        stick_frame(&p, t[4 * i], t[4 * i + 1]);
        if (i % 2 == 0) printf("%s[%.4f,%.4f]", i ? "," : "", p.x, p.z);
    }
    printf("]}\n");
    free(t);
    return 0;
}

static int seeds(const char *list, int draws) {
    FILE *f = fopen(list, "r");
    if (!f) { perror(list); return 1; }
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (!line[0]) continue;
        long frames;
        unsigned char *t = load(line, &frames);
        struct sweep s = SWEEP_START;
        entropy_forget();
        entropy_init();
        long i = 0;
        for (; i < frames && entropy_get_bits() < ENTROPY_BITS; i++) {
            sim_frame();
            frame(&s, t + 4 * i);
        }
        printf("%ld ", entropy_get_bits() >= ENTROPY_BITS ? i : -1);
        for (int d = 0; d < draws; d++) {
            unsigned char out[64];
            if (pspkit_https_seed(out, sizeof(out)) != 0) memset(out, 0, sizeof(out));
            hex(out, 64);
        }
        printf(" ");
        entropy_save(0);
        unsigned char file[33];
        FILE *sf = fopen(seed_path, "rb");
        size_t got = sf ? fread(file, 1, 33, sf) : 0;
        if (sf) fclose(sf);
        if (got == 32) hex(file, 32); else printf("-");
        printf("\n");
        free(t);
    }
    fclose(f);
    return 0;
}

static int fails;
#define CHECK(what, cond) do { int ok_ = (cond); printf("%s  %s\n", ok_ ? "ok  " : "FAIL", what); fails += !ok_; } while (0)

static void sweep_full(uint64_t seed) {
    /* A crude hand good enough for the self test: random headings, a few
       frames each. */
    struct sweep s = SWEEP_START;
    uint64_t st = seed;
    for (int i = 0; i < 60 * 600 && entropy_get_bits() < ENTROPY_BITS; i++) {
        st = st * 6364136223846793005ull + 1442695040888963407ull;
        static int lx = 128, ly = 128, left = 0;
        if (left-- <= 0) {
            lx = 128 + (int)((st >> 33) % 255) - 127;
            ly = 128 + (int)((st >> 41) % 255) - 127;
            left = 6 + (int)((st >> 20) % 20);
        }
        sim_frame();
        stick_frame(&s, (unsigned char)lx, (unsigned char)ly);
    }
}

/* Pushes the stick at angle th (0 right, counter-clockwise, up is away) for
   one frame. */
static void push(struct sweep *s, double th, int jitter) {
    int lx = 128 + (int)lround(127 * cos(th)), ly = 128 - (int)lround(127 * sin(th));
    if (jitter) {
        lx += (int)(sim_rand() % 3) - 1;
        ly += (int)(sim_rand() % 3) - 1;
    }
    lx = lx < 0 ? 0 : lx > 255 ? 255 : lx;
    ly = ly < 0 ? 0 : ly > 255 ? 255 : ly;
    sim_frame();
    stick_frame(s, (unsigned char)lx, (unsigned char)ly);
}

/* A pattern for half a minute from a fresh count; the bits it reached. */
static int pattern(int which) {
    struct sweep s = SWEEP_START;
    double dx = 1, dz = 1;
    entropy_forget();
    entropy_init();
    for (int i = 0; i < 30 * 60; i++) {
        if (s.x >= 0.99f) dx = -1;
        if (s.x <= 0.01f) dx = 1;
        if (s.z >= 0.99f) dz = -1;
        if (s.z <= 0.01f) dz = 1;
        double th;
        if (which == 0) th = 2 * M_PI * i / 40;
        else if (which == 1) th = (i / 6) % 2 ? M_PI / 4 : 0;
        else th = M_PI / 8;
        if (which != 0) th = atan2(sin(th) * dz, cos(th) * dx);
        push(&s, th, which == 2);
    }
    return entropy_get_bits();
}

#ifdef SWEEP_PRESSED
static const unsigned face[4] = { 0x1000, 0x2000, 0x4000, 0x8000 };
static const unsigned all_ten[10] = { 0x10, 0x20, 0x40, 0x80, 0x1000, 0x2000, 0x4000, 0x8000, 0x100, 0x200 };

/* The buttons of a cheap pattern at frame i. */
static unsigned cheap_buttons(int which, int i) {
    switch (which) {
    case 0: return i % 6 < 3 ? 0x4000 : 0;                          /* turbo 10 Hz */
    case 1: return i % 5 < 2 ? 0x4000 : 0;                          /* turbo 12 Hz */
    case 2: return i % 4 < 2 ? 0x4000 : 0;                          /* turbo 15 Hz */
    case 3: return i % 2 < 1 ? 0x4000 : 0;                          /* turbo 30 Hz */
    case 4: return i % 8 < 3 ? ((i / 8) % 2 ? 0x2000 : 0x4000) : 0; /* cross, circle, 7.5 Hz */
    case 5: return i % 6 < 3 ? all_ten[(i / 6) % 10] : 0;           /* all ten round, 10 Hz */
    case 6: return i % 8 < 3 ? face[0] | face[1] | face[2] | face[3] : 0; /* chord */
    case 7: return 0x4000;                                          /* held */
    default: return i % 4 < 2 ? 0x4000 : 0;                         /* with a circling stick */
    }
}

static const char *cheap_name[] = {
    "turbo at 10 Hz", "turbo at 12 Hz", "turbo at 15 Hz", "turbo at 30 Hz",
    "two buttons swapped at 7.5 Hz", "all ten buttons in a round", "a chord hammered",
    "a button held", "a circling stick with turbo",
};

static int cheap_pad(int which) {
    struct sweep s = SWEEP_START;
    entropy_forget();
    entropy_init();
    for (int i = 0; i < 30 * 60; i++) {
        double th = 2 * M_PI * i / 40;
        int circling = which == 8;
        unsigned char lx = circling ? (unsigned char)(128 + lround(127 * cos(th))) : 128;
        unsigned char ly = circling ? (unsigned char)(128 - lround(127 * sin(th))) : 128;
        sim_frame();
        sweep_step(&s, lx, ly, cheap_buttons(which, i));
    }
    return entropy_get_bits();
}

/* Buttons by lot, a button a lot and a gap of 6 to 13 frames: no hand, but
   what a counter has to pay for, since it cannot be told from one. */
static int random_presses(uint64_t seed) {
    struct sweep s = SWEEP_START;
    entropy_forget();
    entropy_init();
    uint64_t st = seed;
    int next = 10, held = 0, i;
    unsigned button = 0;
    for (i = 0; i < 120 * 60 && entropy_get_bits() < ENTROPY_BITS; i++) {
        if (i == next) {
            st = st * 6364136223846793005ull + 1442695040888963407ull;
            button = all_ten[(st >> 33) % 10];
            next = i + 6 + (int)((st >> 41) % 8);
            held = 3;
        }
        sim_frame();
        sweep_step(&s, 128, 128, held-- > 0 ? button : 0);
    }
    return i;
}
#endif

static int file_bytes(unsigned char *buf, int max) {
    FILE *f = fopen(seed_path, "rb");
    if (!f) return -1;
    int n = (int)fread(buf, 1, (size_t)max, f);
    fclose(f);
    return n;
}

static int selftest(void) {
    unsigned char a[64], b[64], f1[40], f2[40];
    unlink(seed_path);
    entropy_forget();
    entropy_init();
#ifdef SWEEP_PRESSED
    entropy_allow_unswept();
    entropy_forget();
    CHECK("forget clears the test waiver", pspkit_https_seed(a, 64) != 0);
    struct sweep events = SWEEP_START;
    struct entropy_press press;
    sweep_step(&events, 128, 128, 0);
    unsigned flags = sweep_step(&events, 128, 128, 0x30);
    entropy_get_last_press(&press);
    CHECK("first chord has an event number", flags == SWEEP_PRESSED && press.seq == 1 &&
          press.button == ENTROPY_BUTTON_NONE && press.verdict == ENTROPY_CHORD);
    sweep_step(&events, 128, 128, 0);
    sweep_step(&events, 128, 128, 0x30);
    entropy_get_last_press(&press);
    CHECK("successive chords have distinct numbers", press.seq == 2);
    entropy_init();
#endif
    CHECK("no draw from a pool never full", pspkit_https_seed(a, 64) != 0);
    CHECK("no save from a pool never full", entropy_save(0) != 0 && file_bytes(f1, 40) < 0);
    sweep_full(42);
    CHECK("a sweep fills the bar", entropy_get_bits() >= ENTROPY_BITS);
    CHECK("draw after a sweep", pspkit_https_seed(a, 64) == 0);
    CHECK("two draws differ", pspkit_https_seed(b, 64) == 0 && memcmp(a, b, 64) != 0);
    CHECK("no save when replaying", entropy_save(1) != 0 && file_bytes(f1, 40) < 0);
    CHECK("save writes 32 bytes", entropy_save(0) == 0 && file_bytes(f1, 40) == 32);

    entropy_stash();
    CHECK("stash removes the file", file_bytes(f2, 40) < 0);
    CHECK("stash counts from zero", entropy_get_bits() == 0 && entropy_get_stashed());
    CHECK("draw still allowed during a stashed sweep", pspkit_https_seed(a, 64) == 0);
    CHECK("save allowed during a stashed sweep", entropy_save(0) == 0 && file_bytes(f2, 40) == 32);
    entropy_restore();
    CHECK("restore puts the count back", entropy_get_bits() >= ENTROPY_BITS && !entropy_get_stashed());
    entropy_restore();
    CHECK("restore without stash changes nothing", entropy_get_bits() >= ENTROPY_BITS);

    entropy_forget();
    entropy_init();
    CHECK("forget: no draw", pspkit_https_seed(a, 64) != 0 && file_bytes(f2, 40) < 0);
    FILE *w = fopen(seed_path, "wb");
    fwrite(f1, 1, 32, w);
    fclose(w);
    CHECK("load takes a 32-byte file", entropy_load() == 1 && entropy_get_bits() == ENTROPY_BITS);
    CHECK("load rolls the file forward", file_bytes(f2, 40) == 32 && memcmp(f1, f2, 32) != 0);
    CHECK("draw after load", pspkit_https_seed(a, 64) == 0);

    entropy_forget();
    entropy_init();
    w = fopen(seed_path, "wb");
    fwrite("PSPDX-TEST-SEED-0000", 1, 20, w);
    fclose(w);
    CHECK("a 20-byte file is refused", entropy_load() == 0 && pspkit_https_seed(a, 64) != 0);
    unlink(seed_path);

    {
        char what[96];
        int b = pattern(0);
        snprintf(what, sizeof(what), "a circling stick stays short for 30 s (%d bits)", b);
        CHECK(what, b < ENTROPY_BITS);
        b = pattern(1);
        snprintf(what, sizeof(what), "two headings swapped every 6 frames stay short for 30 s (%d bits)", b);
        CHECK(what, b < ENTROPY_BITS);
        b = pattern(2);
        snprintf(what, sizeof(what), "a trembling stroke along 22.5 degrees stays short for 30 s (%d bits)", b);
        CHECK(what, b < ENTROPY_BITS);
        entropy_forget();
    }
#ifdef SWEEP_PRESSED
    {
        char what[112];
        for (int which = 0; which < 9; which++) {
            int b = cheap_pad(which);
            snprintf(what, sizeof(what), "%s stays short for 30 s (%d bits)", cheap_name[which], b);
            CHECK(what, b < ENTROPY_BITS);
        }
        int frames = random_presses(7);
        snprintf(what, sizeof(what), "random presses fill the bar (%.1f s)", frames / 60.0);
        CHECK(what, entropy_get_bits() >= ENTROPY_BITS);
        struct entropy_press press;
        entropy_get_last_press(&press);
        CHECK("the latest press is on record", press.seq > 0 && press.button >= 0 && press.button < ENTROPY_BUTTONS);
        entropy_forget();
    }
#endif

    /* stir takes every byte: two stirs that differ only past byte 64 must
       leave different pools. */
    int saved = sim_broken;
    sim_broken = 1;
    unsigned char big[200];
    memset(big, 7, sizeof(big));
    uint64_t clock0 = sim_clock_us;
    entropy_forget(); sim_clock_us = clock0; entropy_init(); entropy_allow_unswept();
    entropy_stir(big, sizeof(big));
    CHECK("first stir seed succeeds", pspkit_https_seed(a, 64) == 0);
    big[150] = 8;
    entropy_forget(); sim_clock_us = clock0; entropy_init();
    entropy_allow_unswept();
    entropy_stir(big, sizeof(big));
    CHECK("second stir seed succeeds", pspkit_https_seed(b, 64) == 0);
    CHECK("stir reads past 64 bytes", memcmp(a, b, 64) != 0);
    sim_broken = saved;
    entropy_forget();
#ifdef SWEEP_PRESSED
    entropy_init();
    sweep_full(42);
    CHECK("seed before hash fault is saved", entropy_save(0) == 0 && file_bytes(f1, 40) == 32);
    sim_hash_fail = 1;
    CHECK("failed derivation is not saved", entropy_save(0) == -1 && file_bytes(f2, 40) == 32 &&
          memcmp(f1, f2, 32) == 0);
    CHECK("hash fault closes the seed gate", pspkit_https_seed(a, 64) != 0);
    CHECK("broken pool cannot report a successful load", entropy_load() == 0);
    entropy_forget();
#endif
    return fails ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: sim run TRACE | seeds LIST [--draws K] | selftest  [--broken] [--rng N]\n");
        return 2;
    }
    int draws = 1;
    uint64_t rng = 0;
    FILE *u = fopen("/dev/urandom", "rb");
    if (u && fread(&rng, sizeof(rng), 1, u) != 1) rng = 1;
    if (u) fclose(u);
    for (int i = 2; i < argc; i++) {
        if (!strcmp(argv[i], "--broken")) sim_broken = 1;
        else if (!strcmp(argv[i], "--draws") && i + 1 < argc) draws = atoi(argv[++i]);
        else if (!strcmp(argv[i], "--rng") && i + 1 < argc) rng = strtoull(argv[++i], NULL, 0);
    }
    sim_seed_rng(rng);
    snprintf(seed_path, sizeof(seed_path), "/tmp/entropy-sim-seed-%d.bin", (int)getpid());
    entropy_set_seed_file(seed_path);
    int r;
    if (!strcmp(argv[1], "run") && argc > 2) r = run(argv[2]);
    else if (!strcmp(argv[1], "seeds") && argc > 2) r = seeds(argv[2], draws);
    else if (!strcmp(argv[1], "selftest")) r = selftest();
    else r = 2;
    unlink(seed_path);
    return r;
}
