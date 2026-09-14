/* The pool: a SHA-256 state that what the device cannot predict is folded
   into, and wolfSSL's seed is drawn from, and the count of what a sweep put
   into it. entropy.h says what is counted and why. */
#include <pspkernel.h>
#include <pspiofilemgr.h>
#include <psprtc.h>
#include <stdio.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "pspkit-https/entropy.h"
#include "wolfssl_seed.h"

/* SHA-256 rather than the kernel's SHA-1: wolfCrypt is linked anyway and its
   DRBG is SHA-256 itself, the state holds 256 bits instead of 160, and
   nobody has to argue why a broken collision resistance does not matter to a
   pool. At one or two blocks per call it costs nothing next to a frame. */
#define POOL_BYTES WC_SHA256_DIGEST_SIZE
#define SEED_BYTES POOL_BYTES

/* The count is kept in sixteenths of a bit: a turn pays between 23 and 32. */
#define UNITS 16
#define FULL (ENTROPY_BITS * UNITS)

static unsigned char pool[POOL_BYTES];
static unsigned int pool_counter;
static int pool_units;
static int pool_broken;         /* a hash failed: nothing is drawn from here on */
static int pool_filled;         /* full once since the last forget */
static int unswept_allowed;
static int stash_units = -1;
static const char *seed_file;

/* The network runs on a thread of its own while a sweep may run on another:
   two threads reach the pool, and through entropy_save two could reach the
   file. The pool lock is taken per operation and never across a write to
   the stick, so a handshake waits neither on a hand at the stick nor on the
   memory stick. The file lock serialises everything that reads, writes or
   removes the seed file, and is always taken before the pool lock. */
static SceUID pool_sema = -1;
static SceUID file_sema = -1;

static void pool_lock(void) {
    if (pool_sema >= 0) sceKernelWaitSema(pool_sema, 1, NULL);
}

static void pool_unlock(void) {
    if (pool_sema >= 0) sceKernelSignalSema(pool_sema, 1);
}

static void file_lock(void) {
    if (file_sema >= 0) sceKernelWaitSema(file_sema, 1, NULL);
}

static void file_unlock(void) {
    if (file_sema >= 0) sceKernelSignalSema(file_sema, 1);
}

/* What each input or output of the pool is, hashed in with it together with
   its length: no input can pass for another kind, two inputs can never run
   together into a third, and an output can never be an input replayed. */
enum {
    IN_INIT = 1,
    IN_JITTER,
    IN_SAMPLE,
    IN_STIR,
    IN_LOAD,
    IN_DRAW,
    OUT_SEED,
    OUT_NEXT,
    OUT_FILE,
};

/* SHA-256 of the pool, the kind, the length and the data, into out -- which
   may be the pool itself: the pool is read in full before out is written. */
static void pool_hash(unsigned char *out, unsigned char kind, const void *data, unsigned int len) {
    wc_Sha256 sha;
    unsigned char head[5] = {
        kind, (unsigned char)len, (unsigned char)(len >> 8),
        (unsigned char)(len >> 16), (unsigned char)(len >> 24),
    };
    int ret = wc_InitSha256(&sha);
    if (ret == 0) ret = wc_Sha256Update(&sha, pool, POOL_BYTES);
    if (ret == 0) ret = wc_Sha256Update(&sha, head, sizeof(head));
    if (ret == 0 && len) ret = wc_Sha256Update(&sha, (const unsigned char *)data, len);
    if (ret == 0) ret = wc_Sha256Final(&sha, out);
    wc_Sha256Free(&sha);
    if (ret != 0) pool_broken = 1;
}

static void pool_absorb(unsigned char kind, const void *data, unsigned int len) {
    pool_hash(pool, kind, data, len);
}

static void pool_absorb_jitter(int rounds) {
    for (int i = 0; i < rounds; i++) {
        unsigned t0 = sceKernelGetSystemTimeLow();
        unsigned spins = 0;
        while (sceKernelGetSystemTimeLow() - t0 < 500) spins++;
        pool_absorb(IN_JITTER, &spins, sizeof(spins));
    }
}

/* ------------------------------------------------------------ seed file */

/* Replaced so that a cut loses nothing: the new seed goes to .new, the old
   one steps aside to .bak, the new one takes the name, and only then does
   the .bak go. A .bak with no file beside it is the seed a cut write left
   behind, and takes its name back before anything reads or writes. All of
   it runs under the file lock. */

static int exists(const char *path) {
    SceIoStat st;
    return sceIoGetstat(path, &st) >= 0;
}

static const char *base_name(const char *path) {
    const char *slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

/* The device a path is on, "ms0:" out of "ms0:/PSP/...", for sceIoSync;
   empty when the path names none. */
static void device_of(const char *path, char *out, size_t size) {
    const char *colon = strchr(path, ':');
    size_t n = colon && (size_t)(colon - path) + 1 < size ? (size_t)(colon - path) + 1 : 0;
    memcpy(out, path, n);
    out[n] = '\0';
}

static int bak_of(char *out, size_t size) {
    return snprintf(out, size, "%s.bak", seed_file) < (int)size;
}

static void recover(const char *bak) {
    if (!exists(seed_file) && exists(bak)) sceIoRename(bak, base_name(seed_file));
}

static int seed_read(unsigned char *out) {
    char bak[256];
    if (!seed_file || !bak_of(bak, sizeof(bak))) return 0;
    recover(bak);
    SceUID fd = sceIoOpen(seed_file, PSP_O_RDONLY, 0777);
    if (fd < 0) return 0;
    unsigned char buf[SEED_BYTES + 1];
    int n = sceIoRead(fd, buf, sizeof(buf));    /* one more: a longer file is no seed */
    sceIoClose(fd);
    if (n != SEED_BYTES) return 0;
    memcpy(out, buf, SEED_BYTES);
    return 1;
}

static int seed_write(const unsigned char *seed) {
    char tmp[256], bak[256], dev[16];
    if (!seed_file || !bak_of(bak, sizeof(bak)) ||
        snprintf(tmp, sizeof(tmp), "%s.new", seed_file) >= (int)sizeof(tmp))
        return -1;
    recover(bak);
    device_of(seed_file, dev, sizeof(dev));
    SceUID fd = sceIoOpen(tmp, PSP_O_WRONLY | PSP_O_CREAT | PSP_O_TRUNC, 0777);
    if (fd < 0) return -1;
    int n = sceIoWrite(fd, seed, SEED_BYTES);
    if (sceIoClose(fd) < 0 || n != SEED_BYTES) {
        sceIoRemove(tmp);
        return -1;
    }
    if (dev[0] && sceIoSync(dev, 0) < 0) return -1;
    if (exists(bak) && sceIoRemove(bak) < 0) return -1;
    int had = exists(seed_file);
    if (had && sceIoRename(seed_file, base_name(bak)) < 0) return -1;
    if (sceIoRename(tmp, base_name(seed_file)) < 0) {
        if (had) sceIoRename(bak, base_name(seed_file));
        return -1;
    }
    if (dev[0] && sceIoSync(dev, 0) < 0) return -1;
    if (had) sceIoRemove(bak);
    return 0;
}

static void seed_remove(void) {
    char bak[256];
    if (!seed_file || !bak_of(bak, sizeof(bak))) return;
    sceIoRemove(bak);
    sceIoRemove(seed_file);
}

void entropy_seed_file(const char *path) { seed_file = path; }

/* ---------------------------------------------------------------- turns */

/* The predictors of entropy.h, in the order their scores are kept. A turn
   is its heading change, 1 to 7 in steps of 45 degrees counter-clockwise;
   0 is a predictor with no guess. */
enum {
    P_LAG1, P_LAG2, P_LAG3, P_LAG4,     /* the turn one to four turns back */
    P_COMMON,                           /* most common of the last sixteen */
    P_FOLLOW1, P_FOLLOW2, P_FOLLOW3,    /* what followed the last one, two, three turns */
    P_BACK2, P_BACK3, P_BACK4,          /* back to the heading two to four turns ago */
    PREDICTORS
};

#define RING 16

static struct {
    unsigned char run_heading;      /* the heading of the samples running now */
    unsigned char run_samples;
    unsigned char run_fields;       /* new fields among them */
    unsigned char heading;          /* the heading of the last turn, ENTROPY_STILL before the first */
    unsigned char walled;           /* a wall held the source back since the last turn */
    unsigned char owed;             /* sixteenths the last turn pays once it reaches new ground */
    unsigned int turns;
    unsigned int headings;
    unsigned char turn_ring[RING];
    unsigned char heading_ring[RING];
    unsigned short follow1[8][8];
    unsigned short follow2[64][8];
    unsigned short follow3[512][8];
    int score[PREDICTORS];          /* recent record, decaying by an eighth per turn */
    unsigned int hits[PREDICTORS];  /* whole record over the sweep */
    unsigned int guessed;           /* turns the guess actually made got right */
} sweep;

static unsigned char field_seen[(ENTROPY_FIELD_COUNT + 7) / 8];

static void sweep_reset(void) {
    memset(&sweep, 0, sizeof(sweep));
    sweep.run_heading = ENTROPY_STILL;
    sweep.heading = ENTROPY_STILL;
    memset(field_seen, 0, sizeof(field_seen));
}

/* The turn k turns back, k from 1; valid while k <= turns. */
static unsigned turn_back(unsigned k) {
    return sweep.turn_ring[(sweep.turns - k) & (RING - 1)];
}

static unsigned heading_back(unsigned k) {
    return sweep.heading_ring[(sweep.headings - k) & (RING - 1)];
}

/* The most frequent entry of a row, the lowest turn on a tie. */
static unsigned most_frequent(const unsigned short *row, unsigned *support) {
    unsigned best = 0, most = 0;
    for (unsigned v = 1; v < 8; v++)
        if (row[v] > most) {
            most = row[v];
            best = v;
        }
    *support = most;
    return best;
}

static void predict(unsigned char guess[PREDICTORS], unsigned support[PREDICTORS]) {
    unsigned n = sweep.turns;
    memset(guess, 0, PREDICTORS);
    memset(support, 0, PREDICTORS * sizeof(support[0]));

    for (unsigned k = 1; k <= 4; k++)
        if (n >= k) guess[P_LAG1 + k - 1] = (unsigned char)turn_back(k);

    if (n) {
        unsigned tally[8] = { 0 }, most = 0, window = n < RING ? n : RING;
        for (unsigned k = 1; k <= window; k++) tally[turn_back(k)]++;
        for (unsigned v = 1; v < 8; v++)
            if (tally[v] > most) most = tally[v];
        for (unsigned k = 1; k <= window; k++)          /* the most recent of the tied */
            if (tally[turn_back(k)] == most) {
                guess[P_COMMON] = (unsigned char)turn_back(k);
                break;
            }
    }

    if (n >= 1)
        guess[P_FOLLOW1] = (unsigned char)most_frequent(sweep.follow1[turn_back(1)], &support[P_FOLLOW1]);
    if (n >= 2)
        guess[P_FOLLOW2] = (unsigned char)most_frequent(
            sweep.follow2[turn_back(2) * 8 + turn_back(1)], &support[P_FOLLOW2]);
    if (n >= 3)
        guess[P_FOLLOW3] = (unsigned char)most_frequent(
            sweep.follow3[(turn_back(3) * 8 + turn_back(2)) * 8 + turn_back(1)], &support[P_FOLLOW3]);

    for (unsigned k = 2; k <= 4; k++)
        if (sweep.headings >= k)
            guess[P_BACK2 + k - 2] = (unsigned char)((heading_back(k) - heading_back(1)) & 7);
}

static unsigned isqrt_up(unsigned v) {
    unsigned r = 0;
    for (unsigned bit = 1u << 30; bit; bit >>= 2)
        if (r + bit <= v) {
            v -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
    return v ? r + 1 : r;
}

/* min(2, -log2 p / (1 - p)) in sixteenths, rounded down, for p = k / 32. */
static const unsigned char credit_for_p[33] = {
    32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32, 32,
    31, 30, 29, 28, 28, 27, 27, 26, 26, 25, 25, 24, 24, 23, 23, 23,
};

/* What an unguessed turn pays: p is how often the best of the guesses has
   been right over the sweep -- the one actually made, or the best single
   predictor in hindsight, whichever did better -- taken with one success
   and one failure added, raised to its 99% upper bound, and rounded up to a
   thirty-second. Every rounding goes against the count. */
static unsigned credit(void) {
    unsigned n = sweep.turns, right = sweep.guessed;
    for (int j = 0; j < PREDICTORS; j++)
        if (sweep.hits[j] > right) right = sweep.hits[j];
    unsigned p = ((right + 1) * 1024 + n + 1) / (n + 2);                 /* in 1024ths */
    unsigned spread = isqrt_up((p * (1024 - p) + n - 1) / n);            /* in 1024ths */
    unsigned upper = p + (2576 * spread + 999) / 1000;
    if (upper > 1024) upper = 1024;
    return credit_for_p[(upper + 31) >> 5];
}

static void turn_to(unsigned heading) {
    if (sweep.heading >= ENTROPY_HEADINGS) {
        /* The first heading of a sweep is where the hand starts, not a turn. */
        sweep.heading = (unsigned char)heading;
        sweep.heading_ring[sweep.headings++ & (RING - 1)] = (unsigned char)heading;
        sweep.walled = 0;
        return;
    }
    unsigned turn = (heading - sweep.heading) & 7;
    unsigned char guess[PREDICTORS];
    unsigned support[PREDICTORS];
    predict(guess, support);

    int winner = 0;
    for (int j = 1; j < PREDICTORS; j++)
        if (sweep.score[j] > sweep.score[winner]) winner = j;
    /* A context seen twice already calls its turn whoever is winning: it is
       what catches a hand that swaps one pattern for another faster than the
       scores can follow. */
    int guessed = guess[winner] == turn ||
                  (guess[P_FOLLOW3] == turn && support[P_FOLLOW3] >= 2) ||
                  (guess[P_FOLLOW2] == turn && support[P_FOLLOW2] >= 3);

    for (int j = 0; j < PREDICTORS; j++) {
        int hit = guess[j] == turn;
        sweep.score[j] += (hit ? 256 : 0) - (sweep.score[j] >> 3);
        sweep.hits[j] += (unsigned)hit;
    }

    /* The contexts this turn followed, read before the turn joins the ring. */
    unsigned n = sweep.turns;
    unsigned c1 = n >= 1 ? turn_back(1) : 0;
    unsigned c2 = n >= 2 ? turn_back(2) * 8 + c1 : 0;
    unsigned c3 = n >= 3 ? turn_back(3) * 64 + c2 : 0;
    if (n >= 1 && sweep.follow1[c1][turn] < 0xFFFF) sweep.follow1[c1][turn]++;
    if (n >= 2 && sweep.follow2[c2][turn] < 0xFFFF) sweep.follow2[c2][turn]++;
    if (n >= 3 && sweep.follow3[c3][turn] < 0xFFFF) sweep.follow3[c3][turn]++;
    sweep.turn_ring[n & (RING - 1)] = (unsigned char)turn;
    sweep.heading_ring[sweep.headings++ & (RING - 1)] = (unsigned char)heading;

    sweep.turns++;
    sweep.guessed += (unsigned)guessed;
    sweep.owed = (unsigned char)(guessed || sweep.walled ? 0 : credit());
    sweep.heading = (unsigned char)heading;
    sweep.walled = 0;
}

static int count_sample(unsigned heading, unsigned field, int walled) {
    if (walled) sweep.walled = 1;
    if (heading >= ENTROPY_HEADINGS || field >= ENTROPY_FIELD_COUNT) return 0;

    unsigned char bit = (unsigned char)(1u << (field & 7));
    int fresh = !(field_seen[field >> 3] & bit);
    field_seen[field >> 3] |= bit;

    if (heading != sweep.run_heading) {
        sweep.run_heading = (unsigned char)heading;
        sweep.run_samples = 0;
        sweep.run_fields = 0;
    }
    if (sweep.run_samples < 255) sweep.run_samples++;
    if (fresh && sweep.run_fields < 255) sweep.run_fields++;

    if (heading != sweep.heading && sweep.run_samples >= ENTROPY_TURN_SAMPLES) turn_to(heading);

    if (sweep.owed && sweep.run_heading == sweep.heading && sweep.run_fields >= ENTROPY_TURN_FIELDS) {
        pool_units += sweep.owed;
        sweep.owed = 0;
        if (pool_units >= FULL) {
            pool_filled = 1;
            stash_units = -1;       /* the new sweep's count is its own now */
        }
        return 1;
    }
    return 0;
}

/* ----------------------------------------------------------------- pool */

void entropy_init(void) {
    if (pool_sema < 0) pool_sema = sceKernelCreateSema("entropy", 0, 1, 1, NULL);
    if (file_sema < 0) file_sema = sceKernelCreateSema("entropy file", 0, 1, 1, NULL);
    /* The wall clock to the microsecond, the time since power-on and where the
       stack happens to be. A copied or rolled-back seed file meets a different
       moment than the run it was written for, so two runs from the same file
       do not start from the same pool; none of it is counted, since an
       observer knows the date and roughly when the PSP was switched on. */
    struct {
        u64 tick;
        unsigned int sys;
        void *sp;
    } boot;
    memset(&boot, 0, sizeof(boot));
    sceRtcGetCurrentTick(&boot.tick);
    boot.sys = sceKernelGetSystemTimeLow();
    boot.sp = &boot;
    pool_lock();
    pool_absorb(IN_INIT, &boot, sizeof(boot));
    pool_absorb_jitter(8);
    pool_units = 0;
    sweep_reset();
    pool_unlock();
}

int entropy_absorb_sample(unsigned char lx, unsigned char ly, unsigned int heading,
                          unsigned int field, int walled) {
    /* Every sample goes in, moving or not: the stick's own reading at rest
       wanders by a count or two, and when a frame reaches this call moves
       with everything the frame drew. Neither is counted. */
    struct {
        unsigned char lx, ly, heading, walled;
        unsigned int field, sys;
    } sample;
    sample.lx = lx;
    sample.ly = ly;
    sample.heading = (unsigned char)heading;
    sample.walled = (unsigned char)(walled != 0);
    sample.field = field;
    sample.sys = sceKernelGetSystemTimeLow();
    pool_lock();
    pool_absorb(IN_SAMPLE, &sample, sizeof(sample));
    int paid = count_sample(heading, field, walled);
    pool_unlock();
    return paid;
}

void entropy_stir(const void *data, unsigned int len) {
    unsigned int sys = sceKernelGetSystemTimeLow();
    pool_lock();
    pool_absorb(IN_STIR, data, len);
    pool_absorb(IN_STIR, &sys, sizeof(sys));
    pool_unlock();
}

int entropy_bits(void) {
    pool_lock();
    int bits = pool_units / UNITS;
    pool_unlock();
    return bits;
}

int entropy_load(void) {
    unsigned char stored[SEED_BYTES], next[SEED_BYTES];
    file_lock();
    if (!seed_read(stored)) {
        file_unlock();
        return 0;
    }
    pool_lock();
    pool_absorb(IN_LOAD, stored, SEED_BYTES);
    pool_absorb_jitter(4);
    pool_units = FULL;
    pool_filled = 1;
    pool_hash(next, OUT_FILE, NULL, 0);
    pool_unlock();
    /* If the successor cannot be written the pool still counts: the stick is
       full or write-protected, and refusing the seed would put a sweep in
       front of every run. What is lost is only protection against a run that
       dies before its save, and the clock entropy_init took still tells two
       such runs apart. */
    seed_write(next);
    file_unlock();
    memset(stored, 0, sizeof(stored));
    return 1;
}

int entropy_save(int replaying) {
    if (replaying) return -1;
    unsigned char next[SEED_BYTES];
    /* The file lock is held across the write, so a forget or a stash waits
       for it rather than having its removal overwritten a moment later; the
       pool lock is not, so a handshake does not wait on the stick. */
    file_lock();
    pool_lock();
    int full = pool_filled && !pool_broken;
    if (full) pool_hash(next, OUT_FILE, NULL, 0);
    pool_unlock();
    int written = full ? seed_write(next) : -1;
    file_unlock();
    memset(next, 0, sizeof(next));
    return written;
}

/* A second sweep can be left before it is done, and leaving may not hand the
   session a pool of nothing to make its keys from. So the pool itself is
   never emptied for it: other threads may open a connection in the middle
   of the sweep, and a handshake seeded from a pool that holds nothing but the
   last few seconds of stick work is one an observer of the stick could
   replay. What was in the pool stays and the sweep is stirred in on top;
   what starts over is the count and the field, which is what a bar shows.
   The seed file goes at once -- somebody asking for a new sweep wants it
   gone -- and entropy_save writes a new one. */
void entropy_stash(void) {
    file_lock();
    pool_lock();
    seed_remove();
    if (stash_units < 0) stash_units = pool_units;
    pool_units = 0;
    sweep_reset();
    pool_unlock();
    file_unlock();
}

int entropy_stashed(void) {
    pool_lock();
    int stashed = stash_units >= 0;
    pool_unlock();
    return stashed;
}

void entropy_restore(void) {
    pool_lock();
    if (stash_units >= 0) pool_units = stash_units;
    stash_units = -1;
    pool_unlock();
}

void entropy_forget(void) {
    file_lock();
    pool_lock();
    seed_remove();
    pool_units = 0;
    pool_filled = 0;
    stash_units = -1;
    memset(pool, 0, sizeof(pool));
    sweep_reset();
    pool_unlock();
    file_unlock();
}

void entropy_allow_unswept(void) { unswept_allowed = 1; }

/* wolfSSL's seed, by the name tools/build-wolfssl compiled into it. The
   moment of the draw goes in first. Each block is the pool hashed with a
   counter under one tag, and when the draw is done the pool moves on under
   another, so no two draws repeat, no draw gives the pool away, and a pool
   read out of memory later says nothing about the draws before it. */
int pspkit_https_seed(unsigned char *seed, unsigned int size) {
    unsigned int sys = sceKernelGetSystemTimeLow();
    pool_lock();
    if (pool_broken || !(pool_filled || unswept_allowed)) {
        pool_unlock();
        return -1;
    }
    pool_absorb(IN_DRAW, &sys, sizeof(sys));
    unsigned char out[POOL_BYTES];
    while (size > 0) {
        pool_hash(out, OUT_SEED, &pool_counter, sizeof(pool_counter));
        pool_counter++;
        unsigned n = size < sizeof(out) ? size : (unsigned)sizeof(out);
        memcpy(seed, out, n);
        seed += n;
        size -= n;
    }
    pool_absorb(OUT_NEXT, &pool_counter, sizeof(pool_counter));
    int broken = pool_broken;
    pool_unlock();
    memset(out, 0, sizeof(out));
    return broken ? -1 : 0;
}
