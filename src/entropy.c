/* The pool: a SHA-256 state that what the device cannot predict is folded
   into, and wolfSSL's seed is drawn from, and the count of what a sweep put
   into it. entropy_internal.h says what is counted and why. */
#include <pspkernel.h>
#include <pspiofilemgr.h>
#include <psprtc.h>
#include <stdio.h>
#include <pthread.h>
#include <limits.h>
#include <string.h>

#include <wolfssl/options.h>
#include <wolfssl/wolfcrypt/sha256.h>

#include "entropy_internal.h"
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
static pthread_mutex_t pool_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
static int initialised;

static void pool_lock(void) { pthread_mutex_lock(&pool_mutex); }
static void pool_unlock(void) { pthread_mutex_unlock(&pool_mutex); }
static void file_lock(void) { pthread_mutex_lock(&file_mutex); }
static void file_unlock(void) { pthread_mutex_unlock(&file_mutex); }

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
    IN_BUTTONS,
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
    if (ret != 0) { pool_broken = 1; return; }
    ret = wc_Sha256Update(&sha, pool, POOL_BYTES);
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

void entropy_set_seed_file(const char *path) {
    file_lock();
    seed_file = path;
    file_unlock();
}

/* ---------------------------------------------------------------- turns */

/* The predictors of entropy_internal.h, in the order their scores are kept. A turn
   is its heading change, 1 to 7 in steps of 45 degrees counter-clockwise;
   0 is a predictor with no guess. */
enum {
    P_LAG1, P_LAG2, P_LAG3, P_LAG4,     /* the turn one to four turns back */
    P_COMMON,                           /* most common of the last sixteen */
    P_FOLLOW1, P_FOLLOW2, P_FOLLOW3,    /* what followed the last one, two, three turns */
    P_BACK2, P_BACK3, P_BACK4,          /* back to the heading two to four turns ago */
    PREDICTORS
};

/* The same for the moment of a turn: how long after the turn before it
   came, as one of CLASSES classes. */
enum {
    Q_LAG1, Q_LAG2, Q_LAG3,             /* the class one to three turns back */
    Q_COMMON,                           /* most common of the last sixteen */
    Q_MEDIAN,                           /* median of the last eight */
    Q_FOLLOW,                           /* what followed the last class */
    Q_BY_TURN,                          /* what came with this same turn */
    Q_BY_BOTH,                          /* ... after the same last class */
    TIMERS
};

#define RING 16
#define CLASSES 16
#define NO_CLASS 0xFF
#define NONE ENTROPY_HEADINGS

/* The gaps between turns, in samples, as classes a quarter wider each: the
   upper bounds of classes 0 to 14, class 15 is anything longer. A quarter is
   about as fine as a hand keeps time -- a thumb that means to turn after 200
   milliseconds turns somewhere between 170 and 250 -- and a sample is 17
   milliseconds, so the lowest classes are a sample or two wide. */
static const unsigned char class_bound[CLASSES - 1] = {
    5, 6, 8, 10, 12, 15, 19, 24, 30, 37, 47, 58, 73, 91, 114,
};

/* The mean motion of two runs points the same way when they are less than
   15 degrees apart: cross < tan 15 * dot, tan 15 standing in as 67 / 250. */
#define SAME_WAY_NUM 67
#define SAME_WAY_DEN 250

static struct {
    unsigned char run_heading;      /* the heading of the samples running now */
    unsigned int run_samples;
    unsigned int run_fields;        /* new fields among them */
    int run_x, run_y;               /* their summed motion */

    unsigned char heading;          /* the heading of the last turn, NONE before the first */
    int heading_x, heading_y;
    unsigned char roll;             /* a turn not yet sure it is not part of a roll, or NONE */
    int roll_x, roll_y;
    unsigned int roll_start, roll_fields;
    unsigned char roll_walled;
    unsigned char walled;           /* a wall held the source back since the last of these */

    unsigned int now;               /* samples since the sweep began */
    unsigned int last_turn;
    unsigned char owed;             /* sixteenths the last turn pays once it reaches new ground */
    unsigned char owed_heading;

    unsigned int turns;
    unsigned int headings;
    unsigned char turn_ring[RING];
    unsigned char heading_ring[RING];
    unsigned char class_ring[RING];
    unsigned short follow1[8][8];
    unsigned short follow2[64][8];
    unsigned short follow3[512][8];
    unsigned short class_follow[CLASSES][CLASSES];
    unsigned short class_by_turn[8][CLASSES];
    unsigned short class_by_both[8][CLASSES][CLASSES];
    int score[PREDICTORS];          /* recent record, decaying by an eighth per turn */
    unsigned int hits[PREDICTORS];  /* whole record over the sweep */
    unsigned int guessed;           /* turns the guess actually made got right */
    int class_score[TIMERS];
    unsigned int class_hits[TIMERS];
    unsigned int class_guessed;
} sweep;

static unsigned char field_seen[(ENTROPY_FIELD_COUNT + 7) / 8];

/* The latest turn as entropy_get_last_turn hands it out; nothing counts on it. */
static struct entropy_turn latest;

/* The predictors for presses, as for turns: which button, and when. */
enum {
    B_LAG1, B_LAG2, B_LAG3,             /* the button one to three presses back */
    B_COMMON,                           /* most common of the last sixteen */
    B_FOLLOW1, B_FOLLOW2,               /* what followed the last one, two presses */
    B_ROTATE,                           /* one step on round the cluster the way the last two went */
    B_GROUP,                            /* the favourite of the last press's cluster */
    BUTTON_PREDICTORS
};

enum {
    R_LAG1, R_LAG2, R_LAG3,             /* the gap class one to three presses back */
    R_COMMON,                           /* most common of the last sixteen */
    R_MEDIAN,                           /* median of the last eight */
    R_FOLLOW,                           /* what followed the last class */
    R_BY_BUTTON,                        /* what came with this button */
    R_BY_BOTH,                          /* ... after the same last class */
    R_MEAN4,                            /* the mean of the last four gaps: a rhythm */
    PRESS_TIMERS
};

#define NO_BUTTON 0xFF
#define BUTTON_CAP (2 * 16)
#define PRESS_MOMENT_CAP (2 * 16)
#define PRESS_SAVED (3 * 16)

/* SceCtrlData's bits for enum entropy_button, in its order. */
static const unsigned int button_bit[ENTROPY_BUTTONS] = {
    0x0010, 0x0020, 0x0040, 0x0080,     /* up, right, down, left */
    0x1000, 0x2000, 0x4000, 0x8000,     /* triangle, circle, cross, square */
    0x0100, 0x0200,                     /* L, R */
};

static struct {
    unsigned int raw;               /* every button last frame, as the pool saw it */
    unsigned int down;              /* the counted ones, as bits of enum entropy_button */
    unsigned char seen;             /* a frame has been seen since the reset */
    unsigned int now;               /* frames since the sweep began */
    unsigned int last_press;        /* the frame of the last press, chords too */
    unsigned int budget;            /* sixteenths presses may still pay */
    unsigned int presses;
    unsigned char button_ring[RING];
    unsigned char class_ring[RING];
    unsigned short gap_ring[RING];
    unsigned short follow1[ENTROPY_BUTTONS][ENTROPY_BUTTONS];
    unsigned short follow2[ENTROPY_BUTTONS * ENTROPY_BUTTONS][ENTROPY_BUTTONS];
    unsigned short in_cluster[3][ENTROPY_BUTTONS];
    unsigned short class_follow[CLASSES][CLASSES];
    unsigned short class_by_button[ENTROPY_BUTTONS][CLASSES];
    unsigned short class_by_both[ENTROPY_BUTTONS][CLASSES][CLASSES];
    int score[BUTTON_PREDICTORS];
    unsigned int hits[BUTTON_PREDICTORS];
    unsigned int guessed;
    int class_score[PRESS_TIMERS];
    unsigned int class_hits[PRESS_TIMERS];
    unsigned int class_guessed;
} keys;

/* The latest press as entropy_get_last_press hands it out; nothing counts on it. */
static struct entropy_press latest_press;
static unsigned press_seq;

static void sweep_reset(void) {
    memset(&sweep, 0, sizeof(sweep));
    memset(&latest, 0, sizeof(latest));
    memset(&keys, 0, sizeof(keys));
    memset(&latest_press, 0, sizeof(latest_press));
    press_seq = 0;
    keys.budget = PRESS_SAVED;
    sweep.run_heading = NONE;
    sweep.heading = NONE;
    sweep.roll = NONE;
    memset(field_seen, 0, sizeof(field_seen));
}

/* A direction as one of eight, 45 degrees each, centred on the axes and the
   diagonals; 5/12 stands in for tan 22.5. */
static unsigned heading_of(int dx, int dy) {
    int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
    if (ay * 12 < ax * 5) return dx > 0 ? 0 : 4;
    if (ax * 12 < ay * 5) return dy > 0 ? 2 : 6;
    if (dx > 0) return dy > 0 ? 1 : 7;
    return dy > 0 ? 3 : 5;
}

static unsigned class_of(unsigned samples) {
    for (unsigned k = 0; k < CLASSES - 1; k++)
        if (samples < class_bound[k]) return k;
    return CLASSES - 1;
}

/* The way a turn went round: 1 counter-clockwise, -1 clockwise, 2 straight
   back. */
static int sense_of(unsigned turn) {
    return turn >= 1 && turn <= 3 ? 1 : turn >= 5 ? -1 : 2;
}

/* The turn k turns back, k from 1; valid while k <= turns. */
static unsigned turn_back(unsigned k) {
    return sweep.turn_ring[(sweep.turns - k) & (RING - 1)];
}

static unsigned class_back(unsigned k) {
    return sweep.class_ring[(sweep.turns - k) & (RING - 1)];
}

static unsigned heading_back(unsigned k) {
    return sweep.heading_ring[(sweep.headings - k) & (RING - 1)];
}

/* The most frequent entry of a row of n, the lowest on a tie; none (and a
   support of 0) for an empty row. */
static unsigned most_frequent(const unsigned short *row, unsigned n, unsigned none, unsigned *support) {
    unsigned best = none, most = 0;
    for (unsigned v = 0; v < n; v++)
        if (row[v] > most) {
            most = row[v];
            best = v;
        }
    if (support) *support = most;
    return best;
}

/* The most common of the last entries of a ring, the most recent on a tie. */
static unsigned most_common(unsigned (*back)(unsigned), unsigned n, unsigned values) {
    unsigned tally[CLASSES] = { 0 }, most = 0, window = n < RING ? n : RING;
    for (unsigned k = 1; k <= window; k++) tally[back(k)]++;
    for (unsigned v = 0; v < values; v++)
        if (tally[v] > most) most = tally[v];
    for (unsigned k = 1; k <= window; k++)
        if (tally[back(k)] == most) return back(k);
    return 0;
}

static void predict(unsigned char guess[PREDICTORS], unsigned support[PREDICTORS]) {
    unsigned n = sweep.turns;
    memset(guess, 0, PREDICTORS);
    memset(support, 0, PREDICTORS * sizeof(support[0]));
    for (unsigned k = 1; k <= 4; k++)
        if (n >= k) guess[P_LAG1 + k - 1] = (unsigned char)turn_back(k);
    if (n) guess[P_COMMON] = (unsigned char)most_common(turn_back, n, 8);
    if (n >= 1)
        guess[P_FOLLOW1] = (unsigned char)most_frequent(sweep.follow1[turn_back(1)] + 1, 7, 0, &support[P_FOLLOW1]);
    if (n >= 2)
        guess[P_FOLLOW2] = (unsigned char)most_frequent(
            sweep.follow2[turn_back(2) * 8 + turn_back(1)] + 1, 7, 0, &support[P_FOLLOW2]);
    if (n >= 3)
        guess[P_FOLLOW3] = (unsigned char)most_frequent(
            sweep.follow3[(turn_back(3) * 8 + turn_back(2)) * 8 + turn_back(1)] + 1, 7, 0, &support[P_FOLLOW3]);
    /* The rows above skip the unused turn 0, so their answers are one low. */
    for (int j = P_FOLLOW1; j <= P_FOLLOW3; j++)
        if (support[j]) guess[j]++;
    for (unsigned k = 2; k <= 4; k++)
        if (sweep.headings >= k)
            guess[P_BACK2 + k - 2] = (unsigned char)((heading_back(k) - heading_back(1)) & 7);
}

static void predict_class(unsigned turn, unsigned char guess[TIMERS]) {
    unsigned n = sweep.turns;
    memset(guess, NO_CLASS, TIMERS);
    for (unsigned k = 1; k <= 3; k++)
        if (n >= k) guess[Q_LAG1 + k - 1] = (unsigned char)class_back(k);
    if (n) {
        guess[Q_COMMON] = (unsigned char)most_common(class_back, n, CLASSES);
        unsigned recent[8], m = n < 8 ? n : 8;
        for (unsigned k = 0; k < m; k++) {          /* insertion sort, eight at most */
            unsigned v = class_back(m - k), j = k;
            while (j > 0 && recent[j - 1] > v) {
                recent[j] = recent[j - 1];
                j--;
            }
            recent[j] = v;
        }
        guess[Q_MEDIAN] = (unsigned char)recent[m / 2];
        guess[Q_FOLLOW] = (unsigned char)most_frequent(sweep.class_follow[class_back(1)], CLASSES, NO_CLASS, NULL);
        guess[Q_BY_BOTH] = (unsigned char)most_frequent(sweep.class_by_both[turn][class_back(1)], CLASSES, NO_CLASS, NULL);
    }
    guess[Q_BY_TURN] = (unsigned char)most_frequent(sweep.class_by_turn[turn], CLASSES, NO_CLASS, NULL);
}

static unsigned isqrt_up(unsigned v) {
    unsigned r = 0, left = v;
    for (unsigned bit = 1u << 30; bit; bit >>= 2)
        if (r + bit <= left) {
            left -= r + bit;
            r = (r >> 1) + bit;
        } else {
            r >>= 1;
        }
    return r * r < v ? r + 1 : r;
}

/* min(4, -log2 p / (1 - p)) in sixteenths, rounded down, for p = k / 32. */
static const unsigned char credit_for_p[33] = {
    64, 64, 64, 60, 54, 50, 47, 44, 42, 40, 39, 37, 36, 35, 33, 32, 32,
    31, 30, 29, 28, 28, 27, 27, 26, 26, 25, 25, 24, 24, 23, 23, 23,
};

/* What an unguessed turn -- or an unguessed moment -- pays, in sixteenths,
   at most cap: p is how often the best guess has been right over the sweep
   (the one actually made, or the best single predictor in hindsight,
   whichever did better) out of n, with one success and one failure added,
   raised to its 99% upper bound and rounded up to a thirty-second. Every
   rounding goes against the count. */
static unsigned credit(unsigned n, unsigned right, const unsigned *hits, int predictors, unsigned cap) {
    for (int j = 0; j < predictors; j++)
        if (hits[j] > right) right = hits[j];
    unsigned p = (unsigned)(((unsigned long long)right * 1024 + 1024 + n + 1) / ((unsigned long long)n + 2));                 /* in 1024ths */
    unsigned spread = isqrt_up((p * (1024 - p) + n - 1) / n);            /* in 1024ths */
    unsigned upper = p + (2576 * spread + 999) / 1000;
    if (upper > 1024) upper = 1024;
    unsigned c = credit_for_p[(upper + 31) >> 5];
    return c < cap ? c : cap;
}

#define DIRECTION_CAP (3 * 16)
#define MOMENT_CAP (3 * 16)

/* A turn to heading, begun at sample start: guessed, scored, learned from,
   and priced. Returns the sixteenths it pays -- 0 when both its direction
   and its moment were called, or a wall made it. */
static unsigned turn_to(unsigned heading, unsigned start, int walled) {
    unsigned turn = (heading - sweep.heading) & 7;
    if (!turn) return 0;

    unsigned char guess[PREDICTORS], when[TIMERS];
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

    unsigned held = start - sweep.last_turn;
    unsigned cls = class_of(held);
    sweep.last_turn = start;
    predict_class(turn, when);
    int timer = 0;
    for (int j = 1; j < TIMERS; j++)
        if (sweep.class_score[j] > sweep.class_score[timer]) timer = j;
    int timed = when[timer] == cls;
    for (int j = 0; j < TIMERS; j++) {
        int hit = when[j] == cls;
        sweep.class_score[j] += (hit ? 256 : 0) - (sweep.class_score[j] >> 3);
        sweep.class_hits[j] += (unsigned)hit;
    }

    /* The contexts this turn followed, read before the turn joins the rings. */
    unsigned n = sweep.turns;
    if (n >= 1) {
        unsigned c1 = turn_back(1), k1 = class_back(1);
        if (sweep.follow1[c1][turn] < 0xFFFF) sweep.follow1[c1][turn]++;
        if (sweep.class_follow[k1][cls] < 0xFFFF) sweep.class_follow[k1][cls]++;
        if (sweep.class_by_both[turn][k1][cls] < 0xFFFF) sweep.class_by_both[turn][k1][cls]++;
    }
    if (n >= 2) {
        unsigned short *c = &sweep.follow2[turn_back(2) * 8 + turn_back(1)][turn];
        if (*c < 0xFFFF) (*c)++;
    }
    if (n >= 3) {
        unsigned short *c = &sweep.follow3[(turn_back(3) * 8 + turn_back(2)) * 8 + turn_back(1)][turn];
        if (*c < 0xFFFF) (*c)++;
    }
    if (sweep.class_by_turn[turn][cls] < 0xFFFF) sweep.class_by_turn[turn][cls]++;
    sweep.turn_ring[n & (RING - 1)] = (unsigned char)turn;
    sweep.class_ring[n & (RING - 1)] = (unsigned char)cls;
    sweep.heading_ring[sweep.headings++ & (RING - 1)] = (unsigned char)heading;
    sweep.heading = (unsigned char)heading;

    sweep.turns++;
    sweep.guessed += (unsigned)guessed;
    sweep.class_guessed += (unsigned)timed;
    unsigned pays = 0;
    if (!walled) {
        if (!guessed) pays += credit(sweep.turns, sweep.guessed, sweep.hits, PREDICTORS, DIRECTION_CAP);
        if (!timed) pays += credit(sweep.turns, sweep.class_guessed, sweep.class_hits, TIMERS, MOMENT_CAP);
    }
    latest.seq = sweep.turns;
    latest.heading = heading;
    latest.turn = turn;
    latest.held = held;
    latest.way_guessed = guessed;
    latest.moment_guessed = timed;
    latest.verdict = walled ? ENTROPY_WALL : pays ? ENTROPY_OWED : ENTROPY_GUESSED;
    latest.sixteenths = pays;
    return pays;
}

static int pay(unsigned units) {
    pool_units += (int)units;
    if (pool_units >= FULL) {
        pool_filled = 1;
        stash_units = -1;       /* the new sweep's count is its own now */
    }
    return 1;
}

/* Settles a turn: paid now when the run under it has already covered its
   new ground, owed until it does otherwise. */
static int settle(unsigned heading, unsigned start, unsigned fields, int walled) {
    unsigned units = turn_to(heading, start, walled);
    sweep.owed = 0;
    if (!units) return 0;
    if (fields >= ENTROPY_TURN_FIELDS) {
        latest.verdict = ENTROPY_PAID;
        return pay(units);
    }
    sweep.owed = (unsigned char)units;
    sweep.owed_heading = (unsigned char)heading;
    return 0;
}

static int same_way(int ax, int ay, int bx, int by) {
    long long dot = (long long)ax * bx + (long long)ay * by;
    long long cross = (long long)ax * by - (long long)ay * bx;
    if (cross < 0) cross = -cross;
    return dot > 0 && cross * SAME_WAY_DEN < dot * SAME_WAY_NUM;
}

static void roll_begin(unsigned heading) {
    sweep.roll = (unsigned char)heading;
    sweep.roll_x = sweep.run_x;
    sweep.roll_y = sweep.run_y;
    sweep.roll_start = sweep.now;
    sweep.roll_fields = sweep.run_fields;
    sweep.roll_walled = sweep.walled;
    sweep.walled = 0;
}

static void roll_settled(void) {
    sweep.heading_x = sweep.roll_x;
    sweep.heading_y = sweep.roll_y;
    sweep.roll = NONE;
}

static int count_sample(int mx, int my, unsigned field, int walled) {
    sweep.now++;
    if (walled) sweep.walled = 1;
    if ((!mx && !my) || field >= ENTROPY_FIELD_COUNT) return 0;
    unsigned heading = heading_of(mx, my);

    unsigned char bit = (unsigned char)(1u << (field & 7));
    int fresh = !(field_seen[field >> 3] & bit);
    field_seen[field >> 3] |= bit;

    if (heading != sweep.run_heading) {
        sweep.run_heading = (unsigned char)heading;
        sweep.run_samples = 0;
        sweep.run_fields = 0;
        sweep.run_x = sweep.run_y = 0;
    }
    sweep.run_samples++;
    if (fresh) sweep.run_fields++;
    sweep.run_x += mx;
    sweep.run_y += my;

    int paid = 0;
    unsigned top = sweep.roll != NONE ? sweep.roll : sweep.heading;
    if (top != NONE && heading == top) {
        if (sweep.roll != NONE) {
            sweep.roll_x += mx;
            sweep.roll_y += my;
            sweep.roll_fields = sweep.run_fields;
        } else {
            sweep.heading_x += mx;
            sweep.heading_y += my;
        }
    }

    /* A heading held ENTROPY_TURN_ROLL samples is no longer on its way to
       another: the turn to it is settled, and only a settled turn pays. */
    if (sweep.roll != NONE && heading == sweep.roll && sweep.now - sweep.roll_start >= ENTROPY_TURN_ROLL) {
        paid |= settle(sweep.roll, sweep.roll_start, sweep.roll_fields, sweep.roll_walled | sweep.walled);
        roll_settled();
        sweep.walled = 0;
        top = sweep.heading;
    }

    if (heading != top && sweep.run_samples >= ENTROPY_TURN_SAMPLES) {
        if (top == NONE) {
            /* The first heading of a sweep is where the hand starts, not a turn. */
            sweep.heading = (unsigned char)heading;
            sweep.heading_ring[sweep.headings++ & (RING - 1)] = (unsigned char)heading;
            sweep.heading_x = sweep.run_x;
            sweep.heading_y = sweep.run_y;
            sweep.last_turn = sweep.now;
            sweep.walled = 0;
        } else {
            int ref_x = sweep.roll != NONE ? sweep.roll_x : sweep.heading_x;
            int ref_y = sweep.roll != NONE ? sweep.roll_y : sweep.heading_y;
            if (same_way(sweep.run_x, sweep.run_y, ref_x, ref_y)) {
                /* The same direction, only across the line between two
                   headings: no turn. */
            } else if (sweep.roll == NONE) {
                roll_begin(heading);
            } else {
                unsigned first = (sweep.roll - sweep.heading) & 7;
                unsigned then = (heading - sweep.roll) & 7;
                int rolling = sense_of(first) == sense_of(then) && sense_of(then) != 2 &&
                              sweep.now - sweep.roll_start < ENTROPY_TURN_ROLL;
                if (rolling) {
                    /* Round the same way before the last heading settled:
                       one turn, from the heading before the roll. */
                    unsigned was_walled = sweep.roll_walled | sweep.walled;
                    roll_begin(heading);
                    sweep.roll_walled = (unsigned char)was_walled;
                    if (heading == sweep.heading) sweep.roll = NONE;
                } else if (sweep.now - sweep.roll_start >= ENTROPY_TURN_ROLL) {
                    /* Kept long enough before the hand went on: settled. */
                    paid |= settle(sweep.roll, sweep.roll_start, sweep.roll_fields, sweep.roll_walled);
                    roll_settled();
                    roll_begin(heading);
                } else {
                    /* Left before it settled, and not round the same way: a
                       flick, or one end of a swing. The predictors learn
                       it -- a hand that swings is guessed on its next swing
                       -- but it pays nothing. */
                    turn_to(sweep.roll, sweep.roll_start, 1);
                    latest.verdict = ENTROPY_FLICK;
                    sweep.owed = 0;
                    roll_settled();
                    roll_begin(heading);
                }
            }
        }
    }

    if (sweep.owed && sweep.run_heading == sweep.owed_heading && sweep.run_fields >= ENTROPY_TURN_FIELDS) {
        unsigned units = sweep.owed;
        sweep.owed = 0;
        if (latest.verdict == ENTROPY_OWED) latest.verdict = ENTROPY_PAID;
        paid |= pay(units);
    }
    return paid;
}

/* -------------------------------------------------------------- presses */

static void bump(unsigned short *count) {
    if (*count < 0xFFFF) (*count)++;
}

static unsigned press_back(unsigned k) {
    return keys.button_ring[(keys.presses - k) & (RING - 1)];
}

static unsigned press_class_back(unsigned k) {
    return keys.class_ring[(keys.presses - k) & (RING - 1)];
}

/* The three clusters a hand's fingers sit on: d-pad, face buttons, shoulders. */
static unsigned cluster_of(unsigned b) { return b < 4 ? 0 : b < 8 ? 1 : 2; }
static unsigned cluster_base(unsigned c) { return c == 0 ? 0 : c == 1 ? 4 : 8; }
static unsigned cluster_size(unsigned c) { return c == 2 ? 2 : 4; }

static void predict_button(unsigned char guess[BUTTON_PREDICTORS], unsigned support[BUTTON_PREDICTORS]) {
    unsigned n = keys.presses;
    memset(guess, NO_BUTTON, BUTTON_PREDICTORS);
    memset(support, 0, BUTTON_PREDICTORS * sizeof(support[0]));
    for (unsigned k = 1; k <= 3; k++)
        if (n >= k) guess[B_LAG1 + k - 1] = (unsigned char)press_back(k);
    if (n) {
        guess[B_COMMON] = (unsigned char)most_common(press_back, n, ENTROPY_BUTTONS);
        guess[B_FOLLOW1] = (unsigned char)most_frequent(keys.follow1[press_back(1)], ENTROPY_BUTTONS, NO_BUTTON,
                                                        &support[B_FOLLOW1]);
        guess[B_GROUP] = (unsigned char)most_frequent(keys.in_cluster[cluster_of(press_back(1))], ENTROPY_BUTTONS,
                                                      NO_BUTTON, NULL);
    }
    if (n >= 2) {
        unsigned a = press_back(2), b = press_back(1), c = cluster_of(b);
        guess[B_FOLLOW2] = (unsigned char)most_frequent(keys.follow2[a * ENTROPY_BUTTONS + b], ENTROPY_BUTTONS,
                                                        NO_BUTTON, &support[B_FOLLOW2]);
        if (a != b && cluster_of(a) == c) {
            unsigned base = cluster_base(c), size = cluster_size(c);
            unsigned step = (b - base + size - (a - base)) % size;
            guess[B_ROTATE] = (unsigned char)(base + (b - base + step) % size);
        }
    }
}

static void predict_press_class(unsigned button, unsigned char guess[PRESS_TIMERS]) {
    unsigned n = keys.presses;
    memset(guess, NO_CLASS, PRESS_TIMERS);
    for (unsigned k = 1; k <= 3; k++)
        if (n >= k) guess[R_LAG1 + k - 1] = (unsigned char)press_class_back(k);
    if (n) {
        guess[R_COMMON] = (unsigned char)most_common(press_class_back, n, CLASSES);
        unsigned recent[8], m = n < 8 ? n : 8;
        for (unsigned k = 0; k < m; k++) {
            unsigned v = press_class_back(m - k), j = k;
            while (j > 0 && recent[j - 1] > v) {
                recent[j] = recent[j - 1];
                j--;
            }
            recent[j] = v;
        }
        guess[R_MEDIAN] = (unsigned char)recent[m / 2];
        guess[R_FOLLOW] = (unsigned char)most_frequent(keys.class_follow[press_class_back(1)], CLASSES, NO_CLASS, NULL);
        guess[R_BY_BOTH] = (unsigned char)most_frequent(keys.class_by_both[button][press_class_back(1)], CLASSES,
                                                        NO_CLASS, NULL);
        unsigned sum = 0, four = n < 4 ? n : 4;
        for (unsigned k = 1; k <= four; k++) sum += keys.gap_ring[(keys.presses - k) & (RING - 1)];
        guess[R_MEAN4] = (unsigned char)class_of((sum + four / 2) / four);
    }
    guess[R_BY_BUTTON] = (unsigned char)most_frequent(keys.class_by_button[button], CLASSES, NO_CLASS, NULL);
}

static int count_buttons(unsigned raw) {
    unsigned down = 0;
    for (unsigned b = 0; b < ENTROPY_BUTTONS; b++)
        if (raw & button_bit[b]) down |= 1u << b;
    unsigned went = keys.seen ? down & ~keys.down : 0;
    keys.down = down;
    keys.seen = 1;
    keys.now++;
    keys.budget += ENTROPY_PRESS_RATE;
    if (keys.budget > PRESS_SAVED) keys.budget = PRESS_SAVED;
    if (!went) return 0;

    unsigned gap = keys.now - keys.last_press;
    keys.last_press = keys.now;
    if (went & (went - 1)) {
        /* A chord: timed, so the next gap runs from it, and nothing more. */
        latest_press.seq = ++press_seq;
        latest_press.button = ENTROPY_BUTTON_NONE;
        latest_press.gap = gap;
        latest_press.button_guessed = latest_press.moment_guessed = 0;
        latest_press.verdict = ENTROPY_CHORD;
        latest_press.sixteenths = 0;
        return ENTROPY_PRESSED;
    }
    unsigned button = 0;
    while (!(went & (1u << button))) button++;

    unsigned char guess[BUTTON_PREDICTORS], when[PRESS_TIMERS];
    unsigned support[BUTTON_PREDICTORS];
    predict_button(guess, support);
    int winner = 0;
    for (int j = 1; j < BUTTON_PREDICTORS; j++)
        if (keys.score[j] > keys.score[winner]) winner = j;
    int called = guess[winner] == button || (guess[B_FOLLOW2] == button && support[B_FOLLOW2] >= 3);
    for (int j = 0; j < BUTTON_PREDICTORS; j++) {
        int hit = guess[j] == button;
        keys.score[j] += (hit ? 256 : 0) - (keys.score[j] >> 3);
        keys.hits[j] += (unsigned)hit;
    }

    unsigned cls = class_of(gap);
    predict_press_class(button, when);
    int timer = 0;
    for (int j = 1; j < PRESS_TIMERS; j++)
        if (keys.class_score[j] > keys.class_score[timer]) timer = j;
    /* A moment one class off the guess is guessed too: a thumb's timing
       wanders by a frame without anyone choosing anything. */
    int timed = when[timer] != NO_CLASS && (unsigned)when[timer] + 1 >= cls && (unsigned)when[timer] <= cls + 1;
    for (int j = 0; j < PRESS_TIMERS; j++) {
        int hit = when[j] != NO_CLASS && (unsigned)when[j] + 1 >= cls && (unsigned)when[j] <= cls + 1;
        keys.class_score[j] += (hit ? 256 : 0) - (keys.class_score[j] >> 3);
        keys.class_hits[j] += (unsigned)hit;
    }

    unsigned n = keys.presses;
    if (n >= 1) {
        bump(&keys.follow1[press_back(1)][button]);
        bump(&keys.class_follow[press_class_back(1)][cls]);
        bump(&keys.class_by_both[button][press_class_back(1)][cls]);
    }
    if (n >= 2) bump(&keys.follow2[press_back(2) * ENTROPY_BUTTONS + press_back(1)][button]);
    bump(&keys.in_cluster[cluster_of(button)][button]);
    bump(&keys.class_by_button[button][cls]);
    keys.button_ring[n & (RING - 1)] = (unsigned char)button;
    keys.class_ring[n & (RING - 1)] = (unsigned char)cls;
    keys.gap_ring[n & (RING - 1)] = (unsigned short)(gap < 0xFFFF ? gap : 0xFFFF);
    keys.presses++;
    keys.guessed += (unsigned)called;
    keys.class_guessed += (unsigned)timed;

    int hurried = gap < ENTROPY_PRESS_GAP;
    unsigned earned = 0;
    if (!hurried) {
        if (!called) earned += credit(keys.presses, keys.guessed, keys.hits, BUTTON_PREDICTORS, BUTTON_CAP);
        /* The moment only counts for a press whose button nobody called: a
           thumb drumming on one button keeps a rhythm, not a choice. */
        if (!timed && !called) earned += credit(keys.presses, keys.class_guessed, keys.class_hits, PRESS_TIMERS, PRESS_MOMENT_CAP);
    }
    unsigned pays = earned < keys.budget ? earned : keys.budget;
    keys.budget -= pays;

    latest_press.seq = ++press_seq;
    latest_press.button = (enum entropy_button)button;
    latest_press.gap = gap;
    latest_press.button_guessed = called;
    latest_press.moment_guessed = timed;
    latest_press.verdict = pays ? ENTROPY_PAID : (hurried || earned) ? ENTROPY_HURRIED : ENTROPY_GUESSED;
    latest_press.sixteenths = pays;
    if (!pays) return ENTROPY_PRESSED;
    pay(pays);
    return ENTROPY_PRESSED | ENTROPY_PRESS_PAID;
}

/* ----------------------------------------------------------------- pool */

void entropy_init(void) {
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
    initialised = 1;
    pool_absorb(IN_INIT, &boot, sizeof(boot));
    pool_absorb_jitter(8);
    pool_units = 0;
    sweep_reset();
    pool_unlock();
}

int entropy_absorb_sample(unsigned char lx, unsigned char ly, int mx, int my,
                          unsigned int field, int walled) {
    /* Every sample goes in, moving or not: the stick's own reading at rest
       wanders by a count or two, and when a frame reaches this call moves
       with everything the frame drew. Neither is counted. */
    struct {
        unsigned char lx, ly, walled, pad;
        int mx, my;
        unsigned int field, sys;
    } sample;
    sample.lx = lx;
    sample.ly = ly;
    sample.walled = (unsigned char)(walled != 0);
    sample.pad = 0;
    sample.mx = mx;
    sample.my = my;
    sample.field = field;
    sample.sys = sceKernelGetSystemTimeLow();
    pool_lock();
    pool_absorb(IN_SAMPLE, &sample, sizeof(sample));
    int paid = initialised ? count_sample(mx, my, field, walled) : 0;
    pool_unlock();
    return paid;
}

int entropy_absorb_buttons(unsigned int buttons) {
    /* Every change of any button reaches the pool with its moment, START and
       HOME included; only the ten of enum entropy_button are counted. */
    struct {
        unsigned int buttons, sys;
    } event;
    event.buttons = buttons;
    event.sys = sceKernelGetSystemTimeLow();
    pool_lock();
    if (buttons != keys.raw || !keys.seen) {
        pool_absorb(IN_BUTTONS, &event, sizeof(event));
        keys.raw = buttons;
    }
    int flags = initialised ? count_buttons(buttons) : 0;
    pool_unlock();
    return flags;
}

void entropy_get_last_press(struct entropy_press *out) {
    pool_lock();
    *out = latest_press;
    pool_unlock();
}

void entropy_get_last_turn(struct entropy_turn *out) {
    pool_lock();
    *out = latest;
    pool_unlock();
}

void entropy_stir(const void *data, size_t len) {
    unsigned int sys = sceKernelGetSystemTimeLow();
    pool_lock();
    /* wolfCrypt lengths are 32-bit even in the host simulation. */
    const unsigned char *bytes = data;
    while (len > UINT_MAX) {
        pool_absorb(IN_STIR, bytes, UINT_MAX);
        bytes += UINT_MAX;
        len -= UINT_MAX;
    }
    pool_absorb(IN_STIR, bytes, (unsigned)len);
    pool_absorb(IN_STIR, &sys, sizeof(sys));
    pool_unlock();
}

int entropy_get_bits(void) {
    pool_lock();
    int bits = pool_units / UNITS;
    pool_unlock();
    return bits;
}

int entropy_load(void) {
    unsigned char stored[SEED_BYTES], next[SEED_BYTES] = {0};
    file_lock();
    if (!seed_read(stored)) {
        file_unlock();
        return 0;
    }
    pool_lock();
    pool_absorb(IN_LOAD, stored, SEED_BYTES);
    pool_absorb_jitter(4);
    pool_hash(next, OUT_FILE, NULL, 0);
    int valid = initialised && !pool_broken;
    if (valid) { pool_units = FULL; pool_filled = 1; stash_units = -1; }
    pool_unlock();
    /* If the successor cannot be written the pool still counts: the stick is
       full or write-protected, and refusing the seed would put a sweep in
       front of every run. What is lost is only protection against a run that
       dies before its save, and the clock entropy_init took still tells two
       such runs apart. */
    if (valid) seed_write(next);
    file_unlock();
    memset(stored, 0, sizeof(stored));
    memset(next, 0, sizeof(next));
    return valid;
}

int entropy_save(int replaying) {
    if (replaying) return -1;
    unsigned char next[SEED_BYTES] = {0};
    /* The file lock is held across the write, so a forget or a stash waits
       for it rather than having its removal overwritten a moment later; the
       pool lock is not, so a handshake does not wait on the stick. */
    file_lock();
    pool_lock();
    int full = pool_filled && !pool_broken;
    if (full) pool_hash(next, OUT_FILE, NULL, 0);
    full = full && !pool_broken;
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

int entropy_get_stashed(void) {
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
    unswept_allowed = 0;
    stash_units = -1;
    memset(pool, 0, sizeof(pool));
    sweep_reset();
    pool_unlock();
    file_unlock();
}

void entropy_allow_unswept(void) {
    pool_lock();
    unswept_allowed = 1;
    pool_unlock();
}

/* wolfSSL's seed, by the name tools/build-wolfssl compiled into it. The
   moment of the draw goes in first. Each block is the pool hashed with a
   counter under one tag, and when the draw is done the pool moves on under
   another, so no two draws repeat, no draw gives the pool away, and a pool
   read out of memory later says nothing about the draws before it. */
int pspkit_https_seed(unsigned char *seed, unsigned int size) {
    unsigned int sys = sceKernelGetSystemTimeLow();
    pool_lock();
    if (!initialised || pool_broken || !(pool_filled || unswept_allowed)) {
        pool_unlock();
        return -1;
    }
    pool_absorb(IN_DRAW, &sys, sizeof(sys));
    unsigned char out[POOL_BYTES] = {0};
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
