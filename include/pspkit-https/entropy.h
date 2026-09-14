#ifndef PSPKIT_HTTPS_ENTROPY_H
#define PSPKIT_HTTPS_ENTROPY_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Call entropy_init on the owner thread before starting network workers or
   sampling. The seed path may be set before init. All operations use locks;
   init, stash, restore, forget and sweep_step must be ordered by the owner
   thread so a reset cannot split a frame. Getters, stir, load and save may
   run on other threads after init. Output pointers must be non-NULL. */

/* The pool wolfSSL draws its seed from. A PSP has no random generator an
   application can reach, so the seed comes from a hand: a sweep of the
   analog stick (sweep.h) fills the pool once, a seed derived from it is
   kept in a file, and later runs start from that file and stir in what
   they see. */

/* The handshake is X25519 with ChaCha20-Poly1305, so it stands on a 128-bit
   security level: the ephemeral key is exactly as guessable as the entropy
   behind it, and nothing above 128 bits buys any strength. The pool is a
   32-byte SHA-256 state, so 128 bits fit in it with room to spare; a larger
   target here would only be a number on screen. This count is a heuristic
   against predictable input, not proof of entropy or resistance to scripts. */
#define ENTROPY_BITS 128

/* Eight headings, one per 45 degrees. */
#define ENTROPY_HEADINGS 8

/* Owner thread: brings the pool up from the clock and the CPU's jitter, and starts the
   count and the field over. It counts nothing itself: a sweep or
   entropy_load has to follow before wolfSSL may draw. Called again, it
   keeps what the pool holds and whether it was ever full. It also keeps
   a stashed count, so a repeated init during a second sweep is safe. */
void entropy_init(void);

/* The file the seed is kept in between runs: 32 bytes, replaced through a
   .new and a .bak so that a cut write never leaves half of one. A file of
   any other length is no seed (the 20-byte files of the SHA-1 pool are
   refused and cost one sweep). Without a path the pool lives in RAM alone
   and entropy_load finds nothing. The string is kept, not copied, and must
   remain valid until the next
   setter call finishes. NULL disables persistence. Call on the owner thread;
   file operations are serialised with this setter. */
void entropy_set_seed_file(const char *path);

/* What the count made of the latest turn, for a sweep screen that wants to
   show the hand what counts. */
enum entropy_verdict {
    ENTROPY_PAID,       /* An unpredictable turn or press earned credit. */
    ENTROPY_OWED,       /* A turn waits for new ground before earning credit. */
    ENTROPY_GUESSED,    /* The predictors called the creditable choices. */
    ENTROPY_WALL,       /* A wall made the turn. */
    ENTROPY_FLICK,      /* A heading was left before it settled. */
    ENTROPY_CHORD,      /* Several buttons came down in one frame. */
    ENTROPY_HURRIED     /* A press was too fast or exceeded the rate budget. */
};

struct entropy_turn {
    unsigned seq;               /* turns so far this sweep; 0 before the first */
    unsigned heading;           /* where the source went since, 0 right, 1 down
                                   and right, 2 down ... 7 up and right, as it
                                   moves on screen */
    unsigned turn;              /* 1 to 7, 45 degrees a step, clockwise on screen */
    unsigned held;              /* samples since the turn before */
    int way_guessed, moment_guessed;
    enum entropy_verdict verdict;
    unsigned sixteenths;        /* sixteenths of a bit it pays, or owes */
};

/* Any thread: copies a snapshot; seq is zero before the first turn. */
void entropy_get_last_turn(struct entropy_turn *out);

/* The buttons a sweep counts, by where they sit: the d-pad and the face
   buttons each clockwise from the top, then the shoulders. START, SELECT,
   HOME and the rest are the screen's own and never counted, though every
   change of them reaches the pool with its moment. */
enum entropy_button {
    ENTROPY_BUTTON_NONE = -1,
    ENTROPY_UP, ENTROPY_RIGHT, ENTROPY_DOWN, ENTROPY_LEFT,
    ENTROPY_TRIANGLE, ENTROPY_CIRCLE, ENTROPY_CROSS, ENTROPY_SQUARE,
    ENTROPY_LTRIGGER, ENTROPY_RTRIGGER
};
#define ENTROPY_BUTTONS 10

struct entropy_press {
    unsigned seq;               /* Press events this sweep, including chords. */
    enum entropy_button button; /* The button, or ENTROPY_BUTTON_NONE for a chord. */
    unsigned gap;               /* frames since the press before */
    int button_guessed, moment_guessed;
    enum entropy_verdict verdict;   /* PAID, GUESSED, CHORD or HURRIED */
    unsigned sixteenths;        /* sixteenths of a bit it paid */
};

/* Any thread: copies a snapshot; seq is zero before the first press.
   Chords also advance seq, so each screen event has a distinct identity. */
void entropy_get_last_press(struct entropy_press *out);

/* Runtime noise: absorbed, never counted. The count is a gate on the first
   handshake, not a running total, and the pool is already full at 128 bits
   -- so what this buys is not strength but freshness. The seed file is
   readable on the stick, and a copy of it otherwise predicts every later
   run, because a stored seed skips the sweep. Stirring the session full of
   things the device does not control is what makes a stolen copy go stale.
   The library stirs in packet arrival and the battery's draw on its own.

   All of it stays in RAM until entropy_save. Call that when the run ends and
   not after every stir: the same sector is written every time, and a memory
   stick has no wear levelling worth the name.

   Any length is taken whole. A timestamp is folded in on every call, so a
   caller may pass the bare value it has. Any thread; data is read only
   during the call and may be NULL only when len is zero. */
void entropy_stir(const void *data, size_t len);

/* Any thread: returns credited bits from zero through ENTROPY_BITS. */
int entropy_get_bits(void);

/* Takes the seed file into the pool, counts the pool full, and puts a
   successor in the file's place at once: a run that dies before its save
   must not leave the next run starting from the same seed. Returns 1 when
   a seed was loaded, 0 when no valid seed was available or the
   pool hash failed. Any thread after init. A failed successor write does
   not reject a loaded seed; the next save retries persistence.

   Counting it full is a trust in the stick, not a measurement: the file is
   derived from a pool that was full, and whoever can read it -- or put an
   old copy back -- knows the start of every run it seeds, up to the clock
   and the jitter this run adds. Nothing an application can reach on a PSP
   keeps a secret from someone holding the memory stick, so this is where
   the design stops; the stirring during the run is what makes such a copy
   go stale. */
int entropy_load(void);

/* Writes a seed derived from the pool, never the pool itself. Nothing is
   written from a pool that has never been full -- a run cut short in its
   first sweep would otherwise leave a file the next run counts as 128 bits
   -- and nothing when replaying is set: a replayed sweep is public input.
   0 when the seed reached the stick, -1 when nothing was written or the
   write failed. A sync failure after replacement can leave the new file
   in place despite a -1 result. Any thread after init. */
int entropy_save(int replaying);

/* Empties the pool and removes the seed file, for a reset that removes
   everything, including the test waiver. wolfSSL cannot draw again until
   a sweep or a load. File removal is best effort; inaccessible media may
   retain an old seed. The path remains configured. Owner thread only. */
void entropy_forget(void);

/* A second sweep in a run that has a pool behind it already: the count is
   set aside and the field starts dry, while the pool keeps what it holds and
   takes the new sweep on top -- other threads run on through it, and a
   handshake in the middle must not draw from an empty pool. Either the new
   sweep finishes and the count is its own (the stash is dropped then), or it
   is abandoned and entropy_restore puts the old count back. entropy_get_stashed
   is what a sweep screen asks to know whether there is anything to go back
   to. Owner thread only; repeated stashes retain the original count and
   restart the sweep. The current seed file is removed. */
void entropy_stash(void);
/* Any thread: returns 1 with a saved count, otherwise 0. */
int entropy_get_stashed(void);
/* Owner thread: restore a stashed count, or do nothing if none exists. */
void entropy_restore(void);

/* wolfSSL's seed fails -- and with it every handshake -- until the pool has
   been full once, through a sweep or a load. A test whose keys protect
   nothing may waive that for the rest of the run; the jitter entropy_init
   gathered is all it gets, and entropy_save still writes nothing from it.
   Any thread after init; repeated calls are harmless. Forget clears it. */
void entropy_allow_unswept(void);

#ifdef __cplusplus
}
#endif

#endif
