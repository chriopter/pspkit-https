#ifndef PSPKIT_HTTPS_ENTROPY_H
#define PSPKIT_HTTPS_ENTROPY_H

/* The pool wolfSSL draws its seed from. A PSP has no random generator an
   application can reach, so the seed comes from a hand: a sweep of the
   analog stick (sweep.h) fills the pool once, a seed derived from it is
   kept in a file, and later runs start from that file and stir in what
   they see. */

/* The handshake is X25519 with ChaCha20-Poly1305, so it stands on a 128-bit
   security level: the ephemeral key is exactly as guessable as the entropy
   behind it, and nothing above 128 bits buys any strength. The pool is a
   32-byte SHA-256 state, so 128 bits fit in it with room to spare; a larger
   target here would only be a number on screen. */
#define ENTROPY_BITS 128

/* The sweep is scored on an invisible 250x250 field. Each point has one
   number, y * 250 + x. A turn only pays once the source has reached ground
   it had not covered, which is what keeps a hand from earning twice for the
   same path. */
#define ENTROPY_FIELD_SIDE 250
#define ENTROPY_FIELD_COUNT (ENTROPY_FIELD_SIDE * ENTROPY_FIELD_SIDE)

/* Eight headings, one per 45 degrees, and a ninth value for a sample in which
   the source did not move: the stick in its dead zone, or pushed into a
   corner that holds the source on both axes. */
#define ENTROPY_HEADINGS 8
#define ENTROPY_STILL ENTROPY_HEADINGS

/* A stroke is not entropy, and neither is every turn. What is counted is a
   turn nobody watching the sweep so far could have called:

   - A turn is a heading the source has actually moved in -- after the walls
     have had their say -- for ENTROPY_TURN_SAMPLES samples running. A stick
     trembling on the line between two headings, a thumb rolling through the
     headings on its way round, two keys landing a frame apart: all of that
     reaches the pool, and none of it is a turn.

   - Every turn is guessed before it is looked at, by predictors that have
     watched all the turns before it in this sweep: the last one to four
     turns repeated, the most common turn of the last sixteen, the turn that
     followed the same one, two or three turns the last times, and a return
     to the heading of two, three or four turns back. The predictor with the
     best recent record makes the guess, and a context that has already
     repeated itself gets a guess of its own. A turn that is guessed pays
     nothing. That is what takes circles, spirals, zigzags and the swing
     between two headings off the bar after two or three rounds.

   - A turn made after the source touched a wall pays nothing: the wall made
     it. A turn pays only once the source has covered ENTROPY_TURN_FIELDS
     fields of new ground under it, so a path retraced is not paid again.

   - A turn nobody guessed pays min(2, -log2 p / (1 - p)) bits, where p is
     the upper 99% bound on how often the best predictor has been right in
     this sweep. Over a sweep that averages to at most -log2 p per turn --
     the min-entropy of a turn as these predictors see it -- whatever p is,
     because -ln p >= 1 - p; the two-bit cap keeps a short sweep with lucky
     misses from claiming more. The moment of a turn, the position and the
     speed reach the pool too and are counted as nothing.

   The honest limit of this: a script is no choice at all and a counter that
   watches the stick cannot tell a clever one from a hand, and a better
   predictor than these would find structure these miss. The count is a
   lower bound against lazy hands, not a proof. tools/entropy-sim measures it
   against a recorded sweep, simulated hands and a set of cheap patterns. */
#define ENTROPY_TURN_SAMPLES 4
#define ENTROPY_TURN_FIELDS 3

/* Brings the pool up from the clock and the CPU's jitter, and starts the
   count and the field over. It counts nothing itself: a sweep or
   entropy_load has to follow before wolfSSL may draw. Called again, it
   keeps what the pool holds and whether it was ever full. */
void entropy_init(void);

/* The file the seed is kept in between runs: 32 bytes, replaced through a
   .new and a .bak so that a cut write never leaves half of one. A file of
   any other length is no seed (the 20-byte files of the SHA-1 pool are
   refused and cost one sweep). Without a path the pool lives in RAM alone
   and entropy_load finds nothing. The string is kept, not copied. */
void entropy_seed_file(const char *path);

/* One pad sample of a sweep, as sweep_step hands it over: the raw stick,
   the heading the source moved in (ENTROPY_STILL when it did not), the field
   it stands on, and whether a wall held it back. Every sample reaches the
   pool with the moment it arrived; the count is the rules above. Returns 1
   when this sample paid for a turn. */
int entropy_absorb_sample(unsigned char lx, unsigned char ly, unsigned int heading,
                          unsigned int field, int walled);

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
   caller may pass the bare value it has. */
void entropy_stir(const void *data, unsigned int len);

/* The bits credited so far; ENTROPY_BITS is a full pool. */
int entropy_bits(void);

/* Takes the seed file into the pool, counts the pool full, and puts a
   successor in the file's place at once: a run that dies before its save
   must not leave the next run starting from the same seed. 0 when there was
   no seed to take.

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
   write failed, in which case the file on the stick is still the one
   before. */
int entropy_save(int replaying);

/* Empties the pool and removes the seed file, for a reset that removes
   everything. wolfSSL cannot draw again until a sweep or a load. */
void entropy_forget(void);

/* A second sweep in a run that has a pool behind it already: the count is
   set aside and the field starts dry, while the pool keeps what it holds and
   takes the new sweep on top -- other threads run on through it, and a
   handshake in the middle must not draw from an empty pool. Either the new
   sweep finishes and the count is its own (the stash is dropped then), or it
   is abandoned and entropy_restore puts the old count back. entropy_stashed
   is what a sweep screen asks to know whether there is anything to go back
   to. */
void entropy_stash(void);
int entropy_stashed(void);
void entropy_restore(void);

/* wolfSSL's seed fails -- and with it every handshake -- until the pool has
   been full once, through a sweep or a load. A test whose keys protect
   nothing may waive that for the rest of the run; the jitter entropy_init
   gathered is all it gets, and entropy_save still writes nothing from it. */
void entropy_allow_unswept(void);

#endif
