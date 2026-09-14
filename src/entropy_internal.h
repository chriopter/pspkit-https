#ifndef PSPKIT_HTTPS_ENTROPY_INTERNAL_H
#define PSPKIT_HTTPS_ENTROPY_INTERNAL_H

#include "pspkit-https/entropy.h"

/* The sweep is scored on an invisible 250x250 field. Each point has one
   number, y * 250 + x. A turn only pays once the source has reached ground
   it had not covered, which is what keeps a hand from earning twice for the
   same path. */
#define ENTROPY_FIELD_SIDE 250
#define ENTROPY_FIELD_COUNT (ENTROPY_FIELD_SIDE * ENTROPY_FIELD_SIDE)


/* A stroke is not entropy, and neither is every turn. What is counted is
   what nobody watching the sweep so far could have called: which way a turn
   went, and when it came.

   - A turn is a heading the source has actually moved in -- after the walls
     have had their say -- for ENTROPY_TURN_SAMPLES samples running, whose
     mean motion is at least 15 degrees off the heading before it. A stick
     trembling on the line between two headings points the same way on both
     sides of it, and two keys landing a frame apart last a sample or two:
     all of it reaches the pool, and none of it is a turn.

   - A turn pays only if its heading is still being kept ENTROPY_TURN_ROLL
     samples after the turn was seen, a sixth of a second: a thumb means a
     heading it keeps. A
     heading left again sooner in the same sense of rotation was part of a
     roll -- the turn runs from the heading before it to the one the roll
     stops on, which is what leaves a circling stick with nothing to show --
     and one left sooner the other way was a flick or one end of a swing:
     the predictors learn it, and it pays nothing.

   - Every turn is guessed twice before it is looked at, by predictors that
     have watched all the turns before it in this sweep. Its direction: the
     last one to four turns repeated, the most common of the last sixteen,
     what followed the same one, two or three turns, a return to the heading
     of two to four turns back; the predictor with the best recent record
     guesses, and a context that has already repeated itself guesses too.
     Its moment -- the samples since the turn before, in classes a quarter
     wider each: the last three classes repeated, the most common and the
     median of the recent ones, what followed the last class, what came with
     this same turn, and with this turn after that class. A part that is
     guessed pays nothing.

   - A turn made after the source touched a wall pays nothing: the wall made
     it, and when. A turn pays only once the source has covered
     ENTROPY_TURN_FIELDS fields of new ground under it.

   - Each part nobody guessed pays min(3, -log2 p / (1 - p)) bits, where p is
     the upper 99% bound on how often the best predictor for that part has
     been right in this sweep. Over a sweep that averages to at most -log2 p
     per turn for each part -- whatever p is, because -ln p >= 1 - p. The
     two parts are added, and that is sound as far as the moment predictors
     see the direction: three of them are handed the turn they are timing, so
     a hand whose moments follow from its directions is guessed there. Three
     bits is the cap because a quarter-wide class of a hand's timing holds
     about an eighth of its turns: a moment carries about three bits and no
     count here claims more.

   The honest limit of this: a script is no choice at all, and a counter that
   watches the stick cannot tell a clever or random one from a hand; a better
   predictor than these would find structure these miss. The count is a
   lower bound against lazy hands, not a proof. tools/entropy-sim measures it
   against a recorded sweep, simulated hands calibrated on it, and a set of
   cheap patterns. */
#define ENTROPY_TURN_SAMPLES 3
#define ENTROPY_TURN_FIELDS 2
#define ENTROPY_TURN_ROLL 10


/* A hand mashing buttons chooses which one and when, and that is counted
   the way turns are:

   - A press is a button going down. Holding it pays nothing more, and a
     frame in which several come down at once is a chord: the thumb's width
     chose it, or a turbo pad did, so it is timed but pays nothing and does
     not join the history of buttons.

   - A press less than ENTROPY_PRESS_GAP frames after the one before is
     hurried: faster than a thumb picks a button, which is what turbo pads
     and buzzing fingers do. It is learned and pays nothing.

   - Which button is guessed by the last one to three repeated, the most
     common of the last sixteen, what followed the same one and two
     presses, one more step round the d-pad or the face buttons the way the
     last two went, and the favourite of the cluster the last press was in.
     The moment -- frames since the press before, in the classes of the
     turns -- by the last three classes, the most common and the median, what
     followed the last class, what came with this button and with this
     button after that class, and the mean of the last four gaps: a rhythm.
     A moment within one class of the guess counts as guessed, since a
     thumb's timing wanders by a frame without anyone choosing it.

   - A button nobody guessed pays min(2, -log2 p / (1 - p)) bits with p the
     upper 99% bound on the best predictor's record, as for turns; its
     moment pays the same way, up to two bits more, but only when the button
     was not guessed either -- a thumb drumming on one button keeps a rhythm,
     it does not choose. Two bits for the button because a mashing thumb
     really uses about four of them; two for the moment because a masher
     keeps a tempo and its gaps fall into three or four classes.

   - However it adds up, presses pay no more than ENTROPY_PRESS_RATE
     sixteenths of a bit per frame (11.25 bits a second), saving up at most
     three bits through a pause. That is a ceiling, not an estimate: a hand
     cannot make more real choices a second than that, and a script can
     make as many as it likes, so no script fills the bar from the buttons
     in less than about eleven seconds.

   Buttons and stick are counted apart and added: they are two hands, and
   neither's predictors see the other. */
#define ENTROPY_PRESS_GAP 5
#define ENTROPY_PRESS_RATE 3

/* The buttons of one frame, as SceCtrlData.Buttons carries them, after
   entropy_absorb_sample. Returns ENTROPY_PRESSED when a counted button went
   down this frame, with ENTROPY_PRESS_PAID when that press paid. */
#define ENTROPY_PRESSED 1
#define ENTROPY_PRESS_PAID 2
int entropy_absorb_buttons(unsigned int buttons);


/* The sweep feeds one stick sample followed by its buttons, on its owner
   thread. These entry points are private so screens cannot count a frame twice. */
int entropy_absorb_sample(unsigned char lx, unsigned char ly, int mx, int my,
                          unsigned field, int walled);
int entropy_absorb_buttons(unsigned buttons);

#endif
