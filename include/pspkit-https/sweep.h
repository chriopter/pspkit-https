#ifndef PSPKIT_HTTPS_SWEEP_H
#define PSPKIT_HTTPS_SWEEP_H

#ifdef __cplusplus
extern "C" {
#endif

/* A sweep: a hand drives a source across an invisible field with the analog
   stick, mashes buttons if it likes, and the pool is paid for the turns and
   presses nobody could have called. This is the part every sweep screen
   shares -- how the
   stick moves the source and what reaches the pool. What the screen looks
   like is the application's: sweep_ascii_run is the plainest one, and any
   other calls sweep_step once a frame, every frame including those with the
   stick at rest, and draws the source where it says. */

struct sweep {
    float x, z;     /* the source: 0 to 1 across, 0 to 1 away from the viewer */
    int moving;     /* the stick was out of its dead zone this frame */
};

/* The source in the middle of the field, standing still. */
#define SWEEP_START { 0.5f, 0.5f, 0 }

/* Owner thread only, after entropy_init: feed exactly one sample each frame,
   including idle frames, with Lx, Ly and Buttons from SceCtrlData. Pass zero
   buttons for a stick-only screen. s must be non-NULL and start at SWEEP_START.
   Returns a bitwise combination of the flags below, or zero for no event.
   entropy_get_last_turn and entropy_get_last_press copy the event details. */
/* A turn earned credit, a counted button went down (including chords),
   or that press earned credit. PRESS_PAID always includes PRESSED. */
#define SWEEP_TURN_PAID 1
#define SWEEP_PRESSED 2
#define SWEEP_PRESS_PAID 4
unsigned sweep_step(struct sweep *s, unsigned char lx, unsigned char ly, unsigned buttons);

/* Any thread after entropy_init: returns zero through 100, reaching 100
   exactly when the pool holds ENTROPY_BITS. */
int sweep_get_percent(void);

/* Owner thread only, after entropy_init. The debug screen shows the field
   as a grid of dots
   the source marks as it goes, and a bar. Starts pspDebugScreen and leaves
   it on. START ends a full sweep; SELECT leaves one that has a stashed pool
   behind it (entropy_stash). Returns the bits in the pool, or 0 when it was left. */
int sweep_ascii_run(void);

#ifdef __cplusplus
}
#endif

#endif
