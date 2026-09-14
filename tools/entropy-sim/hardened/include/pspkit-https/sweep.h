#ifndef PSPKIT_HTTPS_SWEEP_H
#define PSPKIT_HTTPS_SWEEP_H

/* A sweep: a hand drives a source across an invisible field with the analog
   stick, and the pool is paid for turns nobody could have called (entropy.h
   has the rules). This is the part every sweep screen shares -- how the
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

/* One pad sample: lx and ly as SceCtrlData carries them, 0 to 255 with the
   stick at rest near 128. Stick down runs the source at the viewer. */
void sweep_step(struct sweep *s, unsigned char lx, unsigned char ly);

/* The bar: 0 to 100, and 100 exactly when the pool holds ENTROPY_BITS. */
int sweep_percent(void);

/* The plainest sweep screen: the debug screen, the field as a grid of dots
   the source marks as it goes, and a bar. Starts pspDebugScreen and leaves
   it on. X ends a full sweep; O leaves one that has a stashed pool behind it
   (entropy_stash). Returns the bits in the pool, or 0 when it was left. */
int sweep_ascii_run(void);

#endif
