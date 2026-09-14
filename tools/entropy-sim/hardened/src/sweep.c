#include "pspkit-https/entropy.h"
#include "pspkit-https/sweep.h"

/* The stick moves the source across the field at the speed it moved a text
   cursor across 60 by 28 cells, which is what the sweep was first drawn as,
   so a sweep takes as long whatever it is drawn as now. */
#define STEP_X (0.0065f / 60.0f)
#define STEP_Z (0.0040f / 28.0f)
#define DEAD_ZONE 14

/* A direction as one of eight, 45 degrees each, centred on the axes and the
   diagonals; 5/12 stands in for tan 22.5. */
static unsigned heading_of(int dx, int dy) {
    int ax = dx < 0 ? -dx : dx, ay = dy < 0 ? -dy : dy;
    if (ay * 12 < ax * 5) return dx > 0 ? 0 : 4;
    if (ax * 12 < ay * 5) return dy > 0 ? 2 : 6;
    if (dx > 0) return dy > 0 ? 1 : 7;
    return dy > 0 ? 3 : 5;
}

static float clamp01(float v) { return v < 0 ? 0 : v > 1 ? 1 : v; }

static unsigned field_of(const struct sweep *s) {
    int fx = (int)(s->x * (ENTROPY_FIELD_SIDE - 1) + 0.5f);
    int fz = (int)(s->z * (ENTROPY_FIELD_SIDE - 1) + 0.5f);
    return (unsigned)fz * ENTROPY_FIELD_SIDE + (unsigned)fx;
}

void sweep_step(struct sweep *s, unsigned char lx, unsigned char ly) {
    int dx = (int)lx - 128;
    int dy = (int)ly - 128;
    s->moving = dx * dx + dy * dy > DEAD_ZONE * DEAD_ZONE;
    if (!s->moving) {
        entropy_absorb_sample(lx, ly, ENTROPY_STILL, field_of(s), 0);
        return;
    }
    float ux = s->x + dx * STEP_X;
    float uz = s->z - dy * STEP_Z;
    float nx = clamp01(ux), nz = clamp01(uz);
    /* The heading that counts is the way the source went, not the way the
       stick points: pushed into a wall, a diagonal is a slide along it, and
       swinging the stick between the diagonals that all slide the same way
       is no turn. An axis the wall stopped entirely drops out. */
    int walled = nx != ux || nz != uz;
    int mx = nx != s->x ? dx : 0;
    int my = nz != s->z ? dy : 0;
    s->x = nx;
    s->z = nz;
    unsigned heading = mx || my ? heading_of(mx, my) : ENTROPY_STILL;
    entropy_absorb_sample(lx, ly, heading, field_of(s), walled);
}

int sweep_percent(void) {
    int bits = entropy_bits();
    return bits >= ENTROPY_BITS ? 100 : bits * 100 / ENTROPY_BITS;
}
