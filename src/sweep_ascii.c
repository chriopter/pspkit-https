/* The sweep on the debug screen, 60 by 34 characters of 8 by 8 pixels: a
   field of dots, the source as @, the ground it has covered as o, cells a
   button press flipped as * (a press is not a place, so which cells is only
   a picture; a press that paid flips more of them), a bar,
   and under it the last turns as the count saw them -- which way, how long
   the hand held on before, and what each one paid, with the button presses
   among them -- so a hand learns what counts while it sweeps. Nothing but pspdebug, so any application can use
   it before it has a picture of its own. */
#include <pspkernel.h>
#include <pspctrl.h>
#include <pspdebug.h>
#include <pspdisplay.h>
#include <stdio.h>
#include <string.h>

#include "pspkit-https/entropy.h"
#include "pspkit-https/sweep.h"

#define COLS 56
#define ROWS 22
#define LEFT 2
#define TOP 3
#define BAR_ROW (TOP + ROWS + 1)
#define HISTORY_ROW (BAR_ROW + 3)
#define HISTORY 4

static const char *const heading_name[ENTROPY_HEADINGS] = {
    "right", "down-right", "down", "down-left", "left", "up-left", "up", "up-right",
};

static const char *const button_name[ENTROPY_BUTTONS] = {
    "up", "right", "down", "left", "triangle", "circle", "cross", "square", "L", "R",
};

/* A line of the history: a turn or a press, as the count saw it. */
struct seen {
    int press;
    unsigned seq;
    enum entropy_verdict verdict;
    char text[96];
};

static void verdict_text(enum entropy_verdict v, unsigned sixteenths, const char *part, char *out, size_t size) {
    unsigned tenths = (sixteenths * 10 + 8) / 16;
    switch (v) {
    case ENTROPY_PAID: snprintf(out, size, "+%u.%u bits%s", tenths / 10, tenths % 10, part); break;
    case ENTROPY_OWED: snprintf(out, size, "+%u.%u when new", tenths / 10, tenths % 10); break;
    case ENTROPY_GUESSED: snprintf(out, size, "0, guessed"); break;
    case ENTROPY_WALL: snprintf(out, size, "0, wall"); break;
    case ENTROPY_FLICK: snprintf(out, size, "0, flick"); break;
    case ENTROPY_CHORD: snprintf(out, size, "0, chord"); break;
    case ENTROPY_HURRIED: snprintf(out, size, "0, too fast"); break;
    }
}

static unsigned char covered[ROWS][COLS];
static unsigned char flipped[ROWS][COLS];
static int source_col = -1, source_row = -1;

static void put(int col, int row, char c) {
    pspDebugScreenSetXY(LEFT + col, TOP + row);
    pspDebugScreenPrintData(&c, 1);
}

/* A cell as it stands: the source over everything, then a flipped cell,
   then ground covered, then a dot. */
static void draw_cell(int col, int row) {
    char c = col == source_col && row == source_row ? '@'
             : flipped[row][col]                    ? '*'
             : covered[row][col]                    ? 'o'
                                                    : '.';
    put(col, row, c);
}

/* Which cells a press flips: xorshift, seeded from the clock -- a picture
   needs no better, and none of it reaches the pool. */
static unsigned flip_state;

static void flip_some(int count) {
    for (int k = 0; k < count; k++) {
        flip_state ^= flip_state << 13;
        flip_state ^= flip_state >> 17;
        flip_state ^= flip_state << 5;
        int col = (int)(flip_state % COLS), row = (int)((flip_state / COLS) % ROWS);
        flipped[row][col] ^= 1;
        draw_cell(col, row);
    }
}

/* One turn on one line: "right 90   to down-left  14 fr  +3.1 bits". */
static void describe_turn(const struct entropy_turn *t, struct seen *out) {
    char way[16], verdict[32];
    unsigned deg = 45 * (t->turn <= 4 ? t->turn : 8 - t->turn);
    snprintf(way, sizeof(way), "%s %u", t->turn == 4 ? "back" : t->turn < 4 ? "right" : "left", deg);
    verdict_text(t->verdict, t->sixteenths, t->way_guessed ? " way seen" : t->moment_guessed ? " time seen" : "",
                 verdict, sizeof(verdict));
    out->press = 0;
    out->seq = t->seq;
    out->verdict = t->verdict;
    snprintf(out->text, sizeof(out->text), "%-10s to %-10s %3u fr  %s", way,
             heading_name[t->heading % ENTROPY_HEADINGS], t->held, verdict);
}

/* One press on one line: "press circle           7 fr  +1.6 bits". */
static void describe_press(const struct entropy_press *p, struct seen *out) {
    char verdict[32];
    const char *name = p->button >= 0 && p->button < ENTROPY_BUTTONS ? button_name[p->button] : "chord";
    verdict_text(p->verdict, p->sixteenths, p->button_guessed ? " button seen" : p->moment_guessed ? " time seen" : "",
                 verdict, sizeof(verdict));
    out->press = 1;
    out->seq = p->seq;
    out->verdict = p->verdict;
    snprintf(out->text, sizeof(out->text), "press %-18s %3u fr  %s", name, p->gap, verdict);
}

/* A new event goes on top; the same event again is its verdict changing,
   owed to paid. Returns 1 when the list changed. */
static int note(struct seen *shown, int *count, const struct seen *e) {
    for (int i = 0; i < *count; i++)
        if (shown[i].press == e->press && shown[i].seq == e->seq) {
            if (shown[i].verdict == e->verdict) return 0;
            shown[i] = *e;
            return 1;
        }
    for (int i = HISTORY - 1; i > 0; i--) shown[i] = shown[i - 1];
    shown[0] = *e;
    if (*count < HISTORY) (*count)++;
    return 1;
}

int sweep_ascii_run(void) {
    struct sweep s = SWEEP_START;
    struct seen shown[HISTORY];
    int shown_count = 0;
    sceCtrlSetSamplingCycle(0);
    sceCtrlSetSamplingMode(PSP_CTRL_MODE_ANALOG);
    pspDebugScreenInit();
    pspDebugScreenClear();
    pspDebugScreenSetXY(LEFT, 1);
    pspDebugScreenPrintf("Steer the stick or smash buttons. * marks a press.");
    memset(covered, 0, sizeof(covered));
    memset(flipped, 0, sizeof(flipped));
    source_col = source_row = -1;
    flip_state = sceKernelGetSystemTimeLow() | 1;
    for (int r = 0; r < ROWS; r++)
        for (int c = 0; c < COLS; c++) put(c, r, '.');
    pspDebugScreenSetXY(LEFT, HISTORY_ROW - 1);
    pspDebugScreenPrintf("Last turns and presses, newest first:");

    int left = 0;
    for (;;) {
        SceCtrlData pad;
        /* Waits for the next sample, which with a cycle of 0 is the next frame. */
        sceCtrlReadBufferPositive(&pad, 1);
        int happened = sweep_step(&s, pad.Lx, pad.Ly, pad.Buttons);

        int c = (int)(s.x * (COLS - 1) + 0.5f);
        int r = (int)((1.0f - s.z) * (ROWS - 1) + 0.5f);
        if (c != source_col || r != source_row) {
            int was_col = source_col, was_row = source_row;
            source_col = c;
            source_row = r;
            if (was_col >= 0) {
                covered[was_row][was_col] = 1;
                draw_cell(was_col, was_row);
            }
            draw_cell(c, r);
        }
        if (happened & SWEEP_PRESSED) flip_some(happened & SWEEP_PRESS_PAID ? 4 : 1);

        struct entropy_turn t;
        struct entropy_press p;
        struct seen e;
        int changed = 0;
        entropy_get_last_turn(&t);
        if (t.seq) {
            describe_turn(&t, &e);
            changed |= note(shown, &shown_count, &e);
        }
        entropy_get_last_press(&p);
        if (p.seq) {
            describe_press(&p, &e);
            changed |= note(shown, &shown_count, &e);
        }
        if (changed) {
            for (int i = 0; i < shown_count; i++) {
                pspDebugScreenSetXY(LEFT, HISTORY_ROW + i);
                pspDebugScreenPrintf("%-56.56s", shown[i].text);
            }
        }

        int percent = sweep_get_percent();
        char bar[COLS];
        int fill = percent * COLS / 100;
        for (int i = 0; i < COLS; i++) bar[i] = i < fill ? '#' : '-';
        pspDebugScreenSetXY(LEFT, BAR_ROW);
        pspDebugScreenPrintData(bar, COLS);
        pspDebugScreenSetXY(LEFT, BAR_ROW + 1);
        if (percent == 100)
            pspDebugScreenPrintf("%3d bits   START to continue            ", entropy_get_bits());
        else if (entropy_get_stashed())
            pspDebugScreenPrintf("%3d%%   %3d bits   SELECT to go back    ", percent, entropy_get_bits());
        else
            pspDebugScreenPrintf("%3d%%   %3d bits                        ", percent, entropy_get_bits());

        if (percent == 100 && (pad.Buttons & PSP_CTRL_START)) break;
        if (percent < 100 && entropy_get_stashed() && (pad.Buttons & PSP_CTRL_SELECT)) {
            left = 1;
            break;
        }
    }
    return left ? 0 : entropy_get_bits();
}
