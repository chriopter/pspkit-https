#!/usr/bin/env python3
# Stick movements for the entropy simulation, as traces in the format PSPDX
# records and dev/rig replays: { u8 lx, u8 ly, u16 buttons } per 60 Hz frame.
# Every walker is driven by its own random.Random(seed), so a walker is a pure
# function of its seed -- which is exactly what makes the broken variants in
# report.py broken.
import math
import random
import struct

STEP_X = 0.0065 / 60.0
STEP_Z = 0.0040 / 28.0
DEAD = 14


def clamp01(v):
    return 0.0 if v < 0 else 1.0 if v > 1 else v


def stick(m, theta, rnd=None, noise=0.0):
    """Stick deflection m (0..127) at angle theta, screen convention: theta 0
    is right, +90 degrees is up (ly below 128)."""
    dx = m * math.cos(theta)
    dy = -m * math.sin(theta)
    if rnd is not None and noise:
        dx += rnd.gauss(0, noise)
        dy += rnd.gauss(0, noise)
    lx = max(0, min(255, int(round(128 + dx))))
    ly = max(0, min(255, int(round(128 + dy))))
    return lx, ly


class Source:
    """Where the source is, as sweep_step moves it (float64 here; only the
    walkers use it, to steer, never the count)."""

    def __init__(self):
        self.x = self.z = 0.5

    def step(self, lx, ly):
        dx, dy = lx - 128, ly - 128
        if dx * dx + dy * dy <= DEAD * DEAD:
            return
        self.x = clamp01(self.x + dx * STEP_X)
        self.z = clamp01(self.z - dy * STEP_Z)


def run(gen, frames):
    src = Source()
    out = []
    for _ in range(frames):
        lx, ly = gen(src)
        src.step(lx, ly)
        out.append((lx, ly, 0))
    return out


# ------------------------------------------------------------------ human

def human(seed, frames=60 * 120, median=0.26, sigma=0.60, curve=0.0015):
    """A plausible thumb on the PSP's nub, calibrated against the recorded
    sweep: after the same hold and angle filter the counter applies, it turns
    about 4 times a second (recording 3.8), holds a heading a median of 12
    frames (11) with a spread of 0.74 in log (0.73), and two turns in three
    are 45 degrees (65 %). The thumb decides its next turn on a log-normal
    clock, most turns small, rolls through the headings at up to 20 degrees
    a frame, lets the heading wander in slow curves, rests now and then, and
    turns back in when the source nears the edge of what it can see. The
    nub's reading trembles by a count or two."""
    rnd = random.Random(seed)
    st = dict(theta=rnd.uniform(0, 2 * math.pi), curve=0.0, m=rnd.uniform(70, 127),
              m_target=rnd.uniform(60, 127), rest=0, due=0)
    st["target"] = st["theta"]

    def schedule():
        st["due"] = max(6, int(round(60 * median * math.exp(rnd.gauss(0, sigma)))))

    schedule()

    def gen(src):
        if st["rest"] > 0:
            st["rest"] -= 1
            return stick(0, 0, rnd, 1.2)
        if rnd.random() < 1 / 500:
            st["rest"] = rnd.randint(4, 30)
        st["due"] -= 1
        edge = min(src.x, 1 - src.x, src.z, 1 - src.z)
        if edge < 0.05 and rnd.random() < 0.2:
            st["target"] = math.atan2(0.5 - src.z, 0.5 - src.x) + rnd.uniform(-1.1, 1.1)
            schedule()
        elif st["due"] <= 0:
            r = rnd.random()
            if r < 0.75:
                turn = rnd.uniform(0.5, 1.1)
            elif r < 0.95:
                turn = rnd.uniform(1.1, 2.1)
            else:
                turn = rnd.uniform(2.1, 3.1)
            st["target"] = st["theta"] + turn * rnd.choice((-1, 1))
            schedule()
        st["curve"] = 0.97 * st["curve"] + rnd.gauss(0, curve)
        st["target"] += st["curve"] + rnd.gauss(0, 0.03)
        diff = (st["target"] - st["theta"] + math.pi) % (2 * math.pi) - math.pi
        st["theta"] += max(-0.35, min(0.35, diff))
        if rnd.random() < 1 / 50:
            st["m_target"] = rnd.uniform(45, 127)
        st["m"] += (st["m_target"] - st["m"]) * 0.15
        return stick(st["m"], st["theta"], rnd, 1.5)

    return run(gen, frames)


# ------------------------------------------------------------ adversaries

def circle(seed=0, frames=60 * 600, period=40):
    """The stick rolled round its gate, 1.5 turns a second, over and over."""
    k = [0]

    def gen(src):
        k[0] += 1
        return stick(127, 2 * math.pi * k[0] / period)
    return run(gen, frames)


def spiral(seed=0, frames=60 * 600, period=40):
    """The same circle with a drift, so it keeps finding new ground: the
    cheap circle a lazy hand would actually draw."""
    k = [0]
    drift = [0.7, 0.3]

    def gen(src):
        k[0] += 1
        if src.x <= 0.02 or src.x >= 0.98:
            drift[0] = -drift[0] if (src.x < 0.5) == (drift[0] < 0) else drift[0]
        if src.z <= 0.02 or src.z >= 0.98:
            drift[1] = -drift[1] if (src.z < 0.5) == (drift[1] < 0) else drift[1]
        t = 2 * math.pi * k[0] / period
        vx = math.cos(t) + drift[0] * 1.2
        vz = math.sin(t) + drift[1] * 1.2
        return stick(127, math.atan2(vz, vx))
    return run(gen, frames)


def bouncing(angle_fn):
    """Runs angle_fn(k, dirx, dirz) with the base direction reflected at the
    walls, so a pattern keeps reaching new ground."""
    k = [0]
    d = [1.0, 1.0]

    def gen(src):
        k[0] += 1
        if src.x >= 0.99: d[0] = -1.0
        if src.x <= 0.01: d[0] = 1.0
        if src.z >= 0.99: d[1] = -1.0
        if src.z <= 0.01: d[1] = 1.0
        th = angle_fn(k[0], d[0], d[1])
        return stick(127, th)
    return gen


def reflect(theta, dx, dz):
    c, s = math.cos(theta) * dx, math.sin(theta) * dz
    return math.atan2(s, c)


def zigzag(seed=0, frames=60 * 600, leg=12):
    """Up-right, down-right, up-right...: two diagonals, a leg each, the row
    moving on when it meets a wall."""
    def ang(k, dx, dz):
        up = (k // leg) % 2 == 0
        th = math.radians(45 if up else -45)
        return reflect(th, dx, 1.0) + (0 if True else 0)
    g = bouncing(ang)
    # a slow vertical drift so the zigzag does not retrace its own row
    k = [0]

    def gen(src):
        k[0] += 1
        lx, ly = g(src)
        return lx, max(0, min(255, ly + (6 if (k[0] // 900) % 2 else -6)))
    return run(gen, frames)


def boundary(seed=0, frames=60 * 600):
    """A straight stroke along 22.5 degrees, where two headings meet, with
    the ADC's usual trembling of a count or two; reflected at the walls."""
    rnd = random.Random(seed)

    def ang(k, dx, dz):
        return reflect(math.radians(22.5), dx, dz)
    g = bouncing(ang)

    def gen(src):
        lx, ly = g(src)
        return (max(0, min(255, lx + rnd.randint(-1, 1))),
                max(0, min(255, ly + rnd.randint(-1, 1))))
    return run(gen, frames)


def corner(seed=0, frames=60 * 600):
    """The stick pushed into a corner of its gate and held there."""
    return run(lambda src: (255, 255), frames)


def alternate(seed=0, frames=60 * 600, every=1):
    """Right, right-up, right, right-up... switching every `every` frames."""
    def ang(k, dx, dz):
        th = 0.0 if (k // every) % 2 == 0 else math.radians(45)
        return reflect(th, dx, dz)
    return run(bouncing(ang), frames)


def edge_slide(seed=0, frames=60 * 600):
    """Up against the far wall, then along it: the stick cycles through
    up-right, right and up-right-ish, all of which the wall turns into one
    motion to the right; back the other way at the corners."""
    phase = [0]
    d = [1.0]
    k = [0]

    def gen(src):
        k[0] += 1
        if phase[0] == 0:
            if src.z >= 1.0:
                phase[0] = 1
            return stick(127, math.radians(90))
        if src.x >= 1.0: d[0] = -1.0
        if src.x <= 0.0: d[0] = 1.0
        angles = (60, 30, 45, 75)
        th = math.radians(angles[(k[0] // 6) % 4])
        return stick(127, math.atan2(math.sin(th), math.cos(th) * d[0]))
    return run(gen, frames)


def switcher(seed=0, frames=60 * 600):
    """Circle, zigzag, two-heading alternation, three seconds each and round
    again, drifting: a lazy hand that changes its habit to shake a counter
    that has learned the last one."""
    sp = spiral(frames=frames)
    zz = zigzag(frames=frames)
    al = alternate(frames=frames, every=6)
    out = []
    for i in range(frames):
        which = (i // 180) % 3
        out.append((sp, zz, al)[which][i])
    return out


def switcher_steer(seed=0, frames=60 * 600):
    """The pattern changer again, but every pattern steers the one source and
    turns at the walls where the source really is: circle with drift, zigzag,
    two-heading swing, three seconds each."""
    src = Source()
    out = []
    d = [1.0, 1.0]
    for i in range(frames):
        if src.x >= 0.97: d[0] = -1.0
        if src.x <= 0.03: d[0] = 1.0
        if src.z >= 0.97: d[1] = -1.0
        if src.z <= 0.03: d[1] = 1.0
        which = (i // 180) % 3
        if which == 0:
            t = 2 * math.pi * i / 40
            th = math.atan2(math.sin(t) + 0.35 * d[1], math.cos(t) + 0.85 * d[0])
        elif which == 1:
            th = reflect(math.radians(45 if (i // 12) % 2 == 0 else -45), d[0], 1.0)
            th = math.atan2(math.sin(th) + 0.1 * d[1], math.cos(th))
        else:
            th = reflect(0.0 if (i // 6) % 2 == 0 else math.radians(45), d[0], d[1])
        lx, ly = stick(127, th)
        src.step(lx, ly)
        out.append((lx, ly, 0))
    return out


def lcg_script(seed=1, frames=60 * 600):
    """A script: headings from a 16-bit LCG, 8 frames each. It is no choice
    at all, and nothing that watches the stick can tell it from one."""
    state = [seed]
    cur = [0.0]

    def ang(k, dx, dz):
        if k % 8 == 0:
            state[0] = (state[0] * 25173 + 13849) & 0xFFFF
            cur[0] = math.radians(45 * (state[0] >> 13))
        return reflect(cur[0], dx, dz)
    return run(bouncing(ang), frames)


def load_trace(path):
    d = open(path, "rb").read()
    return [struct.unpack_from("<BBH", d, i) for i in range(0, len(d) - 3, 4)]


def save_trace(path, frames):
    with open(path, "wb") as f:
        for lx, ly, b in frames:
            f.write(struct.pack("<BBH", lx, ly, b))


ADVERSARIES = {
    "circle": circle,
    "spiral": spiral,
    "zigzag": zigzag,
    "boundary-22.5": boundary,
    "corner": corner,
    "alternate-1": lambda seed=0, frames=36000: alternate(seed, frames, 1),
    "alternate-6": lambda seed=0, frames=36000: alternate(seed, frames, 6),
    "edge-slide": edge_slide,
    "switcher": switcher,
    "switcher-steer": switcher_steer,
    "lcg-script": lcg_script,
}


# ---------------------------------------------------------------- buttons
#
# SceCtrlData bits in the order of enum entropy_button: d-pad and face
# buttons clockwise from the top, then L and R.
BUTTON_BITS = [0x10, 0x20, 0x40, 0x80, 0x1000, 0x2000, 0x4000, 0x8000, 0x100, 0x200]
CROSS_BIT, CIRCLE_BIT = 0x4000, 0x2000
FACE = [4, 5, 6, 7]


def _rest(rnd):
    return 128 + rnd.randint(-2, 2), 128 + rnd.randint(-2, 2)


def _next_button(rnd, b):
    """Where a mashing hand goes next. On the face buttons the thumb mostly
    stays or rolls to a neighbour; now and then the other thumb takes the
    d-pad or a finger a shoulder."""
    r = rnd.random()
    if 4 <= b <= 7:
        if r < 0.30:
            return b
        if r < 0.70:
            return 4 + (b - 4 + rnd.choice((1, 3))) % 4
        if r < 0.85:
            return 4 + (b - 4 + 2) % 4
        if r < 0.95:
            return rnd.randint(0, 3)
        return rnd.choice((8, 9))
    if b <= 3:
        if r < 0.45:
            return rnd.choice((6, 6, 5, 7, 4))
        if r < 0.75:
            return b
        return (b + rnd.choice((1, 3))) % 4
    return rnd.choice((6, 5)) if r < 0.7 else (17 - b)


def masher(seed, frames=60 * 120, median_gap=7.0, sigma=0.20, single=None):
    """A person mashing buttons, the stick left alone. There is no recording
    of that, so every choice leans the cautious way: bursts of a dozen
    presses or so at a median of 7 frames apart (8.6 a second), the gaps
    spread by only 0.20 in log -- tapping as fast as one can is steadier
    than that, mashing a pad is not much looser -- pauses of about 0.6 s
    between bursts, a press held 2 or 3 frames, and a thumb that mostly stays
    on or rolls between neighbouring face buttons (about 1.7 bits a press
    if nobody learnt it). single= keeps to one button: a lazy hand with a
    human rhythm."""
    rnd = random.Random(seed)
    out = [list(_rest(rnd)) + [0] for _ in range(frames)]
    t = rnd.randint(10, 40)
    button = single if single is not None else rnd.choice(FACE)
    while t < frames:
        burst = max(3, int(rnd.expovariate(1 / 12)))
        for _ in range(burst):
            hold = rnd.randint(2, 3)
            for f in range(t, min(frames, t + hold)):
                out[f][2] |= BUTTON_BITS[button]
            t += max(4, int(round(median_gap * math.exp(rnd.gauss(0, sigma)))))
            if single is None:
                button = _next_button(rnd, button)
            if t >= frames:
                break
        t += max(12, int(round(36 * math.exp(rnd.gauss(0, 0.5)))))
    return [tuple(f) for f in out]


def mixed(seed, frames=60 * 120):
    """One person, two hands, taking turns: the stick for three to six
    seconds -- the calibrated hand, picked up where it left off, since the
    source stands still while the stick rests -- then the buttons for two to
    four, the stick at rest."""
    rnd = random.Random(seed ^ 0x5EED)
    stick_frames = human(seed, frames)
    mash_frames = masher(seed + 100000, frames)
    out = []
    si = mi = 0
    while len(out) < frames:
        n = int(60 * rnd.uniform(3, 6))
        out += stick_frames[si:si + n]
        si += n
        n = int(60 * rnd.uniform(2, 4))
        out += [(128 + rnd.randint(-2, 2), 128 + rnd.randint(-2, 2), b) for _, _, b in mash_frames[mi:mi + n]]
        mi += n
    return out[:frames]


def _pad(frames, fn, stick_fn=None):
    out = []
    for i in range(frames):
        lx, ly = stick_fn(i) if stick_fn else (128, 128)
        out.append((lx, ly, fn(i)))
    return out


def turbo(hz):
    period = int(round(60 / hz))
    return lambda seed=0, frames=36000: _pad(frames, lambda i: CROSS_BIT if i % period < max(1, period // 2) else 0)


def two_buttons(seed=0, frames=36000):
    """Cross and circle in turn at 8 Hz: a period of 7.5 frames, so the gaps
    come out 7, 8, 7, 8."""
    def fn(i):
        k = (i * 8) // 60
        start = -(-k * 60 // 8)
        return (CROSS_BIT if k % 2 == 0 else CIRCLE_BIT) if i - start < 3 else 0
    return _pad(frames, fn)


def ten_round(seed=0, frames=36000):
    return _pad(frames, lambda i: BUTTON_BITS[(i // 6) % 10] if i % 6 < 3 else 0)


def lcg_buttons(seed=1, frames=36000):
    """A 16-bit LCG picks the button and a gap of 5 to 12 frames."""
    state = [seed]
    out = []
    nxt, held, bit = 10, 0, 0
    for i in range(frames):
        if i == nxt:
            state[0] = (state[0] * 25173 + 13849) & 0xFFFF
            bit = BUTTON_BITS[(state[0] >> 8) % 10]
            nxt = i + 5 + ((state[0] >> 13) & 7)
            held = 2
        out.append((128, 128, bit if held > 0 else 0))
        held -= 1
    return out


def chord_smash(seed=0, frames=36000):
    return _pad(frames, lambda i: 0xF000 if i % 8 < 3 else 0)


def hold_button(seed=0, frames=36000):
    return _pad(frames, lambda i: CROSS_BIT)


def circle_turbo(seed=0, frames=36000):
    def st(i):
        th = 2 * math.pi * i / 40
        return stick(127, th)
    return _pad(frames, lambda i: CROSS_BIT if i % 4 < 2 else 0, st)


def one_button(seed=0, frames=36000):
    return masher(seed + 7, frames, single=6)


BUTTON_ATTACKS = {
    "turbo-10": turbo(10),
    "turbo-12": turbo(12),
    "turbo-15": turbo(15),
    "turbo-30": turbo(30),
    "two-buttons": two_buttons,
    "ten-round": ten_round,
    "lcg-buttons": lcg_buttons,
    "chord-smash": chord_smash,
    "hold-button": hold_button,
    "circle-turbo": circle_turbo,
    "one-button": one_button,
}
