#!/usr/bin/env python3
# The numbers behind the entropy report, from the library's own entropy.c
# and sweep.c (built into ./sim) fed with recorded and simulated sweeps.
#
#   make && python3 report.py compute WORK TESTDATA   # writes WORK/data.json
#   python3 report.py render WORK OUT.html            # the page
#
# WORK holds the generated traces and the results; TESTDATA is PSPDX's
# dev/testdata with sweep-full.trace and sweep.trace; a trace named
# WORK/rig-script.trace, if there, is taken as what dev/sweep-trace.py makes
# today. Three counts side by side: "old" is the counting before any of
# this -- a field paid a bit when it was new ground under a stick heading
# other than the last one paid -- ported here, since that code no longer
# exists; "hardened" is the first hardening, kept in hardened/ and built
# into ./sim-hardened; "new" is the library as it is, in ./sim.
import base64
import json
import math
import os
import struct
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import walkers as W  # noqa: E402

SIM = os.path.join(HERE, "sim")
SIM_HARDENED = os.path.join(HERE, "sim-hardened")
HUMANS = 1024
PADS = 256
BITS = 128


# ----------------------------------------------------------- old counting

def f32(v):
    return struct.unpack("f", struct.pack("f", v))[0]


SX, SZ = f32(0.0065 / 60), f32(0.0040 / 28)


def heading_of(dx, dy):
    ax, ay = abs(dx), abs(dy)
    if ay * 12 < ax * 5:
        return 0 if dx > 0 else 4
    if ax * 12 < ay * 5:
        return 2 if dy > 0 else 6
    if dx > 0:
        return 1 if dy > 0 else 7
    return 3 if dy > 0 else 5


def clamp01(v):
    return 0.0 if v < 0 else 1.0 if v > 1 else v


def old_count(frames, stop_at_full=False):
    """(frame, bits) at every credit, the old rule."""
    x = z = 0.5
    seen = set()
    last = None
    bits = 0
    out = []
    for i, (lx, ly, _) in enumerate(frames):
        dx, dy = lx - 128, ly - 128
        if dx * dx + dy * dy <= 196:
            continue
        x = f32(clamp01(f32(x + dx * SX)))
        z = f32(clamp01(f32(z - dy * SZ)))
        f = int(f32(z * 249) + 0.5) * 250 + int(f32(x * 249) + 0.5)
        if f in seen:
            continue
        seen.add(f)
        h = heading_of(dx, dy)
        if h != last:
            last = h
            bits += 1
            out.append((i, bits))
            if stop_at_full and bits >= BITS:
                break
    return out


def full_frame(curve):
    for i, b in curve:
        if b >= BITS:
            return i
    return None


def thin(points, keep=700):
    if len(points) <= keep:
        return points
    step = len(points) / keep
    picked = [points[int(k * step)] for k in range(keep)]
    if picked[-1] != points[-1]:
        picked.append(points[-1])
    return picked


# ------------------------------------------------------------ statistics

def gammaincc(a, x):
    """Regularised upper incomplete gamma Q(a, x)."""
    if x <= 0:
        return 1.0
    lg = math.lgamma(a)
    if x < a + 1:
        term = s = 1.0 / a
        n = a
        for _ in range(10000):
            n += 1
            term *= x / n
            s += term
            if abs(term) < abs(s) * 1e-15:
                break
        return max(0.0, 1.0 - s * math.exp(-x + a * math.log(x) - lg))
    b = x + 1 - a
    c = 1e300
    d = 1 / b
    h = d
    for i in range(1, 10000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = 1e-300 if abs(d) < 1e-300 else d
        c = b + an / c
        c = 1e-300 if abs(c) < 1e-300 else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-15:
            break
    return math.exp(-x + a * math.log(x) - lg) * h


def bits_of(row):
    return [(byte >> (7 - k)) & 1 for byte in row for k in range(8)]


def stats(rows):
    """rows: list of bytes objects of equal length."""
    n_rows, width = len(rows), len(rows[0])
    stream = b"".join(rows)
    n = len(stream)
    hist = [0] * 256
    for v in stream:
        hist[v] += 1
    expect = n / 256
    chi2 = sum((o - expect) ** 2 / expect for o in hist)
    p_chi2 = gammaincc(255 / 2, chi2 / 2)
    entropy = -sum((c / n) * math.log2(c / n) for c in hist if c)
    mean = sum(stream) / n
    # ent's serial correlation, wrapping round
    s1 = sum(stream)
    s2 = sum(v * v for v in stream)
    s12 = sum(stream[i] * stream[(i + 1) % n] for i in range(n))
    scc = (n * s12 - s1 * s1) / (n * s2 - s1 * s1)
    # ent's Monte Carlo pi on 24-bit coordinates
    inside = total = 0
    r2 = (256 ** 3 - 1) ** 2
    for i in range(0, n - 5, 6):
        x = (stream[i] << 16) | (stream[i + 1] << 8) | stream[i + 2]
        y = (stream[i + 3] << 16) | (stream[i + 4] << 8) | stream[i + 5]
        total += 1
        inside += x * x + y * y <= r2
    pi = 4 * inside / total
    # runs test over the bit stream
    bitstream = bits_of(stream)
    nb = len(bitstream)
    ones = sum(bitstream)
    zeros = nb - ones
    runs = 1 + sum(1 for i in range(1, nb) if bitstream[i] != bitstream[i - 1])
    mu = 2 * ones * zeros / nb + 1
    var = (mu - 1) * (mu - 2) / (nb - 1)
    z_runs = (runs - mu) / math.sqrt(var)
    p_runs = math.erfc(abs(z_runs) / math.sqrt(2))
    # fraction of ones per bit position
    matrix = [bits_of(r) for r in rows]
    nbits = width * 8
    bias = [sum(m[j] for m in matrix) / n_rows for j in range(nbits)]
    sigma = math.sqrt(0.25 / n_rows)
    outside3 = sum(1 for b in bias if abs(b - 0.5) > 3 * sigma)
    # correlation between the first 64 bit positions across sweeps
    k = min(64, nbits)
    means = bias[:k]
    sd = [math.sqrt(max(m * (1 - m), 1e-12)) for m in means]
    corr = []
    worst = 0.0
    for a in range(k):
        rowc = []
        for b in range(k):
            if a == b:
                rowc.append(1.0)
                continue
            s = sum(matrix[r][a] * matrix[r][b] for r in range(n_rows)) / n_rows
            c = (s - means[a] * means[b]) / (sd[a] * sd[b])
            rowc.append(round(c, 4))
            if a < b:
                worst = max(worst, abs(c))
        corr.append(rowc)
    # Hamming distance between consecutive sweeps
    ham = [sum(bin(x ^ y).count("1") for x, y in zip(rows[i], rows[i + 1])) for i in range(n_rows - 1)]
    ham_mean = sum(ham) / len(ham)
    ham_sd = math.sqrt(sum((h - ham_mean) ** 2 for h in ham) / len(ham))
    return dict(rows=n_rows, width=width, bytes=n, hist=hist, chi2=chi2, p_chi2=p_chi2,
                entropy=entropy, mean=mean, scc=scc, pi=pi, runs=runs, runs_expected=mu,
                z_runs=z_runs, p_runs=p_runs, bias=[round(b, 4) for b in bias], sigma=sigma,
                outside3=outside3, corr=corr, corr_worst=worst, corr_sigma=1 / math.sqrt(n_rows),
                ham=ham, ham_mean=ham_mean, ham_sd=ham_sd)


# ----------------------------------------------------------------- runs

def sim(*args, binary=SIM):
    cmd = [binary, *args]
    if "--broken" in args:
        # entropy_init absorbs where the stack is, and ASLR moves it between
        # processes; the broken pool is only deterministic with that off.
        cmd = ["setarch", os.uname().machine, "-R", *cmd]
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


def sim_run(path, binary=SIM):
    return json.loads(sim("run", path, binary=binary))


def seeds(listfile, *extra, binary=SIM):
    rows = []
    for line in sim("seeds", listfile, *extra, binary=binary).splitlines():
        frames, draws, filehex = (line.split(" ") + ["", ""])[:3]
        rows.append(dict(frames=int(frames), draws=bytes.fromhex(draws),
                         file=None if filehex == "-" else bytes.fromhex(filehex)))
    return rows


def commit_stats(frames, hold=3, degrees=15):
    """What the counter sees of a hand, before any guessing: turns a second,
    the samples between them (median and spread in log), and how far they
    go. Used to hold the simulated hand against the recorded one."""
    x = z = 0.5
    cand = com = None
    cs = 0
    csum = [0, 0]
    comsum = [0, 0]
    out = []
    tana = math.tan(math.radians(degrees))
    for i, (lx, ly, _) in enumerate(frames):
        dx, dy = lx - 128, ly - 128
        if dx * dx + dy * dy <= 196:
            continue
        nx = f32(clamp01(f32(x + dx * SX)))
        nz = f32(clamp01(f32(z - dy * SZ)))
        mx = dx if nx != x else 0
        my = dy if nz != z else 0
        x, z = nx, nz
        if not (mx or my):
            continue
        h = heading_of(mx, my)
        if h != cand:
            cand, cs, csum = h, 0, [0, 0]
        cs += 1
        csum[0] += mx
        csum[1] += my
        if cand == com:
            comsum[0] += mx
            comsum[1] += my
        if cand != com and cs >= hold:
            if com is not None:
                dot = csum[0] * comsum[0] + csum[1] * comsum[1]
                cr = abs(csum[0] * comsum[1] - csum[1] * comsum[0])
                if dot > 0 and cr < tana * dot:
                    continue
            out.append((i, cand))
            com, comsum = cand, list(csum)
    gaps = [out[k + 1][0] - out[k][0] for k in range(len(out) - 1)]
    turns = [min((out[k + 1][1] - out[k][1]) % 8, 8 - (out[k + 1][1] - out[k][1]) % 8) for k in range(len(out) - 1)]
    logs = [math.log(g) for g in gaps]
    mean = sum(logs) / len(logs)
    return dict(rate=len(out) / (len(frames) / 60), gap_median=sorted(gaps)[len(gaps) // 2],
                gap_logsd=math.sqrt(sum((v - mean) ** 2 for v in logs) / len(logs)),
                steps=[round(100 * turns.count(k) / len(turns)) for k in (1, 2, 3, 4)])


def percentile(values, q):
    v = sorted(values)
    return v[min(len(v) - 1, int(q * (len(v) - 1) + 0.5))]


def compute(work, testdata):
    os.makedirs(os.path.join(work, "humans"), exist_ok=True)
    os.makedirs(os.path.join(work, "adv"), exist_ok=True)
    human_list = os.path.join(work, "humans.list")
    with open(human_list, "w") as L:
        for s in range(HUMANS):
            p = os.path.join(work, "humans", "h%04d.trace" % s)
            if not os.path.exists(p):
                W.save_trace(p, W.human(s, 60 * 120))
            L.write(p + "\n")
    for k, g in W.ADVERSARIES.items():
        p = os.path.join(work, "adv", k + ".trace")
        if not os.path.exists(p):
            W.save_trace(p, g(frames=60 * 600))

    inputs = [
        ("sweep-full", "recorded", os.path.join(testdata, "sweep-full.trace")),
        ("sweep.trace", "script", os.path.join(testdata, "sweep.trace")),
    ]
    if os.path.exists(os.path.join(work, "rig-script.trace")):
        inputs.append(("rig-script", "script", os.path.join(work, "rig-script.trace")))
    inputs.append(("human #0", "simulated hand", os.path.join(work, "humans", "h0000.trace")))
    inputs += [(k, "cheap pattern" if k != "lcg-script" else "script", os.path.join(work, "adv", k + ".trace"))
               for k in W.ADVERSARIES]

    def steps(credits):
        out, last = [], -1
        for c in credits:
            if c[1] != last:
                out.append((c[0], c[1]))
                last = c[1]
        return out

    table = []
    for name, kind, path in inputs:
        frames = W.load_trace(path)
        old = old_count(frames)
        hard = sim_run(path, binary=SIM_HARDENED)
        new = sim_run(path)
        window = new["full"] if new["full"] >= 0 else len(frames)
        window = min(window, 60 * 60) if kind != "recorded" else len(frames)
        entry = dict(
            name=name, kind=kind, seconds=len(frames) / 60,
            old_full=None if full_frame(old) is None else full_frame(old) / 60,
            old_bits=old[-1][1] if old else 0,
            hard_full=None if hard["full"] < 0 else hard["full"] / 60,
            hard_bits=hard["bits"],
            new_full=None if new["full"] < 0 else new["full"] / 60,
            new_bits=new["bits"],
            old_curve=[(round(f / 60, 3), b) for f, b in thin(old)],
            hard_curve=[(round(f / 60, 3), b) for f, b in thin(steps(hard["credits"]))],
            new_curve=[(round(f / 60, 3), b) for f, b in thin(steps(new["credits"]))],
        )
        if name in ("sweep-full", "human #0", "spiral", "boundary-22.5", "switcher-steer", "zigzag"):
            entry["path"] = [(round(x, 3), round(z, 3)) for x, z in new["path"][: window // 2 + 1]]
            entry["path_seconds"] = window / 60
            entry["credited"] = [(round(c[2], 3), round(c[3], 3)) for c in new["credits"] if c[0] <= window]
            old_pts = []
            x = z = 0.5
            olds = {f for f, _ in old if f <= window}
            for i, (lx, ly, _) in enumerate(frames[: window + 1]):
                dx, dy = lx - 128, ly - 128
                if dx * dx + dy * dy > 196:
                    x = f32(clamp01(f32(x + dx * SX)))
                    z = f32(clamp01(f32(z - dy * SZ)))
                if i in olds:
                    old_pts.append((round(x, 3), round(z, 3)))
            entry["old_credited"] = old_pts
        table.append(entry)
        r1 = lambda v: v and round(v, 1)
        print("%-16s old %-6s (%5d)  hardened %-6s (%5d)  new %-6s (%5d)" % (
            name, r1(entry["old_full"]), entry["old_bits"], r1(entry["hard_full"]), entry["hard_bits"],
            r1(entry["new_full"]), entry["new_bits"]), file=sys.stderr)

    # Many hands: how long a sweep takes under each count, and what the new
    # one hands wolfSSL.
    good = seeds(human_list, "--draws", "1")
    hard_rows = seeds(human_list, "--draws", "1", binary=SIM_HARDENED)
    new_times = [r["frames"] / 60 for r in good if r["frames"] >= 0]
    hard_times = [r["frames"] / 60 for r in hard_rows if r["frames"] >= 0]
    old_times = []
    for s in range(256):
        c = old_count(W.load_trace(os.path.join(work, "humans", "h%04d.trace" % s)), stop_at_full=True)
        ff = full_frame(c)
        if ff is not None:
            old_times.append(ff / 60)
    draws = [r["draws"] for r in good if r["frames"] >= 0]
    files = [r["file"] for r in good if r["file"]]

    first512 = os.path.join(work, "humans512.list")
    with open(first512, "w") as L:
        for s in range(512):
            L.write(os.path.join(work, "humans", "h%04d.trace" % s) + "\n")
    one = os.path.join(work, "human0.list")
    with open(one, "w") as L:
        L.write(os.path.join(work, "humans", "h0000.trace") + "\n")
    b1 = seeds(one, "--broken", "--draws", "512")[0]["draws"]
    b1_rows = [b1[i * 64:(i + 1) * 64] for i in range(512)]
    b2a = seeds(first512, "--broken", "--draws", "1")
    b2b = seeds(first512, "--broken", "--draws", "1")
    b2_rows = [r["draws"] for r in b2a]
    b2_same = all(x["draws"] == y["draws"] for x, y in zip(b2a, b2b))
    g2 = seeds(first512, "--draws", "1")
    good_repeat_same = sum(1 for x, y in zip(good[:512], g2) if x["draws"] == y["draws"])

    walker_frames = []
    for s in range(16):
        walker_frames += W.load_trace(os.path.join(work, "humans", "h%04d.trace" % s))[: 60 * 60]
    calibration = dict(real=commit_stats(W.load_trace(os.path.join(testdata, "sweep-full.trace"))),
                       walker=commit_stats(walker_frames))

    def spread(times, n):
        return dict(n=n, finished=len(times), median=percentile(times, 0.5),
                    p10=percentile(times, 0.1), p90=percentile(times, 0.9),
                    times=[round(t, 2) for t in times])

    # Buttons: the cheap ways, and hands that mash, alone and with the stick.
    for name, gen in W.BUTTON_ATTACKS.items():
        path = os.path.join(work, "adv", "pad-" + name + ".trace")
        if not os.path.exists(path):
            W.save_trace(path, gen(frames=60 * 600))
    pad_table = []
    for name in W.BUTTON_ATTACKS:
        path = os.path.join(work, "adv", "pad-" + name + ".trace")
        new = sim_run(path)
        presses = [c for c in new["credits"] if len(c) > 4 and c[4] & 2]
        pad_table.append(dict(name=name, seconds=600, full=None if new["full"] < 0 else new["full"] / 60,
                              bits=new["bits"], paid_presses=len(presses)))
        print("pad %-14s %-6s (%5d)" % (name, pad_table[-1]["full"] and round(pad_table[-1]["full"], 1),
                                          new["bits"]), file=sys.stderr)
    pads = {}
    for kind, gen in (("masher", lambda s: W.masher(s, 60 * 120)), ("mixed", lambda s: W.mixed(s, 60 * 120))):
        os.makedirs(os.path.join(work, kind), exist_ok=True)
        listfile = os.path.join(work, kind + ".list")
        with open(listfile, "w") as L:
            for s in range(PADS):
                path = os.path.join(work, kind, "%s%04d.trace" % (kind[0], s))
                if not os.path.exists(path):
                    W.save_trace(path, gen(s))
                L.write(path + "\n")
        rows = seeds(listfile, "--draws", "0")
        times = [r["frames"] / 60 for r in rows if r["frames"] >= 0]
        pads[kind] = dict(n=len(rows), finished=len(times), median=percentile(times, 0.5),
                          p10=percentile(times, 0.1), p90=percentile(times, 0.9),
                          fastest=min(times), times=[round(t, 2) for t in times])
        print("%s median %.1f (p10 %.1f p90 %.1f, fastest %.1f) finished %d of %d" % (
            kind, pads[kind]["median"], pads[kind]["p10"], pads[kind]["p90"], pads[kind]["fastest"],
            len(times), len(rows)), file=sys.stderr)

    data = dict(
        table=table,
        pad_table=pad_table,
        pads=pads,
        humans=dict(old=spread(old_times, 256), hard=spread(hard_times, len(hard_rows)),
                    new=spread(new_times, len(good))),
        calibration=calibration,
        good=stats(draws), files=stats(files), broken_draws=stats(b1_rows), broken_seeds=stats(b2_rows),
        bitmaps=dict(good=base64.b64encode(b"".join(draws[:512])).decode(),
                     broken_seeds=base64.b64encode(b"".join(b2_rows)).decode(),
                     files=base64.b64encode(b"".join(files[:512])).decode()),
        b2_reproducible=b2_same, good_repeat_same=good_repeat_same,
        selftest=sim("selftest"),
    )
    with open(os.path.join(work, "data.json"), "w") as f:
        json.dump(data, f)
    for key in ("good", "files", "broken_draws", "broken_seeds"):
        s = data[key]
        print("%-13s rows %4d chi2 %.1f p %.3f H %.5f mean %.3f scc %+.5f pi %.4f runs z %+.2f p %.3f bias>3s %d corr %.3f ham %.1f+-%.1f" % (
            key, s["rows"], s["chi2"], s["p_chi2"], s["entropy"], s["mean"], s["scc"], s["pi"], s["z_runs"],
            s["p_runs"], s["outside3"], s["corr_worst"], s["ham_mean"], s["ham_sd"]), file=sys.stderr)
    for k in ("old", "hard", "new"):
        h = data["humans"][k]
        print("humans %-4s median %.1f (p10 %.1f p90 %.1f) finished %d of %d" % (
            k, h["median"], h["p10"], h["p90"], h["finished"], h["n"]), file=sys.stderr)
    print("calibration", json.dumps(calibration), file=sys.stderr)
    print("broken seeds reproducible across processes: %s; good seeds equal on rerun: %d of 512" % (
        b2_same, good_repeat_same), file=sys.stderr)


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "compute":
        compute(sys.argv[2], sys.argv[3])
    elif len(sys.argv) >= 4 and sys.argv[1] == "render":
        from render import render
        render(sys.argv[2], sys.argv[3])
    else:
        print(__doc__ or "usage: report.py compute WORK TESTDATA | render WORK OUT.html")
        sys.exit(2)
