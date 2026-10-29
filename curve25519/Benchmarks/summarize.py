#!/usr/bin/env python3
"""summarize.py -- turn one run.sh results directory into SUMMARY.md.

    python3 summarize.py results/<stamp>        writes results/<stamp>/SUMMARY.md
                                                and prints it

Reads, per configuration directory <stamp>/<cfg>/, one file per process:
    kernel_<v>.txt      "KERNEL <name> <mode> <median> <min> <p10> <p90>"  (cycles/op)
    x25519_<v>_<n>.txt  "X25519 <label> <median> <min> <p10> <p90>"        (cycles)
for v = setcc, adc (and kernel_floor.txt), and <stamp>/meta.txt (key=value
lines written by run.sh). Older runs, where one process timed both variants
(kernel.txt, x25519_<n>.txt), read the same way.

Method, as SUPERCOP: every contender keeps its best configuration. A
configuration's X25519 figure for a contender is the median of its per-run
medians, over every process that timed it (the others run in both the setcc
and the adc binary). A kernel arm's figure is the median over the processes
that timed it. Arith-only is latency minus the floor of its kind: for ours,
the microcode floor (kernel_floor, its own process in the same
configuration); for natives, the native floor of the same process. Then the
best configuration is taken. "Wins" counts configurations in which ours beat
the contender in the same process -- a comparison that does not depend on
picking configurations.
"""
import os, re, statistics, sys

OURS = ["ours/setcc", "ours/adc"]   # the other X25519 contenders are read from the files
BACKENDS = [  # (kernel suffix, description, microcode?)
    ("setcc",    "ours/setcc microcode",          True),
    ("adc",      "ours/adc microcode (ADC\\|MOD2)", True),
    ("openssl",  "OpenSSL fe51 asm",              False),
    ("fiat",     "fiat-crypto",                   False),
    ("cryptopt", "CryptOpt",                      False),
    ("amd64-51", "amd64-51 asm (SUPERCOP)",       False),
    ("handc",    "hand-written `__uint128_t` C",  False),
    ("s2n",      "s2n-bignum `_alt` (4x64)",      False),
]


def cfg_key(name):
    """Sort configs as run.sh lists them: compiler, then -O3 -O2 -Os -O."""
    order = {"O3": 0, "O2": 1, "Os": 2, "O": 3}
    cc, _, opt = name.rpartition("_")
    return (cc, order.get(opt, 9))


def load(root):
    """kern[cfg][proc] = {(name, mode): median}; x[cfg][proc][label] = [runs],
    where proc is the variant a file's process ran ("" for the old
    single-process files)."""
    meta, kern, x = {}, {}, {}
    mp = os.path.join(root, "meta.txt")
    if os.path.exists(mp):
        for line in open(mp):
            if "=" in line:
                k, v = line.rstrip("\n").split("=", 1)
                meta[k] = v
    for cfg in sorted(os.listdir(root), key=cfg_key):
        d = os.path.join(root, cfg)
        if not os.path.isdir(d):
            continue
        for fn in sorted(os.listdir(d)):
            path = os.path.join(d, fn)
            m = re.fullmatch(r"kernel(?:_([a-z0-9]+))?\.txt", fn)
            if m:
                arms = kern.setdefault(cfg, {}).setdefault(m.group(1) or "", {})
                for line in open(path):
                    f = line.split()
                    if len(f) == 7 and f[0] == "KERNEL":
                        arms[(f[1], f[2])] = float(f[3])
            m = re.fullmatch(r"x25519_(?:([a-z0-9]+)_)?\d+\.txt", fn)
            if m:
                procs = x.setdefault(cfg, {}).setdefault(m.group(1) or "", {})
                for line in open(path):
                    f = line.split()
                    if len(f) == 6 and f[0] == "X25519":
                        procs.setdefault(f[1], []).append(tuple(int(v) for v in f[2:]))
    return meta, kern, x


def best(per_cfg):
    """{cfg: value} -> (value, cfg) with the smallest value, or (None, None)."""
    items = [(v, c) for c, v in per_cfg.items() if v is not None]
    return min(items) if items else (None, None)


def fmt(v, nd=1):
    return "n/a" if v is None else f"{v:,.{nd}f}"


def table(head, rows, align=None):
    align = align or ["l"] + ["r"] * (len(head) - 1)
    sep = ["---:" if a == "r" else "---" for a in align]
    out = ["| " + " | ".join(head) + " |", "| " + " | ".join(sep) + " |"]
    out += ["| " + " | ".join(str(c) for c in r) + " |" for r in rows]
    return "\n".join(out)


def median_or_none(vs):
    return statistics.median(vs) if vs else None


def kernel_section(kern):
    cfgs = list(kern)
    multi = len(cfgs) > 1

    def kval(c, name, mode):
        """One configuration's figure: the median over the processes that timed it."""
        return median_or_none([p[(name, mode)] for p in kern[c].values() if (name, mode) in p])

    def arm(name, mode):
        return best({c: kval(c, name, mode) for c in cfgs})

    def arith(op, b, uc):
        per = {}
        for c in cfgs:
            if uc:      # ours minus the microcode floor, each from its own process
                v, f = kval(c, f"Fe_{op}_{b}", "lat"), kval(c, f"Fe_{op}_floor", "lat")
                per[c] = v - f if v is not None and f is not None else None
            else:       # native minus the native floor, within each process
                a, fl = (f"Fe_{op}_{b}", "lat"), (f"Fe_{op}_nfloor", "lat")
                per[c] = median_or_none([p[a] - p[fl] for p in kern[c].values()
                                         if a in p and fl in p])
        return best(per)

    out = ["## Level 1 -- kernels (median cycles per op)", ""]
    rows = []
    for b in ("setcc", "adc"):
        for op in ("mul", "sq"):
            lat, lc = arm(f"Fe_{op}_{b}", "lat")
            r = [f"`Fe_{op}_{b}`", fmt(lat), fmt(arith(op, b, True)[0]),
                 fmt(arm(f"Fe_{op}_{b}", "tput")[0])]
            rows.append(r + ([lc or ""] if multi else []))
    for op in ("mul", "sq"):
        rows.append([f"dispatch floor ({op})", fmt(arm(f"Fe_{op}_floor", "lat")[0]), "",
                     fmt(arm(f"Fe_{op}_floor", "tput")[0])] + ([""] if multi else []))
    out.append(table(["kernel", "latency", "arith only", "throughput"]
                     + (["best config (latency)"] if multi else []), rows,
                     ["l", "r", "r", "r"] + (["l"] if multi else [])))
    out += ["", "latency: dependent chain, memory to memory. arith only: latency minus the "
            "dispatch floor (the same wrapper firing a 1-triad no-op patch, timed by "
            "kernel_floor in its own process). throughput: four independent chains.", ""]

    rows = []
    for b, desc, uc in BACKENDS:
        r = [desc]
        for op in ("mul", "sq"):
            r.append(fmt(arm(f"Fe_{op}_{b}", "lat")[0]))
        for op in ("mul", "sq"):
            r.append(fmt(arith(op, b, uc)[0]))
        for op in ("mul", "sq"):
            r.append(fmt(arm(f"Fe_{op}_{b}", "tput")[0]))
        rows.append(r)
    rows.append(["microcode floor", fmt(arm("Fe_mul_floor", "lat")[0]),
                 fmt(arm("Fe_sq_floor", "lat")[0]), "", "", "", ""])
    rows.append(["native floor", fmt(arm("Fe_mul_nfloor", "lat")[0]),
                 fmt(arm("Fe_sq_nfloor", "lat")[0]), "", "", "", ""])
    out += ["### All backends", "",
            table(["backend", "mul lat", "sq lat", "mul arith", "sq arith", "mul tput", "sq tput"],
                  rows),
            "", "arith = latency minus the floor of its kind, within one configuration. The "
            "sq arith column flatters microcode (FE_SQ's 2a/19a precompute sits in its floor), "
            "so compare mul. Natives without the per-op memory barrier:", ""]
    rows = []
    for b, desc, uc in BACKENDS:
        if not uc:
            rows.append([desc, fmt(arm(f"Fe_mul_{b}", "nb")[0]), fmt(arm(f"Fe_sq_{b}", "nb")[0])])
    out += [table(["backend", "mul lat (no barrier)", "sq lat (no barrier)"], rows), ""]
    return out


def x25519_section(x):
    cfgs = list(x)
    seen = []                       # every label, in the order the binaries print them
    for c in cfgs:
        for procs in x[c].values():
            for l in procs:
                if l not in seen:
                    seen.append(l)
    labels = [l for l in OURS if l in seen] + [l for l in seen if l not in OURS]

    def runs_of(c, l, with_label=None):
        """Every run of l in config c; only from processes that also timed with_label."""
        return [r for procs in x[c].values() if with_label is None or with_label in procs
                for r in procs.get(l, [])]

    # per config: median of run medians, and the run-to-run spread
    med = {l: {} for l in labels}
    spread = {l: {} for l in labels}
    p1090 = {l: {} for l in labels}
    for c in cfgs:
        for l in labels:
            runs = runs_of(c, l)
            if not runs:
                continue
            ms = [r[0] for r in runs]
            med[l][c] = statistics.median(ms)
            spread[l][c] = (max(ms) - min(ms)) / statistics.median(ms) * 100 if len(ms) > 1 else 0
            p1090[l][c] = (statistics.median(r[2] for r in runs), statistics.median(r[3] for r in runs))
    bests = {l: best(med[l]) for l in labels}

    out = ["## Level 2 -- complete X25519 (cycles, RFC 7748 vector 1)", ""]
    head = ["contender", "median", "p10", "p90"]
    multi = len(cfgs) > 1
    if multi:
        head.append("best config")
    for o in OURS:
        if o in labels:
            head.append(f"vs {o}")
    for o in OURS:
        if o in labels and multi:
            head.append(f"{o} wins")
    rows = []
    for l in sorted(labels, key=lambda l: bests[l][0] or 1e18):
        v, c = bests[l]
        p10, p90 = p1090[l].get(c, (None, None))
        r = [f"**{l}**" if l in OURS else l, fmt(v, 0), fmt(p10, 0), fmt(p90, 0)]
        if multi:
            r.append(c)
        for o in OURS:
            if o in labels:
                r.append(f"{v / bests[o][0]:.3f}" if v and bests[o][0] else "n/a")
        for o in OURS:
            if o in labels and multi:
                if l == o:
                    r.append("")
                else:       # ours and l from the same processes only
                    won = n = 0
                    for cc in cfgs:
                        ro, rl = runs_of(cc, o), runs_of(cc, l, with_label=o)
                        if ro and rl:
                            n += 1
                            won += statistics.median(r[0] for r in ro) < \
                                statistics.median(r[0] for r in rl)
                    r.append(f"{won}/{n}" if n else "n/a")   # never in one process
        rows.append(r)
    out.append(table(head, rows, ["l", "r", "r", "r"] + (["l"] if multi else [])
                     + ["r"] * (len(head) - 4 - multi)))
    out += ["", "median: best configuration per contender; within one, the median of "
            "per-run medians. vs ours/x: contender / ours/x, so > 1 means ours is faster."
            + (" wins: configurations where ours won in the same process." if multi else ""), ""]
    if multi:
        rows = []
        for c in cfgs:
            rows.append([c] + [fmt(med[l].get(c), 0) for l in labels])
        worst = max((s for l in labels for s in spread[l].values()), default=0)
        out += ["### Every configuration (median cycles)", "",
                table(["config"] + labels, rows), "",
                f"Worst run-to-run spread of a configuration's medians: {worst:.2f}%.", ""]
    return out


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    root = sys.argv[1].rstrip("/")
    meta, kern, x = load(root)
    out = ["# curve25519 benchmark", ""]
    for k, label in [("date", "Date"), ("git", "Commit"), ("core", "Core"),
                     ("isolation", "Isolation"), ("nohz", "nohz_full/isolcpus"),
                     ("freq", "Frequency"), ("freq_drift", "Frequency drift"),
                     ("configs", "Configurations"), ("runs", "X25519 runs per variant per configuration")]:
        if k in meta:
            out.append(f"- **{label}:** {meta[k]}")
    out.append("")
    if kern:
        out += kernel_section(kern)
    if x:
        out += x25519_section(x)
    if not kern and not x:
        out.append("No results found.")
    text = "\n".join(out) + "\n"
    with open(os.path.join(root, "SUMMARY.md"), "w") as f:
        f.write(text)
    print(text)


if __name__ == "__main__":
    main()
