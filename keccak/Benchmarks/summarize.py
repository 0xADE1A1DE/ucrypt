#!/usr/bin/env python3
"""summarize.py — reduce the repeated runs in a sha3_best.sh log to one table.

Each run of sha3_own prints one machine-readable line per (contender, length):

    sha3_256/<key>: len L perms P min X median Y p10 Z p90 W

The k-th line for a given (contender, length) belongs to run k. Runs are reduced
the way the Curve25519 evaluation reduces them (curve25519_file/lib/build_run.sh):
median of the per-run medians, smallest min, median of the per-run p10 and p90.
The run-to-run spread is (max - min) / min of the per-run medians.

Usage: summarize.py <log>   (markdown to stdout)
"""
import re
import sys
from collections import defaultdict

PAPER = ["openssl", "x86_64_asm", "opt64lcu24"]   # native columns of tab:results-sha3
LABEL = {32: r"32\,B", 128: r"128\,B", 1024: r"1\,KiB", 4096: r"4\,KiB", 16384: r"16\,KiB"}
LINE = re.compile(r"^sha3_256/(\S+): len (\d+) perms (\d+) min (\d+) median (\d+) p10 (\d+) p90 (\d+)$")


def median(v):
    s = sorted(v)
    return s[len(s) // 2]        # middle run for odd counts, as build_run.sh's median_of


def main(path):
    runs = defaultdict(list)     # (key, len) -> [(min, med, p10, p90), ...] in run order
    perms = {}
    with open(path) as f:
        for line in f:
            m = LINE.match(line.strip())
            if not m:
                continue
            key, n, p = m.group(1), int(m.group(2)), int(m.group(3))
            runs[(key, n)].append(tuple(int(x) for x in m.groups()[3:]))
            perms[n] = p
    if not runs:
        sys.exit(f"no sha3_256/ result lines in {path}")

    lengths = sorted(perms)
    nruns = {len(v) for v in runs.values()}
    if len(nruns) != 1:
        sys.exit(f"uneven run counts per contender ({sorted(nruns)}); was a run cut short?")
    nrun = nruns.pop()

    red = {}                     # (key, len) -> dict of reduced statistics
    for (key, n), v in runs.items():
        meds = [r[1] for r in v]
        red[(key, n)] = dict(
            med=median(meds), mn=min(r[0] for r in v),
            p10=median([r[2] for r in v]), p90=median([r[3] for r in v]),
            runs=meds, spread=100.0 * (max(meds) - min(meds)) / min(meds))

    print(f"# SHA3-256, each implementation's own sponge, best-config builds — {nrun} run(s)\n")
    print(f"Source log: `{path}`. Median = median of the {nrun} per-run medians; "
          "min = smallest; p10/p90 = median of the per-run values; "
          "spread = (max - min) / min of the per-run medians.\n")

    worst = (0.0, "")
    for n in lengths:
        keys = sorted({k for (k, m) in red if m == n}, key=lambda k: red[(k, n)]["med"])
        uc = red.get(("microcode", n), {}).get("med")
        print(f"## {n} bytes ({perms[n]} permutation{'s' if perms[n] != 1 else ''})\n")
        print("| contender | median | per-run medians | spread | min | p10 | p90 | x vs microcode |")
        print("|---|---|---|---|---|---|---|---|")
        for k in keys:
            r = red[(k, n)]
            x = f"{r['med'] / uc:.3f}x" if uc else "—"
            print(f"| {k} | {r['med']} | {' / '.join(map(str, r['runs']))} | {r['spread']:.2f}% "
                  f"| {r['mn']} | {r['p10']} | {r['p90']} | {x} |")
            if r["spread"] > worst[0]:
                worst = (r["spread"], f"{k} @ {n} B")
        print()

    print("## per-run speed-up (fastest native median / microcode median, within each run)\n")
    print("| length | " + " | ".join(f"run {i + 1}" for i in range(nrun)) + " |")
    print("|---|" + "---|" * nrun)
    for n in lengths:
        cells = []
        for i in range(nrun):
            natives = [(v[i][1], k) for (k, m), v in runs.items() if m == n and k != "microcode"]
            best, who = min(natives)
            cells.append(f"{best / runs[('microcode', n)][i][1]:.3f}x ({who})")
        print(f"| {n} | " + " | ".join(cells) + " |")
    print()

    print(f"Worst run-to-run spread: **{worst[0]:.2f}%** ({worst[1]}).\n")

    print("## rows for tab:results-sha3\n")
    print("Columns: message, perms, microcode, microcode cyc/byte, " + ", ".join(PAPER) +
          ", speed-up = fastest native (any contender) / microcode.\n")
    print("```latex")
    for n in lengths:
        uc = red[("microcode", n)]["med"]
        cols = [str(red[(k, n)]["med"]) for k in PAPER]
        best, who = min((red[(k, m)]["med"], k) for (k, m) in red if m == n and k != "microcode")
        print(f"{LABEL.get(n, str(n)):<10} & {perms[n]:<3} & \\textbf{{{uc}}} & {uc / n:.2f} & "
              + " & ".join(cols) + f" & {best / uc:.3f}$\\times$ \\\\   % fastest native: {who}")
    print("```")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
