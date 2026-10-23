# curve25519 benchmarks

Two levels, one binary per patch set, one script. Every binary installs its
microcode patches once and never swaps them (see Method).

| level | binary | what it times |
|---|---|---|
| 1 kernels | `kernel_setcc_static` | one fe_mul / fe_sq: `Fe_mul_setcc`, `Fe_sq_setcc`, against OpenSSL fe51, fiat-crypto, CryptOpt, SUPERCOP amd64-51, hand-written C and s2n-bignum |
| | `kernel_adc_static` | the same with `Fe_mul_adc`, `Fe_sq_adc` |
| | `kernel_floor_static` | the microcode dispatch floor (1-triad no-op patches), with the same natives |
| 2 X25519 | `x25519_setcc_static` | one complete X25519: `ours/setcc` against the SUPERCOP implementations that run on Goldmont, s2n-bignum and OpenSSL |
| | `x25519_adc_static` | the same with `ours/adc` |

## Run

```sh
./run.sh                       # all 24 (compiler, -O) pairs, best per contender, ~17 min
./run.sh --quick               # gcc -O3 only, ~1 min
./run.sh --kernels | --x25519  # one level (combines with --quick)
BENCH_CORE=0 RUNS=3 ./run.sh   # core (default 1) and X25519 runs per variant per configuration (default 1)
```

`run.sh` pins the CPU with
`../lib/pin_cpu.sh` (turbo off, every core at its 1.10 GHz base, so RDTSC ticks are
core cycles; the setting stays after the run), checks the frequency, steers
IRQs off the bench core, sets the microcode debug unlock, and then builds and runs
each configuration: setcc first (`kernel_setcc`, then `x25519_setcc`), then adc
(the same), then `kernel_floor`, one process each. The 24 configurations are
SUPERCOP's: gcc 11, 12 and 13 and clang 14, 17 and 18, each at -O3, -O2, -Os and -O; a missing compiler is reported
as a failure. Output goes to `results/<date_time>/`, with one directory per
configuration and a `SUMMARY.md`; `results/latest` points at the newest. Each run's
summary is also copied to `RESULTS_<date_time>.md` in this folder (one file per
run, never overwritten). Nothing is committed. To rebuild a summary:
`./run.sh --summary results/<dir>`. Run it as yourself; it asks for sudo where it
needs it. Started as `sudo ./run.sh`, it hands everything it wrote back to you.

By hand: `make`, `sudo wrmsr -p 1 0x1e6 0x200`, then
`sudo env BENCH_CORE=1 taskset -c 1 ./x25519_setcc_static` (or any other binary).
Without root, every binary runs only the non-microcode part.

The CryptOpt asm it links (`../cryptopt_mul.asm`, `../cryptopt_sq.asm`) ships with
this repository; assembling it needs `nasm`.

## Contenders

**Ours.** One implementation (`ours/ours.h`): the register-chained inline-asm 5x51
ladder, the FE_* wrappers, and the Fermat inversion. It comes in two variants that
differ only in the two microcode patches:

| variant | patches | carries |
|---|---|---|
| `ours/setcc` | `ours/patch_setcc.h` (58 + 41 triads) | per accumulator, SETCC on per-register flags |
| `ours/adc` | `ours/patch_adc.h` (45 + 31 triads) | arch CF: ADD\|MOD2 head + ADC\|MOD2 tail per product |

**Others at the X25519 level:**

| label | what |
|---|---|
| `supercop/amd64-64` | Bernstein-Schwabe, 4x64 asm (lib25519's pick on Goldmont) |
| `supercop/amd64-51` | Bernstein-Schwabe, 5x51 asm |
| `supercop/donna_c64` | Langley, 5x51 C |
| `s2n-bignum` | AWS `curve25519_x25519_alt`, formally verified 4x64 asm; SUPERCOP's `s2n-alt` wraps exactly this |
| `openssl` | OpenSSL's own X25519 (`../openssl_x25519.c`): its C ladder over its fe51 asm, the path it takes without ADX |

The other SUPERCOP implementations cannot run on this core (sandy2x: AVX; s2n:
MULX/ADX; athlon, neon2) or are reference code (ref, ref10, donna).

**Kernel level:** each microcode variant against OpenSSL `x25519_fe51_{mul,sqr}`,
fiat-crypto, CryptOpt, SUPERCOP amd64-51, hand-written C and s2n-bignum
`bignum_{mul,sqr}_p25519_alt` (4x64).

## Method

- **One patch set per process, installed once.** The two patch pairs do not fit in
  the 128-triad patch RAM together. An earlier version swapped them inside one
  process (40 swaps per X25519 run), and both full sweeps that ran it wedged the
  bench core: `CPU 1: NMIs are not reaching exc_nmi() handler`, about 13 minutes in,
  2026-10-08 and 2026-10-09. So each variant, and the dispatch floor, is now its own
  binary built from a short wrapper (`x25519_setcc.c`, `kernel_adc.c`, ...) around
  the shared `x25519.c` / `kernel.c`. Each binary installs its patches before its
  first check and keeps them until it exits. Every binary also times all the other
  contenders, so each variant is compared with them in its own process.
- **Kernels** (`kernel.c`):
  - `lat` is a dependent memory-to-memory chain that ping-pongs between two slots;
    natives get a memory barrier per op.
  - `tput` is four independent chains. `nb` is natives without the barrier.
  - Invocation floors: the microcode wrapper firing a 1-triad no-op patch
    (`kernel_floor`, its own process), and a native call with the same loads and
    stores (in every kernel process). "arith only" = latency minus the floor of its
    kind; for ours `summarize.py` subtracts `kernel_floor`'s floor from the same
    configuration.
  - Quote `Fe_mul` for arithmetic: the fe_sq floor contains FE_SQ's 2a/19a precompute.
- **X25519** times RFC 7748 vector 1 end to end: 1000 round-robin rounds per
  process, one sample of every contender per round. It reports the median with
  min / p10 / p90.
- **Correctness gates.** Nothing is timed until the process's variant and every
  contender pass RFC 7748 (vectors 1, 2, iterated x1 and x1000). Kernels must also
  match a reference on 4000 random operations each. Every timed X25519 output is
  compared with the expected answer. The variant is checked again after timing,
  with the same patches still installed. Any failure means a non-zero exit and no
  numbers.
- **Sweep.** As in SUPERCOP, each contender keeps its best configuration. Within a
  configuration, a contender timed by several processes gets the median over all of
  them. `SUMMARY.md` also reports, per contender, how many configurations ours beat
  it in the same process; that count does not depend on which configurations were
  picked. setcc and adc never share a process, so that count is n/a between them.

## Files

```
run.sh          build, check, isolate, run, summarise
summarize.py    results/<dir> -> SUMMARY.md
kernel.c        level 1, shared by kernel_setcc.c, kernel_adc.c, kernel_floor.c
x25519.c        level 2, shared by x25519_setcc.c, x25519_adc.c
common.h        includes, the variant (BENCH_VARIANT), timing, statistics, RFC 7748 gate
ours/ours.h     our X25519 + wrappers (shared by both variants)
ours/patch_*.h  the two patch pairs
Makefile        SUPERCOP flags; `make CC=clang-18 OPT=-Os`
```

## Where the code comes from

- `ours/ours.h` is copied verbatim from `../full_curve25519_inline2.c`. That code is
  identical in `../full_curve25519_adc_mod2.c`.
- `ours/patch_setcc.h` comes from `../full_curve25519_inline2.c`.
- `ours/patch_adc.h` comes from `../full_curve25519_adc_mod2.c`. Its
  `ADC_MOD2_DRR` really sets the MOD2 bit; check that by eye if you edit it,
  since the macro name alone does not show whether the bit is set.
- The full hardware verification (`verify` mode: edge cases, KATs, OpenSSL
  differential) lives in those parent files. If a patch changes, change it in
  both places.

