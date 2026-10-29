# keccak benchmarks

Three levels, one binary each, one script. Every binary installs its microcode
patch itself and verifies the permutation before it reports a number.

| level | binary | what it times | paper |
|---|---|---|---|
| 1 permutation | `asm_op_keccak_vs_static` | one Keccak-f[1600]: the microcode kernel against every SUPERCOP, XKCP, OpenSSL and s2n-bignum baseline that runs on this core | Table 1 |
| 2 speed-up | `bench_speed-up_static` | the complete kernel against four variants, each undoing exactly one design choice | Table 2 |
| 3 SHA3-256 | `sha3_own_static` | one complete SHA3-256 hash at five message lengths, every contender running its own sponge | Table 3, Figure 4 |

## Run

```sh
./run.sh                       # all three levels, ~40 min
./run.sh --quick               # gcc -O3 only for the sweep, ~3 min
./run.sh --perm                # one level (combines with --quick)
./run.sh --speed-up --sha3     # several levels
BENCH_CORE=0 RUNS=5 ./run.sh   # core (default 1) and SHA3-256 repeats (default 3)
```

`run.sh` runs the levels in the order above, because level 3 depends on level 1:
`sha3_best.sh` reads each contender's winning configuration out of `RESULTS.md`,
which the permutation sweep writes. Starting with `--sha3` on a tree that has no
`RESULTS.md` aborts rather than guess a configuration.

Each level drives one script or binary, and you can use them directly:

```sh
sudo ./bench_keccak_matrix.sh                      # level 1 -> RESULTS.md
make PROG=bench_speed-up && sudo taskset -c 1 ./bench_speed-up_static
./sha3_best.sh                                     # level 3, reads RESULTS.md
```

By hand: `make PROG=asm_op_keccak_vs`, `sudo wrmsr -p 1 0x1e6 0x200`, then
`sudo env BENCH_CORE=1 taskset -c 1 ./asm_op_keccak_vs_static`. `sha3_own_static
--no-ucode` runs the native contenders only and needs no root.

The sweep writes `RESULTS.md`; the run committed here is ours, for comparison.
SHA3-256 output goes to `results/`.

## Contenders

**Ours.** One kernel (`../keccak_perm.h`, `../keccak_perm_body.h`): the complete
25-lane state resident in 13 architectural and 12 temporary registers, a 56-triad
round body looped 24 times in microcode, 108 triads with the entry and exit
sequences. It is a fixed patch image, so the compiler grid does not tune it; its
number is flat across configurations and serves as a sanity baseline.

At the SHA3-256 level the kernel has no sponge of its own, so it runs a plain C
sponge that fires the patch once per permutation.

**Others:**

| label | what |
|---|---|
| `opt64lcu24`, `opt64lcu6`, `opt64u6` | the Keccak team's optimised 64-bit C, lane-complementing and unrolling variants |
| `opt64lcu24shld`, `x86_64_shld` | the same, built on `shld` rotations |
| `x86_64_asm` | Van Keer's x86-64 assembly |
| `simple` | the Keccak team's reference C |
| `sseu2`, `mmxu1` | the SIMD variants that run without AVX |
| `xkcp_g64`, `xkcp_g64lc` | XKCP `plain-64bits`, its `generic64` and `generic64lc` targets |
| `openssl` | OpenSSL's scalar x86-64 assembly, generated from its perlasm |
| `s2n_bignum` | AWS `sha3_keccak_f1600`, a formally verified (HOL Light) port of that assembly |

XKCP ships no SSE single-permutation kernel and Goldmont has no AVX2/AVX-512, so
`plain-64bits` is the only XKCP kernel that runs here. OpenSSL's AVX2 and AVX-512
Keccak need instructions this core lacks, so only its scalar path is comparable.
`xopu24` is omitted: XOP is AMD-only and `#UD`s on Intel.

**Speed-up level:** four variants of our own kernel, each removing one decision
and changing nothing else — not other implementations.

| variant | what it removes |
|---|---|
| `spill_d` | the five D[x] values resident in registers; stores and reloads them instead |
| `no_notand` | the µNOTAND micro-op in χ; uses `(b ⊕ c) ∧ c` instead |
| `savemov_chi` | the move-free χ row update; copies two lanes per row |
| `rc_shift` | the round-constant cursor; counts rounds and computes the table address |

## Method

- **Same process, same frequency.** RDTSC on Goldmont counts at the constant
  reference rate, not the core clock, so the same work reads as ~2.2× more or
  fewer ticks at burst than at base. Timing two implementations in separate runs
  is therefore invalid. Every level interleaves its contenders back-to-back in
  one process after a warm-up, so they see the same frequency and thermal state
  and the ratio between them is frequency-invariant.
- **Permutation** (`asm_op_keccak_vs.c`): one Keccak-f[1600] per sample, all
  contenders sampled per round. `bench_keccak_matrix.sh` rebuilds every C
  baseline under each (compiler, `-O`) pair and keeps the best median per
  contender, which is what SUPERCOP's autotuner would pick. The hand-written
  assembly, the perlasm-generated OpenSSL and s2n-bignum are compiler-independent
  and assemble identically at every configuration.
- **Speed-up** (`bench_speed-up.c`): all five kernels in one process, interleaved
  rep by rep. Switching variants rewrites patch RAM, which happens outside the
  timed region. Patch size does not predict time: `rc_shift` has the same 108
  triads as the complete kernel and is still 68 cycles slower, because the
  round-constant load waits on a shift and an addition.
- **SHA3-256** (`sha3_own.c`): every native contender runs its own complete hash
  path — its own sponge, absorb loop, padding and squeeze around its own
  permutation — one object per contender. Messages of 32 B, 128 B, 1 KiB, 4 KiB
  and 16 KiB, which are 1, 1, 8, 31 and 121 permutations. `sha3_best.sh` builds
  each contender under the configuration that won its row of the permutation
  sweep, verifies the compiler and `-O` recorded in the debug info of every unit,
  and repeats the measurement in `RUNS` separate processes so process-level
  outliers show up; `summarize.py` reports the median of the per-run medians.
- **Correctness gates.** The permutation harness checks one firing against a C
  reference at start-up and every timed batch's end state against the same
  reference. Every variant must reproduce the published f(0) and f(f(0))
  states on hardware before it is timed, so every reported cycle count belongs to
  a correct permutation. The SHA3-256 harness KAT-verifies all thirteen message
  lengths, including the padding boundaries 135, 136 and 137, before timing and
  again after the warm-up, and verifies every hash inside every timed batch. A
  failed check aborts that configuration and reports no number.
- **RSP guard.** The kernel uses RSP as its 32nd data register: the prologue
  saves the architectural value to the working buffer and the epilogue restores
  it. RSP cannot be an inline-asm clobber, so every firing checks that it comes
  back unchanged. Across the sweep committed in `RESULTS.md`, 4 400 022 firings
  returned 0 changed values.
- **Frequency.** `../lib/freq_guard.sh` verifies the core is pinned at its
  1.10 GHz base with turbo off, so RDTSC ticks are core cycles, and re-checks
  afterwards. `ALLOW_UNPINNED=1` overrides it, but then only same-process ratios
  remain meaningful, not absolute counts.

## Files

```
run.sh                   build, check, run, summarise -- all three levels
bench_keccak_matrix.sh   level 1: the (compiler, -O) sweep -> RESULTS.md
sha3_best.sh             level 3: best-config build, verify, repeat
summarize.py             sha3_best.sh log -> one reduced table
asm_op_keccak_vs.c       level 1 harness
bench_speed-up.c         level 2 harness (reads ../speed-up_variants/*.h)
sha3_own.c               level 3 harness
sha3_kc512_shim.c        SUPERCOP keccakc512 sponge + the FIPS 202 domain bits
sha3_ossl_shim.c         OpenSSL's sponge set up as its SHA3-256 provider does
keccak_s2n_glue.S        one-argument entry point for s2n-bignum's permutation
RESULTS.md               our sweep, committed as a reference run
Makefile                 SUPERCOP flags; `make PROG=<harness>`
```

## Where the code comes from

- The kernel under test is `../keccak_perm.h` and `../keccak_perm_body.h`, and
  the variants are `../speed-up_variants/*.h`. All three harnesses list them as
  prerequisites, so editing a patch forces a relink; a stale binary would
  silently benchmark the previous kernel.
- The generator that produced those patch images is not part of this artifact.
  Edit the headers directly.
- The baselines are vendored verbatim under `../third_party/`. Where one needed
  adapting to coexist with the others in a single binary — renaming a symbol,
  generating a `config.h`, changing the SHA3-256 domain byte — the adaptation is
  a build step in the `Makefile`, never an edit to the vendored file. The
  `Makefile` documents each case, and `../../THIRD_PARTY.md` records the terms.
