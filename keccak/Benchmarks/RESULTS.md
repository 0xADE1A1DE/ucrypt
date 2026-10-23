# Keccak SUPERCOP-matrix benchmark

Same methodology as `curve25519/Benchmarks/run.sh`: for each (compiler, -O)
config SUPERCOP tries, rebuild every runnable SUPERCOP Keccak baseline (hand
asm, 64-bit C, x86 SIMD, reference) + the
head-to-head harness, run back-to-back in one process, keep the best per
contender. cyc/perm (RDTSC at TSC rate; pin to base so ticks ≈ true cycles).
Headline statistic is the **median**; min and the p10–p90 spread are also reported.

Configs that ran: 22 / 24

Environment: core 1, base-pinned, turbo off. Delivered core freq 1100 MHz,
TSC (RDTSC) rate 1094 MHz, correction f_core/f_TSC = 1.00548
(aperf/mperf under load, verified before the sweep; ratios invariant to it, multiply
absolute cycle counts by it for true core cycles).

Microcode correctness: one firing is checked against a C reference Keccak-f[1600]
at start-up, and every timed batch's end state against the same reference (a failed
check aborts that config). Firings use the RSP guard (RSP saved before the vmwrite,
restored after): 4400022 microcode firings across the sweep, 0 returned a changed RSP.

## median cyc/perm per (config × contender)

| config | asm | shld | opt24 | opt24shld | lcu6 | u6 | sse | mmx | simple | xg64 | xg64lc | ossl | s2n | ucode |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| gcc-11 -O3 | 2078 | 10132 | 2159 | 10185 | 2209 | 2403 | 3141 | 3885 | 2500 | 2310 | 2169 | 2055 | 2109 | 1902 |
| gcc-11 -O2 | 2075 | 10134 | 2159 | 10188 | 2149 | 2323 | 3046 | 3979 | 2386 | 2307 | 2169 | 2055 | 2109 | 1902 |
| gcc-11 -Os | 2072 | 10136 | 2051 | 10087 | 2088 | 2258 | 2946 | 4226 | 2331 | 2181 | 2057 | 2054 | 2108 | 1901 |
| gcc-12 -O3 | 2077 | 10139 | 2257 | 10302 | 2235 | 2443 | 3141 | 4097 | 2390 | 2392 | 2264 | 2055 | 2109 | 1901 |
| gcc-12 -O2 | 2078 | 10139 | 2256 | 10302 | 2235 | 2442 | 3135 | 4096 | 2388 | 2391 | 2261 | 2055 | 2109 | 1901 |
| gcc-12 -Os | 2075 | 10135 | 2156 | 10199 | 2204 | 2333 | 2946 | 4226 | 2366 | 2286 | 2167 | 2055 | 2109 | 1902 |
| gcc-12 -O | 2079 | 10135 | 2237 | 10331 | 2241 | 2439 | 3328 | 4326 | 2381 | 2378 | 2246 | 2055 | 2109 | 1901 |
| gcc-13 -O3 | 2075 | 10132 | 2234 | 10276 | 2250 | 2440 | 3145 | 4096 | 2390 | 2393 | 2237 | 2055 | 2108 | 1901 |
| gcc-13 -O2 | 2079 | 10130 | 2231 | 10270 | 2247 | 2441 | 3143 | 4096 | 2388 | 2394 | 2237 | 2055 | 2109 | 1901 |
| gcc-13 -Os | 2075 | 10134 | 2141 | 10197 | 2195 | 2334 | 3066 | 3440 | 2367 | 2285 | 2151 | 2055 | 2109 | 1902 |
| gcc-13 -O | 2079 | 10129 | 2221 | 10326 | 2244 | 2440 | 3309 | 4326 | 2383 | 2379 | 2228 | 2055 | 2109 | 1901 |
| clang-14 -O3 | 2078 | 10132 | 2087 | 10102 | 2064 | 2429 | 2618 | 4631 | 2393 | 2309 | 2091 | 2057 | 2109 | 1900 |
| clang-14 -O2 | 2078 | 10130 | 2086 | 10100 | 2064 | 2430 | 2618 | 4630 | 2393 | 2309 | 2091 | 2057 | 2109 | 1900 |
| clang-14 -Os | 2079 | 10131 | 2108 | 10113 | 2065 | 2427 | 2622 | 4630 | 2397 | 2308 | 2115 | 2057 | 2109 | 1900 |
| clang-14 -O | 2079 | 10131 | 2119 | 10160 | 2095 | 2448 | 2689 | 4989 | 2391 | 2345 | 2124 | 2057 | 2109 | 1900 |
| clang-17 -O3 | 2079 | 10133 | 2102 | 10088 | 2074 | 2426 | 2699 | 4631 | 2384 | 2300 | 2106 | 2057 | 2107 | 1900 |
| clang-17 -O2 | 2079 | 10132 | 2101 | 10090 | 2074 | 2426 | 2699 | 4631 | 2385 | 2300 | 2106 | 2057 | 2107 | 1900 |
| clang-17 -Os | 2079 | 10131 | 2090 | 10081 | 2072 | 2423 | 2706 | 4632 | 2386 | 2308 | 2098 | 2057 | 2107 | 1900 |
| clang-17 -O | 2079 | 10132 | 2137 | 10152 | 2101 | 2456 | 2772 | 5019 | 2479 | 2328 | 2143 | 2057 | 2107 | 1900 |
| clang-18 -O3 | 2078 | 10133 | 2095 | 10099 | 2116 | 2431 | 2676 | 4681 | 2342 | 2311 | 2100 | 2057 | 2107 | 1900 |
| clang-18 -O2 | 2078 | 10132 | 2095 | 10098 | 2116 | 2432 | 2678 | 4680 | 2342 | 2311 | 2100 | 2057 | 2107 | 1900 |
| clang-18 -Os | 2078 | 10131 | 2094 | 10095 | 2116 | 2428 | 2664 | 4680 | 2342 | 2311 | 2099 | 2057 | 2107 | 1900 |

## best per contender (what SUPERCOP's autotuner would pick)

Best = lowest **median** across the sweep. `this/microcode` = this_contender_median /
microcode_median; >1 means microcode is faster (e.g. 1.07x = ~7% faster; 1.000x is
microcode itself). p10/p90 are taken at each contender's best-median config.

| contender | median | min | p10 | p90 | winning config | this/microcode |
|---|---|---|---|---|---|---|
| keccak/x86_64_asm | 2072 | 2062 | 2064 | 2084 | gcc-11 -Os | 1.091x |
| keccak/x86_64_shld | 10129 | 10118 | 10121 | 10168 | gcc-13 -O | 5.331x |
| keccak/opt64lcu24 | 2051 | 2043 | 2046 | 2065 | gcc-11 -Os | 1.079x |
| keccak/opt64lcu24shld | 10081 | 10071 | 10073 | 10125 | clang-17 -Os | 5.306x |
| keccak/opt64lcu6 | 2064 | 2057 | 2063 | 2076 | clang-14 -O3 | 1.086x |
| keccak/opt64u6 | 2258 | 2255 | 2257 | 2309 | gcc-11 -Os | 1.188x |
| keccak/sseu2 | 2618 | 2610 | 2613 | 2631 | clang-14 -O3 | 1.378x |
| keccak/mmxu1 | 3440 | 3439 | 3439 | 3456 | gcc-13 -Os | 1.811x |
| keccak/simple | 2331 | 2330 | 2331 | 2347 | gcc-11 -Os | 1.227x |
| keccak/xkcp_g64 | 2181 | 2173 | 2180 | 2234 | gcc-11 -Os | 1.148x |
| keccak/xkcp_g64lc | 2057 | 2050 | 2054 | 2091 | gcc-11 -Os | 1.083x |
| keccak/openssl | 2054 | 2048 | 2054 | 2065 | gcc-11 -Os | 1.081x |
| keccak/s2n_bignum | 2107 | 2101 | 2106 | 2116 | clang-17 -O3 | 1.109x |
| keccak/microcode | 1900 | 1894 | 1895 | 1909 | clang-14 -O3 | 1.000x |

## headline

- fastest SUPERCOP baseline: **keccak/opt64lcu24 = 2051 cyc/perm** (median, gcc-11 -Os)
- microcode (looped): **1900 cyc/perm** (median, clang-14 -O3)
- ratio microcode / fastest SUPERCOP: **0.926x** (microcode WINS)

## configs that did not run (2 of 24)

- **gcc-11 -O**: the harness crashed inside a microcode firing. Kernel log, 2026-10-09
  20:48:19, CPU 1: `segfault at 5d6000 ip 401cd9 sp 56417dba1884dfb0 error 4`.
  ip 0x401cd9 is the timed loop's `vmwrite` (checked by rebuilding this config), and
  sp holds a Keccak lane value, so the fault happened mid-flow while RSP was in use as
  a data register; the RSP guard cannot help there. The faulting address is
  page-aligned and ~5 KB past the RC table; the only load that reaches that far is the
  RC lookup indexed by the round counter, which suggests the round loop did not exit
  after round 24 (inferred, not proven).
- **clang-18 -O**: the run failed; the sweep does not record why. There is no
  kernel-log entry for it (so not a SIGSEGV/#GP); it may have exited on a failed
  correctness check.

Neither config won any contender's row in the previous full 24/24 sweep (2026-10-09,
unguarded), so the best-per-contender table above is unlikely to depend on them.
Every microcode number reported above comes from batches whose end state matched the
C reference.

# SHA3-256, each implementation's own sponge

`sha3_best.sh`, 2026-10-09 22:08:56, 3 runs (separate processes). Same environment
as the permutation sweep: core 1, base-pinned, turbo off. Delivered core freq 1100 MHz
and TSC rate 1094 MHz, both before and after the runs (f_core/f_TSC = 1.00548).
Cycles are RDTSC ticks per complete SHA3-256 hash. Each figure is the median of the 3
per-run medians (51 batches per run). The run-to-run spread is ≤ 0.6% for every
figure except xkcp_g64 @ 32 B (1.75%). Full statistics (per-run medians, min, p10/p90,
LaTeX rows) are in
`results/sha3_best.core1.20261009-220856.summary.md`; the raw log is next to it.

Every native contender runs its own complete SHA3-256 path: its own sponge, absorb,
padding and squeeze, around its own permutation. Each is one object exporting only
`sha3_256_<key>`, built at its winning config from the permutation table above.

- **SUPERCOP packages** (x86_64_asm … mmxu1): each package's `crypto_hash/keccakc512`
  KeccakSponge.c at r=1088 plus the FIPS 202 domain bits.
- **simple:** keccakc512/simple `crypto_hash()`, padding byte 0x06.
- **xkcp_g64 / xkcp_g64lc:** XKCP `SHA3_256()`.
- **openssl:** OpenSSL `crypto/sha/sha3.c` over its SHA3_absorb/SHA3_squeeze asm.
- **microcode:** the kernel is a bare permutation, so it runs a plain C sponge.
- **s2n_bignum** is absent: it ships only the permutation, with no sponge.

Correctness:
- All 13 contenders passed 13 SHA3-256 KATs in every run (39/39). The KATs include
  the 135/136/137 padding boundaries and every timed length. They ran before timing and
  again after the warm-up.
- Every timed hash was verified (digest sum per batch); there were no failures.
- RSP guard: 181185 / 174453 / 179961 microcode firings, 0 returned a changed RSP.

| contender | config | 32 B | 128 B | 1 KiB | 4 KiB | 16 KiB |
|---|---|---|---|---|---|---|
| permutations per hash | | 1 | 1 | 8 | 31 | 121 |
| **microcode** | fixed patch | **2114** | **2129** | **15848** | **60710** | **236592** |
| xkcp_g64lc | gcc-11 -Os | 2320 | 2342 | 17213 | 64695 | 251612 |
| opt64lcu24 | gcc-11 -Os | 2596 | 2589 | 17199 | 65047 | 253042 |
| opt64lcu6 | clang-14 -O3 | 2329 | 2338 | 17013 | 65154 | 253632 |
| x86_64_asm | gcc-11 -Os | 2540 | 2534 | 17246 | 65567 | 254535 |
| openssl | gcc-11 -Os | 2395 | 2387 | 17225 | 65803 | 256306 |
| xkcp_g64 | gcc-11 -Os | 2442 | 2464 | 18196 | 68559 | 266568 |
| opt64u6 | gcc-11 -Os | 2766 | 2758 | 18792 | 71345 | 277242 |
| simple | gcc-11 -Os | 2537 | 2528 | 19215 | 73997 | 288065 |
| sseu2 | clang-14 -O3 | 3050 | 3056 | 21929 | 84173 | 327596 |
| mmxu1 | gcc-13 -Os | 4018 | 4014 | 28702 | 109853 | 428856 |
| opt64lcu24shld | clang-17 -Os | 10387 | 10398 | 81443 | 314936 | 1225780 |
| x86_64_shld | gcc-13 -O | 10538 | 10552 | 82075 | 317572 | 1231270 |
| **fastest native / microcode** | | **1.097x** (xkcp_g64lc) | **1.098x** (opt64lcu6) | **1.074x** (opt64lcu6) | **1.066x** (xkcp_g64lc) | **1.063x** (xkcp_g64lc) |
| microcode cyc/byte | | 66.06 | 16.63 | 15.48 | 14.82 | 14.44 |

Microcode is the fastest SHA3-256 at every length, ahead of the fastest native by 6.3%
(16 KiB) to 9.8% (128 B). Each per-run speed-up is within 0.3% of these figures
(see the summary's per-run table).

## SHA3-256 code size

Measured on the exact objects benchmarked above (`best/sha3own_*.o`, each at its winning
config) with `extra/sha3_codesize.py`. Columns:
- **permutation:** one copy of the 24-round Keccak-f[1600].
- **SHA3-256 code:** every function statically reachable from `sha3_256_<key>`, through
  direct calls/jumps and address-taken references; this is what a linker that keeps
  whole functions would keep.
- **whole object:** all code in the contender's object, including unused variants.

libc calls (memcpy, memset, ...) are excluded throughout.

| contender | permutation (B) | SHA3-256 code (B) | whole object code (B) | static data (B) |
|---|---|---|---|---|
| **microcode** | **108 triads = 2,349 B patch RAM** (3,456 B as stored in the binary) | **503 B x86 sponge + the patch** | — | 192 (RC table) |
| openssl | 864 (`KeccakF1600` + `__KeccakF1600`, looped) | 1,909 | 2,400 | 398 |
| simple | 2,151 (`KeccakF`, looped) | 2,390 | 2,390 | 192 |
| mmxu1 | 2,172 (looped) | 8,072 | 8,142 | 193 |
| sseu2 | 3,120 (unroll 2) | 11,321 | 11,529 | 257 |
| opt64lcu6 | 5,184 (unroll 6) | 17,801 | 18,009 | 193 |
| opt64u6 | 5,639 (unroll 6) | 18,288 | 18,360 | 193 |
| xkcp_g64lc | 18,550 (full unroll) | 39,883 | 255,737 | 192 |
| xkcp_g64 | 19,607 (full unroll) | 41,707 | 266,384 | 192 |
| opt64lcu24 | 18,550 (full unroll) | 57,299 | 57,371 | 193 |
| x86_64_asm | 19,530 (full unroll) | 60,506 | 158,897 | 1 |
| opt64lcu24shld | 19,763 (full unroll) | 60,968 | 61,085 | 241 |
| x86_64_shld | 20,370 (full unroll) | 63,361 | 165,952 | 1 |

Notes:
- **Microcode patch:** 108 triads = 324 µop slots, of which 204 hold a µop; the rest are
  NOPs, mostly in the 1-memory-op-per-triad prologue/epilogue. On the hardware a triad
  is 3 × 48-bit µops + a 30-bit sequence word = 174 bits, so 2,349 B; the C patch array
  stores 32 B per triad.
- **Microcode x86 side:** 503 B (`sha3_256_ucode`: sponge, firing and RSP guard). The
  kernel also uses a 448 B working buffer (`g_keccak_buf`). One-time installation code
  is not counted.
- **Several unrolled copies:** the SUPERCOP packages and XKCP carry 2–3 copies of the
  permutation in their SHA3-256 path. Examples: x86_64_asm's `KeccakPermutation`, its
  1088-bit absorb and the generic absorb; the opt64 packages' `OnWords`,
  `OnWordsAfterXoring` and `…1088bits`. Static reachability counts branches that
  SHA3-256 at r=1088 never executes (e.g. the generic absorb).
- **XKCP and the SUPERCOP asm objects** also contain much unused code: 12-round,
  duplexing and other-rate variants. That is why their whole-object size far exceeds
  the SHA3-256 path.
