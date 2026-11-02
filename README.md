# µcrypt

Artifact for the paper: *Triads below the ISA: Optimizing Cryptographic Software in CPU
Microcode*.

Cryptographic software is normally optimized against the instruction set architecture. 
This work goes one layer below the ISA. It implements Keccak-f[1600] and the Curve25519 field arithmetic **as microcode patches** on an Intel Goldmont core, using the registers, operations and carry mechanisms the microcode layer exposes.
On the target machine both beat every native implementation we could run against them.

| | Microcode | Best Native | |
|---|---|---|---|
| Keccak-f[1600] permutation | **1900** cyc | 2051 cyc (`opt64lcu24`) | 7.36% fewer |
| SHA3-256, 128 B message | **2129** cyc | 2338 cyc (`opt64lcu6`) | 1.098× |
| SHA3-256, 16 KiB message | **236592** cyc | 251612 cyc (`xkcp_g64lc`) | 1.063× |
| Fe_mul (5×51) | **90.0** cyc | 97.1 cyc (OpenSSL fe51) | 7.3% fewer |
| Fe_sq (5×51) | **65.0** cyc | 72.4 cyc (OpenSSL fe51) | 10.2% fewer |
| X25519 scalar multiplication | **225988** cyc | 243654 cyc (s2n-bignum) | 7.3% fewer |

All figures are medians in core cycles on an Intel Celeron N3350 at its 1.10 GHz
base frequency, turbo disabled, and include the cost of entering and leaving
microcode. The native column is each contender's best result across the 24
(compiler, `-O`) configurations SUPERCOP tries.

## ⚠️ A note to the reader

This code **writes to your CPU's Microcode Patch RAM**. To do that it needs the
processor in Intel's undocumented *Red Unlock* debug state, and it sets the
microcode debug-unlock MSR (`0x1e6`) on the benchmark core.

- Red Unlock is reached through a known Intel TXE vulnerability
  ([INTEL-SA-00086](https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00086.html)).
  It **permanently disables** several platform security guarantees on that
  machine. Do this only on a dedicated test board you are willing to lose.
- A faulty patch can hang the core.
- The patches target **Goldmont specifically**. Microcode encodings are neither
  documented nor stable across microarchitectures.

## Hardware

- An Intel processor based on **Goldmont**. We used a **Celeron N3350** 
- That machine placed in **Red Unlock**, following the public procedure based on
  Intel TXE and INTEL-SA-00086 (see [IntelTXE-PoC](https://github.com/ptresearch/IntelTXE-PoC)).
- A second machine to drive it.

## Software

Required:

- `gcc` and GNU `binutils` (`ld`, `objcopy`) — the Keccak baselines are linked
  into one binary by renaming symbols with `objcopy`.
- `perl` — OpenSSL's Keccak assembly is generated from its perlasm.
- `nasm` — assembles the CryptOpt field-arithmetic baselines.
- `python3` — the two `summarize.py` scripts, which reduce a sweep's raw output
  to the paper's tables: each contender's best configuration for Curve25519,
  the median over repeated runs for SHA3-256. Standard library only.
- `msr-tools` (`wrmsr`) and `util-linux` (`taskset`) — debug unlock and core
  pinning. Root is needed to install a patch.

For the full compiler sweep, the benchmark scripts expect `gcc-11`, `gcc-12`,
`gcc-13`, `clang-14`, `clang-17` and `clang-18`, matching SUPERCOP's grid.


## Setup

### 1. This repository

lib-micro is pinned as a git submodule, so clone recursively:

```sh
git clone --recursive https://github.com/0xADE1A1DE/ucrypt.git
cd ucrypt
```

If you already cloned without `--recursive`, fetch the submodule after the fact:

```sh
git submodule update --init
```

### 2. lib-micro

The patches are installed through [lib-micro](https://github.com/zanderdk/lib-micro),
which is **not** vendored here: the `lib-micro/` submodule pins upstream commit
`f3a3a8d` and step 1 fetches it. Build its static library:

```sh
make -C lib-micro static            # produces lib-micro/build/libmicro.a
```

giving:

```
ucrypt/                    # this repository
├── lib-micro/             # submodule, pinned at f3a3a8d
│   ├── build/libmicro.a
│   └── include/{patch.h,ucode_macro.h,misc.h,...}
├── curve25519/
└── keccak/
```

That layout is only the default. Every Makefile finds lib-micro through a
`LIBMICRO` variable, so a checkout anywhere else works:

```sh
make LIBMICRO=/path/to/lib-micro PROG=asm_op_keccak_perm
```

### Our µop findings

A few of the micro-ops used here have no macro in upstream lib-micro, the 64-bit
`MUL` and `ADC` among them. Each 64-bit opcode sits one `0x40` DSZ32 → DSZ64
step above the 32-bit form `opcode.h` already defines, so `_MUL_DSZ64` is
`0x26c` (from `_MUL_DSZ32` `0x22c`, `opcode.h:375`) and `_ADC_DSZ64` is `0x37e`
(from the 32-bit `_ADC`, `0x33e`, `opcode.h:431`).

Rather than ask you to patch lib-micro, this artifact defines what it needs
inside the files that use it, each guarded by `#ifndef`. The pinned submodule is
unmodified upstream, and nothing here edits it. Objects compiled against it are
bit-identical to those compiled against a locally patched lib-micro, so the
patch images are the same either way.

### 3. Debug unlock

Each run needs the microcode debug unlock asserted on the core it will use:

```sh
sudo modprobe msr
sudo wrmsr -p 1 0x1e6 0x200         # core 1, the core the benchmarks measure on
```

## Keccak-f[1600]

The complete permutation runs in **one microcode invocation**: 25 lanes held in
13 architectural and 12 temporary registers across all 24 rounds, a 56-triad
round body looped in microcode, 108 triads in total. The patch is hooked onto
`vmwrite` (microcode entry `0x0cd8` redirected to `0x7c00`).

```sh
cd keccak
make PROG=asm_op_keccak_perm
sudo taskset -c 1 ./asm_op_keccak_perm_static   # correctness, then timing
```

That one command runs the whole case study on hardware. It pins itself to the
benchmark core, installs the 108-triad patch, and fires it.

Correctness comes first. Two published Keccak team vectors are checked lane by
lane against fixed constants rather than against the C reference, f(0) from an
all-zero state and f(f(0)) from a non-zero one. The
all-zero state and one non-trivial state are then compared against a C
reference Keccak-f[1600], followed by 1000 pseudorandom states. Any wrong lane
is printed and the program exits non-zero without timing anything.

If everything passes, it reports the cost of one full permutation and then
sweeps the round count over 1, 2, 4, 8, 12 and 24 rounds. The slope across
that sweep is the per-round cost inside the microcode loop, and the intercept
is the fixed cost of entering and leaving microcode.

### Benchmarks

```sh
cd keccak/Benchmarks
./run.sh                       # all three levels
./run.sh --quick               # gcc -O3 only
./run.sh --perm                # Table 1 only (also --speed-up, --sha3)
```

The permutation sweep writes `RESULTS.md`; the run we took is committed there
for comparison. See `keccak/Benchmarks/README.md` for the contenders, the
method and the file layout.

### Speed-Up Analysis (Table 2)

`speed-up_variants/` holds one variant of the kernel per design choice, each
undoing exactly one decision and changing nothing else:

| variant | what it removes | cost |
|---|---|---|
| `spill_d_body.h` | the five D[x] values resident in registers | +292 cyc (+15.4%) |
| `no_notand_body.h` | the µNOTAND micro-op in χ | +238 cyc (+12.6%) |
| `savemov_chi_body.h` | the move-free χ row update | +141 cyc (+7.4%) |
| `rc_shift_body.h` | the round-constant cursor | +68 cyc (+3.6%) |

The first two are what put the kernel ahead of native code: without either, it
is slower than `opt64lcu24`.

## Curve25519

Field multiplication and squaring are microcoded; the Montgomery ladder,
inversion and encoding stay architectural. Two carry strategies are built from
the same five-accumulator 5×51 schedule:

| program | carries | patch sizes |
|---|---|---|
| `full_curve25519_inline2` | `µSETCC` on per-register flags | fe_mul 58 + fe_sq 41 triads |
| `full_curve25519_adc_mod2` | `µADD\|MOD2` head + `µADC` tail through arch CF | fe_mul 45 + fe_sq 31 triads |

`full_curve25519_adc_mod2` is the paper's headline variant. Multiplication is
hooked onto `vmwrite` (`0x0cd8` → `0x7c00`) and squaring onto `vmread`
(`0x0618` → `0x7cb4`), so a field operation is one instruction.

```sh
cd curve25519
make PROG=full_curve25519_adc_mod2
sudo taskset -c 1 ./full_curve25519_adc_mod2_static          # test vectors, then timing
sudo taskset -c 1 ./full_curve25519_adc_mod2_static verify   # correctness only
```

The first run is the paper's X25519 measurement. It checks the delivered
frequency, pins itself to the benchmark core, installs both field patches, and
runs the RFC 7748 test vectors. A failing vector aborts the run before anything
is timed. Otherwise it times a complete scalar multiplication against every
contender in the same process.

The second run installs the same patches but only checks them, printing one
PASS or FAIL verdict over six stages. It covers the C reference model against
precomputed values and a schoolbook implementation, byte encoding and decoding
round trips, both field operations on hardware across an exhaustive sweep of
edge-value limb combinations and several million random limb patterns at
widths 51 to 54, the X25519 known-answer vectors, 20000 random scalar
multiplications against OpenSSL (a tenth of them with bit 255 set, a hundredth
with u in [p, 2^255)), and the RFC 7748 iterated test. A number after `verify`
changes that 20000, and `--c-only` runs just the two stages that need no patch.

### Benchmarks

`curve25519/Benchmarks/` is the harness behind Tables 4 and 5: one binary per
patch set, each installing its patches once and never swapping them.

```sh
cd curve25519/Benchmarks
./run.sh --quick    # gcc -O3 only, ~1 min
./run.sh            # all 24 configurations, ~17 min
./run.sh --kernels  # one level (also --x25519)
```

See `curve25519/Benchmarks/README.md` for the method, the contenders and the
output layout.


## Layout

The two case studies have the same shape: the implementation and its patch
images at the top, the paper's harness in `Benchmarks/`, shared shell helpers in
`lib/`, vendored baselines in `third_party/`.

```
keccak/
├── asm_op_keccak_perm.c         install the patch and KAT-verify it
├── keccak_perm.h                the patch image (prologue, round body, exit)
├── keccak_perm_body.h           the 56-triad round body
├── speed-up_variants/           one kernel variant per design choice
├── include/bench_core.h         which core a harness pins itself to
├── Benchmarks/                  Tables 1, 2 and 3      
├── lib/                         frequency guard, measurement parsing
└── third_party/                 OpenSSL, XKCP, SUPERCOP, s2n-bignum baselines

curve25519/
├── full_curve25519_inline2.c    install the SETCC patches, benchmark, verify
├── full_curve25519_adc_mod2.c   the same for ADD|MOD2
├── Benchmarks/ours/patch_*.h    the two patch pairs as the harness installs them
├── include/bench_core.h         which core a harness pins itself to
├── Benchmarks/                  Tables 4 and 5
├── lib/                         frequency guard, core isolation, CPU pinning
└── third_party/                 SUPERCOP, s2n-bignum, reference C oracle
```

## Measurement notes

Cycle counts come from RDTSC, which ticks at the TSC rate rather than the core
clock. The scripts pin every core to its base frequency with turbo disabled, so
the two coincide, and verify the delivered frequency with `APERF`/`MPERF` under
load before and after each sweep. They also steer IRQs off the benchmark core
and run under `SCHED_FIFO`. A run whose correctness gates fail produces no
numbers and a non-zero exit.


## Acknowledgements

This work has been supported by an ARC Discovery Project number DP210102670; by the Dutch Ministry of Education, Culture, and Science through Gravitation project ``Challenges in Cyber Security -- 024.006.037''; and by the Deutsche Forschungsgemeinschaft (DFG, German Research Foundation) under Germany's Excellence Strategy - EXC 2092 CASA - 390781972 and through project number 560392681.
