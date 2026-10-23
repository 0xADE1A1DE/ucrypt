# µcrypt

Artifact for the paper: *Triads below the ISA: Optimizing Cryptographic Software in CPU
Microcode*.

Cryptographic software is normally optimized against the instruction set architecture. 
This artifact goes one layer down: it implements Keccak-f[1600] and the Curve25519 field arithmetic **as microcode patches** on an Intel Goldmont core, using the registers, operations and carry mechanisms the microcode layer exposes but the ISA does not. 
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

### 1. lib-micro

The patches are installed through [lib-micro](https://github.com/zanderdk/lib-micro).
It is **not** vendored here. Clone and build it next to this repository:

```sh
git clone --recurse-submodules -j8 https://github.com/zanderdk/lib-micro
make -C lib-micro static            # produces lib-micro/build/libmicro.a
```

so that the two sit side by side:

```
parent/
├── lib-micro/
│   ├── build/libmicro.a
│   └── include/{patch.h,ucode_macro.h,misc.h,...}
└── ucrypt/           # this repository
    ├── curve25519/
    └── keccak/
```

That layout is only the default. Every Makefile finds lib-micro through a
`LIBMICRO` variable, so any other location works:

```sh
make LIBMICRO=/path/to/lib-micro PROG=asm_op_keccak_perm
```

### Our µop findings

A few of the micro-ops used here have no macro in upstream lib-micro, the 64-bit
`MUL` and `ADC` among them. Each 64-bit opcode sits one `0x40` DSZ32 → DSZ64
step above the 32-bit form `opcode.h` already defines, so `_MUL_DSZ64` is
`0x26c` (from `_MUL_DSZ32` `0x22c`) and `_ADC_DSZ64` is `0x37e` (from
`_ADC_DSZ32` `0x33e`).

Rather than ask you to patch lib-micro, this artifact defines what it needs
inside the files that use it, each guarded by `#ifndef`. 
Objects compiled against the original lib-micro are
bit-identical to those compiled against a patched one, so the patch images are
the same either way.

### 2. Debug unlock

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
sudo taskset -c 1 ./asm_op_keccak_perm_static
```

This installs the patch and checks it against the Keccak team's published
intermediate-value test vectors and a C reference on 1000 pseudorandom states.

### Benchmarks

```sh
cd keccak/Benchmarks
./run.sh                       # all three levels
./run.sh --quick               # gcc -O3 only
./run.sh --perm                # Table 1 only (also --ablation, --sha3)
```

The permutation sweep writes `RESULTS.md`; the run we took is committed there
for comparison. See `keccak/Benchmarks/README.md` for the contenders, the
method and the file layout.

### Ablations (Table 2)

`abl/` holds one variant of the kernel per design choice, each undoing exactly
one decision and changing nothing else:

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
sudo taskset -c 1 ./full_curve25519_adc_mod2_static
sudo taskset -c 1 ./full_curve25519_adc_mod2_static verify   # edge cases, KATs, vs OpenSSL
```

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
├── abl/                         one kernel variant per ablated design choice
├── include/bench_core.h         which core a harness pins itself to
├── Benchmarks/                  Tables 1, 2 and 3        (own README)
├── lib/                         frequency guard, measurement parsing
└── third_party/                 OpenSSL, XKCP, SUPERCOP, s2n-bignum baselines

curve25519/
├── full_curve25519_inline2.c    install the SETCC patches, benchmark, verify
├── full_curve25519_adc_mod2.c   the same for ADD|MOD2      <- the paper's
├── Benchmarks/ours/patch_*.h    the two patch pairs as the harness installs them
├── include/bench_core.h         which core a harness pins itself to
├── Benchmarks/                  Tables 4 and 5           (own README)
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

## Citation

The paper is currently under review as an anonymous submission.

```bibtex
@misc{triads-below-the-isa,
  title  = {Triads below the ISA: Optimizing Cryptographic Software in CPU Microcode},
  note   = {Anonymous submission},
  year   = {2026}
}
```

## Acknowledgements

This work has been supported
by an ARC Discovery Project number DP210102670; %Yuval
by the Dutch Ministry of Education, Culture, and Science through Gravitation project ``Challenges in Cyber Security -- 024.006.037''; and
by the Deutsche Forschungsgemeinschaft (DFG, German Research Foundation) under Germany's Excellence Strategy - EXC 2092 CASA - 390781972 and through project number 560392681.
