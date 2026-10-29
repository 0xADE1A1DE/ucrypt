# ---- keccak/Benchmarks Makefile ----
# SUPERCOP-measurement apparatus for the Keccak microcode implementation:
# the head-to-head harness (asm_op_keccak_vs), the SHA3-256 harness (sha3_own),
# the speed-up harness (bench_speed-up), and the SUPERCOP scalar Keccak
# baselines they link against.
# Split out of ../Makefile on 2026-06-16 so the main keccak/ folder holds only
# the implementation.
#
# This Makefile runs from the repository's keccak/Benchmarks/, so:
#   lib-micro     ->  $(LIBMICRO)            (headers and libmicro.a; default below)
#   third party   ->  ../third_party/        (only the baseline files this Makefile reads:
#                     SUPERCOP 20260330, supercop-data brg_endian.h, XKCP, OpenSSL)
#   patch headers (keccak_perm.h / _body.h) live in the parent keccak/, so
#   asm_op_keccak_vs.c includes them as ../keccak_perm.h.
#
# The LIBMICRO default is the pinned submodule at the top of this repository;
# override it for any other location:  make LIBMICRO=/path/to/lib-micro PROG=...
#
# Build: make PROG=asm_op_keccak_vs
# Run:   sudo taskset -c 1 ./asm_op_keccak_vs_static
# Sweep: ./run.sh            (see README.md)
LIBMICRO ?= ../../lib-micro

CC      := gcc
CFLAGS  := -g -O3 -fPIE -ggdb -Wall -masm=intel -march=x86-64-v2 -mtune=generic -I$(LIBMICRO)/include
LDFLAGS := -static
LIBS    := $(LIBMICRO)/build/libmicro.a

# Default to the head-to-head benchmark (microcode vs SUPERCOP scalar variants).
PROG ?= asm_op_keccak_vs
# Output binary. sha3_best.sh overrides it (and EXTRA_OBJS) to link the
# best-config SHA3-256 objects into a separate binary, sha3_own_best_static.
TARGET ?= $(PROG)_static

all: $(TARGET)

# ---- SUPERCOP Keccak baselines (sources in ../third_party/supercop-20260330) ----
# Both impls define a function named `KeccakPermutation`; objcopy renames them
# to unique names so they can coexist in one binary. `keep-global-symbol` hides
# the other (unused) functions so they don't collide either.
SC_KECCAK_DIR := ../third_party/supercop-20260330/crypto_hash/keccakc1024
SC_INC        := ../third_party/supercop-data/include
KECCAK_CFLAGS := $(filter-out -masm=intel,$(CFLAGS)) -masm=att

keccak_x86_64_asm.o: $(SC_KECCAK_DIR)/x86_64_asm/keccak.s
	$(CC) $(KECCAK_CFLAGS) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutation=keccak_x86_64_asm_perm \
	        $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_x86_64_asm_perm \
	        $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

keccak_opt64lcu6.o: $(SC_KECCAK_DIR)/opt64lcu6/KeccakF-1600-opt64.c
	$(CC) $(KECCAK_CFLAGS) -I$(SC_KECCAK_DIR)/opt64lcu6 -I$(SC_INC) \
	      -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutationOnWords=keccak_opt64lcu6_perm \
	        $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_opt64lcu6_perm \
	        $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

keccak_x86_64_shld.o: $(SC_KECCAK_DIR)/x86_64_shld/keccak.s
	$(CC) $(KECCAK_CFLAGS) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutation=keccak_x86_64_shld_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_x86_64_shld_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

keccak_opt64lcu24.o: $(SC_KECCAK_DIR)/opt64lcu24/KeccakF-1600-opt64.c
	$(CC) $(KECCAK_CFLAGS) -I$(SC_KECCAK_DIR)/opt64lcu24 -I$(SC_INC) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutationOnWords=keccak_opt64lcu24_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_opt64lcu24_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

keccak_opt64lcu24shld.o: $(SC_KECCAK_DIR)/opt64lcu24shld/KeccakF-1600-opt64.c
	$(CC) $(KECCAK_CFLAGS) -I$(SC_KECCAK_DIR)/opt64lcu24shld -I$(SC_INC) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutationOnWords=keccak_opt64lcu24shld_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_opt64lcu24shld_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

keccak_opt64u6.o: $(SC_KECCAK_DIR)/opt64u6/KeccakF-1600-opt64.c
	$(CC) $(KECCAK_CFLAGS) -I$(SC_KECCAK_DIR)/opt64u6 -I$(SC_INC) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutationOnWords=keccak_opt64u6_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_opt64u6_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

# SIMD variants: SSE2/SSSE3 + MMX are baseline under -march=x86-64-v2 / -march=native
# on this Goldmont core, so no extra -m flags are needed. (xopu24 is omitted: XOP
# is AMD-only and #UDs on Intel.) Same KeccakPermutationOnWords(UINT64*) entry point.
keccak_sseu2.o: $(SC_KECCAK_DIR)/sseu2/KeccakF-1600-opt64.c
	$(CC) $(KECCAK_CFLAGS) -I$(SC_KECCAK_DIR)/sseu2 -I$(SC_INC) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutationOnWords=keccak_sseu2_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_sseu2_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

keccak_mmxu1.o: $(SC_KECCAK_DIR)/mmxu1/KeccakF-1600-opt64.c
	$(CC) $(KECCAK_CFLAGS) -I$(SC_KECCAK_DIR)/mmxu1 -I$(SC_INC) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakPermutationOnWords=keccak_mmxu1_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_mmxu1_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

# reference C. Keccak-simple.c #includes a SUPERCOP-generated crypto_hash.h; since
# we only extract the bare permutation KeccakF, a one-line stub (just
# crypto_hash_BYTES) satisfies the compile. KeccakF(state, in, laneCount) with
# laneCount=0 (see asm_op_keccak_vs.c) is a pure permutation.
keccak_simple.o: $(SC_KECCAK_DIR)/simple/Keccak-simple.c
	mkdir -p scstub
	printf '#define crypto_hash_BYTES 64\nint crypto_hash(unsigned char*,const unsigned char*,unsigned long long);\n' > scstub/crypto_hash.h
	$(CC) $(KECCAK_CFLAGS) -Iscstub -I$(SC_KECCAK_DIR)/simple -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakF=keccak_simple_F $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_simple_F $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

# ---- XKCP (Keccak team) single Keccak-p[1600], plain-64bits ----
# Goldmont has no AVX2/AVX-512, and XKCP ships NO SSE single-permutation kernel,
# so the only XKCP single-perm that runs here is plain-64bits (its generic64 /
# generic64lc targets; SSSE3/AVX/x86-64 all fall back to it for one permutation).
# Same KeccakP-1600-opt64.c, toggled by a generated config.h:
#   xkcp_g64   = full unroll, no lane-complement   (generic64)
#   xkcp_g64lc = full unroll, lane-complement       (generic64lc - what XKCP runs here)
# Entry point KeccakP1600_plain64_Permute_24rounds(void*) is renamed per variant.
XKCP_K1600 := ../third_party/XKCP/lib/low/KeccakP-1600
XKCP_INC   := -I$(XKCP_K1600)/plain-64bits -I$(XKCP_K1600)/plain-64bits/SnP \
              -I$(XKCP_K1600)/common -I../third_party/XKCP/lib/low/common -I../third_party/XKCP/lib/common

keccak_xkcp_g64.o: $(XKCP_K1600)/plain-64bits/KeccakP-1600-opt64.c
	mkdir -p xkcpcfg_g64
	printf '#define KeccakP1600_plain64_fullUnrolling\n' > xkcpcfg_g64/config.h
	$(CC) $(KECCAK_CFLAGS) -Ixkcpcfg_g64 $(XKCP_INC) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakP1600_plain64_Permute_24rounds=keccak_xkcp_g64_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_xkcp_g64_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

keccak_xkcp_g64lc.o: $(XKCP_K1600)/plain-64bits/KeccakP-1600-opt64.c
	mkdir -p xkcpcfg_g64lc
	printf '#define KeccakP1600_plain64_useLaneComplementing\n#define KeccakP1600_plain64_fullUnrolling\n' > xkcpcfg_g64lc/config.h
	$(CC) $(KECCAK_CFLAGS) -Ixkcpcfg_g64lc $(XKCP_INC) -c $< -o $@.tmp.o
	objcopy --redefine-sym KeccakP1600_plain64_Permute_24rounds=keccak_xkcp_g64lc_perm $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_xkcp_g64lc_perm $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

# ---- OpenSSL keccak1600, x86-64 assembly (crypto/sha/asm, CRYPTOGAMS/Polyakov) ----
# What OpenSSL actually runs on x86-64: plain scalar asm (no BMI/AVX), so it runs
# on Goldmont. Generated from the perlasm via x86_64-xlate.pl. KeccakF1600 isn't
# .globl in the asm (only SHA3_absorb/squeeze are) -> globalize + rename it. The
# trailing .note.gnu.property CET block is emitted in a Solaris #alloc form GNU as
# rejects, and it sits after all code -> stripped. (The avx2/avx512 OpenSSL keccak
# asm needs AVX, which Goldmont lacks, so only this scalar path is benchmarkable.)
OSSL_KECCAK := ../third_party/openssl/crypto/sha/asm/keccak1600-x86_64.pl
keccak_openssl.o: $(OSSL_KECCAK)
	perl $< elf $@.s 2>/dev/null
	sed -i '/\.section[[:space:]].*note\.gnu\.property/,$$d' $@.s
	$(CC) -c $@.s -o $@.tmp.o
	objcopy --globalize-symbol=KeccakF1600 $@.tmp.o $@.tmp1.o
	objcopy --redefine-sym KeccakF1600=keccak_openssl_perm $@.tmp1.o $@.tmp2.o
	objcopy --keep-global-symbol=keccak_openssl_perm $@.tmp2.o $@
	rm -f $@.s $@.tmp.o $@.tmp1.o $@.tmp2.o

# ---- s2n-bignum (AWS) sha3_keccak_f1600, x86-64 assembly ----
# Formally verified (HOL Light) port of the OpenSSL/CRYPTOGAMS scalar asm above;
# plain x86-64 (no BMI/AVX), so it runs on Goldmont. Assembled verbatim from the
# SUPERCOP tree, as ../../curve25519 does for its curve25519 objects.
# Its entry takes (a[25], rc[24]); keccak_s2n_glue.S adds the one-argument
# keccak_s2n_perm(state) that loads rc and tail-jumps in. Compiler-independent.
S2N := ../third_party/supercop-20260330/s2n-bignum
keccak_s2n_bignum.o: $(S2N)/x86/sha3/sha3_keccak_f1600.S keccak_s2n_glue.S
	$(CC) -I$(S2N)/include -c $< -o $@.tmp1.o
	$(CC) -c keccak_s2n_glue.S -o $@.tmp2.o
	ld -r $@.tmp1.o $@.tmp2.o -o $@.tmp.o
	objcopy --keep-global-symbol=keccak_s2n_perm $@.tmp.o $@
	rm -f $@.tmp.o $@.tmp1.o $@.tmp2.o

# ==== SHA3-256 contenders for sha3_own: each implementation's OWN sponge ====
# One object per contender, sha3own_<key>.o, holding that implementation's
# complete SHA3-256 path (its sponge, absorb, padding, squeeze and permutation)
# built with $(CFLAGS), so sha3_best.sh can build each one under the config that
# won its row of the permutation sweep. Every object exports exactly one symbol,
#   int sha3_256_<key>(unsigned char *out, const unsigned char *in,
#                      unsigned long long inlen)
# (SUPERCOP's crypto_hash signature): the parts are joined with `ld -r` and every
# other global is hidden, because the SUPERCOP packages all define the same names
# (InitSponge, Absorb, KeccakPermutation, ...). s2n-bignum ships only a
# permutation, so it has no SHA3-256 contender.

# -- SUPERCOP keccakc512: the Keccak team's SHA-3-256 submission, r=1088 c=512 --
# Same permutation sources as the keccakc1024 objects above (byte-identical);
# keccakc512 differs only in hash.c/api.h and in KeccakF-1600-int-set.h, which
# turns on the rate-1088 fast absorb path. sha3_kc512_shim.c is that package's
# hash.c plus the FIPS 202 domain bits; see the file.
SC512        := ../third_party/supercop-20260330/crypto_hash/keccakc512
SHA3_SC_ASM  := x86_64_asm x86_64_shld
SHA3_SC_C    := opt64lcu24 opt64lcu24shld opt64lcu6 opt64u6 sseu2 mmxu1

$(SHA3_SC_ASM:%=sha3own_%.o): sha3own_%.o: $(SC512)/%/keccak.s sha3_kc512_shim.c
	$(CC) $(KECCAK_CFLAGS) -c $(SC512)/$*/keccak.s -o $@.1.o
	$(CC) $(KECCAK_CFLAGS) -I$(SC512)/$* -c $(SC512)/$*/KeccakF-1600-x86-64-asm.c -o $@.2.o
	$(CC) $(KECCAK_CFLAGS) -I$(SC512)/$* -c $(SC512)/$*/KeccakSponge.c -o $@.3.o
	$(CC) $(KECCAK_CFLAGS) -I$(SC512)/$* -DSHA3_ENTRY=sha3_256_$* -c sha3_kc512_shim.c -o $@.4.o
	ld -r $@.1.o $@.2.o $@.3.o $@.4.o -o $@.tmp.o
	objcopy --keep-global-symbol=sha3_256_$* $@.tmp.o $@
	rm -f $@.1.o $@.2.o $@.3.o $@.4.o $@.tmp.o

$(SHA3_SC_C:%=sha3own_%.o): sha3own_%.o: $(SC512)/%/KeccakF-1600-opt64.c sha3_kc512_shim.c
	$(CC) $(KECCAK_CFLAGS) -I$(SC512)/$* -I$(SC_INC) -c $(SC512)/$*/KeccakF-1600-opt64.c -o $@.1.o
	$(CC) $(KECCAK_CFLAGS) -I$(SC512)/$* -c $(SC512)/$*/KeccakSponge.c -o $@.2.o
	$(CC) $(KECCAK_CFLAGS) -I$(SC512)/$* -DSHA3_ENTRY=sha3_256_$* -c sha3_kc512_shim.c -o $@.3.o
	ld -r $@.1.o $@.2.o $@.3.o -o $@.tmp.o
	objcopy --keep-global-symbol=sha3_256_$* $@.tmp.o $@
	rm -f $@.1.o $@.2.o $@.3.o $@.tmp.o

# -- SUPERCOP keccakc512/simple: the reference C, with its own crypto_hash() --
# Its padding byte is hard-coded to Keccak's 0x01 (Keccak-simple.c:81); SHA3-256
# needs 0x06 (domain bits "01" + the pad start). A build-time copy changes that
# one constant and nothing else; the grep aborts the build if the line moved.
sha3own_simple.o: $(SC512)/simple/Keccak-simple.c
	mkdir -p sha3simple
	printf '#define crypto_hash_BYTES 32\nint crypto_hash(unsigned char*,const unsigned char*,unsigned long long);\n' > sha3simple/crypto_hash.h
	sed 's/temp\[inlen++\] = 1;/temp[inlen++] = 0x06;   \/* SHA3: domain bits 01 + pad (Keccak: 1) *\//' $< > sha3simple/Keccak-simple.c
	test "$$(grep -c 'temp\[inlen++\] = 0x06;' sha3simple/Keccak-simple.c)" = 1
	$(CC) $(KECCAK_CFLAGS) -Isha3simple -I$(SC512)/simple -c sha3simple/Keccak-simple.c -o $@.tmp.o
	objcopy --redefine-sym crypto_hash=sha3_256_simple $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=sha3_256_simple $@.tmp2.o $@
	rm -f $@.tmp.o $@.tmp2.o

# -- XKCP: its SHA3_256() (SimpleFIPS202) on its sponge (KeccakSponge.c) over the
# plain-64bits kernel, configured as XKCP's own K1600-plain-64bits-ua (generic64)
# and -lcua (generic64lc) targets in lib/LowLevel.build.
XKCP_HI := ../third_party/XKCP/lib/high/Keccak
SHA3_XKCP_INC = -Isha3cfg_$* $(XKCP_INC) -I$(XKCP_HI) -I$(XKCP_HI)/FIPS202
sha3own_xkcp_g64.o:   XKCP_CFG := '\#define KeccakP1600_plain64_fullUnrolling\n'
sha3own_xkcp_g64lc.o: XKCP_CFG := '\#define KeccakP1600_plain64_fullUnrolling\n\#define KeccakP1600_plain64_useLaneComplementing\n'
sha3own_xkcp_g64.o sha3own_xkcp_g64lc.o: sha3own_%.o: $(XKCP_K1600)/plain-64bits/KeccakP-1600-opt64.c
	mkdir -p sha3cfg_$*
	printf '#define XKCP_has_KeccakP1600\n#define XKCP_has_Sponge_Keccak\n#define XKCP_has_FIPS202\n'$(XKCP_CFG) > sha3cfg_$*/config.h
	$(CC) $(KECCAK_CFLAGS) $(SHA3_XKCP_INC) -c $< -o $@.1.o
	$(CC) $(KECCAK_CFLAGS) $(SHA3_XKCP_INC) -c $(XKCP_HI)/KeccakSponge.c -o $@.2.o
	$(CC) $(KECCAK_CFLAGS) $(SHA3_XKCP_INC) -c $(XKCP_HI)/FIPS202/SimpleFIPS202.c -o $@.3.o
	ld -r $@.1.o $@.2.o $@.3.o -o $@.tmp.o
	objcopy --redefine-sym SHA3_256=sha3_256_$* $@.tmp.o $@.tmp2.o
	objcopy --keep-global-symbol=sha3_256_$* $@.tmp2.o $@
	rm -f $@.1.o $@.2.o $@.3.o $@.tmp.o $@.tmp2.o

# -- OpenSSL: its sponge (crypto/sha/sha3.c) over its x86-64 asm SHA3_absorb /
# SHA3_squeeze; sha3_ossl_shim.c sets it up as the SHA3-256 provider does.
# sha3.c needs OpenSSL's generated headers (configuration.h, crypto.h, ...). They
# ship pre-generated in $(OSSL)/generated: produced by an out-of-tree
# `Configure linux-x86_64 no-shared` of OpenSSL 4.1.0-dev (commit 43e1e98a26),
# the tree the other OpenSSL files in ../third_party/openssl come from. The
# system's (different) OpenSSL headers in /usr/include are never picked up. The
# headers do not depend on the compiler.
OSSL     := ../third_party/openssl
OSSL_CFG := $(OSSL)/generated
OSSL_INC := -I$(OSSL_CFG)/include -I$(OSSL)/include -I$(OSSL)

sha3own_openssl.o: $(OSSL_KECCAK) $(OSSL)/crypto/sha/sha3.c sha3_ossl_shim.c $(OSSL_CFG)/include/openssl/crypto.h
	perl $(OSSL_KECCAK) elf $@.s 2>/dev/null
	sed -i '/\.section[[:space:]].*note\.gnu\.property/,$$d' $@.s
	$(CC) -c $@.s -o $@.1.o
	$(CC) $(KECCAK_CFLAGS) -DKECCAK1600_ASM $(OSSL_INC) -c $(OSSL)/crypto/sha/sha3.c -o $@.2.o
	$(CC) $(KECCAK_CFLAGS) -DKECCAK1600_ASM $(OSSL_INC) -c sha3_ossl_shim.c -o $@.3.o
	ld -r $@.1.o $@.2.o $@.3.o -o $@.tmp.o
	objcopy --keep-global-symbol=sha3_256_openssl $@.tmp.o $@
	rm -f $@.s $@.1.o $@.2.o $@.3.o $@.tmp.o

SHA3_OWN_OBJS := $(SHA3_SC_ASM:%=sha3own_%.o) $(SHA3_SC_C:%=sha3own_%.o) \
                 sha3own_simple.o sha3own_xkcp_g64.o sha3own_xkcp_g64lc.o \
                 sha3own_openssl.o

# head-to-head: links ALL fast SUPERCOP scalar Keccak variants; -no-pie because
# the harness installs the microcode patch and needs its buffer in the low 4GB
# (LDZX_DSZ64_ASZ32 only takes 32-bit addresses).
# sha3_own is the end-to-end SHA3-256 harness: every native contender runs its
# own complete SHA3-256 (SHA3_OWN_OBJS above). It has the same low-4GB /
# RSP-preservation constraints as asm_op_keccak_vs, so it shares that target's
# flags and pinned harness -O.
ifneq ($(filter $(PROG),asm_op_keccak_vs sha3_own bench_speed-up),)
CFLAGS := $(filter-out -fPIE,$(CFLAGS)) -no-pie
LDFLAGS := -static -no-pie
# Pin the HARNESS translation unit to a fixed, known-good -O. The harness is
# measurement apparatus, NOT an implementation under test - only the SUPERCOP
# baselines (compiled in their own .o rules with the swept $(CFLAGS)) should be
# tuned across the compiler/-O grid. Sweeping the harness's own -O is both
# meaningless (microcode is a fixed patch image; its number must stay flat
# across configs) and dangerous: at -Os GCC reshapes main() with extra
# mid-function push/pop spills and a different stack layout, which collides with
# ucode_perm()'s requirement that the microcode patch preserve RSP (RSP is the
# patch's 32nd data register and cannot be listed as an inline-asm clobber) ->
# SIGSEGV. Appending -O2 after $(CFLAGS) wins (last -O wins for gcc/clang) and
# affects ONLY the $< compile in the build rule, not the prebuilt baseline .o.
HARNESS_OPT := -O2
ifeq ($(PROG),bench_speed-up)
EXTRA_OBJS :=
else ifeq ($(PROG),sha3_own)
EXTRA_OBJS := $(SHA3_OWN_OBJS)
else
EXTRA_OBJS := keccak_x86_64_asm.o keccak_x86_64_shld.o \
              keccak_opt64lcu24.o keccak_opt64lcu24shld.o \
              keccak_opt64lcu6.o keccak_opt64u6.o \
              keccak_sseu2.o keccak_mmxu1.o keccak_simple.o \
              keccak_xkcp_g64.o keccak_xkcp_g64lc.o keccak_openssl.o \
              keccak_s2n_bignum.o
endif
endif

# Build $(PROG)_static from $(PROG).c (+ any extra objs). $(HARNESS_OPT) is empty
# by default and -O2 for asm_op_keccak_vs (see note above); it follows $(CFLAGS)
# so the harness TU's -O is pinned while baselines keep the swept flags.
# The patch headers are real prerequisites: changing the kernel
# (editing keccak_perm*.h or speed-up_variants/*.h) must force a relink, or a stale binary
# silently benchmarks the previous kernel.
GEN_HDRS := ../keccak_perm.h ../keccak_perm_body.h $(wildcard ../speed-up_variants/*.h)

$(TARGET): $(PROG).c $(LIBS) $(EXTRA_OBJS) $(GEN_HDRS)
	$(CC) $(LDFLAGS) $(CFLAGS) $(HARNESS_OPT) $< $(EXTRA_OBJS) $(LIBS) -o $@

clean:
	rm -f *_static *.o keccak_openssl.o.s sha3own_openssl.o.s
	rm -rf scstub xkcpcfg_g64 xkcpcfg_g64lc best
	rm -rf sha3simple sha3cfg_xkcp_g64 sha3cfg_xkcp_g64lc

.PHONY: all clean
