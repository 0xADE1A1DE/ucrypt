# Benchmarks/Makefile -- the curve25519 benchmark binaries, one per patch set.
#
#   x25519_setcc_static  x25519_adc_static                       level 2
#   kernel_setcc_static  kernel_adc_static  kernel_floor_static  level 1
#
# Each is built from a short wrapper (x25519_setcc.c, ...) that names its
# patch set and includes the shared x25519.c / kernel.c. A process installs
# its patch set once and never swaps it (see common.h).
#
#   make                         gcc -O3 (the default configuration)
#   make CC=clang-18 OPT=-Os     any (compiler, -O) pair; `make clean` first,
#                                the SUPERCOP objects keep the flags they were
#                                built with (run.sh does this per config)
#
# Flags are SUPERCOP's (okcompilers/c): -O<n> -fwrapv -fPIC -fPIE -gdwarf-4
# -Wall -march=native, plus -mtune=native for gcc; clang gets
# -Qunused-arguments instead, as in SUPERCOP's clang line.
#
# Everything outside this folder is only read: the SUPERCOP files and its
# libcryptoint.a and fiat-crypto in ../third_party/, libmicro.a and its headers
# through $(LIBMICRO), and from ../ the namespace headers (include/),
# the CryptOpt asm, OpenSSL's fe51 asm and its extracted X25519
# (openssl_x25519.c). Objects go to build/.
#
# The LIBMICRO default assumes lib-micro sits next to this repository; override
# it for any other location:  make LIBMICRO=/path/to/lib-micro

LIBMICRO ?= ../../../lib-micro

CC  = gcc
OPT = -O3

TP       := ../third_party
SC       := $(TP)/supercop-20260330
SCDATA   := $(TP)/supercop-data
LIBMICRO_A := $(LIBMICRO)/build/libmicro.a
NSINC    := ../include
A51      := $(SC)/crypto_scalarmult/curve25519/amd64-51
A64      := $(SC)/crypto_scalarmult/curve25519/amd64-64
S2N      := $(SC)/s2n-bignum
B        := build

BASE := -fwrapv -fPIC -fPIE -gdwarf-4 -Wall -march=native
ifneq (,$(findstring clang,$(CC)))
BASE += -Qunused-arguments
else
BASE += -mtune=native
endif
CFLAGS     := $(OPT) $(BASE) -masm=intel -I$(NSINC) -I$(LIBMICRO)/include
ATT_CFLAGS := $(OPT) $(BASE) -masm=att -I$(NSINC)   -I$(LIBMICRO)/include   # SUPERCOP's inline asm is AT&T

SC_C := mont25519 consts fe25519_invert fe25519_pack fe25519_setint fe25519_unpack
SC_S := fe25519_freeze fe25519_mul fe25519_square ladderstep work_cswap
A51_OBJS := $(patsubst %,$(B)/amd64-51_%.o,$(SC_C) $(SC_S))
A64_OBJS := $(patsubst %,$(B)/amd64-64_%.o,$(SC_C) $(SC_S))
OBJS := $(A51_OBJS) $(A64_OBJS) \
        $(B)/cryptopt_mul.o $(B)/cryptopt_sq.o \
        $(B)/openssl_x25519_asm.o $(B)/openssl_x25519.o \
        $(B)/s2n_mul_p25519_alt.o $(B)/s2n_sqr_p25519_alt.o $(B)/s2n_x25519_alt.o
LIBS := $(LIBMICRO_A) $(SCDATA)/lib/libcryptoint.a
HDRS := common.h ours/ours.h ours/patch_setcc.h ours/patch_adc.h

BINS := kernel_setcc_static kernel_adc_static kernel_floor_static \
        x25519_setcc_static x25519_adc_static

all: $(BINS)

kernel_%_static: kernel_%.c kernel.c $(HDRS) $(OBJS)
	$(CC) -static $(CFLAGS) $< $(OBJS) $(LIBS) -o $@

x25519_%_static: x25519_%.c x25519.c $(HDRS) $(OBJS)
	$(CC) -static $(CFLAGS) $< $(OBJS) $(LIBS) -o $@

$(B):
	mkdir -p $@

# SUPERCOP amd64-51 / amd64-64, symbols renamed by the namespace headers
# (crypto_scalarmult -> x25519_amd64_51 / x25519_amd64_64, fe25519_mul ->
# supercop_amd64_51_fe25519_mul, ...).
A51_CPP := -I$(A51) -I$(SCDATA)/include -include $(NSINC)/amd64_51_namespace.h
A64_CPP := -I$(A64) -I$(SCDATA)/include -include $(NSINC)/amd64_64_namespace.h
$(B)/amd64-51_%.o: $(A51)/%.c | $(B)
	$(CC) $(ATT_CFLAGS) $(A51_CPP) -c $< -o $@
$(B)/amd64-51_%.o: $(A51)/%.S | $(B)
	$(CC) $(ATT_CFLAGS) $(A51_CPP) -c $< -o $@
$(B)/amd64-64_%.o: $(A64)/%.c | $(B)
	$(CC) $(ATT_CFLAGS) $(A64_CPP) -c $< -o $@
$(B)/amd64-64_%.o: $(A64)/%.S | $(B)
	$(CC) $(ATT_CFLAGS) $(A64_CPP) -c $< -o $@

# CryptOpt declares fiat's symbol names; rename them so both link, and add the
# operand size newer NASM requires on `mul [mem]`.
$(B)/cryptopt_mul.o: ../cryptopt_mul.asm | $(B)
	sed -e 's/fiat_curve25519_carry_mul/cryptopt_carry_mul/g' \
	    -e 's/^mul \[/mul qword [/' $< > $@.asm
	nasm -f elf64 -o $@ $@.asm
	rm -f $@.asm
$(B)/cryptopt_sq.o: ../cryptopt_sq.asm | $(B)
	sed -e 's/fiat_curve25519_carry_square/cryptopt_carry_square/g' \
	    -e 's/^mul \[/mul qword [/' $< > $@.asm
	nasm -f elf64 -o $@ $@.asm
	rm -f $@.asm

# OpenSSL fe51 asm from its perlasm; the fe64 entries are ud2 stubs (need ADX).
$(B)/openssl_x25519_asm.o: ../openssl_x25519_asm.s | $(B)
	$(CC) -c $< -o $@
# OpenSSL's own X25519 ladder (C, over the fe51 asm), built with this
# configuration's flags like every other C contender.
$(B)/openssl_x25519.o: ../openssl_x25519.c ../openssl_x25519_core.inc | $(B)
	$(CC) $(CFLAGS) -c $< -o $@

# s2n-bignum: only the _alt variants run here (the others use MULX/ADCX/ADOX).
$(B)/s2n_mul_p25519_alt.o: $(S2N)/x86/curve25519/bignum_mul_p25519_alt.S | $(B)
	$(CC) -I$(S2N)/include -c $< -o $@
$(B)/s2n_sqr_p25519_alt.o: $(S2N)/x86/curve25519/bignum_sqr_p25519_alt.S | $(B)
	$(CC) -I$(S2N)/include -c $< -o $@
$(B)/s2n_x25519_alt.o: $(S2N)/x86/curve25519/curve25519_x25519_alt.S | $(B)
	$(CC) -I$(S2N)/include -c $< -o $@

clean:
	rm -rf $(B) *_static

.PHONY: all clean
