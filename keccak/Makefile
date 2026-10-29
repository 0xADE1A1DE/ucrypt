# ---- keccak Makefile (main implementation) ----
# The Keccak-f[1600] microcode implementation: install the looped 24-round
# permutation patch and KAT-verify it (asm_op_keccak_perm). The patch image
# ships as keccak_perm.h / keccak_perm_body.h; the generator that produced it is
# not part of this artifact, so edit those headers directly if you change it.
#
# The SUPERCOP-measurement apparatus lives in Benchmarks/ (its own Makefile). This
# folder builds only the implementation.
#
# lib-micro is located through LIBMICRO. The default is the pinned submodule at
# the top of this repository; override it for any other location:
#   make LIBMICRO=/path/to/lib-micro PROG=asm_op_keccak_perm
#
# Build: make PROG=asm_op_keccak_perm
# Run:   sudo taskset -c 1 ./asm_op_keccak_perm_static
LIBMICRO ?= ../lib-micro

CC      := gcc
CFLAGS  := -g -O3 -fPIE -ggdb -Wall -masm=intel -march=x86-64-v2 -mtune=generic -I$(LIBMICRO)/include
LDFLAGS := -static
LIBS    := $(LIBMICRO)/build/libmicro.a

PROG ?= asm_op_keccak_perm

all: $(PROG)_static

# ---- asm_op_keccak_perm: needs -no-pie because LDZX_DSZ64_ASZ32 (only ASZ32
# form exists in opcode.h) only takes 32-bit addresses. With -fPIE, static
# globals can land above 4GB; -no-pie forces them low.
ifeq ($(PROG),asm_op_keccak_perm)
CFLAGS := $(filter-out -fPIE,$(CFLAGS)) -no-pie
LDFLAGS := -static -no-pie
endif

# Build $(PROG)_static from $(PROG).c
$(PROG)_static: $(PROG).c $(LIBS)
	$(CC) $(LDFLAGS) $(CFLAGS) $< $(LIBS) -o $@

clean:
	rm -f *_static *.o

.PHONY: all clean
