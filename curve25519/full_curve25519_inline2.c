/*
 * full_curve25519_inline2.c — X25519 with the 5x51 field arithmetic in
 * microcode. SETCC carry variant: fe_mul 58 triads, fe_sq 41.
 * fe_mul is hooked onto vmwrite (0x0cd8 -> U7c00), fe_sq onto vmread (0x0618).
 *
 *   make PROG=full_curve25519_inline2
 *   sudo wrmsr -p 1 0x1e6 0x200                     debug unlock, core 1
 *   sudo taskset -c 1 ./full_curve25519_inline2_static [verify]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>
#include <patch.h>
#include <ucode_macro.h>
#include <misc.h>
#include "include/bench_core.h"
#include "freq_guard.h"

typedef uint64_t fe[5];
#define MASK51 0x7FFFFFFFFFFFFULL

typedef struct {
    uint64_t x1[5];
    uint64_t x2[5];
    uint64_t z2[5];
    uint64_t x3[5];
    uint64_t z3[5];
    uint64_t A[5];
    uint64_t AA[5];
    uint64_t B[5];
    uint64_t BB[5];
    uint64_t E[5];
    uint64_t C[5];
    uint64_t D[5];
    uint64_t DA[5];
    uint64_t CB[5];
    uint64_t t0[5];
} ladder_state_t;

#define X1_OFF  0
#define X2_OFF  40
#define Z2_OFF  80
#define X3_OFF  120
#define Z3_OFF  160
#define A_OFF   200
#define AA_OFF  240
#define B_OFF   280
#define BB_OFF  320
#define E_OFF   360
#define C_OFF   400
#define D_OFF   440
#define DA_OFF  480
#define CB_OFF  520
#define T0_OFF  560

typedef struct {
    uint64_t z[5];
    uint64_t z2[5];
    uint64_t z9[5];
    uint64_t z11[5];
    uint64_t t[5];
    uint64_t t0[5];
    uint64_t t1[5];
    uint64_t t2[5];
    uint64_t t3[5];
    uint64_t sc[5];
} invert_state_t;

#define IZ_OFF    0
#define IZ2_OFF   40
#define IZ9_OFF   80
#define IZ11_OFF  120
#define IT_OFF    160
#define IT0_OFF   200
#define IT1_OFF   240
#define IT2_OFF   280
#define IT3_OFF   320
#define ISC_OFF   360

#define _S(x) #x
#define S(x) _S(x)

#define FE_SQ_R8 "mov r8, 0x7FFFFFFFFFFFF\n\t"

#if defined(SQ_SERIAL) || defined(MUL_A24) || defined(FE_MUL_XOR_ZERO) || \
    defined(MUL_VARIANT_DC) || defined(MUL_VARIANT_G_DENSE) || defined(MUL_VARIANT_G_DC)
#error "SQ_SERIAL / MUL_A24 / FE_MUL_XOR_ZERO / MUL_VARIANT_* were removed from full_curve25519_inline2.c (see a44893a78)"
#endif
#ifndef ENABLE_SQ_5ACC
#define ENABLE_SQ_5ACC
#endif
#ifndef SQ_MASK_R8
#define SQ_MASK_R8
#endif
#ifndef SQ_UNCHAINED
#define SQ_UNCHAINED
#endif

#ifndef _MUL_DSZ64
#define _MUL_DSZ64 (0x26cULL << 32)
#endif
#ifndef MUL_DSZ64_DRR
#define MUL_DSZ64_DRR(dst, src0, src1) ( _MUL_DSZ64 | INSTR_DRR(dst, src0, src1) )
#endif

#ifndef IMUL64L_DSZ64_DRR
#define IMUL64L_DSZ64_DRR(d, a, b) (_IMUL64L_DSZ64 | INSTR_DRR(d, a, b))
#endif
#ifndef IMUL64L_DSZ64_DRI
#define IMUL64L_DSZ64_DRI(d, a, i) (_IMUL64L_DSZ64 | INSTR_DRI(d, a, i))
#endif

/* MICROCODE PATCH INSTALLATION */

static void install_field_patches(void) {
    ucode_t mul_patch[] = {

    { IMUL64L_DSZ64_DRI(TMP3, RBX, 19), IMUL64L_DSZ64_DRI(TMP2, R10, 19),
      IMUL64L_DSZ64_DRI(TMP1, R9, 19), NOP_SEQWORD },

    { IMUL64L_DSZ64_DRI(TMP0, R13, 19), ZEROEXT_DSZ64_DR(TMP4, R15),
      MUL_DSZ64_DRR(TMP9, RDI, TMP4), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(TMP5, R13), MUL_DSZ64_DRR(TMP10, RDI, TMP5),
      ZEROEXT_DSZ64_DR(TMP6, R9), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP11, RDI, TMP6), ZEROEXT_DSZ64_DR(TMP7, R10),
      MUL_DSZ64_DRR(TMP12, RDI, TMP7), NOP_SEQWORD },

    { ZEROEXT_DSZ64_DR(TMP8, RBX), MUL_DSZ64_DRR(TMP13, RDI, TMP8),
      ZEROEXT_DSZ64_DR(RAX, R15), NOP_SEQWORD },
    { MUL_DSZ64_DRR(R8, RSI, RAX), ZEROEXT_DSZ64_DR(RDX, R13),
      MUL_DSZ64_DRR(RBX, RSI, RDX), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP5, TMP5, RAX), SETCC_CONDB_DR(TMP14, TMP5),
      ADD_DSZ64_DRR(R8, R8, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP10, TMP10, R8), ZEROEXT_DSZ64_DR(RDI, R9),
      MUL_DSZ64_DRR(RAX, RSI, RDI), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP6, TMP6, RDX), SETCC_CONDB_DR(TMP15, TMP6),
      ADD_DSZ64_DRR(RBX, RBX, TMP15), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP11, TMP11, RBX), MUL_DSZ64_DRR(R8, RSI, R10),
      ADD_DSZ64_DRR(TMP7, TMP7, RDI), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP14, TMP7), ADD_DSZ64_DRR(RAX, RAX, TMP14),
      ADD_DSZ64_DRR(TMP12, TMP12, RAX), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(RDX, TMP3), MUL_DSZ64_DRR(RBX, RSI, RDX),
      ADD_DSZ64_DRR(TMP8, TMP8, R10), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP15, TMP8), ADD_DSZ64_DRR(R8, R8, TMP15),
      ADD_DSZ64_DRR(TMP13, TMP13, R8), NOP_SEQWORD },

    { ZEROEXT_DSZ64_DR(RDI, R15), MUL_DSZ64_DRR(RSI, R12, RDI),
      ADD_DSZ64_DRR(TMP4, TMP4, RDX), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP14, TMP4), ADD_DSZ64_DRR(RBX, RBX, TMP14),
      ADD_DSZ64_DRR(TMP9, TMP9, RBX), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(R10, R13), MUL_DSZ64_DRR(RAX, R12, R10),
      ADD_DSZ64_DRR(TMP6, TMP6, RDI), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP15, TMP6), ADD_DSZ64_DRR(RSI, RSI, TMP15),
      ADD_DSZ64_DRR(TMP11, TMP11, RSI), NOP_SEQWORD },
    { MUL_DSZ64_DRR(R8, R12, R9), ADD_DSZ64_DRR(TMP7, TMP7, R10),
      SETCC_CONDB_DR(TMP14, TMP7), NOP_SEQWORD },
    { ADD_DSZ64_DRR(RAX, RAX, TMP14), ADD_DSZ64_DRR(TMP12, TMP12, RAX),
      ZEROEXT_DSZ64_DR(RDX, TMP2), NOP_SEQWORD },
    { MUL_DSZ64_DRR(RBX, R12, RDX), ADD_DSZ64_DRR(TMP8, TMP8, R9),
      SETCC_CONDB_DR(TMP15, TMP8), NOP_SEQWORD },
    { ADD_DSZ64_DRR(R8, R8, TMP15), ADD_DSZ64_DRR(TMP13, TMP13, R8),
      ZEROEXT_DSZ64_DR(RDI, TMP3), NOP_SEQWORD },
    { MUL_DSZ64_DRR(RSI, R12, RDI), ADD_DSZ64_DRR(TMP4, TMP4, RDX),
      SETCC_CONDB_DR(TMP14, TMP4), NOP_SEQWORD },

    { ADD_DSZ64_DRR(RBX, RBX, TMP14), ADD_DSZ64_DRR(TMP9, TMP9, RBX),
      ZEROEXT_DSZ64_DR(R10, R15), NOP_SEQWORD },
    { MUL_DSZ64_DRR(R9, R11, R10), ADD_DSZ64_DRR(TMP5, TMP5, RDI),
      SETCC_CONDB_DR(TMP15, TMP5), NOP_SEQWORD },
    { ADD_DSZ64_DRR(RSI, RSI, TMP15), ADD_DSZ64_DRR(TMP10, TMP10, RSI),
      MUL_DSZ64_DRR(R12, R11, R13), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP7, TMP7, R10), SETCC_CONDB_DR(TMP14, TMP7),
      ADD_DSZ64_DRR(R9, R9, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP12, TMP12, R9), ZEROEXT_DSZ64_DR(RAX, TMP1),
      MUL_DSZ64_DRR(R8, R11, RAX), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP8, TMP8, R13), SETCC_CONDB_DR(TMP15, TMP8),
      ADD_DSZ64_DRR(R12, R12, TMP15), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP13, TMP13, R12), ZEROEXT_DSZ64_DR(R13, TMP2),
      MUL_DSZ64_DRR(RDX, R11, R13), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP4, TMP4, RAX), SETCC_CONDB_DR(TMP14, TMP4),
      ADD_DSZ64_DRR(R8, R8, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP9, TMP9, R8), ZEROEXT_DSZ64_DR(RBX, TMP3),
      MUL_DSZ64_DRR(RDI, R11, RBX), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP5, TMP5, R13), SETCC_CONDB_DR(TMP15, TMP5),
      ADD_DSZ64_DRR(RDX, RDX, TMP15), NOP_SEQWORD },

    { ADD_DSZ64_DRR(TMP10, TMP10, RDX), MUL_DSZ64_DRR(RDX, R14, R15),
      ADD_DSZ64_DRR(TMP6, TMP6, RBX), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP14, TMP6), ADD_DSZ64_DRR(RDI, RDI, TMP14),
      ADD_DSZ64_DRR(TMP11, TMP11, RDI), NOP_SEQWORD },
    { MUL_DSZ64_DRR(RBX, R14, TMP0), ADD_DSZ64_DRR(TMP8, TMP8, R15),
      SETCC_CONDB_DR(TMP15, TMP8), NOP_SEQWORD },
    { ADD_DSZ64_DRR(RDX, RDX, TMP15), ADD_DSZ64_DRR(TMP13, TMP13, RDX),
      MUL_DSZ64_DRR(R8, R14, TMP1), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP4, TMP4, TMP0), SETCC_CONDB_DR(TMP14, TMP4),
      ADD_DSZ64_DRR(RBX, RBX, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP9, TMP9, RBX), MUL_DSZ64_DRR(TMP0, R14, TMP2),
      ADD_DSZ64_DRR(TMP5, TMP5, TMP1), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP15, TMP5), ADD_DSZ64_DRR(R8, R8, TMP15),
      ADD_DSZ64_DRR(TMP10, TMP10, R8), NOP_SEQWORD },
    { MUL_DSZ64_DRR(R15, R14, TMP3), ADD_DSZ64_DRR(TMP6, TMP6, TMP2),
      SETCC_CONDB_DR(TMP14, TMP6), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP0, TMP0, TMP14), ADD_DSZ64_DRR(TMP11, TMP11, TMP0),
      ADD_DSZ64_DRR(TMP7, TMP7, TMP3), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP15, TMP7), ADD_DSZ64_DRR(R15, R15, TMP15),
      ADD_DSZ64_DRR(TMP12, TMP12, R15), NOP_SEQWORD },

    { SHL_DSZ64_DRI(TMP9, TMP9, 13), SHR_DSZ64_DRI(TMP0, TMP4, 51),
      AND_DSZ64_DRR(TMP4, TMP4, RCX), NOP_SEQWORD },
    { OR_DSZ64_DRR(TMP9, TMP0, TMP9), SHL_DSZ64_DRI(TMP10, TMP10, 13),
      SHR_DSZ64_DRI(TMP1, TMP5, 51), NOP_SEQWORD },
    { AND_DSZ64_DRR(TMP5, TMP5, RCX), OR_DSZ64_DRR(TMP10, TMP1, TMP10),
      SHL_DSZ64_DRI(TMP11, TMP11, 13), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP2, TMP6, 51), AND_DSZ64_DRR(TMP6, TMP6, RCX),
      OR_DSZ64_DRR(TMP11, TMP2, TMP11), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP12, TMP12, 13), SHR_DSZ64_DRI(TMP0, TMP7, 51),
      AND_DSZ64_DRR(TMP7, TMP7, RCX), NOP_SEQWORD },
    { OR_DSZ64_DRR(TMP12, TMP0, TMP12), SHL_DSZ64_DRI(TMP13, TMP13, 13),
      SHR_DSZ64_DRI(TMP1, TMP8, 51), NOP_SEQWORD },

    { AND_DSZ64_DRR(TMP8, TMP8, RCX), OR_DSZ64_DRR(TMP13, TMP1, TMP13),
      ADD_DSZ64_DRR(TMP5, TMP5, TMP9), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP6, TMP6, TMP10), ADD_DSZ64_DRR(TMP7, TMP7, TMP11),
      ADD_DSZ64_DRR(TMP8, TMP8, TMP12), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP3, TMP13, 4), ADD_DSZ64_DRR(TMP14, TMP13, TMP13),
      ADD_DSZ64_DRR(TMP3, TMP3, TMP14), NOP_SEQWORD },

    { ADD_DSZ64_DRR(TMP3, TMP3, TMP13), ADD_DSZ64_DRR(TMP4, TMP4, TMP3),
      SHR_DSZ64_DRI(TMP9, TMP4, 51), NOP_SEQWORD },
    { AND_DSZ64_DRR(TMP4, TMP4, RCX), SHR_DSZ64_DRI(TMP10, TMP5, 51),
      AND_DSZ64_DRR(TMP5, TMP5, RCX), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP11, TMP6, 51), AND_DSZ64_DRR(TMP6, TMP6, RCX),
      SHR_DSZ64_DRI(TMP12, TMP7, 51), NOP_SEQWORD },
    { AND_DSZ64_DRR(TMP7, TMP7, RCX), SHR_DSZ64_DRI(TMP13, TMP8, 51),
      AND_DSZ64_DRR(TMP8, TMP8, RCX), NOP_SEQWORD },
    { ADD_DSZ64_DRR(R13, TMP5, TMP9), ADD_DSZ64_DRR(R9, TMP6, TMP10),
      ADD_DSZ64_DRR(R10, TMP7, TMP11), NOP_SEQWORD },
    { ADD_DSZ64_DRR(RAX, TMP8, TMP12), SHL_DSZ64_DRI(TMP3, TMP13, 4),
      ADD_DSZ64_DRR(TMP14, TMP13, TMP13), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP3, TMP3, TMP14), ADD_DSZ64_DRR(TMP3, TMP3, TMP13),
      ADD_DSZ64_DRR(R15, TMP4, TMP3), END_SEQWORD },
    };

    static const ucode_t sq_patch_5acc[] = {
    { ZEROEXT_DSZ64_DR(TMP4, RDX), MUL_DSZ64_DRR(TMP9, R9, TMP4),
      ZEROEXT_DSZ64_DR(TMP5, RSI), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP10, R15, TMP5), ZEROEXT_DSZ64_DR(TMP6, R12),
      NOP, NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP11, R15, TMP6), ZEROEXT_DSZ64_DR(TMP7, R11),
      NOP, NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP12, R15, TMP7), ZEROEXT_DSZ64_DR(TMP8, R14),
      NOP, NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP13, R15, TMP8), NOP,
      NOP, NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(R15, RDI), MUL_DSZ64_DRR(RAX, R15, RDI),
      ZEROEXT_DSZ64_DR(TMP2, RSI), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP0, R11, RDX), ADD_DSZ64_DRR(TMP4, TMP4, RDI),
      SETCC_CONDB_DR(TMP14, TMP4), NOP_SEQWORD },
    { ADD_DSZ64_DRR(RAX, RAX, TMP14), ADD_DSZ64_DRR(TMP9, TMP9, RAX),
      MUL_DSZ64_DRR(TMP1, TMP2, RSI), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP5, TMP5, RDX), SETCC_CONDB_DR(TMP15, TMP5),
      ADD_DSZ64_DRR(TMP0, TMP0, TMP15), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP10, TMP10, TMP0), ZEROEXT_DSZ64_DR(TMP2, R12),
      MUL_DSZ64_DRR(TMP3, R13, TMP2), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP6, TMP6, RSI), SETCC_CONDB_DR(TMP14, TMP6),
      ADD_DSZ64_DRR(TMP1, TMP1, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP11, TMP11, TMP1), MUL_DSZ64_DRR(RDI, R13, R11),
      ADD_DSZ64_DRR(TMP7, TMP7, TMP2), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP15, TMP7), ADD_DSZ64_DRR(TMP3, TMP3, TMP15),
      ADD_DSZ64_DRR(TMP12, TMP12, TMP3), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(RDX, RBX), MUL_DSZ64_DRR(RSI, R13, RDX),
      ADD_DSZ64_DRR(TMP8, TMP8, R11), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP14, TMP8), ADD_DSZ64_DRR(RDI, RDI, TMP14),
      ADD_DSZ64_DRR(TMP13, TMP13, RDI), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(R11, RBX), MUL_DSZ64_DRR(RAX, R9, R11),
      ADD_DSZ64_DRR(TMP4, TMP4, RDX), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP15, TMP4), ADD_DSZ64_DRR(RSI, RSI, TMP15),
      ADD_DSZ64_DRR(TMP9, TMP9, RSI), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(TMP0, RBX), MUL_DSZ64_DRR(TMP1, R10, TMP0),
      ADD_DSZ64_DRR(TMP5, TMP5, R11), NOP_SEQWORD },
    { SETCC_CONDB_DR(TMP14, TMP5), ADD_DSZ64_DRR(RAX, RAX, TMP14),
      ADD_DSZ64_DRR(TMP10, TMP10, RAX), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP2, R14, RBX), ADD_DSZ64_DRR(TMP6, TMP6, TMP0),
      SETCC_CONDB_DR(TMP15, TMP6), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(R15, R12), NOP,
      NOP, NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP1, TMP1, TMP15), ADD_DSZ64_DRR(TMP11, TMP11, TMP1),
      MUL_DSZ64_DRR(TMP3, R15, R12), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP7, TMP7, RBX), SETCC_CONDB_DR(TMP14, TMP7),
      ADD_DSZ64_DRR(TMP2, TMP2, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP12, TMP12, TMP2), ADD_DSZ64_DRR(TMP8, TMP8, R12),
      SETCC_CONDB_DR(TMP15, TMP8), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP3, TMP3, TMP15), ADD_DSZ64_DRR(TMP13, TMP13, TMP3),
      SHL_DSZ64_DRI(TMP9, TMP9, 13), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP0, TMP4, 51), AND_DSZ64_DRR(TMP4, TMP4, R8),
      OR_DSZ64_DRR(TMP9, TMP0, TMP9), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP10, TMP10, 13), SHR_DSZ64_DRI(TMP1, TMP5, 51),
      AND_DSZ64_DRR(TMP5, TMP5, R8), NOP_SEQWORD },
    { OR_DSZ64_DRR(TMP10, TMP1, TMP10), SHL_DSZ64_DRI(TMP11, TMP11, 13),
      SHR_DSZ64_DRI(TMP2, TMP6, 51), NOP_SEQWORD },
    { AND_DSZ64_DRR(TMP6, TMP6, R8), OR_DSZ64_DRR(TMP11, TMP2, TMP11),
      SHL_DSZ64_DRI(TMP12, TMP12, 13), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP0, TMP7, 51), AND_DSZ64_DRR(TMP7, TMP7, R8),
      OR_DSZ64_DRR(TMP12, TMP0, TMP12), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP13, TMP13, 13), SHR_DSZ64_DRI(TMP1, TMP8, 51),
      AND_DSZ64_DRR(TMP8, TMP8, R8), NOP_SEQWORD },
    { OR_DSZ64_DRR(TMP13, TMP1, TMP13), ADD_DSZ64_DRR(TMP5, TMP5, TMP9),
      ADD_DSZ64_DRR(TMP6, TMP6, TMP10), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP7, TMP7, TMP11), ADD_DSZ64_DRR(TMP8, TMP8, TMP12),
      SHL_DSZ64_DRI(TMP3, TMP13, 4), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP14, TMP13, TMP13), ADD_DSZ64_DRR(TMP3, TMP3, TMP14),
      ADD_DSZ64_DRR(TMP3, TMP3, TMP13), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP4, TMP4, TMP3), SHR_DSZ64_DRI(TMP9, TMP4, 51),
      AND_DSZ64_DRR(TMP4, TMP4, R8), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP10, TMP5, 51), AND_DSZ64_DRR(TMP5, TMP5, R8),
      SHR_DSZ64_DRI(TMP11, TMP6, 51), NOP_SEQWORD },
    { AND_DSZ64_DRR(TMP6, TMP6, R8), SHR_DSZ64_DRI(TMP12, TMP7, 51),
      AND_DSZ64_DRR(TMP7, TMP7, R8), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP13, TMP8, 51), AND_DSZ64_DRR(TMP8, TMP8, R8),
      ADD_DSZ64_DRR(R9, TMP5, TMP9), NOP_SEQWORD },
    { ADD_DSZ64_DRR(R10, TMP6, TMP10), ADD_DSZ64_DRR(RBX, TMP7, TMP11),
      ADD_DSZ64_DRR(RAX, TMP8, TMP12), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP3, TMP13, 4), ADD_DSZ64_DRR(TMP14, TMP13, TMP13),
      ADD_DSZ64_DRR(TMP3, TMP3, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP3, TMP3, TMP13), ADD_DSZ64_DRR(RDI, TMP4, TMP3),
      NOP, END_SEQWORD },
    };

    _Static_assert(ARRAY_SZ(mul_patch) + ARRAY_SZ(sq_patch_5acc) <= 128,
                   "fe_mul + fe_sq exceed the 128-triad patch RAM budget");

    const uint64_t mul_addr = 0x7c00;
    const uint64_t sq_addr  = mul_addr + ARRAY_SZ(mul_patch) * 4;
    patch_ucode(mul_addr, mul_patch, ARRAY_SZ(mul_patch));
    hook_match_and_patch(0, 0x0cd8, mul_addr);
    patch_ucode(sq_addr, (ucode_t *)sq_patch_5acc, ARRAY_SZ(sq_patch_5acc));
    hook_match_and_patch(1, 0x0618, sq_addr);
    printf("fe_mul: %d triads at U%04lx (vmwrite hook)\n",
           (int)ARRAY_SZ(mul_patch), (unsigned long)mul_addr);
    printf("fe_sq : %d triads at U%04lx (vmread  hook)\n",
           (int)ARRAY_SZ(sq_patch_5acc), (unsigned long)sq_addr);
}

/* INLINE-ASM FIELD-OP MACROS */
#define FE_MUL(out, a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  \
    "mov r12, [rbp + " S(a) " + 16]\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t" \
    "mov r15, [rbp + " S(b) " + 0]\n\t"  \
    "mov r13, [rbp + " S(b) " + 8]\n\t"  \
    "mov r9,  [rbp + " S(b) " + 16]\n\t" \
    "mov r10, [rbp + " S(b) " + 24]\n\t" \
    "mov rbx, [rbp + " S(b) " + 32]\n\t" \
    "mov rcx, 0x7FFFFFFFFFFFF\n\t"       \
    "vmwrite rcx, rdx\n\t"               \
    "mov [rbp + " S(out) " + 0],  r15\n\t" \
    "mov [rbp + " S(out) " + 8],  r13\n\t" \
    "mov [rbp + " S(out) " + 16], r9\n\t"  \
    "mov [rbp + " S(out) " + 24], r10\n\t" \
    "mov [rbp + " S(out) " + 32], rax\n\t"

#define FE_SQ(out, a) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  \
    "mov r12, [rbp + " S(a) " + 16]\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t" \
    "lea r15, [rdi + rdi]\n\t"           \
    "lea r13, [rsi + rsi]\n\t"           \
    "lea r9,  [r12 + r12]\n\t"           \
    "lea r10, [r11 + r11]\n\t"           \
    "imul rbx, r14, 19\n\t"              \
    "imul rdx, r11, 19\n\t"              \
    FE_SQ_R8                             \
    ".byte 0x0f, 0x78, 0xca\n\t"         \
    "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov [rbp + " S(out) " + 8],  r9\n\t"  \
    "mov [rbp + " S(out) " + 16], r10\n\t" \
    "mov [rbp + " S(out) " + 24], rbx\n\t" \
    "mov [rbp + " S(out) " + 32], rax\n\t"

#define FE_ADD(out, a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"   "add rdi, [rbp + " S(b) " + 0]\n\t"   "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"   "add rsi, [rbp + " S(b) " + 8]\n\t"   "mov [rbp + " S(out) " + 8],  rsi\n\t" \
    "mov r12, [rbp + " S(a) " + 16]\n\t"  "add r12, [rbp + " S(b) " + 16]\n\t"  "mov [rbp + " S(out) " + 16], r12\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t"  "add r11, [rbp + " S(b) " + 24]\n\t"  "mov [rbp + " S(out) " + 24], r11\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t"  "add r14, [rbp + " S(b) " + 32]\n\t"  "mov [rbp + " S(out) " + 32], r14\n\t"

#define FE_SUB(out, a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  "mov rcx, 0xFFFFFFFFFFFDA\n\t" "add rdi, rcx\n\t" "sub rdi, [rbp + " S(b) " + 0]\n\t"  "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov rcx, 0xFFFFFFFFFFFFE\n\t" \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  "add rsi, rcx\n\t" "sub rsi, [rbp + " S(b) " + 8]\n\t"  "mov [rbp + " S(out) " + 8],  rsi\n\t" \
    "mov r12, [rbp + " S(a) " + 16]\n\t" "add r12, rcx\n\t" "sub r12, [rbp + " S(b) " + 16]\n\t" "mov [rbp + " S(out) " + 16], r12\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" "add r11, rcx\n\t" "sub r11, [rbp + " S(b) " + 24]\n\t" "mov [rbp + " S(out) " + 24], r11\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t" "add r14, rcx\n\t" "sub r14, [rbp + " S(b) " + 32]\n\t" "mov [rbp + " S(out) " + 32], r14\n\t"

#define FE_ADD_NOSTORE(a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"   "add rdi, [rbp + " S(b) " + 0]\n\t"  \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"   "add rsi, [rbp + " S(b) " + 8]\n\t"  \
    "mov r12, [rbp + " S(a) " + 16]\n\t"  "add r12, [rbp + " S(b) " + 16]\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t"  "add r11, [rbp + " S(b) " + 24]\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t"  "add r14, [rbp + " S(b) " + 32]\n\t"

#define FE_SUB_NOSTORE(a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  "mov rcx, 0xFFFFFFFFFFFDA\n\t" "add rdi, rcx\n\t" "sub rdi, [rbp + " S(b) " + 0]\n\t"  \
    "mov rcx, 0xFFFFFFFFFFFFE\n\t" \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  "add rsi, rcx\n\t" "sub rsi, [rbp + " S(b) " + 8]\n\t"  \
    "mov r12, [rbp + " S(a) " + 16]\n\t" "add r12, rcx\n\t" "sub r12, [rbp + " S(b) " + 16]\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" "add r11, rcx\n\t" "sub r11, [rbp + " S(b) " + 24]\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t" "add r14, rcx\n\t" "sub r14, [rbp + " S(b) " + 32]\n\t"

#define FE_SQ_FROM_REGS(out) \
    "lea r15, [rdi + rdi]\n\t"           \
    "lea r13, [rsi + rsi]\n\t"           \
    "lea r9,  [r12 + r12]\n\t"           \
    "lea r10, [r11 + r11]\n\t"           \
    "imul rbx, r14, 19\n\t"              \
    "imul rdx, r11, 19\n\t"              \
    FE_SQ_R8                             \
    ".byte 0x0f, 0x78, 0xca\n\t"         \
    "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov [rbp + " S(out) " + 8],  r9\n\t"  \
    "mov [rbp + " S(out) " + 16], r10\n\t" \
    "mov [rbp + " S(out) " + 24], rbx\n\t" \
    "mov [rbp + " S(out) " + 32], rax\n\t"

#define FE_MUL_FROM_REGS_A(out, b) \
    "mov r15, [rbp + " S(b) " + 0]\n\t"  \
    "mov r13, [rbp + " S(b) " + 8]\n\t"  \
    "mov r9,  [rbp + " S(b) " + 16]\n\t" \
    "mov r10, [rbp + " S(b) " + 24]\n\t" \
    "mov rbx, [rbp + " S(b) " + 32]\n\t" \
    "mov rcx, 0x7FFFFFFFFFFFF\n\t"       \
    "vmwrite rcx, rdx\n\t"               \
    "mov [rbp + " S(out) " + 0],  r15\n\t" \
    "mov [rbp + " S(out) " + 8],  r13\n\t" \
    "mov [rbp + " S(out) " + 16], r9\n\t"  \
    "mov [rbp + " S(out) " + 24], r10\n\t" \
    "mov [rbp + " S(out) " + 32], rax\n\t"

#define INV_SQ_LOAD(a) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  \
    "mov r12, [rbp + " S(a) " + 16]\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t"

#define INV_SQ_OP \
    "lea r15, [rdi + rdi]\n\t"           \
    "lea r13, [rsi + rsi]\n\t"           \
    "lea r9,  [r12 + r12]\n\t"           \
    "lea r10, [r11 + r11]\n\t"           \
    "imul rbx, r14, 19\n\t"              \
    "imul rdx, r11, 19\n\t"              \
    FE_SQ_R8                             \
    ".byte 0x0f, 0x78, 0xca\n\t"

#define INV_SQ_STORE(out) \
    "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov [rbp + " S(out) " + 8],  r9\n\t"  \
    "mov [rbp + " S(out) " + 16], r10\n\t" \
    "mov [rbp + " S(out) " + 24], rbx\n\t" \
    "mov [rbp + " S(out) " + 32], rax\n\t"

#define INV_SQ(out, a) INV_SQ_LOAD(a) INV_SQ_OP INV_SQ_STORE(out)

#define INV_MUL(out, a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  \
    "mov r12, [rbp + " S(a) " + 16]\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t" \
    "mov r15, [rbp + " S(b) " + 0]\n\t"  \
    "mov r13, [rbp + " S(b) " + 8]\n\t"  \
    "mov r9,  [rbp + " S(b) " + 16]\n\t" \
    "mov r10, [rbp + " S(b) " + 24]\n\t" \
    "mov rbx, [rbp + " S(b) " + 32]\n\t" \
    "mov rcx, 0x7FFFFFFFFFFFF\n\t"       \
    "vmwrite rcx, rdx\n\t"               \
    "mov [rbp + " S(out) " + 0],  r15\n\t" \
    "mov [rbp + " S(out) " + 8],  r13\n\t" \
    "mov [rbp + " S(out) " + 16], r9\n\t"  \
    "mov [rbp + " S(out) " + 24], r10\n\t" \
    "mov [rbp + " S(out) " + 32], rax\n\t"

/* LADDER STEP — one big asm block per iteration */

static void fe_mul121665_native(uint64_t *out, const uint64_t *a) {
    uint64_t r0, r1, r2, r3, r4, q0, q1, q2, q3, q4;
#define MUL121665_LIMB(i, R, Q) do {                                          \
        uint64_t _hi = a[i] >> 26, _lo = a[i] & ((1ULL << 26) - 1);            \
        uint64_t _P  = _hi * 121665, _Q = _lo * 121665;                        \
        uint64_t _P1 = _P >> 25,     _P0 = _P & ((1ULL << 25) - 1);            \
        uint64_t _low = (_P0 << 26) + _Q;                                      \
        (Q) = _P1 + (_low >> 51);                                              \
        (R) = _low & MASK51;                                                   \
    } while (0)
    MUL121665_LIMB(0, r0, q0);
    MUL121665_LIMB(1, r1, q1);
    MUL121665_LIMB(2, r2, q2);
    MUL121665_LIMB(3, r3, q3);
    MUL121665_LIMB(4, r4, q4);
#undef MUL121665_LIMB

    uint64_t t0    = r0 + 19 * q4;
    uint64_t carry = t0 >> 51;
    out[0] = t0 & MASK51;
    out[1] = r1 + q0 + carry;
    out[2] = r2 + q1;
    out[3] = r3 + q2;
    out[4] = r4 + q3;
}

static void ladder_step(ladder_state_t *st) {

    register ladder_state_t *_st asm("rbp") = st;
    asm volatile(

        FE_ADD(A_OFF, X2_OFF, Z2_OFF)
        FE_SQ_FROM_REGS(AA_OFF)

        FE_SUB(B_OFF, X2_OFF, Z2_OFF)
        FE_SQ_FROM_REGS(BB_OFF)

        FE_SUB(E_OFF, AA_OFF, BB_OFF)

        FE_SUB_NOSTORE(X3_OFF, Z3_OFF)
        FE_MUL_FROM_REGS_A(DA_OFF, A_OFF)
        FE_ADD_NOSTORE(X3_OFF, Z3_OFF)
        FE_MUL_FROM_REGS_A(CB_OFF, B_OFF)

        FE_ADD_NOSTORE(DA_OFF, CB_OFF)
        FE_SQ_FROM_REGS(X3_OFF)

        FE_SUB_NOSTORE(DA_OFF, CB_OFF)
        FE_SQ_FROM_REGS(Z3_OFF)

        FE_MUL(Z3_OFF, X1_OFF, Z3_OFF)

        FE_MUL(X2_OFF, AA_OFF, BB_OFF)
        :
        : "r"(_st)
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "memory", "cc"
    );

    fe_mul121665_native(st->t0, st->E);
    register ladder_state_t *_st2 asm("rbp") = st;
    asm volatile(
        FE_ADD_NOSTORE(AA_OFF, T0_OFF)
        FE_MUL_FROM_REGS_A(Z2_OFF, E_OFF)
        :
        : "r"(_st2)
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "memory", "cc"
    );
}

/* cswap, frombytes, tobytes, invert, ladder driver */

static inline void fe_cswap(uint64_t a[5], uint64_t b[5], uint64_t swap) {
    swap = (uint64_t)(-(int64_t)swap);
    for (int i = 0; i < 5; i++) {
        uint64_t x = (a[i] ^ b[i]) & swap;
        a[i] ^= x;
        b[i] ^= x;
    }
}

static void fe_frombytes(uint64_t out[5], const uint8_t in[32]) {
    uint64_t t[5];
    t[0]  = ((uint64_t)in[0])  | ((uint64_t)in[1] << 8) | ((uint64_t)in[2] << 16)
          | ((uint64_t)in[3] << 24) | ((uint64_t)in[4] << 32) | ((uint64_t)in[5] << 40)
          | ((uint64_t)(in[6] & 0x07) << 48);
    t[1]  = ((uint64_t)in[6] >> 3) | ((uint64_t)in[7] << 5) | ((uint64_t)in[8] << 13)
          | ((uint64_t)in[9] << 21) | ((uint64_t)in[10] << 29) | ((uint64_t)in[11] << 37)
          | ((uint64_t)(in[12] & 0x3f) << 45);
    t[2]  = ((uint64_t)in[12] >> 6) | ((uint64_t)in[13] << 2) | ((uint64_t)in[14] << 10)
          | ((uint64_t)in[15] << 18) | ((uint64_t)in[16] << 26) | ((uint64_t)in[17] << 34)
          | ((uint64_t)in[18] << 42) | ((uint64_t)(in[19] & 0x01) << 50);
    t[3]  = ((uint64_t)in[19] >> 1) | ((uint64_t)in[20] << 7) | ((uint64_t)in[21] << 15)
          | ((uint64_t)in[22] << 23) | ((uint64_t)in[23] << 31) | ((uint64_t)in[24] << 39)
          | ((uint64_t)(in[25] & 0x0f) << 47);
    t[4]  = ((uint64_t)in[25] >> 4) | ((uint64_t)in[26] << 4) | ((uint64_t)in[27] << 12)
          | ((uint64_t)in[28] << 20) | ((uint64_t)in[29] << 28) | ((uint64_t)in[30] << 36)
          | ((uint64_t)(in[31] & 0x7f) << 44);
    memcpy(out, t, 40);
}

static void fe_reduce(uint64_t out[5], const uint64_t in[5]) {
    uint64_t h[5];
    memcpy(h, in, 40);
    uint64_t c = h[0] >> 51; h[0] &= MASK51; h[1] += c;
    c = h[1] >> 51; h[1] &= MASK51; h[2] += c;
    c = h[2] >> 51; h[2] &= MASK51; h[3] += c;
    c = h[3] >> 51; h[3] &= MASK51; h[4] += c;
    c = h[4] >> 51; h[4] &= MASK51; h[0] += 19 * c;
    c = h[0] >> 51; h[0] &= MASK51; h[1] += c;

    uint64_t q = (h[0] + 19) >> 51;
    q = (h[1] + q) >> 51;
    q = (h[2] + q) >> 51;
    q = (h[3] + q) >> 51;
    q = (h[4] + q) >> 51;
    h[0] += 19 * q;
    h[1] += h[0] >> 51; h[0] &= MASK51;
    h[2] += h[1] >> 51; h[1] &= MASK51;
    h[3] += h[2] >> 51; h[2] &= MASK51;
    h[4] += h[3] >> 51; h[3] &= MASK51;
    h[4] &= MASK51;
    memcpy(out, h, 40);
}

static void fe_tobytes(uint8_t out[32], const uint64_t in[5]) {
    uint64_t h[5];
    fe_reduce(h, in);
    out[0]  = (uint8_t)h[0];
    out[1]  = (uint8_t)(h[0] >> 8);
    out[2]  = (uint8_t)(h[0] >> 16);
    out[3]  = (uint8_t)(h[0] >> 24);
    out[4]  = (uint8_t)(h[0] >> 32);
    out[5]  = (uint8_t)(h[0] >> 40);
    out[6]  = (uint8_t)((h[0] >> 48) | (h[1] << 3));
    out[7]  = (uint8_t)(h[1] >> 5);
    out[8]  = (uint8_t)(h[1] >> 13);
    out[9]  = (uint8_t)(h[1] >> 21);
    out[10] = (uint8_t)(h[1] >> 29);
    out[11] = (uint8_t)(h[1] >> 37);
    out[12] = (uint8_t)((h[1] >> 45) | (h[2] << 6));
    out[13] = (uint8_t)(h[2] >> 2);
    out[14] = (uint8_t)(h[2] >> 10);
    out[15] = (uint8_t)(h[2] >> 18);
    out[16] = (uint8_t)(h[2] >> 26);
    out[17] = (uint8_t)(h[2] >> 34);
    out[18] = (uint8_t)(h[2] >> 42);
    out[19] = (uint8_t)((h[2] >> 50) | (h[3] << 1));
    out[20] = (uint8_t)(h[3] >> 7);
    out[21] = (uint8_t)(h[3] >> 15);
    out[22] = (uint8_t)(h[3] >> 23);
    out[23] = (uint8_t)(h[3] >> 31);
    out[24] = (uint8_t)(h[3] >> 39);
    out[25] = (uint8_t)((h[3] >> 47) | (h[4] << 4));
    out[26] = (uint8_t)(h[4] >> 4);
    out[27] = (uint8_t)(h[4] >> 12);
    out[28] = (uint8_t)(h[4] >> 20);
    out[29] = (uint8_t)(h[4] >> 28);
    out[30] = (uint8_t)(h[4] >> 36);
    out[31] = (uint8_t)(h[4] >> 44);
}

#define INV_CLOB "rax","rbx","rcx","rdx","rsi","rdi", \
                 "r8","r9","r10","r11","r12","r13","r14","r15","memory","cc"
#define INV_BLK(code) do {                                        \
        register invert_state_t *_b asm("rbp") = &st;             \
        asm volatile(code : : "r"(_b) : INV_CLOB);                \
    } while (0)

#define INV_C_ODD(dst, a, pairs) do {                             \
        INV_BLK(INV_SQ(dst, a));                                  \
        for (int _i = 0; _i < (pairs); _i++) {                    \
            INV_BLK(INV_SQ(ISC_OFF, dst));                        \
            INV_BLK(INV_SQ(dst, ISC_OFF)); } } while (0)

#define INV_C_EVEN(dst, a, pairs) do {                            \
        INV_BLK(INV_SQ(ISC_OFF, a));                              \
        INV_BLK(INV_SQ(dst, ISC_OFF));                            \
        for (int _i = 0; _i < (pairs); _i++) {                    \
            INV_BLK(INV_SQ(ISC_OFF, dst));                        \
            INV_BLK(INV_SQ(dst, ISC_OFF)); } } while (0)

static void fe_invert(uint64_t out[5], const uint64_t z[5]) {
    invert_state_t st;
    st.z[0] = z[0]; st.z[1] = z[1]; st.z[2] = z[2]; st.z[3] = z[3]; st.z[4] = z[4];

    INV_BLK(INV_SQ(IZ2_OFF, IZ_OFF));
    INV_C_EVEN(IT_OFF, IZ2_OFF, 0);
    INV_BLK(INV_MUL(IZ9_OFF,  IT_OFF,  IZ_OFF));
    INV_BLK(INV_MUL(IZ11_OFF, IZ9_OFF, IZ2_OFF));
    INV_BLK(INV_SQ(IT_OFF, IZ11_OFF));
    INV_BLK(INV_MUL(IT0_OFF, IT_OFF, IZ9_OFF));
    INV_C_ODD (IT1_OFF, IT0_OFF, 2);
    INV_BLK(INV_MUL(IT1_OFF, IT1_OFF, IT0_OFF));
    INV_C_EVEN(IT2_OFF, IT1_OFF, 4);
    INV_BLK(INV_MUL(IT2_OFF, IT2_OFF, IT1_OFF));
    INV_C_EVEN(IT3_OFF, IT2_OFF, 9);
    INV_BLK(INV_MUL(IT3_OFF, IT3_OFF, IT2_OFF));
    INV_C_EVEN(IT3_OFF, IT3_OFF, 4);
    INV_BLK(INV_MUL(IT1_OFF, IT3_OFF, IT1_OFF));
    INV_C_EVEN(IT2_OFF, IT1_OFF, 24);
    INV_BLK(INV_MUL(IT2_OFF, IT2_OFF, IT1_OFF));
    INV_C_EVEN(IT3_OFF, IT2_OFF, 49);
    INV_BLK(INV_MUL(IT3_OFF, IT3_OFF, IT2_OFF));
    INV_C_EVEN(IT3_OFF, IT3_OFF, 24);
    INV_BLK(INV_MUL(IT1_OFF, IT3_OFF, IT1_OFF));
    INV_C_ODD (IT1_OFF, IT1_OFF, 2);
    INV_BLK(INV_MUL(IT1_OFF, IT1_OFF, IZ11_OFF));

    out[0] = st.t1[0]; out[1] = st.t1[1]; out[2] = st.t1[2];
    out[3] = st.t1[3]; out[4] = st.t1[4];
}

static void scalar_clamp(uint8_t s[32]) {
    s[0] &= 248; s[31] &= 127; s[31] |= 64;
}

static void x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    scalar_clamp(e);

    ladder_state_t st;
    fe_frombytes(st.x1, point);
    memcpy(st.x2, (const uint64_t[]){1, 0, 0, 0, 0}, 40);
    memset(st.z2, 0, 40);
    memcpy(st.x3, st.x1, 40);
    memcpy(st.z3, (const uint64_t[]){1, 0, 0, 0, 0}, 40);

    uint64_t swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(st.x2, st.x3, swap);
        fe_cswap(st.z2, st.z3, swap);
        swap = bit;
        ladder_step(&st);
    }
    fe_cswap(st.x2, st.x3, swap);
    fe_cswap(st.z2, st.z3, swap);

    fe_invert(st.z2, st.z2);

    {
        register ladder_state_t *_st asm("rbp") = &st;
        asm volatile(
            FE_MUL(X2_OFF, X2_OFF, Z2_OFF)
            :
            : "r"(_st)
            : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
              "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
              "memory", "cc"
        );
    }
    fe_tobytes(out, st.x2);
}

/* Shared utilities (hex, timing). */

static void hex_to_bytes(const char *hex, uint8_t *out, int len) {
    for (int i = 0; i < len; i++) {
        unsigned int val;
        sscanf(hex + 2*i, "%02x", &val);
        out[i] = (uint8_t)val;
    }
}

static void print_hex(const char *label, const uint8_t *data, int len) {
    printf("  %s: ", label);
    for (int i = 0; i < len; i++) printf("%02x", data[i]);
    printf("\n");
}

static int memcmp_hex(const uint8_t *data, const char *hex, int len) {
    uint8_t expected[32];
    hex_to_bytes(hex, expected, len);
    return memcmp(data, expected, len);
}

static inline uint64_t rdtsc_start(void) {
    uint32_t lo, hi;
    asm volatile("cpuid\n\trdtsc" : "=a"(lo), "=d"(hi) :: "rbx", "rcx", "memory");
    return ((uint64_t)hi << 32) | lo;
}
static inline uint64_t rdtsc_end(void) {
    uint32_t lo, hi;
    asm volatile("rdtscp" : "=a"(lo), "=d"(hi) :: "rcx", "memory");
    asm volatile("cpuid" ::: "rax", "rbx", "rcx", "rdx", "memory");
    return ((uint64_t)hi << 32) | lo;
}

#define BENCH_REPS 1000

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* CONTENDER BACKENDS */
/* NATIVE C FIELD OPERATIONS (compiled with -O3) */

static void fe_mul_native(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    uint64_t a0=a[0], a1=a[1], a2=a[2], a3=a[3], a4=a[4];
    uint64_t b0=b[0], b1=b[1], b2=b[2], b3=b[3], b4=b[4];
    uint64_t r1=19*b1, r2=19*b2, r3=19*b3, r4=19*b4;

    __uint128_t c0 = (__uint128_t)a0*b0 + (__uint128_t)a1*r4
                   + (__uint128_t)a2*r3 + (__uint128_t)a3*r2 + (__uint128_t)a4*r1;
    __uint128_t c1 = (__uint128_t)a0*b1 + (__uint128_t)a1*b0
                   + (__uint128_t)a2*r4 + (__uint128_t)a3*r3 + (__uint128_t)a4*r2;
    __uint128_t c2 = (__uint128_t)a0*b2 + (__uint128_t)a1*b1
                   + (__uint128_t)a2*b0 + (__uint128_t)a3*r4 + (__uint128_t)a4*r3;
    __uint128_t c3 = (__uint128_t)a0*b3 + (__uint128_t)a1*b2
                   + (__uint128_t)a2*b1 + (__uint128_t)a3*b0 + (__uint128_t)a4*r4;
    __uint128_t c4 = (__uint128_t)a0*b4 + (__uint128_t)a1*b3
                   + (__uint128_t)a2*b2 + (__uint128_t)a3*b1 + (__uint128_t)a4*b0;

    uint64_t carry;
    carry = (uint64_t)(c0>>51); out[0] = (uint64_t)c0 & MASK51;
    c1 += carry;
    carry = (uint64_t)(c1>>51); out[1] = (uint64_t)c1 & MASK51;
    c2 += carry;
    carry = (uint64_t)(c2>>51); out[2] = (uint64_t)c2 & MASK51;
    c3 += carry;
    carry = (uint64_t)(c3>>51); out[3] = (uint64_t)c3 & MASK51;
    c4 += carry;
    carry = (uint64_t)(c4>>51); out[4] = (uint64_t)c4 & MASK51;
    out[0] += carry * 19;
    carry = out[0] >> 51; out[0] &= MASK51;
    out[1] += carry;
}

static void fe_sq_native(const uint64_t *a, uint64_t *out) {
    uint64_t a0=a[0], a1=a[1], a2=a[2], a3=a[3], a4=a[4];
    uint64_t d0=2*a0, d1=2*a1, d2=2*a2, d3=2*a3;
    uint64_t r3=19*a3, r4=19*a4;

    __uint128_t c0 = (__uint128_t)a0*a0 + (__uint128_t)d1*r4 + (__uint128_t)d2*r3;
    __uint128_t c1 = (__uint128_t)d0*a1 + (__uint128_t)r3*a3 + (__uint128_t)d2*r4;
    __uint128_t c2 = (__uint128_t)d0*a2 + (__uint128_t)a1*a1 + (__uint128_t)d3*r4;
    __uint128_t c3 = (__uint128_t)d0*a3 + (__uint128_t)d1*a2 + (__uint128_t)r4*a4;
    __uint128_t c4 = (__uint128_t)d0*a4 + (__uint128_t)d1*a3 + (__uint128_t)a2*a2;

    uint64_t carry;
    carry = (uint64_t)(c0>>51); out[0] = (uint64_t)c0 & MASK51;
    c1 += carry;
    carry = (uint64_t)(c1>>51); out[1] = (uint64_t)c1 & MASK51;
    c2 += carry;
    carry = (uint64_t)(c2>>51); out[2] = (uint64_t)c2 & MASK51;
    c3 += carry;
    carry = (uint64_t)(c3>>51); out[3] = (uint64_t)c3 & MASK51;
    c4 += carry;
    carry = (uint64_t)(c4>>51); out[4] = (uint64_t)c4 & MASK51;
    out[0] += carry * 19;
    carry = out[0] >> 51; out[0] &= MASK51;
    out[1] += carry;
}

/* MICROCODE C-WRAPPER FIELD OPS (the non-inline "ours/setcc_ucode" backend) */

void fe_mul_ucode(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    register const uint64_t *_a   asm("rdi") = a;
    register const uint64_t *_b   asm("rsi") = b;
    register       uint64_t *_out asm("rdx") = out;

    asm volatile(

        "mov rbp, rdx\n\t"

        "mov r15, [rsi]\n\t"
        "mov r13, [rsi + 8]\n\t"
        "mov r9,  [rsi + 16]\n\t"
        "mov r10, [rsi + 24]\n\t"
        "mov rbx, [rsi + 32]\n\t"

        "mov rsi, [rdi + 8]\n\t"
        "mov r12, [rdi + 16]\n\t"
        "mov r11, [rdi + 24]\n\t"
        "mov r14, [rdi + 32]\n\t"
        "mov rdi, [rdi]\n\t"

        "mov rcx, 0x7FFFFFFFFFFFF\n\t"

        "vmwrite rcx, rdx\n\t"

        "mov [rbp],      r15\n\t"
        "mov [rbp + 8],  r13\n\t"
        "mov [rbp + 16], r9\n\t"
        "mov [rbp + 24], r10\n\t"
        "mov [rbp + 32], rax\n\t"

        : "+r"(_a), "+r"(_b), "+r"(_out)
        :
        : "rax", "rbx", "rcx", "rbp",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "memory", "cc"
    );
}

void fe_sq_ucode(const uint64_t *a, uint64_t *out) {
    register const uint64_t *_a   asm("rdi") = a;
    register       uint64_t *_out asm("rsi") = out;

    asm volatile(

        "mov rbp, rsi\n\t"
        "mov rcx, [rdi]\n\t"
        "mov rsi, [rdi + 8]\n\t"
        "mov r12, [rdi + 16]\n\t"
        "mov r11, [rdi + 24]\n\t"
        "mov r14, [rdi + 32]\n\t"
        "mov rdi, rcx\n\t"

        "lea r15, [rdi + rdi]\n\t"
        "lea r13, [rsi + rsi]\n\t"
        "lea r9,  [r12 + r12]\n\t"
        "lea r10, [r11 + r11]\n\t"
        "imul rbx, r14, 19\n\t"
        "imul rdx, r11, 19\n\t"

        FE_SQ_R8

        ".byte 0x0f, 0x78, 0xca\n\t"

        "mov [rbp],      rdi\n\t"
        "mov [rbp + 8],  r9\n\t"
        "mov [rbp + 16], r10\n\t"
        "mov [rbp + 24], rbx\n\t"
        "mov [rbp + 32], rax\n\t"

        : "+r"(_a), "+r"(_out)
        :
        : "rax", "rbx", "rcx", "rdx", "rbp",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "memory", "cc"
    );
}

static void fe_sq_ucode_n(uint64_t *out, const uint64_t *a, int n) {
    uint64_t t[2][5];
    fe_sq_ucode(a, t[0]);
    for (int i = 1; i < n; i++) fe_sq_ucode(t[(i - 1) & 1], t[i & 1]);
    memcpy(out, t[(n - 1) & 1], 40);
}

/* FIAT-CRYPTO FIELD OPERATIONS */

#include "third_party/curvesC/curve25519_mul.c"
#include "third_party/curvesC/curve25519_square.c"

static inline void fe_mul_fiat(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    fiat_curve25519_carry_mul(out, a, b);
}

static inline void fe_sq_fiat(const uint64_t *a, uint64_t *out) {
    fiat_curve25519_carry_square(out, a);
}

extern void cryptopt_carry_mul(uint64_t out[5], const uint64_t a[5], const uint64_t b[5]);
extern void cryptopt_carry_square(uint64_t out[5], const uint64_t a[5]);

static inline void fe_mul_cryptopt(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    cryptopt_carry_mul(out, a, b);
}

static inline void fe_sq_cryptopt(const uint64_t *a, uint64_t *out) {
    cryptopt_carry_square(out, a);
}

/* SUPERCOP donna_c64 ( from supercop-20260330) */

#define crypto_scalarmult x25519_donna_c64
#include "third_party/supercop-20260330/crypto_scalarmult/curve25519/donna_c64/smult.c"
#undef crypto_scalarmult

extern int x25519_donna_c64(unsigned char *mypublic,
                            const unsigned char *secret,
                            const unsigned char *basepoint);

/* SUPERCOP amd64-51 (hand-tuned x86-64 assembly, Bernstein/Schwabe 2011) */

extern int x25519_amd64_51(unsigned char *out,
                           const unsigned char *scalar,
                           const unsigned char *point);

/* SUPERCOP amd64-64 (4x64-bit saturated, Bernstein/Schwabe) */

extern int x25519_amd64_64(unsigned char *out,
                           const unsigned char *scalar,
                           const unsigned char *point);

/* COMMON FIELD OPERATIONS (pure C, used by all backends) */

static inline void fe_add(fe out, const fe a, const fe b) {
    out[0] = a[0] + b[0];
    out[1] = a[1] + b[1];
    out[2] = a[2] + b[2];
    out[3] = a[3] + b[3];
    out[4] = a[4] + b[4];
}

static inline void fe_sub(fe out, const fe a, const fe b) {
    out[0] = (a[0] + 0xFFFFFFFFFFFDAULL) - b[0];
    out[1] = (a[1] + 0xFFFFFFFFFFFFEULL) - b[1];
    out[2] = (a[2] + 0xFFFFFFFFFFFFEULL) - b[2];
    out[3] = (a[3] + 0xFFFFFFFFFFFFEULL) - b[3];
    out[4] = (a[4] + 0xFFFFFFFFFFFFEULL) - b[4];
}

static void fe_mul121665(fe out, const fe a) {
    uint64_t r0, r1, r2, r3, r4, q0, q1, q2, q3, q4;
#define MUL121665_LIMB(i, R, Q) do {                                          \
        uint64_t _hi = a[i] >> 26, _lo = a[i] & ((1ULL << 26) - 1);            \
        uint64_t _P  = _hi * 121665, _Q = _lo * 121665;                        \
        uint64_t _P1 = _P >> 25,     _P0 = _P & ((1ULL << 25) - 1);            \
        uint64_t _low = (_P0 << 26) + _Q;                                      \
        (Q) = _P1 + (_low >> 51);                                              \
        (R) = _low & MASK51;                                                   \
    } while (0)
    MUL121665_LIMB(0, r0, q0);
    MUL121665_LIMB(1, r1, q1);
    MUL121665_LIMB(2, r2, q2);
    MUL121665_LIMB(3, r3, q3);
    MUL121665_LIMB(4, r4, q4);
#undef MUL121665_LIMB

    uint64_t t0    = r0 + 19 * q4;
    uint64_t carry = t0 >> 51;
    out[0] = t0 & MASK51;
    out[1] = r1 + q0 + carry;
    out[2] = r2 + q1;
    out[3] = r3 + q2;
    out[4] = r4 + q3;
}

static inline void fe_copy(fe out, const fe a) {
    memcpy(out, a, 5 * sizeof(uint64_t));
}

static void fe_invert_native(fe out, const fe z) {
    fe z2, z9, z11, t, t0, t1, t2, t3;
    int i;

    fe_sq_native(z, z2);
    fe_sq_native(z2, t);
    fe_sq_native(t, t);
    fe_mul_native(t, z, z9);
    fe_mul_native(z9, z2, z11);
    fe_sq_native(z11, t);
    fe_mul_native(t, z9, t0);

    fe_sq_native(t0, t1);
    for (i = 1; i < 5; i++) fe_sq_native(t1, t1);
    fe_mul_native(t1, t0, t1);

    fe_sq_native(t1, t2);
    for (i = 1; i < 10; i++) fe_sq_native(t2, t2);
    fe_mul_native(t2, t1, t2);

    fe_sq_native(t2, t3);
    for (i = 1; i < 20; i++) fe_sq_native(t3, t3);
    fe_mul_native(t3, t2, t3);

    for (i = 0; i < 10; i++) fe_sq_native(t3, t3);
    fe_mul_native(t3, t1, t1);

    fe_sq_native(t1, t2);
    for (i = 1; i < 50; i++) fe_sq_native(t2, t2);
    fe_mul_native(t2, t1, t2);

    fe_sq_native(t2, t3);
    for (i = 1; i < 100; i++) fe_sq_native(t3, t3);
    fe_mul_native(t3, t2, t3);

    for (i = 0; i < 50; i++) fe_sq_native(t3, t3);
    fe_mul_native(t3, t1, t1);

    fe_sq_native(t1, t1);
    fe_sq_native(t1, t1);
    fe_sq_native(t1, t1);
    fe_sq_native(t1, t1);
    fe_sq_native(t1, t1);
    fe_mul_native(t1, z11, out);
}

static void fe_invert_ucode(fe out, const fe z) {
    fe z2, z9, z11, t, t0, t1, t2, t3;

    fe_sq_ucode(z, z2);
    fe_sq_ucode(z2, t);
    fe_sq_ucode(t, t);
    fe_mul_ucode(z, t, z9);
    fe_mul_ucode(z9, z2, z11);
    fe_sq_ucode(z11, t);
    fe_mul_ucode(z9, t, t0);

    fe_sq_ucode_n(t1, t0,   5);
    fe_mul_ucode(t0, t1, t1);

    fe_sq_ucode_n(t2, t1,  10);
    fe_mul_ucode(t1, t2, t2);

    fe_sq_ucode_n(t3, t2,  20);
    fe_mul_ucode(t2, t3, t3);

    fe_sq_ucode_n(t3, t3,  10);
    fe_mul_ucode(t1, t3, t1);

    fe_sq_ucode_n(t2, t1,  50);
    fe_mul_ucode(t1, t2, t2);

    fe_sq_ucode_n(t3, t2, 100);
    fe_mul_ucode(t2, t3, t3);

    fe_sq_ucode_n(t3, t3,  50);
    fe_mul_ucode(t1, t3, t1);

    fe_sq_ucode_n(t1, t1,   5);
    fe_mul_ucode(z11, t1, out);
}

static void fe_invert_fiat(fe out, const fe z) {
    fe z2, z9, z11, t, t0, t1, t2, t3;
    int i;

    fe_sq_fiat(z, z2);
    fe_sq_fiat(z2, t);
    fe_sq_fiat(t, t);
    fe_mul_fiat(t, z, z9);
    fe_mul_fiat(z9, z2, z11);
    fe_sq_fiat(z11, t);
    fe_mul_fiat(t, z9, t0);

    fe_sq_fiat(t0, t1);
    for (i = 1; i < 5; i++) fe_sq_fiat(t1, t1);
    fe_mul_fiat(t1, t0, t1);

    fe_sq_fiat(t1, t2);
    for (i = 1; i < 10; i++) fe_sq_fiat(t2, t2);
    fe_mul_fiat(t2, t1, t2);

    fe_sq_fiat(t2, t3);
    for (i = 1; i < 20; i++) fe_sq_fiat(t3, t3);
    fe_mul_fiat(t3, t2, t3);

    for (i = 0; i < 10; i++) fe_sq_fiat(t3, t3);
    fe_mul_fiat(t3, t1, t1);

    fe_sq_fiat(t1, t2);
    for (i = 1; i < 50; i++) fe_sq_fiat(t2, t2);
    fe_mul_fiat(t2, t1, t2);

    fe_sq_fiat(t2, t3);
    for (i = 1; i < 100; i++) fe_sq_fiat(t3, t3);
    fe_mul_fiat(t3, t2, t3);

    for (i = 0; i < 50; i++) fe_sq_fiat(t3, t3);
    fe_mul_fiat(t3, t1, t1);

    fe_sq_fiat(t1, t1);
    fe_sq_fiat(t1, t1);
    fe_sq_fiat(t1, t1);
    fe_sq_fiat(t1, t1);
    fe_sq_fiat(t1, t1);
    fe_mul_fiat(t1, z11, out);
}

static void fe_invert_cryptopt(fe out, const fe z) {
    fe z2, z9, z11, t, t0, t1, t2, t3;
    int i;

    fe_sq_cryptopt(z, z2);
    fe_sq_cryptopt(z2, t);
    fe_sq_cryptopt(t, t);
    fe_mul_cryptopt(t, z, z9);
    fe_mul_cryptopt(z9, z2, z11);
    fe_sq_cryptopt(z11, t);
    fe_mul_cryptopt(t, z9, t0);

    fe_sq_cryptopt(t0, t1);
    for (i = 1; i < 5; i++) fe_sq_cryptopt(t1, t1);
    fe_mul_cryptopt(t1, t0, t1);

    fe_sq_cryptopt(t1, t2);
    for (i = 1; i < 10; i++) fe_sq_cryptopt(t2, t2);
    fe_mul_cryptopt(t2, t1, t2);

    fe_sq_cryptopt(t2, t3);
    for (i = 1; i < 20; i++) fe_sq_cryptopt(t3, t3);
    fe_mul_cryptopt(t3, t2, t3);

    for (i = 0; i < 10; i++) fe_sq_cryptopt(t3, t3);
    fe_mul_cryptopt(t3, t1, t1);

    fe_sq_cryptopt(t1, t2);
    for (i = 1; i < 50; i++) fe_sq_cryptopt(t2, t2);
    fe_mul_cryptopt(t2, t1, t2);

    fe_sq_cryptopt(t2, t3);
    for (i = 1; i < 100; i++) fe_sq_cryptopt(t3, t3);
    fe_mul_cryptopt(t3, t2, t3);

    for (i = 0; i < 50; i++) fe_sq_cryptopt(t3, t3);
    fe_mul_cryptopt(t3, t1, t1);

    fe_sq_cryptopt(t1, t1);
    fe_sq_cryptopt(t1, t1);
    fe_sq_cryptopt(t1, t1);
    fe_sq_cryptopt(t1, t1);
    fe_sq_cryptopt(t1, t1);
    fe_mul_cryptopt(t1, z11, out);
}

static void x25519_native(uint8_t out[32], const uint8_t scalar[32],
                           const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    scalar_clamp(e);

    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB, t0;

    fe_frombytes(x1, point);
    fe_copy(x2, (const uint64_t[]){1,0,0,0,0});
    memset(z2, 0, sizeof(fe));
    fe_copy(x3, x1);
    fe_copy(z3, (const uint64_t[]){1,0,0,0,0});

    uint64_t swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(A, x2, z2);
        fe_sq_native(A, AA);
        fe_sub(B, x2, z2);
        fe_sq_native(B, BB);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul_native(D, A, DA);
        fe_mul_native(C, B, CB);

        fe_add(t0, DA, CB);
        fe_sq_native(t0, x3);

        fe_sub(t0, DA, CB);
        fe_sq_native(t0, z3);
        fe_mul_native(x1, z3, z3);

        fe_mul_native(AA, BB, x2);

        fe_mul121665(t0, E);
        fe_add(t0, AA, t0);
        fe_mul_native(E, t0, z2);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert_native(z2, z2);
    fe_mul_native(x2, z2, x2);
    fe_tobytes(out, x2);
}

static void x25519_ucode(uint8_t out[32], const uint8_t scalar[32],
                          const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    scalar_clamp(e);

    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB, t0;

    fe_frombytes(x1, point);
    fe_copy(x2, (const uint64_t[]){1,0,0,0,0});
    memset(z2, 0, sizeof(fe));
    fe_copy(x3, x1);
    fe_copy(z3, (const uint64_t[]){1,0,0,0,0});

    uint64_t swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(A, x2, z2);
        fe_sq_ucode(A, AA);
        fe_sub(B, x2, z2);
        fe_sq_ucode(B, BB);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul_ucode(D, A, DA);
        fe_mul_ucode(C, B, CB);

        fe_add(t0, DA, CB);
        fe_sq_ucode(t0, x3);

        fe_sub(t0, DA, CB);
        fe_sq_ucode(t0, z3);
        fe_mul_ucode(x1, z3, z3);

        fe_mul_ucode(AA, BB, x2);

        fe_mul121665(t0, E);
        fe_add(t0, AA, t0);
        fe_mul_ucode(E, t0, z2);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert_ucode(z2, z2);
    fe_mul_ucode(x2, z2, x2);
    fe_tobytes(out, x2);
}

static void x25519_fiat(uint8_t out[32], const uint8_t scalar[32],
                        const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    scalar_clamp(e);

    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB, t0;

    fe_frombytes(x1, point);
    fe_copy(x2, (const uint64_t[]){1,0,0,0,0});
    memset(z2, 0, sizeof(fe));
    fe_copy(x3, x1);
    fe_copy(z3, (const uint64_t[]){1,0,0,0,0});

    uint64_t swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(A, x2, z2);
        fe_sq_fiat(A, AA);
        fe_sub(B, x2, z2);
        fe_sq_fiat(B, BB);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul_fiat(D, A, DA);
        fe_mul_fiat(C, B, CB);

        fe_add(t0, DA, CB);
        fe_sq_fiat(t0, x3);

        fe_sub(t0, DA, CB);
        fe_sq_fiat(t0, z3);
        fe_mul_fiat(x1, z3, z3);

        fe_mul_fiat(AA, BB, x2);

        fe_mul121665(t0, E);
        fe_add(t0, AA, t0);
        fe_mul_fiat(E, t0, z2);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert_fiat(z2, z2);
    fe_mul_fiat(x2, z2, x2);
    fe_tobytes(out, x2);
}

static void x25519_cryptopt(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    scalar_clamp(e);

    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB, t0;

    fe_frombytes(x1, point);
    fe_copy(x2, (const uint64_t[]){1,0,0,0,0});
    memset(z2, 0, sizeof(fe));
    fe_copy(x3, x1);
    fe_copy(z3, (const uint64_t[]){1,0,0,0,0});

    uint64_t swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(A, x2, z2);
        fe_sq_cryptopt(A, AA);
        fe_sub(B, x2, z2);
        fe_sq_cryptopt(B, BB);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul_cryptopt(D, A, DA);
        fe_mul_cryptopt(C, B, CB);

        fe_add(t0, DA, CB);
        fe_sq_cryptopt(t0, x3);

        fe_sub(t0, DA, CB);
        fe_sq_cryptopt(t0, z3);
        fe_mul_cryptopt(x1, z3, z3);

        fe_mul_cryptopt(AA, BB, x2);

        fe_mul121665(t0, E);
        fe_add(t0, AA, t0);
        fe_mul_cryptopt(E, t0, z2);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert_cryptopt(z2, z2);
    fe_mul_cryptopt(x2, z2, x2);
    fe_tobytes(out, x2);
}

/* amd64-51 ASM FIELD OPS ON THE SHARED C LADDER  ("a51ops/C-ladder") */
typedef struct { unsigned long long v[5]; } a51_fe_t;
extern void supercop_amd64_51_fe25519_mul(a51_fe_t *r, const a51_fe_t *x, const a51_fe_t *y);
extern void supercop_amd64_51_fe25519_square(a51_fe_t *r, const a51_fe_t *x);

static inline void fe_mul_a51(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    supercop_amd64_51_fe25519_mul((a51_fe_t *)out, (const a51_fe_t *)a, (const a51_fe_t *)b);
}

static inline void fe_sq_a51(const uint64_t *a, uint64_t *out) {
    supercop_amd64_51_fe25519_square((a51_fe_t *)out, (const a51_fe_t *)a);
}

static void fe_invert_a51(fe out, const fe z) {
    fe z2, z9, z11, t, t0, t1, t2, t3;
    int i;

    fe_sq_a51(z, z2);
    fe_sq_a51(z2, t);
    fe_sq_a51(t, t);
    fe_mul_a51(t, z, z9);
    fe_mul_a51(z9, z2, z11);
    fe_sq_a51(z11, t);
    fe_mul_a51(t, z9, t0);

    fe_sq_a51(t0, t1);
    for (i = 1; i < 5; i++) fe_sq_a51(t1, t1);
    fe_mul_a51(t1, t0, t1);

    fe_sq_a51(t1, t2);
    for (i = 1; i < 10; i++) fe_sq_a51(t2, t2);
    fe_mul_a51(t2, t1, t2);

    fe_sq_a51(t2, t3);
    for (i = 1; i < 20; i++) fe_sq_a51(t3, t3);
    fe_mul_a51(t3, t2, t3);

    for (i = 0; i < 10; i++) fe_sq_a51(t3, t3);
    fe_mul_a51(t3, t1, t1);

    fe_sq_a51(t1, t2);
    for (i = 1; i < 50; i++) fe_sq_a51(t2, t2);
    fe_mul_a51(t2, t1, t2);

    fe_sq_a51(t2, t3);
    for (i = 1; i < 100; i++) fe_sq_a51(t3, t3);
    fe_mul_a51(t3, t2, t3);

    for (i = 0; i < 50; i++) fe_sq_a51(t3, t3);
    fe_mul_a51(t3, t1, t1);

    fe_sq_a51(t1, t1);
    fe_sq_a51(t1, t1);
    fe_sq_a51(t1, t1);
    fe_sq_a51(t1, t1);
    fe_sq_a51(t1, t1);
    fe_mul_a51(t1, z11, out);
}

static void x25519_a51ops(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    scalar_clamp(e);

    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB, t0;

    fe_frombytes(x1, point);
    fe_copy(x2, (const uint64_t[]){1,0,0,0,0});
    memset(z2, 0, sizeof(fe));
    fe_copy(x3, x1);
    fe_copy(z3, (const uint64_t[]){1,0,0,0,0});

    uint64_t swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(A, x2, z2);
        fe_sq_a51(A, AA);
        fe_sub(B, x2, z2);
        fe_sq_a51(B, BB);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul_a51(D, A, DA);
        fe_mul_a51(C, B, CB);

        fe_add(t0, DA, CB);
        fe_sq_a51(t0, x3);

        fe_sub(t0, DA, CB);
        fe_sq_a51(t0, z3);
        fe_mul_a51(x1, z3, z3);

        fe_mul_a51(AA, BB, x2);

        fe_mul121665(t0, E);
        fe_add(t0, AA, t0);
        fe_mul_a51(E, t0, z2);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert_a51(z2, z2);
    fe_mul_a51(x2, z2, x2);
    fe_tobytes(out, x2);
}

/* OpenSSL fe51 ASM FIELD OPS ON THE SHARED C LADDER  ("osslops/C-ladder") */
void x25519_fe51_mul(uint64_t h[5], const uint64_t f[5], const uint64_t g[5]);
void x25519_fe51_sqr(uint64_t h[5], const uint64_t f[5]);

static inline void fe_mul_ossl(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    x25519_fe51_mul(out, a, b);
}

static inline void fe_sq_ossl(const uint64_t *a, uint64_t *out) {
    x25519_fe51_sqr(out, a);
}

static void fe_invert_ossl(fe out, const fe z) {
    fe z2, z9, z11, t, t0, t1, t2, t3;
    int i;

    fe_sq_ossl(z, z2);
    fe_sq_ossl(z2, t);
    fe_sq_ossl(t, t);
    fe_mul_ossl(t, z, z9);
    fe_mul_ossl(z9, z2, z11);
    fe_sq_ossl(z11, t);
    fe_mul_ossl(t, z9, t0);

    fe_sq_ossl(t0, t1);
    for (i = 1; i < 5; i++) fe_sq_ossl(t1, t1);
    fe_mul_ossl(t1, t0, t1);

    fe_sq_ossl(t1, t2);
    for (i = 1; i < 10; i++) fe_sq_ossl(t2, t2);
    fe_mul_ossl(t2, t1, t2);

    fe_sq_ossl(t2, t3);
    for (i = 1; i < 20; i++) fe_sq_ossl(t3, t3);
    fe_mul_ossl(t3, t2, t3);

    for (i = 0; i < 10; i++) fe_sq_ossl(t3, t3);
    fe_mul_ossl(t3, t1, t1);

    fe_sq_ossl(t1, t2);
    for (i = 1; i < 50; i++) fe_sq_ossl(t2, t2);
    fe_mul_ossl(t2, t1, t2);

    fe_sq_ossl(t2, t3);
    for (i = 1; i < 100; i++) fe_sq_ossl(t3, t3);
    fe_mul_ossl(t3, t2, t3);

    for (i = 0; i < 50; i++) fe_sq_ossl(t3, t3);
    fe_mul_ossl(t3, t1, t1);

    fe_sq_ossl(t1, t1);
    fe_sq_ossl(t1, t1);
    fe_sq_ossl(t1, t1);
    fe_sq_ossl(t1, t1);
    fe_sq_ossl(t1, t1);
    fe_mul_ossl(t1, z11, out);
}

static void x25519_osslops(uint8_t out[32], const uint8_t scalar[32],
                            const uint8_t point[32]) {
    uint8_t e[32];
    memcpy(e, scalar, 32);
    scalar_clamp(e);

    fe x1, x2, z2, x3, z3;
    fe A, AA, B, BB, E, C, D, DA, CB, t0;

    fe_frombytes(x1, point);
    fe_copy(x2, (const uint64_t[]){1,0,0,0,0});
    memset(z2, 0, sizeof(fe));
    fe_copy(x3, x1);
    fe_copy(z3, (const uint64_t[]){1,0,0,0,0});

    uint64_t swap = 0;

    for (int pos = 254; pos >= 0; pos--) {
        uint64_t bit = (e[pos >> 3] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(x2, x3, swap);
        fe_cswap(z2, z3, swap);
        swap = bit;

        fe_add(A, x2, z2);
        fe_sq_ossl(A, AA);
        fe_sub(B, x2, z2);
        fe_sq_ossl(B, BB);
        fe_sub(E, AA, BB);
        fe_add(C, x3, z3);
        fe_sub(D, x3, z3);
        fe_mul_ossl(D, A, DA);
        fe_mul_ossl(C, B, CB);

        fe_add(t0, DA, CB);
        fe_sq_ossl(t0, x3);

        fe_sub(t0, DA, CB);
        fe_sq_ossl(t0, z3);
        fe_mul_ossl(x1, z3, z3);

        fe_mul_ossl(AA, BB, x2);

        fe_mul121665(t0, E);
        fe_add(t0, AA, t0);
        fe_mul_ossl(E, t0, z2);
    }

    fe_cswap(x2, x3, swap);
    fe_cswap(z2, z3, swap);

    fe_invert_ossl(z2, z2);
    fe_mul_ossl(x2, z2, x2);
    fe_tobytes(out, x2);
}

static uint64_t pctl_u64(const uint64_t *sorted, int n, double pct) {
    if (n <= 0) return 0;
    int idx = (int)(pct / 100.0 * (n - 1) + 0.5);
    if (idx < 0) idx = 0;
    if (idx >= n) idx = n - 1;
    return sorted[idx];
}

static void bench_stats(uint64_t *samples, int n, uint64_t *out_min, uint64_t *out_median,
                        uint64_t *out_p10, uint64_t *out_p90) {
    qsort(samples, n, sizeof(uint64_t), cmp_u64);
    *out_min    = samples[0];
    *out_median = samples[n / 2];
    *out_p10    = pctl_u64(samples, n, 10.0);
    *out_p90    = pctl_u64(samples, n, 90.0);
}

/* RFC 7748 TEST VECTORS — verifies every contender against the spec. */

static int test_rfc7748(void) {
    int pass = 0, fail = 0;
    uint8_t scalar[32], point[32], result_native[32], result_ucode[32];

    printf("=== RFC 7748 Test Vectors ===\n\n");

    printf("--- Test vector 1 ---\n");
    hex_to_bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                 scalar, 32);
    hex_to_bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                 point, 32);
    x25519_native(result_native, scalar, point);
    x25519_ucode(result_ucode, scalar, point);

    print_hex("native", result_native, 32);
    print_hex("ucode ", result_ucode, 32);

    if (memcmp_hex(result_native,
                   "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                   32) == 0) {
        printf("  native: PASS\n"); pass++;
    } else {
        printf("  native: FAIL\n"); fail++;
    }
    if (memcmp_hex(result_ucode,
                   "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                   32) == 0) {
        printf("  ucode:  PASS\n"); pass++;
    } else {
        printf("  ucode:  FAIL\n"); fail++;
    }

    printf("\n--- Test vector 2 ---\n");
    hex_to_bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                 scalar, 32);
    hex_to_bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                 point, 32);
    x25519_native(result_native, scalar, point);
    x25519_ucode(result_ucode, scalar, point);

    print_hex("native", result_native, 32);
    print_hex("ucode ", result_ucode, 32);

    if (memcmp_hex(result_native,
                   "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
                   32) == 0) {
        printf("  native: PASS\n"); pass++;
    } else {
        printf("  native: FAIL\n"); fail++;
    }
    if (memcmp_hex(result_ucode,
                   "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
                   32) == 0) {
        printf("  ucode:  PASS\n"); pass++;
    } else {
        printf("  ucode:  FAIL\n"); fail++;
    }

    printf("\n--- Iterated test (1 iteration) ---\n");
    {
        uint8_t k[32] = {0}, u[32] = {0}, r[32];
        k[0] = 9;
        u[0] = 9;

        x25519_native(r, k, u);

        print_hex("native after 1", r, 32);
        if (memcmp_hex(r,
                       "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                       32) == 0) {
            printf("  native: PASS\n"); pass++;
        } else {
            printf("  native: FAIL\n"); fail++;
        }

        x25519_ucode(r, k, u);
        print_hex("ucode  after 1", r, 32);
        if (memcmp_hex(r,
                       "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079",
                       32) == 0) {
            printf("  ucode:  PASS\n"); pass++;
        } else {
            printf("  ucode:  FAIL\n"); fail++;
        }
    }

    printf("\n--- Iterated test (1000 iterations) ---\n");
    {
        uint8_t k[32] = {0}, u[32] = {0}, r[32];
        k[0] = 9;
        u[0] = 9;

        uint8_t kn[32], un[32];
        memcpy(kn, k, 32);
        memcpy(un, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_native(r, kn, un);
            memcpy(un, kn, 32);
            memcpy(kn, r, 32);
        }
        print_hex("native after 1000", kn, 32);
        if (memcmp_hex(kn,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  native: PASS\n"); pass++;
        } else {
            printf("  native: FAIL\n"); fail++;
        }

        uint8_t ku[32], uu[32];
        memcpy(ku, k, 32);
        memcpy(uu, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_ucode(r, ku, uu);
            memcpy(uu, ku, 32);
            memcpy(ku, r, 32);
        }
        print_hex("ucode  after 1000", ku, 32);
        if (memcmp_hex(ku,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  ucode:  PASS\n"); pass++;
        } else {
            printf("  ucode:  FAIL\n"); fail++;
        }

        uint8_t kf[32], uf[32];
        memcpy(kf, k, 32);
        memcpy(uf, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_fiat(r, kf, uf);
            memcpy(uf, kf, 32);
            memcpy(kf, r, 32);
        }
        print_hex("fiat   after 1000", kf, 32);
        if (memcmp_hex(kf,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  fiat:   PASS\n"); pass++;
        } else {
            printf("  fiat:   FAIL\n"); fail++;
        }

        uint8_t kq[32], uq[32];
        memcpy(kq, k, 32);
        memcpy(uq, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_a51ops(r, kq, uq);
            memcpy(uq, kq, 32);
            memcpy(kq, r, 32);
        }
        print_hex("a51ops after 1000", kq, 32);
        if (memcmp_hex(kq,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  a51ops: PASS\n"); pass++;
        } else {
            printf("  a51ops: FAIL\n"); fail++;
        }

        uint8_t kd[32], ud[32];
        memcpy(kd, k, 32);
        memcpy(ud, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_donna_c64(r, kd, ud);
            memcpy(ud, kd, 32);
            memcpy(kd, r, 32);
        }
        print_hex("donna  after 1000", kd, 32);
        if (memcmp_hex(kd,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  donna:  PASS\n"); pass++;
        } else {
            printf("  donna:  FAIL\n"); fail++;
        }

        uint8_t ka[32], ua[32];
        memcpy(ka, k, 32);
        memcpy(ua, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_amd64_51(r, ka, ua);
            memcpy(ua, ka, 32);
            memcpy(ka, r, 32);
        }
        print_hex("amd51  after 1000", ka, 32);
        if (memcmp_hex(ka,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  amd51:  PASS\n"); pass++;
        } else {
            printf("  amd51:  FAIL\n"); fail++;
        }

        uint8_t ka4[32], ua4[32];
        memcpy(ka4, k, 32);
        memcpy(ua4, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_amd64_64(r, ka4, ua4);
            memcpy(ua4, ka4, 32);
            memcpy(ka4, r, 32);
        }
        print_hex("amd64  after 1000", ka4, 32);
        if (memcmp_hex(ka4,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  amd64:  PASS\n"); pass++;
        } else {
            printf("  amd64:  FAIL\n"); fail++;
        }

        uint8_t kc[32], uc[32];
        memcpy(kc, k, 32);
        memcpy(uc, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519_cryptopt(r, kc, uc);
            memcpy(uc, kc, 32);
            memcpy(kc, r, 32);
        }
        print_hex("crypto after 1000", kc, 32);
        if (memcmp_hex(kc,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  crypto: PASS\n"); pass++;
        } else {
            printf("  crypto: FAIL\n"); fail++;
        }

        uint8_t kil[32], uil[32];
        memcpy(kil, k, 32);
        memcpy(uil, u, 32);
        for (int i = 0; i < 1000; i++) {
            x25519(r, kil, uil);
            memcpy(uil, kil, 32);
            memcpy(kil, r, 32);
        }
        print_hex("inline after 1000", kil, 32);
        if (memcmp_hex(kil,
                       "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51",
                       32) == 0) {
            printf("  inline: PASS\n"); pass++;
        } else {
            printf("  inline: FAIL\n"); fail++;
        }

        if (memcmp(kn, ku, 32) == 0) {
            printf("  native==ucode: PASS\n"); pass++;
        } else {
            printf("  native==ucode: FAIL\n"); fail++;
        }
        if (memcmp(kn, kf, 32) == 0) {
            printf("  native==fiat:  PASS\n"); pass++;
        } else {
            printf("  native==fiat:  FAIL\n"); fail++;
        }
        if (memcmp(kn, kd, 32) == 0) {
            printf("  native==donna: PASS\n"); pass++;
        } else {
            printf("  native==donna: FAIL\n"); fail++;
        }
        if (memcmp(kn, ka, 32) == 0) {
            printf("  native==amd51: PASS\n"); pass++;
        } else {
            printf("  native==amd51: FAIL\n"); fail++;
        }
        if (memcmp(kn, ka4, 32) == 0) {
            printf("  native==amd64: PASS\n"); pass++;
        } else {
            printf("  native==amd64: FAIL\n"); fail++;
        }
        if (memcmp(kn, kc, 32) == 0) {
            printf("  native==crypto: PASS\n"); pass++;
        } else {
            printf("  native==crypto: FAIL\n"); fail++;
        }
        if (memcmp(kn, kil, 32) == 0) {
            printf("  native==inline: PASS\n"); pass++;
        } else {
            printf("  native==inline: FAIL\n"); fail++;
        }
    }

    printf("\n=== RFC 7748: %d passed, %d failed ===\n\n", pass, fail);
    return fail;
}

/* BENCHMARK — every contender */
typedef void (*bench_fn)(uint8_t *out, const uint8_t *scalar, const uint8_t *point);

#define BENCH_THUNK(TH, CALL)                                                \
    static void TH(uint8_t *o, const uint8_t *s, const uint8_t *p) { CALL; }

extern void curve25519_x25519_alt(uint64_t res[4], const uint64_t scalar[4],
                                  const uint64_t point[4]);
static void x25519_s2n(uint8_t out[32], const uint8_t scalar[32],
                       const uint8_t point[32]) {
    uint64_t r[4], n[4], q[4];
    memcpy(n, scalar, 32);
    memcpy(q, point, 32);
    curve25519_x25519_alt(r, n, q);
    memcpy(out, r, 32);
}

BENCH_THUNK(bt_s2n,      x25519_s2n(o, s, p))

extern void x25519_openssl(uint8_t out[32], const uint8_t scalar[32],
                           const uint8_t point[32]);
BENCH_THUNK(bt_openssl,  x25519_openssl(o, s, p))
BENCH_THUNK(bt_osslops,  x25519_osslops(o, s, p))
BENCH_THUNK(bt_hand_c,   x25519_native(o, s, p))
BENCH_THUNK(bt_fiat,     x25519_fiat(o, s, p))
BENCH_THUNK(bt_cryptopt, x25519_cryptopt(o, s, p))
BENCH_THUNK(bt_a51ops,   x25519_a51ops(o, s, p))
BENCH_THUNK(bt_donna,    (void)x25519_donna_c64(o, s, p))
BENCH_THUNK(bt_a51_asm,  (void)x25519_amd64_51(o, s, p))
BENCH_THUNK(bt_a64_asm,  (void)x25519_amd64_64(o, s, p))
BENCH_THUNK(bt_ours_uc,  x25519(o, s, p))
BENCH_THUNK(bt_uc_clad,  x25519_ucode(o, s, p))

static const struct { const char *label; bench_fn fn; } BENCH_TAB[] = {
    { "ours/hand-C:",          bt_hand_c   },
    { "ours/fiat:",            bt_fiat     },
    { "ours/cryptopt:",        bt_cryptopt },

    { "a51ops/C-ladder:",      bt_a51ops   },
    { "donna_c64:",            bt_donna    },
    { "amd64-51/asm:",         bt_a51_asm  },
    { "amd64-64/asm:",         bt_a64_asm  },

    { "ours/setcc_ucode:",     bt_ours_uc  },
    { "ucode/C-ladder:",       bt_uc_clad  },
    { "s2n-bignum/asm:",       bt_s2n      },
    { "osslops/C-ladder:",     bt_osslops  },
    { "openssl:",              bt_openssl  },
};
#define N_BENCH ((int)(sizeof BENCH_TAB / sizeof BENCH_TAB[0]))

static uint64_t bench_samples[N_BENCH][BENCH_REPS];

static int bench_selected(const char *label) {
    const char *only = getenv("BENCH_ONLY");
    if (!only || !*only) return 1;
    size_t n = strlen(only), i = 0;
    while (i < n) {
        size_t j = i;
        while (j < n && only[j] != ',') j++;
        if (j > i && strncmp(label, only + i, j - i) == 0) return 1;
        i = j + 1;
    }
    return 0;
}

static void benchmark(void) {
    uint8_t scalar[32] = {0}, point[32] = {0}, out[32];
    uint64_t mn, med, p10, p90;
    int sel[N_BENCH], nsel = 0;
    for (int c = 0; c < N_BENCH; c++)
        if (bench_selected(BENCH_TAB[c].label)) sel[nsel++] = c;
    if (nsel == 0) { printf("BENCH_ONLY matched no contender; nothing to do.\n"); return; }

    hex_to_bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4", scalar, 32);
    hex_to_bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c", point, 32);

    printf("=== X25519 Benchmark (%d repetitions, interleaved) ===\n\n", BENCH_REPS);

    {
        int bad = 0;
        for (int k = 0; k < nsel; k++) {
            int c = sel[k];
            BENCH_TAB[c].fn(out, scalar, point);
            if (memcmp_hex(out,
                    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                    32) != 0) {
                printf("  %-20s RFC 7748 vector 1 MISMATCH\n", BENCH_TAB[c].label);
                bad++;
            }
        }
        printf("  contender verification: %s (%d of %d failed)\n",
               bad ? "FAIL" : "all pass", bad, nsel);
        printf("  contenders in the round-robin: %d of %d%s\n\n", nsel, N_BENCH,
               nsel == N_BENCH ? "" : "  [BENCH_ONLY active]");
    }

    for (int r = 0; r < BENCH_REPS; r++) {
        for (int k = 0; k < nsel; k++) {
            int c = sel[k];
            uint64_t t0 = rdtsc_start();
            BENCH_TAB[c].fn(out, scalar, point);
            uint64_t t1 = rdtsc_end();
            bench_samples[c][r] = t1 - t0;
        }
    }

    for (int k = 0; k < nsel; k++) {
        int c = sel[k];
        bench_stats(bench_samples[c], BENCH_REPS, &mn, &med, &p10, &p90);
        printf("%-20s median %8" PRIu64 "  min %8" PRIu64 "  p10 %8" PRIu64
               "  p90 %8" PRIu64 " cycles\n", BENCH_TAB[c].label, med, mn, p10, p90);
    }

    printf("\n");
}

/* MAIN — the inline-asm 5×51 ladder (x25519) is the canonical "ours". */
#define VERIFY_NAME "full_curve25519_inline2.c (SETCC)"
/* VERIFY MODE */
#include "tests/verify_x25519_vectors.h"

typedef unsigned __int128 v_u128;
#define V_M51 ((1ULL << 51) - 1)
#define V_BOUND (1ULL << 54)
#define V_CLOB "rax", "rbx", "rcx", "rdx", "rsi", "rdi", \
               "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory", "cc"

static uint64_t v_rng = 0x2545F4914F6CDD1DULL;
static uint64_t v_rand(void) {
    v_rng ^= v_rng >> 12; v_rng ^= v_rng << 25; v_rng ^= v_rng >> 27;
    return v_rng * 0x2545F4914F6CDD1DULL;
}

static __attribute__((noinline)) void hw_mul(uint64_t out[5], const uint64_t a[5],
                                             const uint64_t b[5]) {
    ladder_state_t st;
    memcpy(st.A, a, 40);
    memcpy(st.B, b, 40);
    register ladder_state_t *_st asm("rbp") = &st;
    asm volatile(FE_MUL(T0_OFF, A_OFF, B_OFF) : : "r"(_st) : V_CLOB);
    memcpy(out, st.t0, 40);
}

static __attribute__((noinline)) void hw_sq(uint64_t out[5], const uint64_t a[5]) {
    ladder_state_t st;
    memcpy(st.A, a, 40);
    register ladder_state_t *_st asm("rbp") = &st;
    asm volatile(FE_SQ(T0_OFF, A_OFF) : : "r"(_st) : V_CLOB);
    memcpy(out, st.t0, 40);
}

static void v_acc(v_u128 acc[5], const uint64_t a[5], const uint64_t b[5]) {
    for (int k = 0; k < 5; k++) acc[k] = 0;
    for (int i = 0; i < 5; i++)
        for (int j = 0; j < 5; j++) {
            v_u128 p = (v_u128)a[i] * b[j];
            if (i + j < 5) acc[i + j] += p;
            else           acc[i + j - 5] += 19 * p;
        }
}

static void v_model(uint64_t out[5], const uint64_t a[5], const uint64_t b[5]) {
    v_u128 acc[5];
    uint64_t q[5], t[5], c[5];
    v_acc(acc, a, b);
    for (int j = 0; j < 5; j++) q[j] = (uint64_t)(acc[j] >> 51);
    t[0] = ((uint64_t)acc[0] & V_M51) + 19 * q[4];
    for (int j = 1; j < 5; j++) t[j] = ((uint64_t)acc[j] & V_M51) + q[j - 1];
    for (int j = 0; j < 5; j++) c[j] = t[j] >> 51;
    out[0] = (t[0] & V_M51) + 19 * c[4];
    for (int j = 1; j < 5; j++) out[j] = (t[j] & V_M51) + c[j - 1];
}

static void v_canon(uint64_t r[5], const v_u128 in[5]) {
    v_u128 l[5];
    for (int k = 0; k < 5; k++) l[k] = in[k];
    for (;;) {
        for (int k = 0; k < 4; k++) { l[k + 1] += l[k] >> 51; l[k] &= V_M51; }
        v_u128 top = l[4] >> 51;
        l[4] &= V_M51;
        l[0] += 19 * top;
        if (top == 0 && (l[0] >> 51) == 0) break;
    }
    int ge_p = l[0] >= V_M51 - 18 && l[1] == V_M51 && l[2] == V_M51 &&
               l[3] == V_M51 && l[4] == V_M51;
    if (ge_p) { l[0] -= V_M51 - 18; l[1] = l[2] = l[3] = l[4] = 0; }
    for (int k = 0; k < 5; k++) r[k] = (uint64_t)l[k];
}

static void v_canon64(uint64_t r[5], const uint64_t in[5]) {
    v_u128 w[5];
    for (int k = 0; k < 5; k++) w[k] = in[k];
    v_canon(r, w);
}

static void v_bytes(uint8_t out[32], const uint64_t canon[5]) {
    memset(out, 0, 32);
    for (int bit = 0; bit < 255; bit++)
        if ((canon[bit / 51] >> (bit % 51)) & 1) out[bit >> 3] |= (uint8_t)(1 << (bit & 7));
}

static void v_print5(const char *tag, const uint64_t x[5]) {
    printf("      %-6s", tag);
    for (int k = 0; k < 5; k++) printf(" %014" PRIx64, x[k]);
    printf("\n");
}

static int test_refs(void) {

    static const uint64_t kv[3][3][5] = {
        {{0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL}, {0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL}, {0x800000000678aULL, 0x800000000132aULL, 0x8000000000fb8ULL, 0x8000000000c46ULL, 0x80000000008d4ULL}},
        {{0x7ffffffffffedULL, 0x7ffffffffffffULL, 0x7ffffffffffffULL, 0x7ffffffffffffULL, 0x7ffffffffffffULL}, {0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL, 0x3fffffffffffffULL}, {0x7ffffffffffedULL, 0x7ffffffffffffULL, 0x7ffffffffffffULL, 0x7ffffffffffffULL, 0x7ffffffffffffULL}},
        {{0x1fffffffffffffULL, 0x3fffffffffffffULL, 0x8000000000000ULL, 0x1ULL, 0x3fffffffffffffULL}, {0x13ULL, 0xfffffffffffffULL, 0x0ULL, 0x3fffffffffffffULL, 0x7ffffffffffedULL}, {0x13abULL, 0x7fffffffff907ULL, 0x80000000000cbULL, 0x83ULL, 0x7fffffffff968ULL}},
    };
    const uint64_t omax[5] = {V_M51 + 27968, V_M51 + 6080, V_M51 + 4928,
                              V_M51 + 3776, V_M51 + 2624};
    int fail = 0;
    long n = 0;
    uint64_t lim[5], cg[5], cw[5], a[5], b[5];
    v_u128 acc[5];
    for (int t = 0; t < 3; t++, n++) {
        v_model(lim, kv[t][0], kv[t][1]);
        if (memcmp(lim, kv[t][2], 40) != 0) { fail++; printf("    v_model != Python model (%d)\n", t); }
    }

    for (long t = 0; t < 2000000; t++, n++) {
        int w = 51 + (int)(t & 3);
        for (int k = 0; k < 5; k++) {
            a[k] = v_rand() & ((1ULL << w) - 1);
            b[k] = (t & 4) ? a[k] : v_rand() & ((1ULL << w) - 1);
        }
        if (t < 10) for (int k = 0; k < 5; k++) a[k] = b[k] = V_BOUND - 1;
        v_model(lim, a, b);
        v_acc(acc, a, b);
        v_canon(cw, acc);
        v_canon64(cg, lim);
        int bad = memcmp(cg, cw, 40) != 0;
        for (int k = 0; k < 5; k++) if (lim[k] > omax[k]) bad = 1;
        if (bad) { if (fail < 4) printf("    v_model/v_canon disagree\n"); fail++; }
    }
    printf("[0] C references: model bit-exact vs Python, model == schoolbook, %ld cases  %s\n",
           n, fail ? "FAIL" : "PASS");
    return fail;
}

static int test_encoding(void) {
    int fail = 0, n = 0;

    for (int t = 0; t < N_X25519_KAT + 64; t++) {
        uint8_t u[32];
        if (t < N_X25519_KAT) memcpy(u, X25519_KAT[t].u, 32);
        else if (t == N_X25519_KAT) memset(u, 0xff, 32);
        else for (int i = 0; i < 32; i++) u[i] = (uint8_t)v_rand();
        uint64_t got[5], want[5] = {0};
        fe_frombytes(got, u);
        for (int bit = 0; bit < 255; bit++)
            if ((u[bit >> 3] >> (bit & 7)) & 1) want[bit / 51] |= 1ULL << (bit % 51);
        n++;
        if (memcmp(got, want, 40) != 0) {
            fail++;
            printf("    fe_frombytes MISMATCH (case %d)\n", t);
        }
    }
    const uint64_t M = V_M51, P0 = V_M51 - 18;
    const uint64_t vecs[][5] = {
        {0, 0, 0, 0, 0}, {1, 0, 0, 0, 0},
        {P0 - 1, M, M, M, M},
        {P0, M, M, M, M},
        {P0 + 1, M, M, M, M},
        {M, M, M, M, M},
        {P0 + 18, M, M, M, M},
        {M + 1, M, M, M, M},
        {2 * P0, 2 * M, 2 * M, 2 * M, 2 * M},
        {2 * P0 - 1, 2 * M, 2 * M, 2 * M, 2 * M},
        {M + 27967, M + 6079, M + 4927, M + 3775, M + 2623},
        {M + 27968, M + 6080, M + 4928, M + 3776, M + 2624},
        {0, 0, 0, 0, M + 2624}, {M + 27968, 0, 0, 0, 0},
        {1ULL << 51, 1ULL << 51, 1ULL << 51, 1ULL << 51, 1ULL << 51},
        {0, M + 1, 0, M + 1, 0},
    };
    const int nv = (int)(sizeof vecs / sizeof vecs[0]);
    const uint64_t omax[5] = {M + 27968, M + 6080, M + 4928, M + 3776, M + 2624};
    for (int t = 0; t < nv + 200000; t++) {
        uint64_t l[5], c[5];
        if (t < nv) memcpy(l, vecs[t], 40);
        else for (int k = 0; k < 5; k++) l[k] = v_rand() % (omax[k] + 1);
        uint8_t got[32], want[32];
        fe_tobytes(got, l);
        v_canon64(c, l);
        v_bytes(want, c);
        n++;
        if (memcmp(got, want, 32) != 0) {
            if (fail < 8) { printf("    fe_tobytes MISMATCH\n"); v_print5("in", l); }
            fail++;
        }
    }
    printf("[1] encoding: fe_frombytes + fe_tobytes, %d cases            %s\n",
           n, fail ? "FAIL" : "PASS");
    return fail;
}

static long f_n, f_fail;

static void check_op(int sq, const uint64_t a[5], const uint64_t b[5]) {
    uint64_t got[5], lim[5], cg[5], cw[5];
    v_u128 acc[5];
    if (sq) hw_sq(got, a); else hw_mul(got, a, b);
    v_model(lim, a, b);
    v_acc(acc, a, b);
    v_canon(cw, acc);
    v_canon64(cg, got);
    f_n++;
    int bad_l = memcmp(got, lim, 40) != 0, bad_v = memcmp(cg, cw, 40) != 0;
    if (bad_l || bad_v) {
        if (f_fail < 8) {
            printf("    %s MISMATCH (%s%s)\n", sq ? "fe_sq" : "fe_mul",
                   bad_l ? "limbs " : "", bad_v ? "value" : "");
            v_print5("a", a); if (!sq) v_print5("b", b);
            v_print5("got", got); v_print5("model", lim);
        }
        f_fail++;
    }
}

static int test_field_ops(void) {
    static const uint64_t E[10] = {
        0, 1, 19, (1ULL << 51) - 19, (1ULL << 51) - 1, 1ULL << 51,
        (1ULL << 52) - 1, (1ULL << 53) - 1, 1ULL << 53, V_BOUND - 1 };
    const uint64_t M = V_M51, B = V_BOUND - 1;
    static uint64_t partners[5][5];
    const uint64_t pp[5][5] = { {B, B, B, B, B}, {M, M, M, M, M},
                                {M - 18, M, M, M, M}, {0, 0, 0, 0, 0},
                                {(1ULL << 53) - 1, B, 1ULL << 51, 1, B} };
    memcpy(partners, pp, sizeof pp);
    uint64_t a[5], b[5];
    long n0;

    for (int sq = 1; sq >= 0; sq--) {
        const char *nm = sq ? "fe_sq " : "fe_mul";
        f_n = f_fail = 0;
        for (int idx = 0; idx < 100000; idx++) {
            for (int k = 0, x = idx; k < 5; k++, x /= 10) a[k] = E[x % 10];
            if (sq) check_op(1, a, a);
            else for (int p = 0; p < 5; p++) {
                check_op(0, a, partners[p]);
                check_op(0, partners[p], a);
            }
        }
        n0 = f_n;
        for (long t = 0; t < 1000000; t++) {
            for (int k = 0; k < 5; k++) { a[k] = E[v_rand() % 10]; b[k] = E[v_rand() % 10]; }
            check_op(sq, a, sq ? a : b);
        }
        for (int w = 51; w <= 54; w++)
            for (long t = 0; t < 1000000; t++) {
                for (int k = 0; k < 5; k++) {
                    a[k] = v_rand() & ((1ULL << w) - 1);
                    b[k] = v_rand() & ((1ULL << w) - 1);
                }
                check_op(sq, a, sq ? a : b);
            }
        printf("[2] %s on hardware: %ld firings (%ld edge-combination), "
               "limbs bit-exact + value        %s\n",
               nm, f_n, n0, f_fail ? "FAIL" : "PASS");
        if (f_fail) return (int)f_fail;
    }
    return 0;
}

static int test_kat(void) {
    int fail = 0, ofail = 0;
    for (int t = 0; t < N_X25519_KAT; t++) {
        uint8_t r[32], ro[32];
        x25519(r, X25519_KAT[t].scalar, X25519_KAT[t].u);
        x25519_openssl(ro, X25519_KAT[t].scalar, X25519_KAT[t].u);
        if (memcmp(r, X25519_KAT[t].out, 32) != 0) {
            if (fail < 8) printf("    KAT FAIL: %s\n", X25519_KAT[t].name);
            fail++;
        }
        if (memcmp(ro, X25519_KAT[t].out, 32) != 0) ofail++;
    }
    printf("[3] X25519 known answers: %d vectors                        %s\n",
           N_X25519_KAT, fail ? "FAIL" : "PASS");
    printf("    (OpenSSL against the same answers: %d differ%s)\n", ofail,
           ofail ? " -- the oracle and OpenSSL disagree, investigate" : "");
    return fail + ofail;
}

static int test_differential(long n) {
    long fail = 0;
    static const uint8_t pbytes[32] = {
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f };
    long n_hi = n / 10, n_nc = n / 100;
    for (long t = 0; t < n + n_hi + n_nc; t++) {
        uint8_t s[32], u[32], r[32], ro[32];
        for (int i = 0; i < 32; i += 8) {
            uint64_t x = v_rand(), y = v_rand();
            memcpy(s + i, &x, 8); memcpy(u + i, &y, 8);
        }
        if (t < n) u[31] &= 0x7f;
        else if (t < n + n_hi) u[31] |= 0x80;
        else {
            memcpy(u, pbytes, 32);
            u[0] = (uint8_t)(0xed + v_rand() % 19);
        }
        x25519(r, s, u);
        x25519_openssl(ro, s, u);
        if (memcmp(r, ro, 32) != 0) {
            if (fail < 8) print_hex("    differs, u", u, 32);
            fail++;
        }
    }
    printf("[4] X25519 vs OpenSSL: %ld random, %ld with bit 255 set, %ld u in [p, 2^255)  %s\n",
           n, n_hi, n_nc, fail ? "FAIL" : "PASS");
    return (int)fail;
}

static int test_iterated(void) {
    uint8_t k[32] = {9}, u[32] = {9}, r[32];
    long iters = getenv("VERIFY_ITER1M") ? 1000000 : 1000;
    for (long i = 0; i < iters; i++) {
        x25519(r, k, u);
        memcpy(u, k, 32);
        memcpy(k, r, 32);
    }
    const char *want = iters == 1000
        ? "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"
        : "7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424";
    int bad = memcmp_hex(k, want, 32) != 0;
    printf("[5] RFC 7748 iterated x%ld                                   %s\n",
           iters, bad ? "FAIL" : "PASS");
    return bad;
}

static int verify_main(int argc, char **argv) {
    int c_only = argc > 1 && strcmp(argv[1], "--c-only") == 0;
    long n_rand = (argc > 1 && !c_only) ? atol(argv[1]) : 20000;
    int fail = 0;
    printf("=== verify: %s ===\n", VERIFY_NAME);
    fail += test_refs();
    fail += test_encoding();
    if (c_only) {
        printf("VERDICT (encoding only): %s\n", fail ? "FAIL" : "PASS");
        return fail != 0;
    }
    init_match_and_patch();
    do_fix_IN_patch();
    install_field_patches();
    fail += test_field_ops();
    if (!fail) fail += test_kat();
    if (!fail) fail += test_differential(n_rand);
    if (!fail) fail += test_iterated();
    init_match_and_patch();
    do_fix_IN_patch();
    printf("VERDICT: %s\n", fail ? "FAIL" : "PASS");
    return fail != 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "verify") == 0)
        return verify_main(argc - 1, argv + 1);

    printf("=== Full X25519: every contender (inline-asm 5×51 is canonical ours) ===\n\n");

    if (freq_guard()) return 2;

    bench_pin();
    init_match_and_patch();
    do_fix_IN_patch();
    install_field_patches();
    printf("\n");

    int failures = test_rfc7748();
    if (failures) {
        printf("Test vectors FAILED (%d errors), skipping benchmark.\n", failures);
        init_match_and_patch();
        do_fix_IN_patch();
        return 1;
    }

    benchmark();

    init_match_and_patch();
    do_fix_IN_patch();
    printf("Done.\n");
    return 0;
}
