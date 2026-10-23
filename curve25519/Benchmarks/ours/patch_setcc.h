/*
 * patch_setcc.h -- ours/setcc: the five-accumulator fe_mul + fe_sq patches
 * whose per-accumulator carries run through SETCC (per-register flags).
 *
 * Copied verbatim from ../../full_curve25519_inline2.c (install_field_patches,
 * 2026-10-08); only the function name and the verbose flag are new. The array
 * names mul_patch / sq_patch_5acc are unchanged.
 */
#ifndef OURS_PATCH_SETCC_H
#define OURS_PATCH_SETCC_H

/* Upstream lib-micro has no 64-bit MUL: its opcode.h stops at _MUL_DSZ32
 * (0x22c) and its gen_inst.py has no MUL entry, so the generated inst.h emits
 * no MUL macro. We place the 64-bit form at 0x26c, one 0x40 DSZ32 -> DSZ64
 * step above the 32-bit opcode. MUL is destructive: srcB takes the low half of
 * the product and dst the high half, while srcA survives. Defined here so this
 * builds against an unmodified checkout; guarded in case lib-micro adds it. */
#ifndef _MUL_DSZ64
#define _MUL_DSZ64 (0x26cULL << 32)
#endif
#ifndef MUL_DSZ64_DRR
#define MUL_DSZ64_DRR(dst, src0, src1) ( _MUL_DSZ64 | INSTR_DRR(dst, src0, src1) )
#endif

/* ════════════════════════════════════════════════════════════════════
 * MICROCODE PATCH INSTALLATION
 *
 * fe_mul: five independent 128-bit accumulators (PLAN_kernel_optimization.md
 * section 5.0), replacing the single serial accumulator and its
 * 0->1->2->3->4 carry chain. Structure follows OpenSSL x25519_fe51_mul:
 *
 *   PREP      g_j = 19*b_j for j=1..4, one non-destructive IMUL64L each.
 *   row 0     a0*b_j initialises accumulator j. MUL writes its low half into
 *             srcB, so staging b_j into lo_j IS the initialisation: no ADD
 *             and no SETCC for the first product of each limb (PLAN 5.1B).
 *   rows 1-4  the other 20 products accumulate with NO inter-limb carry
 *             propagation. Each accumulator runs its own SETCC chain --
 *             domain #1 flags are PER-REGISTER, so five chains coexist and
 *             stay mutually independent. One accumulate is
 *                 ADD(lo_j, lo_j, lo_p)   SETCC(c, lo_j)
 *                 ADD(hi_p, hi_p, c)      ADD(hi_j, hi_j, hi_p)
 *             folding the carry into the product's high half rather than
 *             into hi_j, which halves the hi_j chain (4 deep, not 8).
 *
 *             This is 4 ops where the GENARITHFLAGS carry bridge would be
 *             3 (ADD / GFL_RR(lo_j,lo_j) / ADC), and the bridge was built
 *             and MEASURED: 52 triads, 154 ops, and 104.0 cyc against this
 *             version's 102.8. It loses because all 20 bridged carries
 *             funnel through the ONE architectural CF, so they serialise,
 *             where five SETCC domains do not. Per-register flags are the
 *             whole reason the parallel structure pays off; do not "save"
 *             the fourth op. See PLAN 5.0-lever-1.
 *   reduce    two fully parallel passes, NOT OpenSSL's partial tree.
 *             OpenSSL propagates each carry into the 128-bit accumulator
 *             (add+adc, two instructions); in microcode that costs
 *             ADD+SETCC+ADD. Splitting every accumulator into
 *                 r_j = lo_j & MASK        q_j = (lo_j>>51)|(hi_j<<13)
 *             first makes every carry add a plain 64-bit ADD, and all five
 *             splits issue in parallel. Pass 1 lands t_j < 2^63.6, pass 2
 *             lands every limb at < 2^51 + 2^17.
 *
 * INPUT BOUND: limbs must be < 2^54. The binding constraint is
 * 19*q_4 < 2^64 with q_4 = acc_4 >> 51 and acc_4 < 5*2^(2L), which needs
 * L < 54.2; hi_j<<13 < 2^64 needs L < 54.4. The ladder feeds this at most
 * 2^53.1 (FE_SUB's 2p bias on top of a < 2^52 limb).
 *
 * The wrapper must pass 2^51-1 in RCX (see FE_MUL): the patch masks with a
 * single AND against that register instead of a SHL13/SHR13 pair (PLAN
 * 5.1E). RCX was free -- the old patch used it as MUL's high destination,
 * and MUL's destination is free to be any register.
 *
 * fe_sq: sq_patch_5acc, the same five-accumulator structure over the 15
 * squaring products, with the same two-pass reduction. Wrapper contract:
 * 2^51-1 in R8 (see FE_SQ_R8 for the register-chaining hazard).
 *
 * Register map (fe_mul):
 *   a0..a4  RDI RSI R12 R11 R14   always MUL srcA, so preserved
 *   b0..b4  R15 R13 R9  R10 RBX   from the wrapper, consumed as srcB
 *   g1..g4  TMP0..TMP3            19*b_j
 *   lo0..4  TMP4..TMP8            MUST be TMP: SETCC reads domain #1
 *   hi0..4  TMP9..TMP13
 *   mask    RCX
 *   carry   TMP14 TMP15 (alternating SETCC destinations)
 *   scratch RAX R8 RDX, plus every register as it dies: RBX and RDI after
 *           row 0, then b_j and a_i as their last product is issued.
 * ════════════════════════════════════════════════════════════════════ */

__attribute__((unused))   /* each binary installs one patch set */
static void install_setcc_patches(int verbose) {
    ucode_t mul_patch[] = {
    /* PREP: g_j = 19*b_j, non-destructive, both sources survive */
    { IMUL64L_DSZ64_DRI(TMP3, RBX, 19), IMUL64L_DSZ64_DRI(TMP2, R10, 19),
      IMUL64L_DSZ64_DRI(TMP1, R9, 19), NOP_SEQWORD },
    /* row 0: a0*b_j initialises accumulator j -- no ADD, no SETCC */
    { IMUL64L_DSZ64_DRI(TMP0, R13, 19), ZEROEXT_DSZ64_DR(TMP4, R15),
      MUL_DSZ64_DRR(TMP9, RDI, TMP4), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(TMP5, R13), MUL_DSZ64_DRR(TMP10, RDI, TMP5),
      ZEROEXT_DSZ64_DR(TMP6, R9), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP11, RDI, TMP6), ZEROEXT_DSZ64_DR(TMP7, R10),
      MUL_DSZ64_DRR(TMP12, RDI, TMP7), NOP_SEQWORD },
    /* row 1: a1 x b, five independent accumulates */
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
    /* row 2: a2 x b, five independent accumulates */
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
    /* row 3: a3 x b, five independent accumulates */
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
    /* row 4: a4 x b, five independent accumulates */
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
    /* reduce pass 1: split all five accs, r_j = acc_j & M, q_j = acc_j >> 51 */
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
    /* t_j = r_j + q_{j-1}, and t_0 = r_0 + 19*q_4 */
    { AND_DSZ64_DRR(TMP8, TMP8, RCX), OR_DSZ64_DRR(TMP13, TMP1, TMP13),
      ADD_DSZ64_DRR(TMP5, TMP5, TMP9), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP6, TMP6, TMP10), ADD_DSZ64_DRR(TMP7, TMP7, TMP11),
      ADD_DSZ64_DRR(TMP8, TMP8, TMP12), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP3, TMP13, 4), ADD_DSZ64_DRR(TMP14, TMP13, TMP13),
      ADD_DSZ64_DRR(TMP3, TMP3, TMP14), NOP_SEQWORD },
    /* reduce pass 2: same split again, t_j < 2^63.6 -> limbs < 2^51 + 2^17 */
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





    /* Five-accumulator fe_sq, 41 triads. Row A
     * initialises the five accumulators, the other ten products accumulate with
     * per-register SETCC carries, then the same two-pass split reduction as
     * fe_mul. Takes a, 2a_0..2a_3, 19a_3 (RDX) and 19a_4 (RBX) as FE_SQ stages
     * them and 2^51-1 in R8; returns h in RDI R9 R10 RBX RAX. */
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

    /* Patch RAM: 128 triads from U7c00, 4 address units each. U7de0-U7df0 is
     * the lib-micro bootstrap staging area, dead only because the helpers run
     * before patch_ucode here (project note patch-ram-bootstrap-reclaim).
     * 58 + 41 = 99 triads, the last at U7d88. */
    _Static_assert(ARRAY_SZ(mul_patch) + ARRAY_SZ(sq_patch_5acc) <= 128,
                   "fe_mul + fe_sq exceed the 128-triad patch RAM budget");

    const uint64_t mul_addr = 0x7c00;
    const uint64_t sq_addr  = mul_addr + ARRAY_SZ(mul_patch) * 4;
    patch_ucode(mul_addr, mul_patch, ARRAY_SZ(mul_patch));
    hook_match_and_patch(0, 0x0cd8, mul_addr);
    patch_ucode(sq_addr, (ucode_t *)sq_patch_5acc, ARRAY_SZ(sq_patch_5acc));
    hook_match_and_patch(1, 0x0618, sq_addr);
    if (verbose) printf("fe_mul: %d triads at U%04lx (vmwrite hook)\n",
           (int)ARRAY_SZ(mul_patch), (unsigned long)mul_addr);
    if (verbose) printf("fe_sq : %d triads at U%04lx (vmread  hook)\n",
           (int)ARRAY_SZ(sq_patch_5acc), (unsigned long)sq_addr);
}

#endif
