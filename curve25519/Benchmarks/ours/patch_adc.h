/*
 * patch_adc.h -- ours/adc: the five-accumulator fe_mul + fe_sq patches whose
 * carries run through architectural CF, ADD|MOD2 head + ADC|MOD2 tail per
 * product, like x86 add/adc.
 *
 * Copied verbatim from ../../full_curve25519_adc_mod2.c
 * (install_field_patches); only the function name and the verbose flag are
 * new.
 * (the simulators model ADC_MOD2_DRR by name, so they cannot tell whether the
 * macro below really sets MOD2 -- check it by eye.)
 */
#ifndef OURS_PATCH_ADC_H
#define OURS_PATCH_ADC_H

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

/* Upstream lib-micro has no ADC macro either. We place the 64-bit form at
 * 0x37e, the same 0x40 step above _ADC_DSZ32 (0x33e). Defined here so this
 * builds against an unmodified checkout; guarded in case lib-micro adds it. */
#ifndef _ADC_DSZ64
#define _ADC_DSZ64 (0x37eUL << 32)
#endif
#ifndef ADC_DSZ64_DRR
#define ADC_DSZ64_DRR(dst, src0, src1) ( _ADC_DSZ64 | INSTR_DRR(dst, src0, src1) )
#endif
/* ADC that also writes its carry-out to arch CF, so it chains like x86 ADC
 * (project note adc-mod2-writes-cf). Plain ADC_DSZ64 only reads arch CF. */
#define ADC_MOD2_DRR(dst, src0, src1) (ADC_DSZ64_DRR((dst), (src0), (src1)) | MOD2)
/* ADD that writes its carry-out to arch CF WITHOUT reading it, like x86 ADD:
 * the head of each add/adc pair. */
#define ADD_MOD2_DRR(dst, src0, src1) (ADD_DSZ64_DRR((dst), (src0), (src1)) | MOD2)

/* ════════════════════════════════════════════════════════════════════
 * MICROCODE PATCH INSTALLATION
 *
 * fe_mul: five independent 128-bit accumulators (PLAN_kernel_optimization.md
 * section 5.0), replacing the single serial accumulator and its
 * 0->1->2->3->4 carry chain. Structure follows OpenSSL x25519_fe51_mul:
 *
 *   PREP      g_j = 19*b_j for j=1..4, one non-destructive IMUL64L each.
 *   row 0     a0*b_j initialises accumulator j. MUL writes its low half into
 *             srcB, so staging b_j into lo_j IS the initialisation: no
 *             accumulate for the first product of each limb (PLAN 5.1B).
 *   rows 1-4  the other 20 products accumulate with NO inter-limb carry
 *             propagation. THIS IS THE ONLY CHANGE FROM INLINE2. inline2 runs
 *             each accumulator's own SETCC chain in the per-register flags,
 *                 ADD(lo_j, lo_j, lo_p)   SETCC(c, lo_j)
 *                 ADD(hi_p, hi_p, c)      ADD(hi_j, hi_j, hi_p)
 *             and here the carry goes through arch CF, exactly as x86
 *             `add lo, rax / adc hi, rdx`:
 *                 ADD|MOD2(lo_j, lo_j, lo_p)   ADC|MOD2(hi_j, hi_j, hi_p)
 *             The head must be ADD|MOD2: plain microcode ADD does not write
 *             arch CF. The two links of one product are always adjacent, so
 *             no other CF writer sits between them. MUL, ZEROEXT, ADD, SHL,
 *             SHR and OR leave arch CF alone (tests/arch_cf_survival.c).
 *
 *             Do not make the head ADC|MOD2. That version (an ADC|MOD2 head,
 *             which reads CF as well as writing it) is
 *             also correct, since every hi link leaves CF = 0, but each head
 *             then READS CF, which ties every pair to the one before it: 41
 *             serial CF steps per fe_mul, 21 per fe_sq, ~80k per X25519. It
 *             measured 290k against inline2's 250k (2026-10-07). An ADD|MOD2
 *             head starts a fresh CF value, so each pair is its own two-step
 *             chain and the 20 pairs overlap, as x86's renamed flags let
 *             OpenSSL's 40 add/adc do. Dependency depth (1 cyc per CF step): fe_mul 54.6 -> 22.5, fe_sq 34.6 -> 17.6,
 *             against inline2's SETCC 25.4 / 20.5. No head reads CF, so no CF
 *             clear is needed on entry, and the wrappers are inline2's,
 *             unchanged.
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
 * squaring products, with the same ADD|MOD2 + ADC|MOD2 accumulate and
 * two-pass reduction. Wrapper contract: 2^51-1 in R8 (see FE_SQ_R8 for the
 * register-chaining hazard). Unlike inline2's fe_sq it also uses RCX as
 * scratch; every asm block that fires it already clobbers RCX.
 *
 * Register map (fe_mul):
 *   a0..a4  RDI RSI R12 R11 R14   always MUL srcA, so preserved
 *   b0..b4  R15 R13 R9  R10 RBX   from the wrapper, consumed as srcB
 *   g1..g4  TMP0..TMP3            19*b_j
 *   lo0..4  TMP4..TMP8
 *   hi0..4  TMP9..TMP13
 *   mask    RCX
 *   carry   arch CF, live only between a pair's two links
 *   scratch RAX R8 RDX TMP14 TMP15, plus every register as it dies.
 *
 * The generator that produced these arrays is not part of this artifact, so
 * edit them here.
 * ════════════════════════════════════════════════════════════════════ */

__attribute__((unused))   /* each binary installs one patch set */
static void install_adc_patches(int verbose) {
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
      MUL_DSZ64_DRR(TMP14, RSI, RDX), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(TMP15, R9), MUL_DSZ64_DRR(RBX, RSI, TMP15),
      ADD_MOD2_DRR(TMP5, TMP5, RAX), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP10, TMP10, R8), MUL_DSZ64_DRR(RDI, RSI, R10),
      ADD_MOD2_DRR(TMP6, TMP6, RDX), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP11, TMP11, TMP14), ZEROEXT_DSZ64_DR(RAX, TMP3),
      MUL_DSZ64_DRR(R8, RSI, RAX), NOP_SEQWORD },
    { ADD_MOD2_DRR(TMP7, TMP7, TMP15), ADC_MOD2_DRR(TMP12, TMP12, RBX),
      ZEROEXT_DSZ64_DR(RDX, R15), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP14, R12, RDX), ADD_MOD2_DRR(TMP8, TMP8, R10),
      ADC_MOD2_DRR(TMP13, TMP13, RDI), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(TMP15, R13), MUL_DSZ64_DRR(RBX, R12, TMP15),
      ADD_MOD2_DRR(TMP4, TMP4, RAX), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP9, TMP9, R8), MUL_DSZ64_DRR(RDI, R12, R9),
      ADD_MOD2_DRR(TMP6, TMP6, RDX), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP11, TMP11, TMP14), ZEROEXT_DSZ64_DR(RSI, TMP2),
      MUL_DSZ64_DRR(R10, R12, RSI), NOP_SEQWORD },
    { ADD_MOD2_DRR(TMP7, TMP7, TMP15), ADC_MOD2_DRR(TMP12, TMP12, RBX),
      ZEROEXT_DSZ64_DR(RAX, TMP3), NOP_SEQWORD },
    { MUL_DSZ64_DRR(R8, R12, RAX), ADD_MOD2_DRR(TMP8, TMP8, R9),
      ADC_MOD2_DRR(TMP13, TMP13, RDI), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(R12, R15), MUL_DSZ64_DRR(R9, R11, R12),
      ADD_MOD2_DRR(TMP4, TMP4, RSI), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP9, TMP9, R10), MUL_DSZ64_DRR(RDX, R11, R13),
      ADD_MOD2_DRR(TMP5, TMP5, RAX), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP10, TMP10, R8), ZEROEXT_DSZ64_DR(TMP14, TMP1),
      MUL_DSZ64_DRR(TMP15, R11, TMP14), NOP_SEQWORD },
    { ADD_MOD2_DRR(TMP7, TMP7, R12), ADC_MOD2_DRR(TMP12, TMP12, R9),
      ZEROEXT_DSZ64_DR(RBX, TMP2), NOP_SEQWORD },
    { MUL_DSZ64_DRR(RDI, R11, RBX), ADD_MOD2_DRR(TMP8, TMP8, R13),
      ADC_MOD2_DRR(TMP13, TMP13, RDX), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(RSI, TMP3), MUL_DSZ64_DRR(R10, R11, RSI),
      ADD_MOD2_DRR(TMP4, TMP4, TMP14), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP9, TMP9, TMP15), MUL_DSZ64_DRR(R12, R14, R15),
      ADD_MOD2_DRR(TMP5, TMP5, RBX), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP10, TMP10, RDI), MUL_DSZ64_DRR(R9, R14, TMP0),
      ADD_MOD2_DRR(TMP6, TMP6, RSI), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP11, TMP11, R10), MUL_DSZ64_DRR(R13, R14, TMP1),
      ADD_MOD2_DRR(TMP8, TMP8, R15), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP13, TMP13, R12), MUL_DSZ64_DRR(R11, R14, TMP2),
      ADD_MOD2_DRR(TMP4, TMP4, TMP0), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP9, TMP9, R9), MUL_DSZ64_DRR(R15, R14, TMP3),
      ADD_MOD2_DRR(TMP5, TMP5, TMP1), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP10, TMP10, R13), ADD_MOD2_DRR(TMP6, TMP6, TMP2),
      ADC_MOD2_DRR(TMP11, TMP11, R11), NOP_SEQWORD },
    { ADD_MOD2_DRR(TMP7, TMP7, TMP3), ADC_MOD2_DRR(TMP12, TMP12, R15),
      SHL_DSZ64_DRI(TMP9, TMP9, 13), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP0, TMP4, 51), AND_DSZ64_DRR(TMP4, TMP4, RCX),
      OR_DSZ64_DRR(TMP9, TMP0, TMP9), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP10, TMP10, 13), SHR_DSZ64_DRI(TMP1, TMP5, 51),
      AND_DSZ64_DRR(TMP5, TMP5, RCX), NOP_SEQWORD },
    { OR_DSZ64_DRR(TMP10, TMP1, TMP10), SHL_DSZ64_DRI(TMP11, TMP11, 13),
      SHR_DSZ64_DRI(TMP2, TMP6, 51), NOP_SEQWORD },
    { AND_DSZ64_DRR(TMP6, TMP6, RCX), OR_DSZ64_DRR(TMP11, TMP2, TMP11),
      SHL_DSZ64_DRI(TMP12, TMP12, 13), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP0, TMP7, 51), AND_DSZ64_DRR(TMP7, TMP7, RCX),
      OR_DSZ64_DRR(TMP12, TMP0, TMP12), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP13, TMP13, 13), SHR_DSZ64_DRI(TMP1, TMP8, 51),
      AND_DSZ64_DRR(TMP8, TMP8, RCX), NOP_SEQWORD },
    { OR_DSZ64_DRR(TMP13, TMP1, TMP13), ADD_DSZ64_DRR(TMP5, TMP5, TMP9),
      ADD_DSZ64_DRR(TMP6, TMP6, TMP10), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP7, TMP7, TMP11), ADD_DSZ64_DRR(TMP8, TMP8, TMP12),
      SHL_DSZ64_DRI(TMP3, TMP13, 4), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP14, TMP13, TMP13), ADD_DSZ64_DRR(TMP3, TMP3, TMP14),
      ADD_DSZ64_DRR(TMP3, TMP3, TMP13), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP4, TMP4, TMP3), SHR_DSZ64_DRI(TMP9, TMP4, 51),
      AND_DSZ64_DRR(TMP4, TMP4, RCX), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP10, TMP5, 51), AND_DSZ64_DRR(TMP5, TMP5, RCX),
      SHR_DSZ64_DRI(TMP11, TMP6, 51), NOP_SEQWORD },
    { AND_DSZ64_DRR(TMP6, TMP6, RCX), SHR_DSZ64_DRI(TMP12, TMP7, 51),
      AND_DSZ64_DRR(TMP7, TMP7, RCX), NOP_SEQWORD },
    { SHR_DSZ64_DRI(TMP13, TMP8, 51), AND_DSZ64_DRR(TMP8, TMP8, RCX),
      ADD_DSZ64_DRR(R13, TMP5, TMP9), NOP_SEQWORD },
    { ADD_DSZ64_DRR(R9, TMP6, TMP10), ADD_DSZ64_DRR(R10, TMP7, TMP11),
      ADD_DSZ64_DRR(RAX, TMP8, TMP12), NOP_SEQWORD },
    { SHL_DSZ64_DRI(TMP3, TMP13, 4), ADD_DSZ64_DRR(TMP14, TMP13, TMP13),
      ADD_DSZ64_DRR(TMP3, TMP3, TMP14), NOP_SEQWORD },
    { ADD_DSZ64_DRR(TMP3, TMP3, TMP13), ADD_DSZ64_DRR(R15, TMP4, TMP3),
      NOP, END_SEQWORD },
    };





    /* Five-accumulator fe_sq, 31 triads. Row A
     * initialises the five accumulators, the other ten products accumulate with
     * ADD|MOD2 + ADC|MOD2 pairs, then the same two-pass split reduction as
     * fe_mul. Takes a, 2a_0..2a_3, 19a_3 (RDX) and 19a_4 (RBX) as FE_SQ stages
     * them and 2^51-1 in R8; returns h in RDI R9 R10 RBX RAX. */
    static const ucode_t sq_patch_5acc[] = {
    { ZEROEXT_DSZ64_DR(TMP4, RDX), MUL_DSZ64_DRR(TMP9, R9, TMP4),
      ZEROEXT_DSZ64_DR(TMP5, RSI), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP10, R15, TMP5), ZEROEXT_DSZ64_DR(TMP6, R12),
      MUL_DSZ64_DRR(TMP11, R15, TMP6), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(TMP7, R11), MUL_DSZ64_DRR(TMP12, R15, TMP7),
      ZEROEXT_DSZ64_DR(TMP8, R14), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP13, R15, TMP8), ZEROEXT_DSZ64_DR(RAX, RDI),
      MUL_DSZ64_DRR(RCX, RAX, RDI), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP0, R11, RDX), ZEROEXT_DSZ64_DR(TMP1, RSI),
      MUL_DSZ64_DRR(TMP2, TMP1, RSI), NOP_SEQWORD },
    { ADD_MOD2_DRR(TMP4, TMP4, RDI), ADC_MOD2_DRR(TMP9, TMP9, RCX),
      ZEROEXT_DSZ64_DR(TMP3, R12), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP14, R13, TMP3), ADD_MOD2_DRR(TMP5, TMP5, RDX),
      ADC_MOD2_DRR(TMP10, TMP10, TMP0), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP15, R13, R11), ADD_MOD2_DRR(TMP6, TMP6, RSI),
      ADC_MOD2_DRR(TMP11, TMP11, TMP2), NOP_SEQWORD },
    { MUL_DSZ64_DRR(R15, RBX, R13), ADD_MOD2_DRR(TMP7, TMP7, TMP3),
      ADC_MOD2_DRR(TMP12, TMP12, TMP14), NOP_SEQWORD },
    { MUL_DSZ64_DRR(RAX, RBX, R9), ADD_MOD2_DRR(TMP8, TMP8, R11),
      ADC_MOD2_DRR(TMP13, TMP13, TMP15), NOP_SEQWORD },
    { MUL_DSZ64_DRR(RCX, RBX, R10), ADD_MOD2_DRR(TMP4, TMP4, R13),
      ADC_MOD2_DRR(TMP9, TMP9, R15), NOP_SEQWORD },
    { MUL_DSZ64_DRR(TMP0, R14, RBX), ADD_MOD2_DRR(TMP5, TMP5, R9),
      ADC_MOD2_DRR(TMP10, TMP10, RAX), NOP_SEQWORD },
    { ZEROEXT_DSZ64_DR(TMP1, R12), MUL_DSZ64_DRR(TMP2, TMP1, R12),
      ADD_MOD2_DRR(TMP6, TMP6, R10), NOP_SEQWORD },
    { ADC_MOD2_DRR(TMP11, TMP11, RCX), ADD_MOD2_DRR(TMP7, TMP7, RBX),
      ADC_MOD2_DRR(TMP12, TMP12, TMP0), NOP_SEQWORD },
    { ADD_MOD2_DRR(TMP8, TMP8, R12), ADC_MOD2_DRR(TMP13, TMP13, TMP2),
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
     * 45 + 31 = 76 triads, the last at U7d2c. */
    _Static_assert(ARRAY_SZ(mul_patch) + ARRAY_SZ(sq_patch_5acc) <= 128,
                   "fe_mul + fe_sq exceed the 128-triad patch RAM budget");

    const uint64_t mul_addr = 0x7c00;
    const uint64_t sq_addr  = mul_addr + ARRAY_SZ(mul_patch) * 4;
    patch_ucode(mul_addr, mul_patch, ARRAY_SZ(mul_patch));
    hook_match_and_patch(0, 0x0cd8, mul_addr);
    patch_ucode(sq_addr, (ucode_t *)sq_patch_5acc, ARRAY_SZ(sq_patch_5acc));
    hook_match_and_patch(1, 0x0618, sq_addr);
    if (verbose) printf("fe_mul: ADD|MOD2+ADC|MOD2 patch, %d triads at U%04lx (vmwrite hook)\n",
           (int)ARRAY_SZ(mul_patch), (unsigned long)mul_addr);
    if (verbose) printf("fe_sq : ADD|MOD2+ADC|MOD2 patch, %d triads at U%04lx (vmread  hook)\n",
           (int)ARRAY_SZ(sq_patch_5acc), (unsigned long)sq_addr);
}

#endif
