/*
 * ours.h -- our complete 5x51 X25519, shared by ours/setcc and ours/adc.
 *
 * The two variants differ ONLY in the microcode patches behind the two hooked
 * instructions (vmwrite -> fe_mul, vmread -> fe_sq):
 *   ours/setcc  patch_setcc.h   per-accumulator carries through SETCC
 *   ours/adc    patch_adc.h     carries through arch CF, ADD|MOD2 + ADC|MOD2
 * Everything else -- the FE_* wrapper macros, the register-chained inline-asm
 * Montgomery ladder, the Fermat inversion, encoding -- is this file, so one
 * x25519_ours() serves both: install a variant's patches, then call it.
 * Each benchmark process installs one variant, once.
 *
 * Copied verbatim from ../../full_curve25519_inline2.c (2026-10-08): the types
 * and offsets (its lines 44-129), the IMUL64L macros (150-156) and the
 * wrappers through x25519() (464-1065, renamed x25519_ours). That code is
 * byte-identical in ../../full_curve25519_adc_mod2.c apart from one comment.
 * New here: the one-shot uc_fe_mul/uc_fe_sq helpers.
 *
 * Include patch.h, ucode_macro.h and misc.h before this file.
 */
#ifndef OURS_H
#define OURS_H

#include <stdint.h>
#include <string.h>
#include <stdio.h>

typedef uint64_t fe[5];
#define MASK51 0x7FFFFFFFFFFFFULL

/*
 * Ladder state: all field elements live in this struct on the stack,
 * accessed by the inline asm via [rbp + offset]. Offsets are fixed
 * constants the asm uses directly.
 */
typedef struct {
    uint64_t x1[5];     /* offset 0   */
    uint64_t x2[5];     /* offset 40  */
    uint64_t z2[5];     /* offset 80  */
    uint64_t x3[5];     /* offset 120 */
    uint64_t z3[5];     /* offset 160 */
    uint64_t A[5];      /* offset 200 */
    uint64_t AA[5];     /* offset 240 */
    uint64_t B[5];      /* offset 280 */
    uint64_t BB[5];     /* offset 320 */
    uint64_t E[5];      /* offset 360 */
    uint64_t C[5];      /* offset 400 */
    uint64_t D[5];      /* offset 440 */
    uint64_t DA[5];     /* offset 480 */
    uint64_t CB[5];     /* offset 520 */
    uint64_t t0[5];     /* offset 560 */
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

/* Invert state - local to fe_invert, kept on stack with rbp pointing at it
 * during the inverse exponentiation. Held in its own struct so the offsets
 * are independent of ladder_state_t. */
typedef struct {
    uint64_t z[5];     /* offset 0   - input copy */
    uint64_t z2[5];    /* offset 40  */
    uint64_t z9[5];    /* offset 80  */
    uint64_t z11[5];   /* offset 120 */
    uint64_t t[5];     /* offset 160 */
    uint64_t t0[5];    /* offset 200 */
    uint64_t t1[5];    /* offset 240 */
    uint64_t t2[5];    /* offset 280 */
    uint64_t t3[5];    /* offset 320 */
    uint64_t sc[5];    /* offset 360 -- ping-pong scratch for fe_invert's runs */
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

/* Two-step stringify so macro args like X2_OFF expand to their integer
 * literal before being placed into the asm string. */
#define _S(x) #x
#define S(x) _S(x)

/* -- fe_sq: the five-accumulator patch (sq_patch_5acc) ------------------
 * It hard-resets the machine when fe_sq firings are REGISTER-CHAINED (one
 * firing's outputs renamed straight into the next firing's inputs), and only
 * then: 2000 full X25519 with no chained firing passed (test_sq_soak ladder
 * 2000, ~5.1M firings). So every squaring here round-trips through memory,
 * including fe_invert's Fermat chain (one firing per asm block, ping-pong
 * through a scratch slot), and fe_sq_ucode_n is n separate calls. See
 * five_accu.md.
 *
 * Wrapper contract: 2^51-1 in R8, the patch's AND mask. (fe_mul takes it in
 * RCX, loaded by FE_MUL.) */
#define FE_SQ_R8 "mov r8, 0x7FFFFFFFFFFFF\n\t"

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

/* _IMUL64L_DSZ64 (0x264) is in opcode.h but inst.h generates no macro for it.
 * It is a NON-DESTRUCTIVE 64-bit low multiply: both sources survive, unlike
 * MUL_DSZ64_*, whose srcB receives the low half. Verified on hardware by
 * probe_opsem entries [2] and [3] (probe_opsem_out.txt).
 */
#ifndef IMUL64L_DSZ64_DRR
#define IMUL64L_DSZ64_DRR(d, a, b) (_IMUL64L_DSZ64 | INSTR_DRR(d, a, b))
#endif
#ifndef IMUL64L_DSZ64_DRI
#define IMUL64L_DSZ64_DRI(d, a, i) (_IMUL64L_DSZ64 | INSTR_DRI(d, a, i))
#endif


#include "patch_setcc.h"
#include "patch_adc.h"

/* ====================================================================
 * INLINE-ASM FIELD-OP MACROS
 *
 * Each macro emits an asm string fragment. The fragments share the state
 * pointer in RBP and clobber the same set of GP regs across the whole
 * asm block - GCC only spills around the outer asm block, not between
 * sub-ops. The patches' caller conventions are matched per op.
 *
 * Operand convention: offsets are integer literals relative to [rbp].
 *
 * NOTE: rbp is *not* a callee-saved reg requirement here - we save/restore
 * it manually at the asm block boundary so we can use it as the state
 * pointer throughout.
 * ==================================================================== */

/* FE_MUL(out, a, b) - fires the mul patch with inputs from [rbp+a/b],
 * stores h[0..4] to [rbp+out].
 *
 * rcx carries 2^51-1: the patch masks each limb with one AND against it
 * instead of a SHL13/SHR13 pair. One extra caller instruction (~0.3 cyc of
 * invocation floor) for 7 fewer patch ops. rcx was already free - it is the
 * vmwrite operand and the old patch only used it as MUL's high destination.
 *
 * The load and store order is load-bearing: both run limb 0 -> limb 4, and
 * a descending load order puts the first load of one op one instruction
 * after the last store of the previous op, which costs ~30 cyc on Goldmont
 * (probe_ldorder; see the note above FE_SQ). Do not reorder the memory ops.
 * There is no xor eax / xor r8d: the patch writes RAX and R8 before reading
 * them, so zeroing them only added two caller instructions per firing, worth
 * 1.04 cyc/mul (probe_patch_loads, arm A2). */
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

/* FE_SQ(out, a) - fires the sq patch (vmread). Precompute 2*a and 19*a
 * happen inline. Output: rdi=h0, r9=h1, r10=h2, rbx=h3, rax=h4.
 *
 * The five loads MUST run limb 0 -> limb 4, matching the store order below.
 * They used to run 4 -> 0. Stores are ascending, so a descending load order
 * makes the first load of one op read [x+32] one instruction after the last
 * store of the previous op wrote it; that store-to-load distance of 1 costs
 * ~30 cyc on Goldmont. Ascending puts each load five instructions after its
 * producing store and the stall disappears: measured 122.3 -> 81.8 cyc per
 * dependent fe_sq, with the patch untouched (probe_ldorder, arms A2/A3/B1/B2).
 * Do not "tidy" these back into descending order. */
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

/* FE_ADD(out, a, b) - 5-limb add. Restructured to leave the 5 result limbs
 * in {rdi, rsi, r12, r11, r14} so a downstream FE_SQ_FROM_REGS / FE_MUL_FROM_REGS_A
 * can pick them up without reloading from memory. We still store to [out] because
 * non-chained consumers (downstream MUL/SUB in other slots) need the memory copy.
 *
 * Cost vs original (rax-through-serialization): identical instruction count
 * (5 loads + 5 adds + 5 stores), no extra movs. */
#define FE_ADD(out, a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"   "add rdi, [rbp + " S(b) " + 0]\n\t"   "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"   "add rsi, [rbp + " S(b) " + 8]\n\t"   "mov [rbp + " S(out) " + 8],  rsi\n\t" \
    "mov r12, [rbp + " S(a) " + 16]\n\t"  "add r12, [rbp + " S(b) " + 16]\n\t"  "mov [rbp + " S(out) " + 16], r12\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t"  "add r11, [rbp + " S(b) " + 24]\n\t"  "mov [rbp + " S(out) " + 24], r11\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t"  "add r14, [rbp + " S(b) " + 32]\n\t"  "mov [rbp + " S(out) " + 32], r14\n\t"

/* FE_SUB(out, a, b) - adds 2*p as bias to keep limbs positive.
 * limb 0 bias: 2*(2^51 - 19) = 0xFFFFFFFFFFFDA
 * limbs 1..4 bias: 2*(2^51 - 1) = 0xFFFFFFFFFFFFE
 *
 * Restructured to leave 5 result limbs in {rdi, rsi, r12, r11, r14} (chain-ready).
 * Tightened: the limb1..4 bias is loaded into rcx once and reused, saving 3 movs
 * relative to the original macro. */
#define FE_SUB(out, a, b) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  "mov rcx, 0xFFFFFFFFFFFDA\n\t" "add rdi, rcx\n\t" "sub rdi, [rbp + " S(b) " + 0]\n\t"  "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov rcx, 0xFFFFFFFFFFFFE\n\t" \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  "add rsi, rcx\n\t" "sub rsi, [rbp + " S(b) " + 8]\n\t"  "mov [rbp + " S(out) " + 8],  rsi\n\t" \
    "mov r12, [rbp + " S(a) " + 16]\n\t" "add r12, rcx\n\t" "sub r12, [rbp + " S(b) " + 16]\n\t" "mov [rbp + " S(out) " + 16], r12\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" "add r11, rcx\n\t" "sub r11, [rbp + " S(b) " + 24]\n\t" "mov [rbp + " S(out) " + 24], r11\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t" "add r14, rcx\n\t" "sub r14, [rbp + " S(b) " + 32]\n\t" "mov [rbp + " S(out) " + 32], r14\n\t"

/* FE_ADD_NOSTORE / FE_SUB_NOSTORE - FE_ADD / FE_SUB without the store-back.
 *
 * The five result limbs are left in {rdi, rsi, r12, r11, r14}, ready for
 * FE_SQ_FROM_REGS / FE_MUL_FROM_REGS_A, and nothing is written to memory.
 *
 * ladder_step issued 90 stores per iteration and 25 of them -- 28% -- were
 * never read back:
 *   C, D   consumed from registers by the CB and DA multiplies; the C_OFF and
 *          D_OFF slots are not read by anything, in this step or the next.
 *   t0     written FOUR times per step, three of them dead: the add is
 *          overwritten by the sub, the sub is overwritten by mul121665 (which
 *          writes t0 without reading it), and the tail add is consumed from
 *          registers by the z2 multiply.
 * That was 6,375 dead stores per X25519. Each affected op drops from 15
 * instructions to 10.
 *
 * ONLY use these where the [rbp+out] slot is provably dead. The whole point is
 * that nothing reloads it, so a later consumer that expects the memory copy
 * would silently read a stale value from the previous ladder iteration. */
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

/* FE_SQ_FROM_REGS(out) - assumes a[0..4] already in {rdi, rsi, r12, r11, r14}.
 * Skips the 5 input loads vs FE_SQ; everything else identical. */
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

/* FE_MUL_FROM_REGS_A(out, b) - assumes a[0..4] already in {rdi, rsi, r12, r11, r14}.
 * Only loads b into {r15, r13, r9, r10, rbx}; skips the 5 input loads for a. */
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

/* Use a C helper for fe_mul121665 - too complex to write cleanly inline. */

/* ====================================================================
 * INVERT MACROS -- one field op each, memory to memory. The sq patch's
 * caller convention is
 *   inputs : a in {rdi, rsi, r12, r11, r14}
 *   outputs: h in {rdi, r9, r10, rbx, rax}
 * ==================================================================== */

/* Load `a` from [rbp+a_off] into the sq input registers. */
#define INV_SQ_LOAD(a) \
    "mov rdi, [rbp + " S(a) " + 0]\n\t"  \
    "mov rsi, [rbp + " S(a) " + 8]\n\t"  \
    "mov r12, [rbp + " S(a) " + 16]\n\t" \
    "mov r11, [rbp + " S(a) " + 24]\n\t" \
    "mov r14, [rbp + " S(a) " + 32]\n\t"


/* One squaring: inputs in the sq input regs, outputs in the sq output regs.
 * Identical to FE_SQ's body without the load/store wrappers. */
#define INV_SQ_OP \
    "lea r15, [rdi + rdi]\n\t"           \
    "lea r13, [rsi + rsi]\n\t"           \
    "lea r9,  [r12 + r12]\n\t"           \
    "lea r10, [r11 + r11]\n\t"           \
    "imul rbx, r14, 19\n\t"              \
    "imul rdx, r11, 19\n\t"              \
    FE_SQ_R8                             \
    ".byte 0x0f, 0x78, 0xca\n\t"

/* Store sq output to [rbp+out_off]. */
#define INV_SQ_STORE(out) \
    "mov [rbp + " S(out) " + 0],  rdi\n\t" \
    "mov [rbp + " S(out) " + 8],  r9\n\t"  \
    "mov [rbp + " S(out) " + 16], r10\n\t" \
    "mov [rbp + " S(out) " + 24], rbx\n\t" \
    "mov [rbp + " S(out) " + 32], rax\n\t"


/* Single sq (memory -> memory). */
#define INV_SQ(out, a) INV_SQ_LOAD(a) INV_SQ_OP INV_SQ_STORE(out)

/* MUL (memory -> memory). Standalone; standard fe_mul caller convention. */
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

/* ====================================================================
 * LADDER STEP - one big asm block per iteration
 * ==================================================================== */

static void fe_mul121665_native(uint64_t *out, const uint64_t *a) {
    /* Multiply by the 17-bit constant WITHOUT a 128-bit product.
     *
     * The 128-bit form is what made this slow. `(__uint128_t)a[i] * 121665`
     * compiles to x86's one-operand `mul r64`, which implicitly reads RAX and
     * writes RDX:RAX -- so all five products contend for the SAME register
     * pair and serialise, no matter how independent the source looks. Goldmont
     * has no BMI2, so there is no `mulx` to escape with. An earlier rewrite
     * made the five products independent in C and kept __uint128_t; it bought
     * 0.9 cyc, because the bottleneck was never the source-level dependency.
     *
     * The 128-bit product is not needed. a_i < 2^53 (the ladder feeds
     * E = AA - BB carrying FE_SUB's 2p bias) and K = 121665 < 2^17, so
     * splitting a_i at 26 bits keeps every intermediate inside 64 bits:
     *
     *   hi = a>>26          lo = a & (2^26-1)
     *   P  = hi*K < 2^44    Q  = lo*K < 2^43          a*K = P*2^26 + Q
     *   P1 = P>>25          P0 = P & (2^25-1)
     *   low = (P0<<26) + Q  < 2^51 + 2^43             a*K = P1*2^51 + low
     *   q  = P1 + (low>>51) r  = low & MASK51
     *
     * Every multiply is now 3-operand `imul r64, r64, imm` -- one destination,
     * no RDX:RAX -- so the five run genuinely in parallel. Verified
     * bit-identical to the 128-bit form over 25 edge cases and 2,000,000
     * random inputs at limbs < 2^53.
     *
     * OpenSSL reaches the same place by shipping x25519_fe51_mul121666 as hand
     * written assembly; this is the portable equivalent, and it is most of the
     * ladder gap to their implementation.
     *
     * Congruence is unchanged: sum_i a_i*K*2^(51i) = sum_i r_i 2^(51i)
     * + sum_i q_i 2^(51(i+1)), and the q_4 term is q_4 2^255 = 19 q_4 (mod p). */
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
    /* The asm block computes:
     *   A   = x2 + z2
     *   AA  = sq(A)
     *   B   = x2 - z2
     *   BB  = sq(B)
     *   E   = AA - BB
     *   C   = x3 + z3
     *   D   = x3 - z3
     *   DA  = mul(D, A)
     *   CB  = mul(C, B)
     *   t0  = DA + CB
     *   x3' = sq(t0)        (stored to st->x3)
     *   t0  = DA - CB
     *   z3' = sq(t0)        (temp; next mul finishes z3)
     *   z3  = mul(x1, z3')  (stored to st->z3 via t0 slot then mul'd)
     *   x2' = mul(AA, BB)   (stored to st->x2)
     * And then in C (outside asm):
     *   t0  = mul121665(E)
     *   t0  = AA + t0
     *   z2  = mul(E, t0)
     *
     * We split: do the bulk in asm; do mul121665 + the final two in C with
     * the regular asm wrappers (they pay the wrapper cost, but it's only
     * 2 ops out of 9 per iter). */

    register ladder_state_t *_st asm("rbp") = st;
    asm volatile(
        /* 1->2 chain: FE_ADD leaves A in {rdi,rsi,r12,r11,r14}; SQ_FROM_REGS picks up. */
        FE_ADD(A_OFF, X2_OFF, Z2_OFF)
        FE_SQ_FROM_REGS(AA_OFF)
        /* 3->4 chain: FE_SUB leaves B in same regs. */
        FE_SUB(B_OFF, X2_OFF, Z2_OFF)
        FE_SQ_FROM_REGS(BB_OFF)
        /* Step 5: full FE_SUB (AA, BB both reloaded from memory). */
        FE_SUB(E_OFF, AA_OFF, BB_OFF)
        /* Reordered 7-8-6-9 to enable two chains in this section.
         * Original: 6 (C=ADD), 7 (D=SUB), 8 (DA=MUL(D,A)), 9 (CB=MUL(C,B)) - one chain (7->8).
         * Reordered: 7 (D=SUB) -> 8 (DA chain), 6 (C=ADD) -> 9 (CB chain) - two chains.
         * Dataflow is preserved: C and D both depend only on x3, z3, and feed different muls. */
        FE_SUB_NOSTORE(X3_OFF, Z3_OFF)          /* D: consumed from regs below */
        FE_MUL_FROM_REGS_A(DA_OFF, A_OFF)
        FE_ADD_NOSTORE(X3_OFF, Z3_OFF)          /* C: consumed from regs below */
        FE_MUL_FROM_REGS_A(CB_OFF, B_OFF)
        /* 10->11 chain: FE_ADD leaves t0 in regs; SQ_FROM_REGS picks up. */
        FE_ADD_NOSTORE(DA_OFF, CB_OFF)          /* t0: overwritten by the sub */
        FE_SQ_FROM_REGS(X3_OFF)
        /* 12->13 chain: FE_SUB leaves t0 in regs; SQ_FROM_REGS picks up. */
        FE_SUB_NOSTORE(DA_OFF, CB_OFF)          /* t0: overwritten by mul121665 */
        FE_SQ_FROM_REGS(Z3_OFF)
        /* Step 14: full FE_MUL (sq output regs don't match mul input regs; reload from mem). */
        FE_MUL(Z3_OFF, X1_OFF, Z3_OFF)
        /* Step 15: full FE_MUL. */
        FE_MUL(X2_OFF, AA_OFF, BB_OFF)
        :
        : "r"(_st)
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "memory", "cc"
    );

    /* Tail: mul121665 (C) + add + mul (inline asm).
     * Chain: FE_ADD leaves t0 in {rdi,rsi,r12,r11,r14}; FE_MUL_FROM_REGS_A
     * consumes t0 as its `a` operand. Since mul commutes, t0*E = E*t0 = z2. */
    fe_mul121665_native(st->t0, st->E);
    register ladder_state_t *_st2 asm("rbp") = st;
    asm volatile(
        FE_ADD_NOSTORE(AA_OFF, T0_OFF)          /* t0: consumed from regs by z2 */
        FE_MUL_FROM_REGS_A(Z2_OFF, E_OFF)
        :
        : "r"(_st2)
        : "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
          "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
          "memory", "cc"
    );
}

/* ====================================================================
 * cswap, frombytes, tobytes, invert, ladder driver
 * (these match full_curve25519.c's 5x51 implementations)
 * ==================================================================== */

static inline void fe_cswap(uint64_t a[5], uint64_t b[5], uint64_t swap) {
    swap = (uint64_t)(-(int64_t)swap);
    for (int i = 0; i < 5; i++) {
        uint64_t x = (a[i] ^ b[i]) & swap;
        a[i] ^= x;
        b[i] ^= x;
    }
}

/* MEASURED AND REJECTED: merging the ladder's two conditional swaps.
 *
 * ladder_state_t lays x2,z2 out contiguously (40..119) and x3,z3 contiguously
 * (120..199), so `fe_cswap(x2,x3,s); fe_cswap(z2,z3,s);` is one conditional
 * swap of two adjacent 10-limb blocks. A single 10-iteration fe_cswap2 derived
 * the mask once instead of twice and let the compiler vectorise all 80 bytes
 * in one loop; gcc duly emitted pxor/pand/pxor over XMM.
 *
 * It was SLOWER: +187 cyc/X25519 at gcc-11 -O3, against a control band of
 * -11..+21 across the four untouched contenders in the same run, so the sign
 * is not in doubt. The wider loop spills in the ladder's hot path where the
 * two narrow ones did not. Two 5-limb cswaps stay.
 *
 * Do not retry this without a reason to expect different register pressure. */
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
    /* Now h < 2^255 + 18; conditionally subtract p. */
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

/* fe_invert - inverse via Fermat's little theorem, z^(p-2): 254 squarings
 * in runs of 1, 2, 1, 5, 10, 20, 10, 50, 100, 50, 5, separated by 11 muls.
 * The result lands in the t1 slot and is copied to *out. */
/* One firing per asm block: the Fermat chain is emitted as a sequence of
 * small asm blocks instead of one ~2,500-instruction block
 * containing all 266 firings.
 *
 * Why: measured 2026-09-15 on the five-accumulator fe_sq, the variable that
 * separates every clean run from every crash is FIRINGS PER ASM BLOCK, not the
 * patch, the operands, the wrapper, the RCX state, or firing density --
 *     tight 100,000 firings, 1 per block            PASS
 *     mixed 200,000 firings, 1 per block            PASS
 *     ctx   100,000 firings, 2 per block            PASS
 *     step  180,000 firings, 7 and 2 per block      PASS   (full ladder_step)
 *     rfc     2,561 firings, 266 in ONE block       HARD RESET
 * 580,000 firings survived at <= 7 per block; the only construct never
 * exercised below a crash was fe_invert's single giant block.
 *
 * Each INV_BLK is its own asm volatile, so the compiler re-establishes RBP and
 * the firing sits in a block the size of the ones proven above. The runs
 * ping-pong through a scratch slot: storing and reloading the SAME address
 * back to back is the ~30 cycle store-to-load stall probe_ldorder found. */
#define INV_CLOB "rax","rbx","rcx","rdx","rsi","rdi", \
                 "r8","r9","r10","r11","r12","r13","r14","r15","memory","cc"
#define INV_BLK(code) do {                                        \
        register invert_state_t *_b asm("rbp") = &st;             \
        asm volatile(code : : "r"(_b) : INV_CLOB);                \
    } while (0)
/* n squarings a -> dst. ODD: one, then (n-1)/2 ping-pong pairs.  */
#define INV_C_ODD(dst, a, pairs) do {                             \
        INV_BLK(INV_SQ(dst, a));                                  \
        for (int _i = 0; _i < (pairs); _i++) {                    \
            INV_BLK(INV_SQ(ISC_OFF, dst));                        \
            INV_BLK(INV_SQ(dst, ISC_OFF)); } } while (0)
/* EVEN: two, then (n-2)/2 pairs. */
#define INV_C_EVEN(dst, a, pairs) do {                            \
        INV_BLK(INV_SQ(ISC_OFF, a));                              \
        INV_BLK(INV_SQ(dst, ISC_OFF));                            \
        for (int _i = 0; _i < (pairs); _i++) {                    \
            INV_BLK(INV_SQ(ISC_OFF, dst));                        \
            INV_BLK(INV_SQ(dst, ISC_OFF)); } } while (0)

static void fe_invert(uint64_t out[5], const uint64_t z[5]) {
    invert_state_t st;
    st.z[0] = z[0]; st.z[1] = z[1]; st.z[2] = z[2]; st.z[3] = z[3]; st.z[4] = z[4];

    INV_BLK(INV_SQ(IZ2_OFF, IZ_OFF));                 /* z2  = z^2        */
    INV_C_EVEN(IT_OFF, IZ2_OFF, 0);                   /* t   = z2^(2^2)   */
    INV_BLK(INV_MUL(IZ9_OFF,  IT_OFF,  IZ_OFF));      /* z9  = t * z      */
    INV_BLK(INV_MUL(IZ11_OFF, IZ9_OFF, IZ2_OFF));     /* z11 = z9 * z2    */
    INV_BLK(INV_SQ(IT_OFF, IZ11_OFF));                /* t   = z11^2      */
    INV_BLK(INV_MUL(IT0_OFF, IT_OFF, IZ9_OFF));       /* t0  = t * z9     */
    INV_C_ODD (IT1_OFF, IT0_OFF, 2);                  /* t1  = t0^(2^5)   */
    INV_BLK(INV_MUL(IT1_OFF, IT1_OFF, IT0_OFF));
    INV_C_EVEN(IT2_OFF, IT1_OFF, 4);                  /* t2  = t1^(2^10)  */
    INV_BLK(INV_MUL(IT2_OFF, IT2_OFF, IT1_OFF));
    INV_C_EVEN(IT3_OFF, IT2_OFF, 9);                  /* t3  = t2^(2^20)  */
    INV_BLK(INV_MUL(IT3_OFF, IT3_OFF, IT2_OFF));
    INV_C_EVEN(IT3_OFF, IT3_OFF, 4);                  /* t3  = t3^(2^10)  */
    INV_BLK(INV_MUL(IT1_OFF, IT3_OFF, IT1_OFF));
    INV_C_EVEN(IT2_OFF, IT1_OFF, 24);                 /* t2  = t1^(2^50)  */
    INV_BLK(INV_MUL(IT2_OFF, IT2_OFF, IT1_OFF));
    INV_C_EVEN(IT3_OFF, IT2_OFF, 49);                 /* t3  = t2^(2^100) */
    INV_BLK(INV_MUL(IT3_OFF, IT3_OFF, IT2_OFF));
    INV_C_EVEN(IT3_OFF, IT3_OFF, 24);                 /* t3  = t3^(2^50)  */
    INV_BLK(INV_MUL(IT1_OFF, IT3_OFF, IT1_OFF));
    INV_C_ODD (IT1_OFF, IT1_OFF, 2);                  /* t1  = t1^(2^5)   */
    INV_BLK(INV_MUL(IT1_OFF, IT1_OFF, IZ11_OFF));     /* out = t1 * z11   */

    out[0] = st.t1[0]; out[1] = st.t1[1]; out[2] = st.t1[2];
    out[3] = st.t1[3]; out[4] = st.t1[4];
}

static void scalar_clamp(uint8_t s[32]) {
    s[0] &= 248; s[31] &= 127; s[31] |= 64;
}

static void x25519_ours(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]) {
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
    /* Final x2 = x2 * z2 - inlined as one FE_MUL on the ladder_state. */
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

/* ====================================================================
 * VARIANTS -- the two patch sets this file's code runs on:
 * install_setcc_patches() (patch_setcc.h) and install_adc_patches()
 * (patch_adc.h).
 *
 * Both pairs start at U7c00 and use the same two hooks, and they do not fit in
 * the 128-triad patch RAM together (58+41 and 45+31). So a process installs
 * exactly one of them, once (BENCH_VARIANT in ../common.h). Do not reinstall
 * or switch patch sets inside a running process: full sweeps that did that 40
 * times per process wedged the bench core twice (2026-10-08 and 2026-10-09).
 * ==================================================================== */

/* One field op through whatever patch is installed, C-callable, for the
 * correctness checks. One firing per asm block, memory round trip on both
 * sides: the shape the five-accumulator fe_sq is proven stable in (FE_SQ_R8).
 * The asm points RBP at the scratch state itself and restores it from a
 * RIP-relative slot, so no C operand is bound to RBP and the helpers are right
 * whether or not the compiler uses RBP as a frame pointer. */
__attribute__((used)) static ladder_state_t ours_scratch;
__attribute__((used)) static uint64_t ours_rbp_save;
#define OURS_ASM(BODY)                                                     \
    asm volatile("mov qword ptr [rip + ours_rbp_save], rbp\n\t"            \
                 "lea rbp, [rip + ours_scratch]\n\t"                       \
                 BODY                                                      \
                 "mov rbp, qword ptr [rip + ours_rbp_save]\n\t"            \
                 ::: "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", \
                     "r10", "r11", "r12", "r13", "r14", "r15", "memory", "cc")

__attribute__((unused))
static void uc_fe_mul(uint64_t out[5], const uint64_t a[5], const uint64_t b[5]) {
    memcpy(ours_scratch.A, a, 40);
    memcpy(ours_scratch.z2, b, 40);
    OURS_ASM(FE_MUL(B_OFF, A_OFF, Z2_OFF));
    memcpy(out, ours_scratch.B, 40);
}

__attribute__((unused))
static void uc_fe_sq(uint64_t out[5], const uint64_t a[5]) {
    memcpy(ours_scratch.A, a, 40);
    OURS_ASM(FE_SQ(B_OFF, A_OFF));
    memcpy(out, ours_scratch.B, 40);
}

#endif /* OURS_H */
