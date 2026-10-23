/*
 * keccak_s2n_glue.S — one-argument entry for s2n-bignum's Keccak-f[1600].
 *
 * s2n-bignum exports sha3_keccak_f1600(uint64_t a[25], const uint64_t rc[24]);
 * the harnesses call every backend as perm(state). keccak_s2n_perm supplies the
 * 24 round constants in RSI and tail-jumps into s2n's code, so the timed path is
 * s2n's own function plus one lea and one jmp (no extra frame, no call/ret).
 * Linked with sha3_keccak_f1600.o into keccak_s2n_bignum.o by the Makefile.
 */
        .intel_syntax noprefix
        .text
        .globl  keccak_s2n_perm
        .type   keccak_s2n_perm, @function
keccak_s2n_perm:
        lea     rsi, [rip + keccak_s2n_rc]
        jmp     sha3_keccak_f1600
        .size   keccak_s2n_perm, .-keccak_s2n_perm

        .section .rodata
        .balign 64
keccak_s2n_rc:
        .quad   0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000
        .quad   0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009
        .quad   0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a
        .quad   0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003
        .quad   0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a
        .quad   0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008

        .section .note.GNU-stack, "", @progbits
