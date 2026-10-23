SECTION .text
	GLOBAL fiat_curve25519_carry_mul
fiat_curve25519_carry_mul:
mov r10, rdx; spill arg2 to r10
mov rax, [rsi + 0x0]; arg1[0] -> rax
mul [r10 + 0x0]; x25_1:x25_0 <- arg1[0] * arg2[0]
mov r11, rax; spill x25_0 to r11
mov rcx, rdx; spill x25_1 to rcx
mov rax, [rsi + 0x8]; arg1[1] -> rax
mul [r10 + 0x18]; x17_1:x17_0 <- arg1[1] * arg2[3]
imul r8, [ r10 + 0x18 ], 0x13; x10001 <- arg2[3] * 0x13
mov r9, rax; spill x17_0 to r9
mov [ rsp - 0x80 ], rbx; spilling calSv-rbx to mem
mov rbx, rdx; spill x17_1 to rbx
mov rax, [rsi + 0x20]; arg1[4] -> rax
mul r8; x2_1:x2_0 <- arg1[4] * x10001
mov [ rsp - 0x78 ], rbp; spilling calSv-rbp to mem
mov rbp, [ r10 + 0x10 ]; load m64 arg2[2] to register64
mov [ rsp - 0x70 ], r12; spilling calSv-r12 to mem
mov [ rsp - 0x68 ], r13; spilling calSv-r13 to mem
lea r12, [rbp + 8 * rbp]; TMP <- arg2[2] * 9 
lea r13, [rbp + 2 * r12]; x10002 <- arg2[2]*19: arg2[2] + 2 * TMP = arg2[2] + 2 * 9 * arg2[2]
mov rbp, rax; spill x2_0 to rbp
mov r12, rdx; spill x2_1 to r12
mov rax, [rsi + 0x18]; arg1[3] -> rax
mul r13; x7_1:x7_0 <- arg1[3] * x10002
mov [ rsp - 0x60 ], r14; spilling calSv-r14 to mem
mov r14, rax; spill x7_0 to r14
mov [ rsp - 0x58 ], r15; spilling calSv-r15 to mem
mov r15, rdx; spill x7_1 to r15
mov rax, [rsi + 0x0]; arg1[0] -> rax
mul [r10 + 0x18]; x22_1:x22_0 <- arg1[0] * arg2[3]
mov [ rsp - 0x200 ], rax; spill x22_0 to stack
mov [ rsp - 0x208 ], rdx; spill x22_1 to stack
mov rax, [rsi + 0x10]; arg1[2] -> rax
mul r8; x9_1:x9_0 <- arg1[2] * x10001
mov [ rsp - 0x50 ], rdi; spilling out1 to mem
mov rdi, [ r10 + 0x8 ]; load m64 arg2[1] to register64
mov [ rsp - 0x48 ], rbx; spilling x17_1 to mem
mov [ rsp - 0x40 ], r9; spilling x17_0 to mem
lea rbx, [rdi + 8 * rdi]; TMP <- arg2[1] * 9 
lea r9, [rdi + 2 * rbx]; x10003 <- arg2[1]*19: arg2[1] + 2 * TMP = arg2[1] + 2 * 9 * arg2[1]
mov rdi, rax; spill x9_0 to rdi
mov rbx, rdx; spill x9_1 to rbx
mov rax, [rsi + 0x18]; arg1[3] -> rax
mul [r10 + 0x0]; x13_1:x13_0 <- arg1[3] * arg2[0]
mov [ rsp - 0x38 ], r12; spilling x2_1 to mem
mov r12, [ r10 + 0x20 ]; load m64 arg2[4] to register64
mov [ rsp - 0x30 ], rbp; spilling x2_0 to mem
mov [ rsp - 0x28 ], rcx; spilling x25_1 to mem
lea rbp, [r12 + 8 * r12]; TMP <- arg2[4] * 9 
lea rcx, [r12 + 2 * rbp]; x10000 <- arg2[4]*19: arg2[4] + 2 * TMP = arg2[4] + 2 * 9 * arg2[4]
mov rbp, rax; spill x13_0 to rbp
mov r12, rdx; spill x13_1 to r12
mov rax, [rsi + 0x20]; arg1[4] -> rax
mul rcx; x1_1:x1_0 <- arg1[4] * x10000
add rax, rbp; could be done better, if r0 has been u8 as well
adc r12, rdx
mov rbp, rax; spill x10010_0 to rbp
mov rax, [rsi + 0x20]; arg1[4] -> rax
mul r9; x4_1:x4_0 <- arg1[4] * x10003
mov r9, rax; spill x4_0 to r9
mov [ rsp - 0x210 ], rdx; spill x4_1 to stack
mov rax, [rsi + 0x20]; arg1[4] -> rax
mul r13; x3_1:x3_0 <- arg1[4] * x10002
add r9, r14; could be done better, if r0 has been u8 as well
adc r15, [ rsp - 0x210 ]
add r9, rdi; could be done better, if r0 has been u8 as well
adc rbx, r15
mov r13, rax; spill x3_0 to r13
mov r14, rdx; spill x3_1 to r14
mov rax, [rsi + 0x18]; arg1[3] -> rax
mul r8; x6_1:x6_0 <- arg1[3] * x10001
add r13, rax; could be done better, if r0 has been u8 as well
adc rdx, r14
mov r8, rdx; spill x10016_1 to r8
mov rax, [rsi + 0x8]; arg1[1] -> rax
mul rcx; x10_1:x10_0 <- arg1[1] * x10000
mov rdi, rax; spill x10_0 to rdi
mov r14, rdx; spill x10_1 to r14
mov rax, [rsi + 0x10]; arg1[2] -> rax
mul rcx; x8_1:x8_0 <- arg1[2] * x10000
mov r15, rax; spill x8_0 to r15
mov [ rsp - 0x218 ], rdx; spill x8_1 to stack
mov rax, [rsi + 0x8]; arg1[1] -> rax
mul [r10 + 0x0]; x20_1:x20_0 <- arg1[1] * arg2[0]
add r13, r15; could be done better, if r0 has been u8 as well
adc r8, [ rsp - 0x218 ]
add r13, rax; could be done better, if r0 has been u8 as well
adc rdx, r8
mov r15, rdx; spill x10018_1 to r15
mov rax, [rsi + 0x0]; arg1[0] -> rax
mul [r10 + 0x8]; x24_1:x24_0 <- arg1[0] * arg2[1]
add r9, rdi; could be done better, if r0 has been u8 as well
adc r14, rbx
add r9, r11; could be done better, if r0 has been u8 as well
adc r14, [ rsp - 0x28 ]
add r13, rax; could be done better, if r0 has been u8 as well
adc rdx, r15
mov r11, r9;
shrd r11, r14, 51; x27 <- x26_1||x26_0 >> 51
mov rbx, rdx; spill x32_1 to rbx
mov rax, [rsi + 0x18]; arg1[3] -> rax
mul rcx; x5_1:x5_0 <- arg1[3] * x10000
mov rcx, 0x7ffffffffffff ; moving imm to reg
and r9, rcx; x28 <- x26_0&0x7ffffffffffff
mov rdi, rax;
add rdi, [ rsp - 0x30 ]; could be done better, if r0 has been u8 as well
adc rdx, [ rsp - 0x38 ]
mov r8, rdx; spill x10013_1 to r8
mov rax, [rsi + 0x10]; arg1[2] -> rax
mul [r10 + 0x0]; x16_1:x16_0 <- arg1[2] * arg2[0]
add r13, r11; could be done better, if r0 has been u8 as well
adc rbx, 0x0; add CF to r0's alloc
add rdi, rax; could be done better, if r0 has been u8 as well
adc rdx, r8
mov r15, rdx; spill x10014_1 to r15
mov rax, [rsi + 0x10]; arg1[2] -> rax
mul [r10 + 0x8]; x15_1:x15_0 <- arg1[2] * arg2[1]
mov r14, rax; spill x15_0 to r14
mov r11, rdx; spill x15_1 to r11
mov rax, [rsi + 0x0]; arg1[0] -> rax
mul [r10 + 0x10]; x23_1:x23_0 <- arg1[0] * arg2[2]
mov r8, rax; spill x23_0 to r8
mov [ rsp - 0x220 ], rdx; spill x23_1 to stack
mov rax, [rsi + 0x8]; arg1[1] -> rax
mul [r10 + 0x8]; x19_1:x19_0 <- arg1[1] * arg2[1]
add rdi, rax; could be done better, if r0 has been u8 as well
adc rdx, r15
add rdi, r8; could be done better, if r0 has been u8 as well
adc rdx, [ rsp - 0x220 ]
mov r15, r13;
and r15, rcx; x35 <- x33_0&0x7ffffffffffff
mov r8, rdx; spill x31_1 to r8
mov rax, [rsi + 0x8]; arg1[1] -> rax
mul [r10 + 0x10]; x18_1:x18_0 <- arg1[1] * arg2[2]
add rbp, r14; could be done better, if r0 has been u8 as well
adc r11, r12
shrd r13, rbx, 51; x34 <- x33_1||x33_0 >> 51
add rbp, rax; could be done better, if r0 has been u8 as well
adc rdx, r11
add rbp, [ rsp - 0x200 ]; could be done better, if r0 has been u8 as well
adc rdx, [ rsp - 0x208 ]
add rdi, r13; could be done better, if r0 has been u8 as well
adc r8, 0x0; add CF to r0's alloc
mov r12, rdi;
shrd r12, r8, 51; x37 <- x36_1||x36_0 >> 51
mov rbx, rdx; spill x30_1 to rbx
mov rax, [rsi + 0x18]; arg1[3] -> rax
mul [r10 + 0x8]; x12_1:x12_0 <- arg1[3] * arg2[1]
mov r14, rax; spill x12_0 to r14
mov r11, rdx; spill x12_1 to r11
mov rax, [rsi + 0x10]; arg1[2] -> rax
mul [r10 + 0x10]; x14_1:x14_0 <- arg1[2] * arg2[2]
and rdi, rcx; x38 <- x36_0&0x7ffffffffffff
mov r13, rax; spill x14_0 to r13
mov r8, rdx; spill x14_1 to r8
mov rax, [rsi + 0x20]; arg1[4] -> rax
mul [r10 + 0x0]; x11_1:x11_0 <- arg1[4] * arg2[0]
add rax, r14; could be done better, if r0 has been u8 as well
adc r11, rdx
add rax, r13; could be done better, if r0 has been u8 as well
adc r8, r11
mov r14, rax; spill x10008_0 to r14
mov rax, [rsi + 0x0]; arg1[0] -> rax
mul [r10 + 0x20]; x21_1:x21_0 <- arg1[0] * arg2[4]
add r14, [ rsp - 0x40 ]; could be done better, if r0 has been u8 as well
adc r8, [ rsp - 0x48 ]
add rbp, r12; could be done better, if r0 has been u8 as well
adc rbx, 0x0; add CF to r0's alloc
mov r12, rbp;
shrd r12, rbx, 51; x40 <- x39_1||x39_0 >> 51
add r14, rax; could be done better, if r0 has been u8 as well
adc rdx, r8
and rbp, rcx; x41 <- x39_0&0x7ffffffffffff
add r14, r12; could be done better, if r0 has been u8 as well
adc rdx, 0x0; add CF to r0's alloc
mov r13, [ rsp - 0x50 ]; load m64 out1 to register64
mov [ r13 + 0x18 ], rbp; out1[3] = x41
mov r11, r14;
and r11, rcx; x44 <- x42_0&0x7ffffffffffff
mov [ r13 + 0x20 ], r11; out1[4] = x44
shrd r14, rdx, 51; x43 <- x42_1||x42_0 >> 51
imul rax, r14, 0x13; x45 <- x43 * 0x13
lea r9, [ r9 + rax ]
mov r8, r9;
shr r8, 51; x47 <- x46>> 51
lea r8, [ r8 + r15 ]
and r9, rcx; x48 <- x46&0x7ffffffffffff
mov r15, r8;
shr r15, 51; x50 <- x49>> 51
lea r15, [ r15 + rdi ]
mov [ r13 + 0x10 ], r15; out1[2] = x52
and r8, rcx; x51 <- x49&0x7ffffffffffff
mov [ r13 + 0x8 ], r8; out1[1] = x51
mov [ r13 + 0x0 ], r9; out1[0] = x48
mov rbx, [ rsp - 0x80 ]; pop
mov rbp, [ rsp - 0x78 ]; pop
mov r12, [ rsp - 0x70 ]; pop
mov r13, [ rsp - 0x68 ]; pop
mov r14, [ rsp - 0x60 ]; pop
mov r15, [ rsp - 0x58 ]; pop
ret
; cpu Intel(R) Celeron(R) CPU N3350 @ 1.10GHz
; ratio 0.9723
; seed 1747922712025508 
; CC / CFLAGS gcc / -march=native -mtune=native -O3 
; cyclegoal; 10000
; using counter; PMC
; framePointer omit
; memoryConstraints none
; time needed: 279586 ms on 8000 evaluations.
; Time spent for assembling and measuring (initial batch_size=43, initial num_batches=31): 14457 ms
; number of used evaluations: 8000
; Ratio (time for assembling + measure)/(total runtime for 8000 evals): 0.05170859771233181
; number reverted permutation / tried permutation: 2388 / 3984 =59.940%
; number reverted decision / tried decision: 2396 / 4015 =59.676%