/*
 * asm_op_keccak_vs.c — Head-to-head, SAME PROCESS / SAME FREQUENCY:
 *   SUPERCOP x86_64_asm KeccakPermutation  vs.  microcode looped permutation.
 *
 * Build: make PROG=asm_op_keccak_vs
 * Run:   sudo taskset -c 1 ./asm_op_keccak_vs_static
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <patch.h>
#include <ucode_macro.h>
#include <misc.h>
#include "../include/bench_core.h"

/* median over a sample of per-rep batch totals (sorts in place). */
static int cmp_u64(const void *a, const void *b){
    uint64_t x=*(const uint64_t*)a, y=*(const uint64_t*)b;
    return (x>y)-(x<y);
}
static uint64_t median_u64(uint64_t *v, int n){
    qsort(v, n, sizeof(uint64_t), cmp_u64);
    return (n&1) ? v[n/2] : (v[n/2-1]+v[n/2])/2;
}

static uint64_t robust_min(const uint64_t *sorted, int n, uint64_t med){
    uint64_t floor = med/2;
    for(int i=0;i<n;i++) if(sorted[i]>=floor) return sorted[i];
    return sorted[n-1];
}
/* Nearest-rank percentile of an ascending-sorted array (0<=pct<=100). Call
 * after median_u64 has sorted the array in place. Used for the p10/p90 spread. */
static uint64_t percentile_u64(const uint64_t *sorted, int n, double pct){
    if(n<=0) return 0;
    int idx = (int)(pct/100.0*(n-1) + 0.5);
    if(idx<0) idx=0;
    if(idx>=n) idx=n-1;
    return sorted[idx];
}

#include "../keccak_perm.h"
static uint64_t g_keccak_buf[KECCAK_BUFLEN];

/* SUPERCOP Keccak permutations — benchmark vs EVERY keccakc1024 variant that
 * runs on this x86-64 Goldmont core (hand asm, 64-bit C, x86 SIMD) plus the
 * reference C*/
extern void keccak_x86_64_asm_perm(uint64_t state[25]);        /* hand asm, ROL */
extern void keccak_x86_64_shld_perm(uint64_t state[25]);       /* hand asm, SHLD */
extern void keccak_opt64lcu24_perm(uint64_t state[25]);        /* 64-bit C, lane-compl + unroll 24 */
extern void keccak_opt64lcu24shld_perm(uint64_t state[25]);    /* 64-bit C, SHLD + unroll 24 */
extern void keccak_opt64lcu6_perm(uint64_t state[25]);         /* 64-bit C, lane-compl + unroll 6 */
extern void keccak_opt64u6_perm(uint64_t state[25]);           /* 64-bit C, plain + unroll 6 */
extern void keccak_sseu2_perm(uint64_t state[25]);             /* SSE2/SSSE3 SIMD */
extern void keccak_mmxu1_perm(uint64_t state[25]);             /* MMX SIMD */
extern void keccak_simple_F(uint64_t *state, const uint64_t *in, int laneCount); /* reference C */
/* simple's KeccakF absorbs `laneCount` lanes then permutes; laneCount=0 skips the
 * absorb (while(--0>=0) is false) -> a pure Keccak-f[1600] permutation. */
static void keccak_simple_perm(uint64_t s[25]){ keccak_simple_F(s, s, 0); }

/* XKCP (eXtended Keccak Code Package) single Keccak-p[1600], plain-64bits.  */
extern void keccak_xkcp_g64_perm(uint64_t state[25]);    /* generic64   : full unroll, no lane-complement */
extern void keccak_xkcp_g64lc_perm(uint64_t state[25]);  /* generic64lc : full unroll, lane-complement (Goldmont default) */

/* OpenSSL keccak1600, x86-64 scalar assembly (CRYPTOGAMS/Polyakov) */
extern void keccak_openssl_perm(uint64_t state[25]);

/* s2n-bignum (AWS) sha3_keccak_f1600: a formally verified (HOL Light) port of
 * the OpenSSL asm above, plain x86-64. */
extern void keccak_s2n_perm(uint64_t state[25]);

static const uint64_t KECCAK_RC[24] = {
    0x0000000000000001ULL,0x0000000000008082ULL,0x800000000000808aULL,0x8000000080008000ULL,
    0x000000000000808bULL,0x0000000080000001ULL,0x8000000080008081ULL,0x8000000000008009ULL,
    0x000000000000008aULL,0x0000000000000088ULL,0x0000000080008009ULL,0x000000008000000aULL,
    0x000000008000808bULL,0x800000000000008bULL,0x8000000000008089ULL,0x8000000000008003ULL,
    0x8000000000008002ULL,0x8000000000000080ULL,0x000000000000800aULL,0x800000008000000aULL,
    0x8000000080008081ULL,0x8000000000008080ULL,0x0000000080000001ULL,0x8000000080008008ULL,
};

static void install_perm_patch(void){
    ucode_t patch[] = {
        #include "../keccak_perm_body.h"
    };
    hook_match_and_patch(0, 0x0cd8, 0x7c00);
    patch_ucode(0x7c00, patch, KECCAK_PERM_TRIADS);
}
static void reset_control(void){
    g_keccak_buf[KECCAK_COUNTER_LANE]=(KECCAK_RCTAB_LANE-KECCAK_BASE_LANE)*8;
    for(int r=0;r<24;r++) g_keccak_buf[KECCAK_RCTAB_LANE+r]=KECCAK_RC[r];
}
/* RSP guard */
static uint64_t g_rsp_save, g_rsp_back;
static long g_ucode_fires, g_rsp_changed;
static inline void ucode_perm(void){
    register uint64_t *_b asm("rcx") = &g_keccak_buf[KECCAK_BASE_LANE];
    asm volatile("mov %[sv], rsp\n\t"
                 "vmwrite rcx, rcx\n\t"
                 "mov %[bk], rsp\n\t"
                 "mov rsp, %[sv]\n\t"
        : "+r"(_b), [sv] "+m"(g_rsp_save), [bk] "=m"(g_rsp_back) :
        : "rax","rbx","rdx","rdi","rsi","rbp","r8","r9","r10","r11",
          "r12","r13","r14","r15","memory","cc");
    g_ucode_fires++;
    if(g_rsp_back!=g_rsp_save) g_rsp_changed++;
}
static void print_rsp_guard(void){
    printf("RSP-GUARD: %ld microcode firings, %ld returned a changed RSP (restored by the wrapper)\n",
           g_ucode_fires, g_rsp_changed);
}

/* C reference Keccak-f[1600] */
static const int KECCAK_ROTC[24] = {
    1,3,6,10,15,21,28,36,45,55,2,14,27,41,56,8,25,43,62,18,39,61,20,44 };
static const int KECCAK_PILN[24] = {
    10,7,11,17,18,3,5,16,8,21,24,4,15,23,19,13,12,2,20,14,22,9,6,1 };
#define ROL64(x,n) (((x)<<(n))|((x)>>(64-(n))))
static void ref_perm(uint64_t st[25]){
    uint64_t bc[5], t;
    for(int r=0;r<24;r++){
        for(int i=0;i<5;i++) bc[i]=st[i]^st[i+5]^st[i+10]^st[i+15]^st[i+20];
        for(int i=0;i<5;i++){
            t=bc[(i+4)%5]^ROL64(bc[(i+1)%5],1);
            for(int j=0;j<25;j+=5) st[j+i]^=t;
        }
        t=st[1];
        for(int i=0;i<24;i++){
            int j=KECCAK_PILN[i]; bc[0]=st[j]; st[j]=ROL64(t,KECCAK_ROTC[i]); t=bc[0];
        }
        for(int j=0;j<25;j+=5){
            for(int i=0;i<5;i++) bc[i]=st[j+i];
            for(int i=0;i<5;i++) st[j+i]^=(~bc[(i+1)%5])&bc[(i+2)%5];
        }
        st[0]^=KECCAK_RC[r];
    }
}

static inline uint64_t rdtsc_start(void){uint32_t lo,hi;asm volatile("cpuid\n\trdtsc":"=a"(lo),"=d"(hi)::"rbx","rcx","memory");return((uint64_t)hi<<32)|lo;}
static inline uint64_t rdtsc_end(void){uint32_t lo,hi;asm volatile("rdtscp":"=a"(lo),"=d"(hi)::"rcx","memory");asm volatile("cpuid":::"rax","rbx","rcx","rdx","memory");return((uint64_t)hi<<32)|lo;}
#define BATCH 1000
#define REPS  200

int main(void){
    printf("=== Keccak head-to-head (same process, same frequency) ===\n");
    printf("g_keccak_buf @ %p\n", (void*)g_keccak_buf);
    if((uint64_t)g_keccak_buf>=0x100000000ULL){printf("FATAL >4GB\n");return 1;}
    assign_to_core(bench_core());
    printf("pinned to core %d\n", bench_core());
    init_match_and_patch(); do_fix_IN_patch();
    install_perm_patch(); reset_control();

    /* Correctness. The microcode is checked EXACTLY against the C reference
     * permutation (ref_perm): one firing here, and every timed batch below.*/
    uint64_t a[25], b[25], ref[25];
    for(int i=0;i<25;i++){ a[i]=0x0123456789ABCDEFULL*(i+1); b[i]=a[i]; }
    keccak_x86_64_asm_perm(a);
    memcpy(g_keccak_buf,b,25*8); reset_control(); ucode_perm();
    memcpy(ref,b,25*8); ref_perm(ref);
    int sc_perm = memcmp(a,b,25*8)!=0;
    int uc_ok   = memcmp(g_keccak_buf,ref,25*8)==0;
    printf("check: SUPERCOP x86_64_asm permutes=%d, microcode == C reference permutation: %s\n",
           sc_perm, uc_ok ? "yes" : "NO");
    if(!sc_perm || !uc_ok){ printf("FAIL: correctness check\n"); init_match_and_patch(); do_fix_IN_patch(); return 1; }

    uint64_t uc_expect[25];
    for(int i=0;i<25;i++) uc_expect[i]=0x0123456789ABCDEFULL*(i+1);
    for(int i=0;i<BATCH;i++) ref_perm(uc_expect);

    /* warmup to reach steady frequency */
    volatile uint64_t w=0; for(uint64_t i=0;i<200000000ULL;i++) w+=i; (void)w;

    typedef void (*permfn)(uint64_t*);
    #define NCONT 13
    struct { const char *name; const char *type; const char *key; permfn fn; uint64_t min; uint64_t med; uint64_t p10; uint64_t p90; } C[NCONT] = {
        {"x86_64_asm",     "asm",  "x86_64_asm",     keccak_x86_64_asm_perm,     UINT64_MAX, 0},
        {"x86_64_shld",    "asm",  "x86_64_shld",    keccak_x86_64_shld_perm,    UINT64_MAX, 0},
        {"openssl",        "asm",  "openssl",        keccak_openssl_perm,        UINT64_MAX, 0},
        {"s2n_bignum",     "asm",  "s2n_bignum",     keccak_s2n_perm,            UINT64_MAX, 0},
        {"opt64lcu24",     "C64",  "opt64lcu24",     keccak_opt64lcu24_perm,     UINT64_MAX, 0},
        {"opt64lcu24shld", "C64",  "opt64lcu24shld", keccak_opt64lcu24shld_perm, UINT64_MAX, 0},
        {"opt64lcu6",      "C64",  "opt64lcu6",      keccak_opt64lcu6_perm,      UINT64_MAX, 0},
        {"opt64u6",        "C64",  "opt64u6",        keccak_opt64u6_perm,        UINT64_MAX, 0},
        {"sseu2",          "SSE2", "sseu2",          keccak_sseu2_perm,          UINT64_MAX, 0},
        {"mmxu1",          "MMX",  "mmxu1",          keccak_mmxu1_perm,          UINT64_MAX, 0},
        {"simple",         "ref",  "simple",         keccak_simple_perm,         UINT64_MAX, 0},
        {"xkcp_g64",       "xkcp", "xkcp_g64",       keccak_xkcp_g64_perm,       UINT64_MAX, 0},
        {"xkcp_g64lc",     "xkcp", "xkcp_g64lc",     keccak_xkcp_g64lc_perm,     UINT64_MAX, 0},
    };
    int NC = NCONT;
    uint64_t sc_state[25];
    uint64_t uc_min=UINT64_MAX, uc_med=0;
    /* per-rep batch totals, kept so we can compute median + a robust min. */
    static uint64_t cval[NCONT][REPS];
    static uint64_t ucval[REPS];
    for(int r=0;r<REPS;r++){
        for(int c=0;c<NC;c++){
            for(int i=0;i<25;i++) sc_state[i]=0x0123456789ABCDEFULL*(i+1);
            uint64_t t0=rdtsc_start();
            for(int i=0;i<BATCH;i++) C[c].fn(sc_state);
            uint64_t t1=rdtsc_end();
            cval[c][r]=t1-t0;
        }
        for(int i=0;i<25;i++) g_keccak_buf[i]=0x0123456789ABCDEFULL*(i+1);
        uint64_t t2=rdtsc_start();
        for(int i=0;i<BATCH;i++){ g_keccak_buf[KECCAK_COUNTER_LANE]=(KECCAK_RCTAB_LANE-KECCAK_BASE_LANE)*8; ucode_perm(); }
        uint64_t t3=rdtsc_end();
        ucval[r]=t3-t2;
        if(memcmp(g_keccak_buf,uc_expect,25*8)){
            printf("\nBATCH FAIL microcode rep %d: end state != %d reference permutations; run invalid\n", r, BATCH);
            print_rsp_guard();
            init_match_and_patch(); do_fix_IN_patch();
            return 2;
        }
    }
    /* median sorts each sample array in place; robust_min then reads the sorted
     * array, skipping implausible near-zero batches (see robust_min above). */
    for(int c=0;c<NC;c++){
        C[c].med=median_u64(cval[c],REPS);
        C[c].min=robust_min(cval[c],REPS,C[c].med);
        C[c].p10=percentile_u64(cval[c],REPS,10.0);
        C[c].p90=percentile_u64(cval[c],REPS,90.0);
    }
    uc_med=median_u64(ucval,REPS);
    uc_min=robust_min(ucval,REPS,uc_med);
    uint64_t uc_p10=percentile_u64(ucval,REPS,10.0);
    uint64_t uc_p90=percentile_u64(ucval,REPS,90.0);

    /* median is the headline statistic. */
    uint64_t uc=uc_med/BATCH;

    /* Assemble all rows (every SUPERCOP variant + microcode), sort ascending by
     * min cyc/perm, and print one aligned table. */
    struct row { const char *name; const char *type; uint64_t min, med, p10, p90; int uco; };
    struct row R[NCONT+1];
    for(int c=0;c<NC;c++) R[c]=(struct row){C[c].name, C[c].type,
        C[c].min/BATCH, C[c].med/BATCH, C[c].p10/BATCH, C[c].p90/BATCH, 0};
    R[NC]=(struct row){"microcode", "ucode",
        uc_min/BATCH, uc_med/BATCH, uc_p10/BATCH, uc_p90/BATCH, 1};
    int NR=NC+1;
    /* sort ascending by MEDIAN — the headline statistic. */
    for(int i=1;i<NR;i++){ struct row k=R[i]; int j=i-1;
        while(j>=0 && R[j].med>k.med){ R[j+1]=R[j]; j--; } R[j+1]=k; }

    /* fastest non-microcode contender (by median) = the baseline we must beat */
    uint64_t best=UINT64_MAX; const char *bestname=""; const char *besttype="";
    for(int c=0;c<NC;c++){ uint64_t v=C[c].med/BATCH;
        if(v<best){best=v; bestname=C[c].name; besttype=C[c].type;} }

    printf("\n--- Keccak-f[1600] head-to-head: same process & frequency (cyc/perm) ---\n");
    printf("  %-15s %-5s %8s %8s %8s %8s   %s\n",
           "contender","type","median","min","p10","p90","x vs ucode");
    printf("  %-15s %-5s %8s %8s %8s %8s   %s\n",
           "---------------","-----","--------","--------","--------","--------","----------");
    for(int i=0;i<NR;i++){
        double x=(double)R[i].med/(double)uc;       /* ratio from medians */
        printf("  %-15s %-5s %8" PRIu64 " %8" PRIu64 " %8" PRIu64 " %8" PRIu64 "   %6.2fx%s\n",
               R[i].name, R[i].type, R[i].med, R[i].min, R[i].p10, R[i].p90, x,
               R[i].uco ? "  <== microcode" : (R[i].med<uc ? "  (beats ucode!)" : ""));
    }
    printf("\n  fastest non-microcode:   %s (%s) = %" PRIu64 " cyc/perm (median)\n", bestname, besttype, best);
    printf("  microcode (looped):      %" PRIu64 " cyc/perm (median)\n", uc);
    printf("  ratio microcode/fastest: %.3fx  (%s)\n",
           (double)uc/(double)best,
           uc<best ? "*** microcode WINS vs the fastest runnable variant ***" : "microcode loses");
    printf("  every microcode batch verified against the C reference (%d reps x %d perms)\n", REPS, BATCH);
    printf("  "); print_rsp_guard();
    printf("\n(all measured back-to-back at the same CPU frequency -> ratios valid)\n");

    printf("\n=== matrix-parse ===\n");
    for(int c=0;c<NC;c++)
        printf("keccak/%s: min %" PRIu64 " median %" PRIu64 " p10 %" PRIu64 " p90 %" PRIu64 "\n",
               C[c].key, C[c].min/BATCH, C[c].med/BATCH, C[c].p10/BATCH, C[c].p90/BATCH);
    printf("keccak/microcode: min %" PRIu64 " median %" PRIu64 " p10 %" PRIu64 " p90 %" PRIu64 "\n",
           uc_min/BATCH, uc_med/BATCH, uc_p10/BATCH, uc_p90/BATCH);

    init_match_and_patch(); do_fix_IN_patch();
    return 0;
}
