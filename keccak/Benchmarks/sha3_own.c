/*
 * sha3_own.c — End-to-end SHA3-256 head-to-head, SAME PROCESS / SAME FREQUENCY.
 *
 * asm_op_keccak_vs.c compares the bare Keccak-f[1600] permutation. This harness
 * compares complete SHA3-256 hashes: absorbing the message into the rate lanes,
 * padding, the permutations, and squeezing the digest out.
 *
 * Method: every contender runs ITS OWN SHA3-256. Each native row is the
 * implementation's complete hash path — its own sponge, absorb loop, padding and
 * squeeze around its own permutation — linked from one object per contender
 * (Makefile, "SHA3-256 contenders for sha3_own"):
 *
 *   x86_64_asm ... mmxu1  SUPERCOP crypto_hash/keccakc512/<impl>: the package's
 *                         KeccakSponge.c at r=1088, c=512 plus the FIPS 202
 *                         domain bits (sha3_kc512_shim.c)
 *   simple                SUPERCOP keccakc512/simple's crypto_hash(), padding
 *                         byte 0x01 -> 0x06 (the only change)
 *   xkcp_g64, xkcp_g64lc  XKCP SHA3_256() (SimpleFIPS202 + KeccakSponge.c)
 *   openssl               OpenSSL crypto/sha/sha3.c over its SHA3_absorb /
 *                         SHA3_squeeze asm, set up as its SHA3-256 provider does
 *                         (sha3_ossl_shim.c)
 *   microcode             the microcode kernel has no sponge of its own; it runs
 *                         the plain C sponge below
 *
 * sha3_best.sh builds each native object under the compiler configuration that
 * won its row of the permutation sweep (bench_keccak_matrix.sh).
 *
 * Every contender is KAT-verified against SHA3-256 vectors at thirteen message
 * lengths, including the padding boundaries 135/136/137 and every timed length,
 * before any timing is reported, and again after the frequency warm-up. Every
 * hash inside every timed batch is verified too (digest sum per batch); one
 * wrong hash aborts the run with exit status 2.
 *
 * Build: make PROG=sha3_own
 * Run:   sudo taskset -c 1 ./sha3_own_static
 *        ./sha3_own_static --no-ucode     (natives only; no root needed)
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

/* ────────────────────────── statistics ────────────────────────── */

static int cmp_u64(const void *a, const void *b){
    uint64_t x=*(const uint64_t*)a, y=*(const uint64_t*)b;
    return (x>y)-(x<y);
}
static uint64_t median_u64(uint64_t *v, int n){
    qsort(v, n, sizeof(uint64_t), cmp_u64);
    return (n&1) ? v[n/2] : (v[n/2-1]+v[n/2])/2;
}
/* Smallest sample that isn't an implausible downward glitch. Cycle counts only
 * grow under noise, so a sample below half the median means that batch was
 * mis-measured (e.g. a P-state transition straddling the rdtsc bracket). */
static uint64_t robust_min(const uint64_t *sorted, int n, uint64_t med){
    uint64_t floor_ = med/2;
    for(int i=0;i<n;i++) if(sorted[i]>=floor_) return sorted[i];
    return sorted[n-1];
}
static uint64_t percentile_u64(const uint64_t *sorted, int n, double pct){
    if(n<=0) return 0;
    int idx=(int)(pct/100.0*(n-1)+0.5);
    if(idx<0) idx=0;
    if(idx>=n) idx=n-1;
    return sorted[idx];
}

/* ────────────────────────── microcode kernel ────────────────────────── */

#include "../keccak_perm.h"
static uint64_t g_keccak_buf[KECCAK_BUFLEN];

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
/* The round-constant cursor is a byte offset that the kernel advances by 8 each
 * round; it must be rewound before every firing. The RC table itself is written
 * once, but rewriting it is harmless and keeps the reset self-contained. */
static void reset_rc_table(void){
    for(int r=0;r<24;r++) g_keccak_buf[KECCAK_RCTAB_LANE+r]=KECCAK_RC[r];
}
static inline void reset_counter(void){
    g_keccak_buf[KECCAK_COUNTER_LANE]=(KECCAK_RCTAB_LANE-KECCAK_BASE_LANE)*8;
}
/* One firing = one full 24-round permutation of lanes 0..24 of g_keccak_buf.
 * The base pointer is centred at lane 16 so every state lane is reachable with
 * the 8-bit SIGNED displacement the load/store micro-ops take.
 *
 * RSP guard: the kernel uses RSP as its 32nd data register (the prologue saves
 * it to lane 31 in the prologue and reloads it in the epilogue). Fired bare, it
 * failed in this harness within ~360 firings in 4 of 5 sha3_best.sh runs
 * (2026-10-09: SIGABRT stack-protector, #GP on stack loads, a hang, a wrong
 * digest), while sha3_ucode_test with RSP saved before and restored after the
 * vmwrite ran 3.52M firings clean. So the wrapper saves RSP itself, restores it
 * after the firing, and records what the kernel handed back (g_rsp_back) so a
 * changed RSP is counted rather than silently repaired. */
static uint64_t g_rsp_save, g_rsp_back;
static long g_ucode_fires, g_rsp_changed;
static inline void ucode_perm_raw(void){
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

/* ─────────────── microcode SHA3-256 (the kernel's sponge) ─────────────── */
/* The microcode kernel is a bare permutation, so its SHA3-256 is a plain C
 * sponge. The code from here to DEFINE_SPONGE(ucode, ...) is copied VERBATIM
 * from the earlier shared-sponge harness (sha3_vs.c, git HEAD b4b347a87 era),
 * whose microcode row ran 7 complete sha3_best.sh runs on HW; it is called the
 * same way too (sha3_256_run below: one indirect call with mask = MASK_STD and
 * st = g_keccak_buf). Only the microcode instantiation is kept. */

static uint64_t MASK_STD[25];   /* all zero  */

#define SHA3_256_RATE 136          /* bytes  */
#define SHA3_256_RATE_LANES 17
#define SHA3_256_OUT 32

static inline uint64_t ld64le(const uint8_t *p){
    uint64_t v; memcpy(&v,p,8); return v;   /* x86-64 is little-endian */
}
static inline void st64le(uint8_t *p, uint64_t v){ memcpy(p,&v,8); }

#define DEFINE_SPONGE(NAME, PERM)                                             \
static void sha3_256_##NAME(uint8_t out[SHA3_256_OUT], const uint8_t *in,     \
                            size_t inlen, const uint64_t *mask, uint64_t *st) \
{                                                                             \
    for(int i=0;i<25;i++) st[i]=mask[i];                                      \
                                                                              \
    while(inlen >= SHA3_256_RATE){                                            \
        for(int i=0;i<SHA3_256_RATE_LANES;i++) st[i]^=ld64le(in+8*i);         \
        PERM(st);                                                             \
        in+=SHA3_256_RATE; inlen-=SHA3_256_RATE;                              \
    }                                                                         \
    uint8_t last[SHA3_256_RATE];                                              \
    memset(last,0,sizeof last);                                               \
    memcpy(last,in,inlen);                                                    \
    last[inlen]           ^= 0x06;   /* domain separation + pad10*1 start */  \
    last[SHA3_256_RATE-1] ^= 0x80;   /* pad10*1 end                       */  \
    for(int i=0;i<SHA3_256_RATE_LANES;i++) st[i]^=ld64le(last+8*i);           \
    PERM(st);                                                                 \
                                                                              \
    for(int i=0;i<SHA3_256_OUT/8;i++) st64le(out+8*i, st[i]^mask[i]);         \
}

/* The microcode "permutation call" is the firing itself: rewind the round-
 * constant cursor, then execute the hooked instruction. Fired inline, never
 * through a pointer — the kernel borrows RSP as a data register
 * (see the patch prologue), and reaching it through a call would make GCC bracket
 * the vmwrite with push/pop pairs whose restore depends on RSP returning
 * exactly right. `st` is g_keccak_buf, which the kernel is hard-wired to. */
#define UCODE_PERM(st) do { (void)(st); reset_counter(); ucode_perm_raw(); } while(0)

DEFINE_SPONGE(ucode,          UCODE_PERM)

typedef void (*spongefn)(uint8_t*, const uint8_t*, size_t, const uint64_t*, uint64_t*);

/* ─────────────── native SHA3-256 implementations (own sponges) ─────────────── */

typedef int (*sha3fn)(unsigned char *out, const unsigned char *in, unsigned long long inlen);

extern int sha3_256_x86_64_asm    (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_x86_64_shld   (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_opt64lcu24    (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_opt64lcu24shld(unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_opt64lcu6     (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_opt64u6       (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_sseu2         (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_mmxu1         (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_simple        (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_xkcp_g64      (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_xkcp_g64lc    (unsigned char*, const unsigned char*, unsigned long long);
extern int sha3_256_openssl       (unsigned char*, const unsigned char*, unsigned long long);

/* ────────────────────────── contenders ────────────────────────── */

struct contender {
    const char *name, *key, *type;
    sha3fn      fn;        /* native: the implementation's own SHA3-256 */
    spongefn    usponge;   /* microcode: the copied sponge above (fn is NULL) */
    const char *sponge;    /* whose sponge this row runs, printed in the log */
    int         is_ucode;
    int         usable;    /* KAT passed */
    uint64_t    med, min, p10, p90;
};

#define SC512 "SUPERCOP keccakc512/"
static struct contender C[] = {
  {"x86_64_asm",    "x86_64_asm",    "asm",  sha3_256_x86_64_asm, NULL,     SC512 "x86_64_asm KeccakSponge.c",     0,0,0,0,0,0},
  {"x86_64_shld",   "x86_64_shld",   "asm",  sha3_256_x86_64_shld, NULL,    SC512 "x86_64_shld KeccakSponge.c",    0,0,0,0,0,0},
  {"openssl",       "openssl",       "asm",  sha3_256_openssl, NULL,        "OpenSSL crypto/sha/sha3.c + SHA3_absorb/SHA3_squeeze asm", 0,0,0,0,0,0},
  {"opt64lcu24",    "opt64lcu24",    "C64",  sha3_256_opt64lcu24, NULL,     SC512 "opt64lcu24 KeccakSponge.c",     0,0,0,0,0,0},
  {"opt64lcu24shld","opt64lcu24shld","C64",  sha3_256_opt64lcu24shld, NULL, SC512 "opt64lcu24shld KeccakSponge.c", 0,0,0,0,0,0},
  {"opt64lcu6",     "opt64lcu6",     "C64",  sha3_256_opt64lcu6, NULL,      SC512 "opt64lcu6 KeccakSponge.c",      0,0,0,0,0,0},
  {"opt64u6",       "opt64u6",       "C64",  sha3_256_opt64u6, NULL,        SC512 "opt64u6 KeccakSponge.c",        0,0,0,0,0,0},
  {"sseu2",         "sseu2",         "SSE2", sha3_256_sseu2, NULL,          SC512 "sseu2 KeccakSponge.c",          0,0,0,0,0,0},
  {"mmxu1",         "mmxu1",         "MMX",  sha3_256_mmxu1, NULL,          SC512 "mmxu1 KeccakSponge.c",          0,0,0,0,0,0},
  {"simple",        "simple",        "ref",  sha3_256_simple, NULL,         SC512 "simple crypto_hash(), pad 0x06", 0,0,0,0,0,0},
  {"xkcp_g64",      "xkcp_g64",      "xkcp", sha3_256_xkcp_g64, NULL,       "XKCP SHA3_256() (SimpleFIPS202, KeccakSponge.c)", 0,0,0,0,0,0},
  {"xkcp_g64lc",    "xkcp_g64lc",    "xkcp", sha3_256_xkcp_g64lc, NULL,     "XKCP SHA3_256() (SimpleFIPS202, KeccakSponge.c)", 0,0,0,0,0,0},
  {"microcode",     "microcode",     "ucode",NULL, sha3_256_ucode,          "our C sponge, copied verbatim from sha3_vs.c (kernel has no sponge)", 1,0,0,0,0,0},
};
#define NCONT ((int)(sizeof C / sizeof C[0]))

/* One indirect call per HASH — identical for every contender, and outside the
 * per-permutation work that the measurement is about. */
static void sha3_256_run(uint8_t out[SHA3_256_OUT], const uint8_t *in, size_t len,
                         const struct contender *c)
{
    if(c->usponge) c->usponge(out,in,len,MASK_STD,g_keccak_buf);   /* as in sha3_vs.c */
    else           c->fn(out,in,(unsigned long long)len);
}

/* ────────────────────────── known-answer tests ────────────────────────── */

static const struct { int len; const char *hex; } KAT[] = {
    {     0, "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"},
    {     1, "5d53469f20fef4f8eab52b88044ede69c77a6a68a60728609fc4a65ff531e7d0"},
    {    32, "050a48733bd5c2756ba95c5828cc83ee16fabcd3c086885b7744f84a0f9e0d94"},
    {    64, "c8ad478f4e1dd9d47dfc3b985708d92db1f8db48fe9cddd459e63c321f490402"},
    {   135, "fded8fd9d6551c601eeb3b7c6bc5e5cfd8aad1d015b7e9aaa9c9b9475231d5e2"},
    {   136, "cf3ccff92480a29160c2d38317c430e14749bfee1788106957dfe73f8c4930e5"},
    {   137, "ce9d7dc90913ee5d92745019479a5352c6d6279bef18ed07dc0a83ee8084daca"},
    {   272, "0b21ec4a8eff6d179e09ba9fe0ab08515b24e0923fbf419f5c30a38e64577db5"},
    {   512, "d4728ea5e9f3819f2b4760151a8f802dbe9f941fd6fb59b3715892436555772a"},
    {  1024, "b6c70631c6ff932b9f380d9cde8750eb9bea393817a9aea410c2119eb7b9b870"},
    {  4096, "eeb3b4cee65cffa2a31365e3e7c38701109cbbf44ec146e098431e87ca70ec83"},
    { 16384, "7435e80063c52cc3a94baa99430ec3c54db49f05f92a215902ae960b7133ff8c"},
    {   128, "bec3ebfba06834f224543cca2a427cb9329147be93e19aeb0e33a7119c7f63ef"},  /* timed length */
};
#define NKAT ((int)(sizeof KAT / sizeof KAT[0]))

static const char *kat_hex(int len){
    for(int k=0;k<NKAT;k++) if(KAT[k].len==len) return KAT[k].hex;
    return NULL;
}
static void hex_to_words(const char *hex, uint64_t w[4]){
    uint8_t d[32];
    for(int i=0;i<32;i++){ unsigned v; sscanf(hex+2*i,"%2x",&v); d[i]=(uint8_t)v; }
    memcpy(w,d,32);
}
#define MAXMSG 16384

static uint8_t g_msg[MAXMSG];
static void fill_msg(void){ for(int i=0;i<MAXMSG;i++) g_msg[i]=(uint8_t)(i&0xff); }

static void hex32(char *dst, const uint8_t d[32]){
    static const char *h="0123456789abcdef";
    for(int i=0;i<32;i++){ dst[2*i]=h[d[i]>>4]; dst[2*i+1]=h[d[i]&15]; }
    dst[64]='\0';
}

/* Returns 1 if every vector matches. */
static int kat_check(struct contender *c, int verbose)
{
    uint8_t out[32]; char got[65];
    for(int k=0;k<NKAT;k++){
        sha3_256_run(out, g_msg, (size_t)KAT[k].len, c);
        hex32(got,out);
        if(strcmp(got,KAT[k].hex)){
            if(verbose){
                printf("    KAT FAIL %-15s len=%d\n      got %s\n      exp %s\n",
                       c->name, KAT[k].len, got, KAT[k].hex);
            }
            return 0;
        }
    }
    return 1;
}

/* ────────────────────────── timing ────────────────────────── */

static inline uint64_t rdtsc_start(void){
    uint32_t lo,hi; asm volatile("cpuid\n\trdtsc":"=a"(lo),"=d"(hi)::"rbx","rcx","memory");
    return ((uint64_t)hi<<32)|lo;
}
static inline uint64_t rdtsc_end(void){
    uint32_t lo,hi; asm volatile("rdtscp":"=a"(lo),"=d"(hi)::"rcx","memory");
    asm volatile("cpuid":::"rax","rbx","rcx","rdx","memory");
    return ((uint64_t)hi<<32)|lo;
}

#define REPS 51
#define TARGET_BATCH_CYCLES 1500000ULL

static const int MSG_LENS[] = {32, 128, 1024, 4096, 16384};
#define NLEN ((int)(sizeof MSG_LENS / sizeof MSG_LENS[0]))

/* Permutations a message of `len` bytes costs: full rate blocks plus the padded
 * final block. */
static int perms_for(int len){ return len/SHA3_256_RATE + 1; }

/* Pilot a few hashes to size the batch so every (contender,length) pair times a
 * comparable amount of work, rather than a fixed hash count that would make the
 * slow contenders dominate the runtime. */
static int size_batch(struct contender *c, int len)
{
    uint8_t out[32];
    uint64_t t0=rdtsc_start();
    for(int i=0;i<4;i++) sha3_256_run(out,g_msg,(size_t)len,c);
    uint64_t t1=rdtsc_end();
    uint64_t per = (t1-t0)/4; if(!per) per=1;
    uint64_t b = TARGET_BATCH_CYCLES/per;
    if(b<4) b=4;
    if(b>20000) b=20000;
    return (int)b;
}

int main(int argc, char **argv)
{
    int use_ucode = 1;
    const char *only = NULL;
    int skip_warmup = 0;
    /* Unbuffered: if a run faults, everything printed up to the fault must
     * already have reached the terminal. Through a pipe stdout would otherwise
     * be block-buffered and the last few KB — precisely the interesting part —
     * would be lost. */
    setvbuf(stdout, NULL, _IONBF, 0);
    for(int i=1;i<argc;i++){
        if(!strcmp(argv[i],"--no-ucode")) use_ucode=0;
        else if(!strcmp(argv[i],"--only") && i+1<argc) only=argv[++i];
        else if(!strcmp(argv[i],"--skip-warmup")) skip_warmup=1;
    }

    printf("=== SHA3-256 end-to-end head-to-head (same process, same frequency) ===\n");
    printf("Each contender runs its own SHA3-256 (own sponge). Rate %d bytes, digest %d bytes.\n",
           SHA3_256_RATE, SHA3_256_OUT);
    printf("\n--- sponge per contender ---\n");
    for(int i=0;i<NCONT;i++) printf("  %-15s %s\n", C[i].name, C[i].sponge);

    fill_msg();

    if(use_ucode){
        printf("\ng_keccak_buf @ %p\n",(void*)g_keccak_buf);
        if((uint64_t)g_keccak_buf>=0x100000000ULL){ printf("FATAL >4GB\n"); return 1; }
        assign_to_core(bench_core());
        printf("pinned to core %d\n", bench_core());
        init_match_and_patch(); do_fix_IN_patch();
        install_perm_patch(); reset_rc_table();
    } else {
        printf("\n(--no-ucode: native contenders only, microcode kernel skipped)\n");
    }

    /* ── correctness ── */
    printf("\n--- SHA3-256 known-answer tests (%d vectors, incl. padding boundaries) ---\n", NKAT);
    int nusable=0;
    for(int i=0;i<NCONT;i++){
        if(C[i].is_ucode && !use_ucode) continue;
        if(kat_check(&C[i],1)){ printf("  %-15s PASS (%d/%d)\n", C[i].name, NKAT, NKAT); C[i].usable=1; nusable++; }
        else printf("  %-15s FAIL — excluded from timing\n", C[i].name);
    }
    if(only){
        for(int i=0;i<NCONT;i++)
            if(C[i].usable && !strstr(C[i].name,only)){ C[i].usable=0; nusable--; }
        printf("\n(--only %s: %d contender(s) will be timed)\n", only, nusable);
    }
    if(!nusable){ printf("\nNo usable contenders. Abort.\n"); if(use_ucode){init_match_and_patch();do_fix_IN_patch();} return 1; }

    /* warm-up to reach steady frequency before the first counter read */
    if(skip_warmup) printf("\n(--skip-warmup: frequency warm-up skipped)\n");
    else { volatile uint64_t w=0; for(uint64_t i=0;i<200000000ULL;i++) w+=i; (void)w; }

    /* Re-verify AFTER the warm-up. The KAT above runs before it; if a contender
     * passes there and fails here, the warm-up itself is implicated (patch RAM
     * or hook state lost across it) rather than the hash. */
    printf("\n--- post-warm-up re-verification ---\n");
    for(int i=0;i<NCONT;i++){
        if(!C[i].usable) continue;
        printf("  %-15s ", C[i].name);
        if(kat_check(&C[i],1)) printf("PASS\n");
        else { printf("FAIL — excluded\n"); C[i].usable=0; nusable--; }
    }
    if(!nusable){ printf("\nNo contenders survived re-verification. Abort.\n");
                  if(use_ucode){init_match_and_patch();do_fix_IN_patch();} return 1; }

    /* ── timing ── */
    static uint64_t sample[NCONT][REPS];
    static int batch[NCONT];

    for(int L=0;L<NLEN;L++){
        int len=MSG_LENS[L], np=perms_for(len);
        uint64_t expw[4];
        if(!kat_hex(len)){ printf("FATAL: no expected digest for len %d\n", len);
                           if(use_ucode){init_match_and_patch();do_fix_IN_patch();} return 1; }
        hex_to_words(kat_hex(len), expw);

        printf("\n[len=%d] sizing batches...\n", len);
        for(int i=0;i<NCONT;i++) if(C[i].usable){
            printf("  [len=%d] %-15s pilot...", len, C[i].name);
            batch[i]=size_batch(&C[i],len);
            printf(" batch=%d\n", batch[i]);
        }
        printf("[len=%d] timing %d reps...\n", len, REPS);

        /* Interleave contenders inside each rep so they all see the same
         * frequency and thermal state.
         * Every timed hash is verified: the four digest words are summed over
         * the batch (4 loads + 4 adds per hash, the same for every contender)
         * and checked against batch x expected after the batch, so one wrong
         * hash anywhere invalidates the run instead of producing a number. */
        for(int r=0;r<REPS;r++){
            for(int i=0;i<NCONT;i++){
                if(!C[i].usable) continue;
                if(r==0) printf("  [len=%d rep0] %-15s ...\n", len, C[i].name);
                uint8_t out[32];
                uint64_t acc0=0, acc1=0, acc2=0, acc3=0;
                uint64_t t0=rdtsc_start();
                for(int b=0;b<batch[i];b++){
                    sha3_256_run(out,g_msg,(size_t)len,C+i);
                    uint64_t w[4]; memcpy(w,out,32);
                    acc0+=w[0]; acc1+=w[1]; acc2+=w[2]; acc3+=w[3];
                }
                uint64_t t1=rdtsc_end();
                sample[i][r]=(t1-t0)/(uint64_t)batch[i];
                uint64_t nb=(uint64_t)batch[i];
                if(acc0!=nb*expw[0] || acc1!=nb*expw[1] || acc2!=nb*expw[2] || acc3!=nb*expw[3]){
                    printf("\n  BATCH DIGEST FAIL %s len=%d rep %d: a hash in this timed batch was wrong; run invalid\n",
                           C[i].name, len, r);
                    if(use_ucode){ print_rsp_guard(); init_match_and_patch(); do_fix_IN_patch(); }
                    return 2;
                }
            }
        }
        for(int i=0;i<NCONT;i++){
            if(!C[i].usable) continue;
            C[i].med=median_u64(sample[i],REPS);
            C[i].min=robust_min(sample[i],REPS,C[i].med);
            C[i].p10=percentile_u64(sample[i],REPS,10.0);
            C[i].p90=percentile_u64(sample[i],REPS,90.0);
        }

        uint64_t uc = 0;
        for(int i=0;i<NCONT;i++) if(C[i].is_ucode && C[i].usable) uc=C[i].med;

        int order[NCONT], no=0;
        for(int i=0;i<NCONT;i++) if(C[i].usable) order[no++]=i;
        for(int a=1;a<no;a++){ int k=order[a],b=a-1;
            while(b>=0 && C[order[b]].med>C[k].med){ order[b+1]=order[b]; b--; } order[b+1]=k; }

        printf("\n--- SHA3-256, message = %d bytes (%d permutation%s) ---\n",
               len, np, np==1?"":"s");
        printf("  %-15s %-5s %10s %10s %10s %10s %9s   %s\n",
               "contender","type","median","min","p10","p90","cyc/byte","x vs ucode");
        for(int a=0;a<no;a++){
            int i=order[a];
            printf("  %-15s %-5s %10"PRIu64" %10"PRIu64" %10"PRIu64" %10"PRIu64" %9.2f",
                   C[i].name,C[i].type,C[i].med,C[i].min,C[i].p10,C[i].p90,
                   (double)C[i].med/(double)len);
            if(uc) printf("   %6.3fx%s",(double)C[i].med/(double)uc,
                          C[i].is_ucode?"  <== microcode":(C[i].med<uc?"  (beats ucode!)":""));
            printf("\n");
        }
        if(uc){
            uint64_t best=UINT64_MAX; const char *bn="";
            for(int i=0;i<NCONT;i++) if(C[i].usable&&!C[i].is_ucode&&C[i].med<best){best=C[i].med;bn=C[i].name;}
            printf("  fastest native: %s = %"PRIu64" cyc  |  microcode = %"PRIu64" cyc  |  %.3fx %s\n",
                   bn,best,uc,(double)best/(double)uc, uc<best?"(microcode WINS)":"(microcode loses)");
        }

        printf("\n=== matrix-parse len=%d ===\n", len);
        for(int i=0;i<NCONT;i++){
            if(!C[i].usable) continue;
            printf("sha3_256/%s: len %d perms %d min %"PRIu64" median %"PRIu64
                   " p10 %"PRIu64" p90 %"PRIu64"\n",
                   C[i].key,len,np,C[i].min,C[i].med,C[i].p10,C[i].p90);
        }
    }

    if(use_ucode){ printf("\n"); print_rsp_guard(); init_match_and_patch(); do_fix_IN_patch(); }
    printf("\n(all measured back-to-back at the same CPU frequency -> ratios valid)\n");
    return 0;
}
