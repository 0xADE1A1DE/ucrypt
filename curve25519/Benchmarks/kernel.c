
#define _GNU_SOURCE
#include "common.h"

/* -- harness geometry (unchanged from bench/bench_kernel.c) ---------- */
#define K_UNROLL 16
#define K_INNER  8
#define K_REPS   50
#define K_PHASES 20
#define K_POOL   (K_REPS * K_PHASES)
#define K_OPS    (K_INNER * K_UNROLL)

#define REP2(x)  x x
#define REP4(x)  REP2(x) REP2(x)
#define REP8(x)  REP4(x) REP4(x)

/* -- native backends ------------------------------------------------- */
#include "../third_party/curvesC/curve25519_mul.c"  /* fiat-crypto */
#include "../third_party/curvesC/curve25519_square.c"

extern void cryptopt_carry_mul(uint64_t out[5], const uint64_t a[5], const uint64_t b[5]);
extern void cryptopt_carry_square(uint64_t out[5], const uint64_t a[5]);
typedef struct { unsigned long long v[5]; } a51_fe_t;
extern void supercop_amd64_51_fe25519_mul(a51_fe_t *r, const a51_fe_t *x, const a51_fe_t *y);
extern void supercop_amd64_51_fe25519_square(a51_fe_t *r, const a51_fe_t *x);
void x25519_fe51_mul(uint64_t h[5], const uint64_t f[5], const uint64_t g[5]);
void x25519_fe51_sqr(uint64_t h[5], const uint64_t f[5]);
void bignum_mul_p25519_alt(uint64_t z[4], const uint64_t x[4], const uint64_t y[4]);
void bignum_sqr_p25519_alt(uint64_t z[4], const uint64_t x[4]);

/* All take (a[, b], out), the order the timing macros use. */
static inline void fe_mul_fiat(const uint64_t *a, const uint64_t *b, uint64_t *out)
{ fiat_curve25519_carry_mul(out, a, b); }
static inline void fe_sq_fiat(const uint64_t *a, uint64_t *out)
{ fiat_curve25519_carry_square(out, a); }
static inline void fe_mul_cryptopt(const uint64_t *a, const uint64_t *b, uint64_t *out)
{ cryptopt_carry_mul(out, a, b); }
static inline void fe_sq_cryptopt(const uint64_t *a, uint64_t *out)
{ cryptopt_carry_square(out, a); }
/* amd64-51's fe25519 is 5x51 radix 2^51, our layout, so the cast is a no-op. */
static inline void fe_mul_a51(const uint64_t *a, const uint64_t *b, uint64_t *out)
{ supercop_amd64_51_fe25519_mul((a51_fe_t *)out, (const a51_fe_t *)a, (const a51_fe_t *)b); }
static inline void fe_sq_a51(const uint64_t *a, uint64_t *out)
{ supercop_amd64_51_fe25519_square((a51_fe_t *)out, (const a51_fe_t *)a); }
static inline void fe_mul_ossl(const uint64_t *a, const uint64_t *b, uint64_t *out)
{ x25519_fe51_mul(out, a, b); }
static inline void fe_sq_ossl(const uint64_t *a, uint64_t *out)
{ x25519_fe51_sqr(out, a); }
static inline void fe_mul_s2n(const uint64_t *a, const uint64_t *b, uint64_t *out)
{ bignum_mul_p25519_alt(out, a, b); }
static inline void fe_sq_s2n(const uint64_t *a, uint64_t *out)
{ bignum_sqr_p25519_alt(out, a); }

static void fe_mul_handc(const uint64_t *a, const uint64_t *b, uint64_t *out) {
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

static void fe_sq_handc(const uint64_t *a, uint64_t *out) {
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

/* Native invocation floor: the call shape and memory traffic of a field op,
 * no arithmetic. noinline forces the call; the XORs keep both operand streams
 * live so the chain through `out` is real. (clang has no noclone.) */
#ifdef __clang__
#define NOINLINE_NOCLONE __attribute__((noinline))
#else
#define NOINLINE_NOCLONE __attribute__((noinline, noclone))
#endif
NOINLINE_NOCLONE
static void fe_mul_nfloor(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    uint64_t t0=a[0]^b[0], t1=a[1]^b[1], t2=a[2]^b[2], t3=a[3]^b[3], t4=a[4]^b[4];
    out[0]=t0; out[1]=t1; out[2]=t2; out[3]=t3; out[4]=t4;
    asm volatile("" ::: "memory");
}
NOINLINE_NOCLONE
static void fe_sq_nfloor(const uint64_t *a, uint64_t *out) {
    uint64_t t0=a[0], t1=a[1], t2=a[2], t3=a[3], t4=a[4];
    out[0]=t0; out[1]=t1; out[2]=t2; out[3]=t3; out[4]=t4;
    asm volatile("" ::: "memory");
}

/* -- operand storage ------------------------------------------------- */
/* Microcode operands live in g_st, addressed by the FE_* macros as [rbp+off].
 * The timed asm points RBP at g_st itself, saving the caller's RBP in
 * g_rbp_save, both RIP-relative: no C operand is bound to RBP, so the timing
 * loop is correct whether or not the compiler uses RBP as a frame pointer
 * (gcc -Os gives main one; see project note inline2-adc-mod2). */
__attribute__((used)) static ladder_state_t g_st;
__attribute__((used)) static uint64_t g_rbp_save;
static uint64_t pa[5], pb[5], pk[5];           /* native ping-pong + multiplier */
static uint64_t qa[5], qb[5], ra[5], rb[5], sa[5], sb[5];   /* tput chains     */
static uint64_t xa[4], xb[4], xk[4];           /* the same, 4x64 for s2n        */
static uint64_t ya[4], yb[4], za[4], zb[4], wa[4], wb[4];

static void bytes_to_4x64(uint64_t o[4], const uint8_t in[32]) {
    for (int i = 0; i < 4; i++) {
        uint64_t v = 0;
        for (int j = 7; j >= 0; j--) v = (v << 8) | in[i * 8 + j];
        o[i] = v;
    }
}

static void init_operands(void) {
    uint64_t *p = (uint64_t *)&g_st;
    for (size_t i = 0; i < sizeof(g_st) / 8; i++)
        p[i] = (0x123456789ABCDULL * (i + 1)) & MASK51;
    for (int i = 0; i < 5; i++) {
        pa[i] = (0x13579BDF02468ULL * (i + 1)) & MASK51;
        pb[i] = (0x2468ACE013579ULL * (i + 1)) & MASK51;
        pk[i] = (0x0FEDCBA987654ULL * (i + 1)) & MASK51;
        qa[i] = pa[i] ^ 0x11; qb[i] = pb[i] ^ 0x11;
        ra[i] = pa[i] ^ 0x22; rb[i] = pb[i] ^ 0x22;
        sa[i] = pa[i] ^ 0x33; sb[i] = pb[i] ^ 0x33;
    }
    /* s2n multiplies the same field elements, re-encoded. */
    uint8_t t[32];
    fe_tobytes(t, pa); bytes_to_4x64(xa, t);
    fe_tobytes(t, pb); bytes_to_4x64(xb, t);
    fe_tobytes(t, pk); bytes_to_4x64(xk, t);
    memcpy(ya, xa, 32); memcpy(yb, xb, 32);
    memcpy(za, xa, 32); memcpy(zb, xb, 32);
    memcpy(wa, xa, 32); memcpy(wb, xb, 32);
}

/* -- correctness ----------------------------------------------------- */
static uint64_t rng = 0x2545F4914F6CDD1DULL;
static uint64_t rnd(void) {                     /* xorshift64* */
    rng ^= rng >> 12; rng ^= rng << 25; rng ^= rng >> 27;
    return rng * 0x2545F4914F6CDD1DULL;
}
static void rnd_fe(uint64_t a[5], int bits) {
    for (int i = 0; i < 5; i++) a[i] = rnd() >> (64 - bits);
}
/* Canonical encodings must match the reference (hand-written C, exact for
 * limbs < 2^54). Microcode at limbs < 2^53, the most the ladder feeds it;
 * natives at < 2^51, inside every native backend's input contract. */
static int check_mul(void (*f)(const uint64_t *, const uint64_t *, uint64_t *),
                     int bits, int n) {
    uint64_t a[5], b[5], got[5], want[5];
    uint8_t g[32], w[32];
    int bad = 0;
    for (int k = 0; k < n; k++) {
        rnd_fe(a, bits); rnd_fe(b, bits);
        f(a, b, got); fe_mul_handc(a, b, want);
        fe_tobytes(g, got); fe_tobytes(w, want);
        bad += memcmp(g, w, 32) != 0;
    }
    return bad;
}
static int check_sq(void (*f)(const uint64_t *, uint64_t *), int bits, int n) {
    uint64_t a[5], got[5], want[5];
    uint8_t g[32], w[32];
    int bad = 0;
    for (int k = 0; k < n; k++) {
        rnd_fe(a, bits);
        f(a, got); fe_sq_handc(a, want);
        fe_tobytes(g, got); fe_tobytes(w, want);
        bad += memcmp(g, w, 32) != 0;
    }
    return bad;
}
static void s2n_mul_5(const uint64_t *a, const uint64_t *b, uint64_t *out) {
    uint64_t x[4], y[4], z[4]; uint8_t t[32];
    fe_tobytes(t, a); bytes_to_4x64(x, t);
    fe_tobytes(t, b); bytes_to_4x64(y, t);
    bignum_mul_p25519_alt(z, x, y);
    memcpy(t, z, 32); t[31] &= 0x7f;            /* z < p: plain 255-bit value */
    fe_frombytes(out, t);
}
static void s2n_sq_5(const uint64_t *a, uint64_t *out) {
    uint64_t x[4], z[4]; uint8_t t[32];
    fe_tobytes(t, a); bytes_to_4x64(x, t);
    bignum_sqr_p25519_alt(z, x);
    memcpy(t, z, 32); t[31] &= 0x7f;
    fe_frombytes(out, t);
}
static void uc_mul_ab(const uint64_t *a, const uint64_t *b, uint64_t *out) { uc_fe_mul(out, a, b); }
static void uc_sq_a(const uint64_t *a, uint64_t *out) { uc_fe_sq(out, a); }

#define CHECK_N 2000
static int check_natives(void) {
    struct { const char *n; void (*m)(const uint64_t *, const uint64_t *, uint64_t *);
             void (*s)(const uint64_t *, uint64_t *); } B[] = {
        { "openssl",  fe_mul_ossl,     fe_sq_ossl     },
        { "fiat",     fe_mul_fiat,     fe_sq_fiat     },
        { "cryptopt", fe_mul_cryptopt, fe_sq_cryptopt },
        { "amd64-51", fe_mul_a51,      fe_sq_a51      },
        { "s2n",      s2n_mul_5,       s2n_sq_5       },
    };
    int bad = 0;
    for (unsigned i = 0; i < sizeof B / sizeof B[0]; i++) {
        int b = check_mul(B[i].m, 51, CHECK_N) + check_sq(B[i].s, 51, CHECK_N);
        if (b) printf("  kernel check %-9s FAIL (%d of %d)\n", B[i].n, b, 2 * CHECK_N);
        bad += b;
    }
    printf("  kernel check natives    %s (5 backends x %d random mul+sq vs hand-C)\n",
           bad ? "FAIL" : "pass", 2 * CHECK_N);
    return bad;
}
static int check_ours(const char *name) {
    int b = check_mul(uc_mul_ab, 53, CHECK_N) + check_sq(uc_sq_a, 53, CHECK_N);
    printf("  kernel check %-10s %s (%d random mul+sq, limbs < 2^53, vs hand-C)\n",
           name, b ? "FAIL" : "pass", 2 * CHECK_N);
    return b;
}

/* -- the 1-triad no-op probe (dispatch floor): kernel_floor's "variant" -- */
__attribute__((unused))
static void install_floor_patches(int verbose) {
    ucode_t probe_mul[] = { { ZEROEXT_DSZ64_DR(RDI, RDI), NOP, NOP, END_SEQWORD } };
    ucode_t probe_sq[]  = { { ZEROEXT_DSZ64_DR(RDI, RDI), NOP, NOP, END_SEQWORD } };
    patch_ucode(0x7c00, probe_mul, 1);
    hook_match_and_patch(0, 0x0cd8, 0x7c00);
    patch_ucode(0x7c04, probe_sq, 1);
    hook_match_and_patch(1, 0x0618, 0x7c04);
    if (verbose) printf("fe_mul, fe_sq: 1-triad no-op patches at U7c00, U7c04\n");
}
/* The floor binary has nothing of ours to check: a no-op patch computes nothing. */
static int is_floor(void) { return !strcmp(VARIANT_NAME, "floor"); }

/* -- microcode arm bodies, 16 firings each --------------------------- */
/* Dependent: ping-pong A <-> B, each op reads the previous op's output from
 * a different address than it writes. */
#define UC_MUL_LAT  REP8(FE_MUL(B_OFF, A_OFF, Z2_OFF) FE_MUL(A_OFF, B_OFF, Z2_OFF))
#define UC_SQ_LAT   REP8(FE_SQ(B_OFF, A_OFF)          FE_SQ(A_OFF, B_OFF))
/* Independent: four disjoint ping-pong pairs. */
#define UC_MUL_TPUT REP4(FE_MUL(B_OFF, A_OFF, Z2_OFF)   FE_MUL(BB_OFF, AA_OFF, Z2_OFF) \
                         FE_MUL(D_OFF, C_OFF, Z2_OFF)   FE_MUL(DA_OFF, CB_OFF, Z2_OFF))
#define UC_SQ_TPUT  REP4(FE_SQ(B_OFF, A_OFF)   FE_SQ(BB_OFF, AA_OFF) \
                         FE_SQ(D_OFF, C_OFF)   FE_SQ(DA_OFF, CB_OFF))

/* -- arms: pooled samples per (name, mode) --------------------------- */
#define MAX_ARMS 64
typedef struct { char name[24]; const char *mode; int n; uint64_t pool[K_POOL]; } arm_t;
static arm_t g_arm[MAX_ARMS];
static int   g_narms;
static uint64_t g_smp[K_REPS];

static arm_t *arm_find(const char *name, const char *mode) {
    for (int i = 0; i < g_narms; i++)
        if (!strcmp(g_arm[i].name, name) && !strcmp(g_arm[i].mode, mode)) return &g_arm[i];
    return NULL;
}
static void arm_record(const char *name, const char *mode, const uint64_t *smp, int n) {
    arm_t *a = arm_find(name, mode);
    if (!a) {
        if (g_narms >= MAX_ARMS) { fprintf(stderr, "kernel: raise MAX_ARMS\n"); exit(1); }
        a = &g_arm[g_narms++];
        snprintf(a->name, sizeof a->name, "%s", name);
        a->mode = mode;
        a->n = 0;
    }
    for (int k = 0; k < n && a->n < K_POOL; k++) a->pool[a->n++] = smp[k];
}
/* Median cycles per op, or -1 if the arm did not run. Sorts the pool. */
static double arm_med(const char *name, const char *mode) {
    arm_t *a = arm_find(name, mode);
    if (!a || !a->n) return -1;
    qsort(a->pool, a->n, sizeof(uint64_t), cmp_u64);
    return (double)a->pool[a->n / 2] / K_OPS;
}

#define UC_CLOBBERS "rax", "rbx", "rcx", "rdx", "rsi", "rdi", \
                    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "memory", "cc"
/* Time a microcode body: K_INNER asm blocks of 16 firings per sample. */
#define TIME_UC(NAME, MODE, BODY) do {                                        \
    for (int q = 0; q < K_REPS; q++) {                                        \
        uint64_t _a = rdtsc_start();                                          \
        for (int _i = 0; _i < K_INNER; _i++)                                  \
            asm volatile("mov qword ptr [rip + g_rbp_save], rbp\n\t"          \
                         "lea rbp, [rip + g_st]\n\t"                          \
                         BODY                                                 \
                         "mov rbp, qword ptr [rip + g_rbp_save]\n\t"          \
                         ::: UC_CLOBBERS);                                    \
        g_smp[q] = rdtsc_end() - _a;                                          \
    }                                                                         \
    arm_record(NAME, MODE, g_smp, K_REPS);                                    \
} while (0)

/* Time a native backend: K_OPS/4 groups of 4 calls per sample. */
#define TIME_C(NAME, MODE, GROUP, BARRIER) do {                               \
    for (int q = 0; q < K_REPS; q++) {                                        \
        uint64_t _a = rdtsc_start();                                          \
        for (int _i = 0; _i < K_OPS / 4; _i++) { GROUP; BARRIER; }            \
        g_smp[q] = rdtsc_end() - _a;                                          \
    }                                                                         \
    arm_record(NAME, MODE, g_smp, K_REPS);                                    \
} while (0)

#define BAR   asm volatile("" ::: "memory")
#define NOBAR ((void)0)
#define C_MUL_LAT(F)   F(pa, pk, pb); F(pb, pk, pa); F(pa, pk, pb); F(pb, pk, pa)
#define C_SQ_LAT(F)    F(pa, pb);     F(pb, pa);     F(pa, pb);     F(pb, pa)
#define C_MUL_TPUT(F)  F(pa, pk, pb); F(qa, pk, qb); F(ra, pk, rb); F(sa, pk, sb)
#define C_SQ_TPUT(F)   F(pa, pb);     F(qa, qb);     F(ra, rb);     F(sa, sb)
#define C4_MUL_LAT(F)  F(xa, xk, xb); F(xb, xk, xa); F(xa, xk, xb); F(xb, xk, xa)
#define C4_SQ_LAT(F)   F(xa, xb);     F(xb, xa);     F(xa, xb);     F(xb, xa)
#define C4_MUL_TPUT(F) F(xa, xk, xb); F(ya, xk, yb); F(za, xk, zb); F(wa, xk, wb)
#define C4_SQ_TPUT(F)  F(xa, xb);     F(ya, yb);     F(za, zb);     F(wa, wb)

/* Every arm of one native backend. P = "" for 5x51, "4" for 4x64 operands. */
#define TIME_NATIVE(NAME, FM, FS, P) do {                                     \
    TIME_C("Fe_mul_" NAME, "lat",  C##P##_MUL_LAT(FM),  BAR);                 \
    TIME_C("Fe_sq_"  NAME, "lat",  C##P##_SQ_LAT(FS),   BAR);                 \
    TIME_C("Fe_mul_" NAME, "nb",   C##P##_MUL_LAT(FM),  NOBAR);               \
    TIME_C("Fe_sq_"  NAME, "nb",   C##P##_SQ_LAT(FS),   NOBAR);               \
    TIME_C("Fe_mul_" NAME, "tput", C##P##_MUL_TPUT(FM), BAR);                 \
    TIME_C("Fe_sq_"  NAME, "tput", C##P##_SQ_TPUT(FS),  BAR);                 \
} while (0)

/* -- report ---------------------------------------------------------- */
/* Each process has one microcode row (its variant, or the floor); rows
 * without data are skipped. */
static const struct { const char *name, *desc; int uc; } BACKENDS[] = {
    { "setcc",    "ours/setcc microcode",           1 },
    { "adc",      "ours/adc microcode (ADC|MOD2)",  1 },
    { "floor",    "microcode dispatch floor",       1 },
    { "openssl",  "OpenSSL fe51 asm",               0 },
    { "fiat",     "fiat-crypto",                    0 },
    { "cryptopt", "CryptOpt",                       0 },
    { "amd64-51", "amd64-51 asm (SUPERCOP)",        0 },
    { "handc",    "hand-written __uint128_t C",     0 },
    { "s2n",      "s2n-bignum _alt (4x64)",         0 },
};
#define N_BACKENDS ((int)(sizeof BACKENDS / sizeof BACKENDS[0]))

static double kmed(const char *op, const char *backend, const char *mode) {
    char name[32];
    snprintf(name, sizeof name, "Fe_%s_%s", op, backend);
    return arm_med(name, mode);
}
static void cell(double v) { if (v >= 0) printf(" %9.1f", v); else printf(" %9s", "n/a"); }
static int ran(int b) { return kmed("mul", BACKENDS[b].name, "lat") >= 0; }

static void report(void) {
    double nm = arm_med("Fe_mul_nfloor", "lat"), ns = arm_med("Fe_sq_nfloor", "lat");

    printf("\n=== %s (median cycles per op) ===\n\n",
           is_floor() ? "Microcode dispatch floor: 1-triad no-op patches" : "ours/" VARIANT_NAME);
    printf("  %-16s %9s %9s\n", "kernel", "latency", "tput");
    for (int o = 0; o < 2; o++) {
        const char *op = o ? "sq" : "mul";
        char name[32];
        snprintf(name, sizeof name, "Fe_%s_%s", op, VARIANT_NAME);
        printf("  %-16s", name);
        cell(kmed(op, VARIANT_NAME, "lat")); cell(kmed(op, VARIANT_NAME, "tput"));
        printf("\n");
    }
    if (!is_floor())
        printf("  arith only = latency - dispatch floor, in SUMMARY.md: kernel_floor\n"
               "  measures the floor in its own process\n");

    printf("\n=== All backends: latency, dependent chain, memory to memory ===\n\n");
    printf("  %-32s %9s %9s %9s %9s\n", "backend", "Fe_mul", "Fe_sq", "mul arith", "sq arith");
    for (int b = 0; b < N_BACKENDS; b++) {
        if (!ran(b)) continue;
        double m = kmed("mul", BACKENDS[b].name, "lat"), s = kmed("sq", BACKENDS[b].name, "lat");
        printf("  %-32s", BACKENDS[b].desc);
        cell(m); cell(s);
        if (BACKENDS[b].uc) printf(" %9s %9s", "", "");
        else { cell(m >= 0 && nm >= 0 ? m - nm : -1); cell(s >= 0 && ns >= 0 ? s - ns : -1); }
        printf("\n");
    }
    printf("  %-32s", "native floor"); cell(nm); cell(ns); printf("\n");
    printf("  arith = latency - native floor, natives only; ours is in SUMMARY.md.\n");

    printf("\n=== All backends: throughput, four independent chains ===\n\n");
    printf("  %-32s %9s %9s\n", "backend", "Fe_mul", "Fe_sq");
    for (int b = 0; b < N_BACKENDS; b++) {
        if (!ran(b)) continue;
        printf("  %-32s", BACKENDS[b].desc);
        cell(kmed("mul", BACKENDS[b].name, "tput")); cell(kmed("sq", BACKENDS[b].name, "tput"));
        printf("\n");
    }

    printf("\n=== Natives without the per-op memory barrier (their best case) ===\n\n");
    printf("  %-32s %9s %9s\n", "backend", "Fe_mul", "Fe_sq");
    for (int b = 0; b < N_BACKENDS; b++) {
        if (BACKENDS[b].uc || !ran(b)) continue;
        printf("  %-32s", BACKENDS[b].desc);
        cell(kmed("mul", BACKENDS[b].name, "nb")); cell(kmed("sq", BACKENDS[b].name, "nb"));
        printf("\n");
    }

    printf("\n");
    for (int i = 0; i < g_narms; i++) {
        arm_t *a = &g_arm[i];
        stats_t s = stats_of(a->pool, a->n);
        printf("KERNEL %s %s %.2f %.2f %.2f %.2f\n", a->name, a->mode,
               (double)s.med / K_OPS, (double)s.min / K_OPS,
               (double)s.p10 / K_OPS, (double)s.p90 / K_OPS);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* static binary: keep output on a crash */
    printf("=== Kernels: fe_mul / fe_sq, %s and the natives, 5x51 (s2n 4x64) ===\n",
           is_floor() ? "the dispatch floor" : "ours/" VARIANT_NAME);
    if (freq_guard()) return 2;
    bench_pin();
    int root = geteuid() == 0;
    printf("method: %d ops/sample, %d samples x %d phases = %d pooled samples/arm;"
           " patches installed once, never swapped%s\n\n",
           K_OPS, K_REPS, K_PHASES, K_POOL,
           root ? "" : "\nNOT ROOT: microcode arms skipped, natives only");

    int bad = check_natives();
    if (root) {
        ucode_setup();
        install_variant(1);
        if (!is_floor()) {
            bad += check_ours(VARIANT_NAME);
            bad += rfc7748_check("ours/" VARIANT_NAME, x25519_ours, 0);
        }
    }
    if (bad) {
        printf("\nCORRECTNESS CHECK FAILED -- nothing timed.\n");
        if (root) ucode_teardown();
        return 1;
    }

    for (int ph = 0; ph < K_PHASES; ph++) {
        if (root) {
            init_operands();
            TIME_UC("Fe_mul_" VARIANT_NAME, "lat",  UC_MUL_LAT);
            TIME_UC("Fe_sq_"  VARIANT_NAME, "lat",  UC_SQ_LAT);
            TIME_UC("Fe_mul_" VARIANT_NAME, "tput", UC_MUL_TPUT);
            TIME_UC("Fe_sq_"  VARIANT_NAME, "tput", UC_SQ_TPUT);
        }
        init_operands();
        TIME_NATIVE("openssl",  fe_mul_ossl,     fe_sq_ossl,     );
        TIME_NATIVE("fiat",     fe_mul_fiat,     fe_sq_fiat,     );
        TIME_NATIVE("cryptopt", fe_mul_cryptopt, fe_sq_cryptopt, );
        TIME_NATIVE("amd64-51", fe_mul_a51,      fe_sq_a51,      );
        TIME_NATIVE("handc",    fe_mul_handc,    fe_sq_handc,    );
        TIME_NATIVE("s2n",      fe_mul_s2n,      fe_sq_s2n,      4);
        TIME_C("Fe_mul_nfloor", "lat", C_MUL_LAT(fe_mul_nfloor), BAR);
        TIME_C("Fe_sq_nfloor",  "lat", C_SQ_LAT(fe_sq_nfloor),   BAR);
    }

    if (root) {
        /* The same patches, still installed: check them again after timing. */
        if (!is_floor()) {
            printf("\n");
            bad += check_ours(VARIANT_NAME);
        }
        ucode_teardown();
        if (bad) {
            printf("\nKERNEL RE-CHECK FAILED after the timed phases -- results discarded.\n");
            return 1;
        }
    }

    report();

    /* Sinks, so no chain can be optimised away. */
    volatile uint64_t sink = 0;
    for (int i = 0; i < 5; i++) sink ^= pa[i] ^ pb[i] ^ qa[i] ^ qb[i] ^ ra[i] ^ rb[i] ^ sa[i] ^ sb[i];
    for (int i = 0; i < 4; i++) sink ^= xa[i] ^ xb[i] ^ ya[i] ^ yb[i] ^ za[i] ^ zb[i] ^ wa[i] ^ wb[i];
    for (size_t i = 0; i < sizeof(g_st) / 8; i++) sink ^= ((uint64_t *)&g_st)[i];
    printf("(checksum %llu)\nDONE kernel\n", (unsigned long long)sink);
    return 0;
}
