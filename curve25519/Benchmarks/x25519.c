/*
 * x25519.c -- LEVEL 2: one complete X25519 (RFC 7748 vector 1), end to end.
 *
 * Shared body of x25519_setcc.c and x25519_adc.c. Each binary times ONE of our
 * variants against the SUPERCOP implementations that run on this core,
 * s2n-bignum and OpenSSL.
 *
 *   ours/setcc          ours.h ladder + patch_setcc.h (SETCC carries)
 *   ours/adc            ours.h ladder + patch_adc.h   (ADD|MOD2 + ADC|MOD2)
 *   supercop/amd64-64   Bernstein-Schwabe, 4x64 asm (lib25519's pick on Goldmont)
 *   supercop/amd64-51   Bernstein-Schwabe, 5x51 asm
 *   supercop/donna_c64  Langley, 5x51 C
 *   s2n-bignum          AWS s2n-bignum curve25519_x25519_alt, formally verified
 *                       4x64 asm. SUPERCOP's s2n-alt is a wrapper of exactly
 *                       this; the non-_alt version needs MULX/ADX, absent here
 *   openssl             OpenSSL's own X25519 (../openssl_x25519.c): its 5x51 C
 *                       ladder and inversion over its fe51 asm field kernels,
 *                       the path OpenSSL selects on a core without ADX
 *
 * Not runnable here, so not contenders: sandy2x (AVX), s2n (MULX/ADX), athlon
 * (32-bit), neon2 (ARM). The reference codes (ref, ref10, donna) are omitted.
 *
 * Method. The variant's patches are installed once, before any check, and
 * stay installed until the process exits: never swapped (see ../common.h).
 * Then X_ROUNDS round-robin rounds of {ours/<variant>, every other contender},
 * one sample each per round, so slow drift is spread over all of them. The
 * other variant is a separate process (run.sh runs setcc, then adc), and
 * the other contenders are timed in both.
 *
 * Correctness. Every contender passes RFC 7748 (vectors 1 and 2, iterated x1
 * and x1000) before any timing; every timed call's output is then compared
 * with the vector 1 answer, and ours is re-checked at the end. Any failure
 * exits non-zero and prints no results.
 *
 * Output: one "X25519 <label> <median> <min> <p10> <p90>" line per contender
 * (cycles; parsed by summarize.py) and a table with ratios to ours.
 *
 * Build: make            Run: sudo env BENCH_CORE=1 taskset -c 1 ./x25519_setcc_static
 * Needs the microcode debug unlock first: sudo wrmsr -p 1 0x1e6 0x200.
 * run.sh does all of this, plus core isolation and the compiler sweep.
 */
#define _GNU_SOURCE
#include "common.h"

#define X_ROUNDS 1000
#define OURS_LABEL "ours/" VARIANT_NAME

/* ── the other contenders ────────────────────────────────────────────
 * donna_c64 is one C file, compiled into this translation unit with its entry
 * point renamed; its static helpers do not clash with ours.h. amd64-51 and
 * amd64-64 are separate objects (Makefile), renamed by the namespace headers.
 * s2n-bignum's entry takes 64-bit words; x86 is little endian, so the byte
 * arrays are copied into aligned word buffers. It clamps the scalar itself.
 * OpenSSL's is a separate object built from ../openssl_x25519.c. */
#define crypto_scalarmult x25519_donna_c64
#include "../third_party/supercop-20260330/crypto_scalarmult/curve25519/donna_c64/smult.c"
#undef crypto_scalarmult

extern int x25519_amd64_64(unsigned char *out, const unsigned char *scalar,
                           const unsigned char *point);
extern int x25519_amd64_51(unsigned char *out, const unsigned char *scalar,
                           const unsigned char *point);
extern void curve25519_x25519_alt(uint64_t res[4], const uint64_t scalar[4],
                                  const uint64_t point[4]);
extern void x25519_openssl(uint8_t out[32], const uint8_t scalar[32],
                           const uint8_t point[32]);

static void sc_amd64_64(uint8_t o[32], const uint8_t s[32], const uint8_t p[32])
{ (void)x25519_amd64_64(o, s, p); }
static void sc_amd64_51(uint8_t o[32], const uint8_t s[32], const uint8_t p[32])
{ (void)x25519_amd64_51(o, s, p); }
static void sc_donna(uint8_t o[32], const uint8_t s[32], const uint8_t p[32])
{ (void)x25519_donna_c64(o, s, p); }
static void s2n_bignum(uint8_t o[32], const uint8_t s[32], const uint8_t p[32]) {
    uint64_t r[4], n[4], q[4];
    memcpy(n, s, 32);
    memcpy(q, p, 32);
    curve25519_x25519_alt(r, n, q);
    memcpy(o, r, 32);
}

static const struct { const char *label; x25519_fn fn; } OTHERS[] = {
    { "supercop/amd64-64",  sc_amd64_64    },
    { "supercop/amd64-51",  sc_amd64_51    },
    { "supercop/donna_c64", sc_donna       },
    { "s2n-bignum",         s2n_bignum     },
    { "openssl",            x25519_openssl },
};
#define N_OTH ((int)(sizeof OTHERS / sizeof OTHERS[0]))

static uint64_t ours_smp[X_ROUNDS];
static uint64_t oth_smp[N_OTH][X_ROUNDS];

/* One table row; ratio = this median / ours's (> 1 = ours faster). */
static void row(const char *label, stats_t s, uint64_t ours_med) {
    printf("  %-20s %9" PRIu64 " %9" PRIu64 " %9" PRIu64 " %9" PRIu64,
           label, s.med, s.min, s.p10, s.p90);
    if (ours_med) printf(" %8.3f", (double)s.med / ours_med);
    printf("\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);   /* static binary: keep output on a crash */
    printf("=== X25519, complete implementations (" OURS_LABEL
           " 5x51 microcode vs SUPERCOP, s2n-bignum, OpenSSL) ===\n");
    if (freq_guard()) return 2;
    bench_pin();
    int root = geteuid() == 0;
    printf("method: %d round-robin rounds; " OURS_LABEL "'s patches installed once, never swapped%s\n\n",
           X_ROUNDS, root ? "" : "\nNOT ROOT: " OURS_LABEL " skipped, the others only");

    int bad = 0;
    for (int c = 0; c < N_OTH; c++)
        bad += rfc7748_check(OTHERS[c].label, OTHERS[c].fn, 1);
    if (root) {
        ucode_setup();
        install_variant(1);
        bad += rfc7748_check(OURS_LABEL, x25519_ours, 1);
    }
    if (bad) {
        printf("\nRFC 7748 FAILED (%d checks) -- nothing timed.\n", bad);
        if (root) ucode_teardown();
        return 1;
    }
    printf("\n");

    uint8_t scalar[32], point[32], want[32], out[32];
    hex_to_bytes(RFC_V1_SCALAR, scalar, 32);
    hex_to_bytes(RFC_V1_POINT, point, 32);
    hex_to_bytes(RFC_V1_OUT, want, 32);
    long wrong = 0;

    for (int r = 0; r < X_ROUNDS; r++) {
        if (root) {
            uint64_t t0 = rdtsc_start();
            x25519_ours(out, scalar, point);
            uint64_t t1 = rdtsc_end();
            ours_smp[r] = t1 - t0;
            wrong += memcmp(out, want, 32) != 0;
        }
        for (int c = 0; c < N_OTH; c++) {
            uint64_t t0 = rdtsc_start();
            OTHERS[c].fn(out, scalar, point);
            uint64_t t1 = rdtsc_end();
            oth_smp[c][r] = t1 - t0;
            wrong += memcmp(out, want, 32) != 0;
        }
    }

    /* The same patches, still installed: check them again after timing. */
    if (root) {
        bad += rfc7748_check(OURS_LABEL " (after)", x25519_ours, 0);
        ucode_teardown();
    }
    if (wrong || bad) {
        printf("\nFAILED: %ld timed calls returned a wrong answer, %d re-checks failed"
               " -- results discarded.\n", wrong, bad);
        return 1;
    }
    printf("  every timed call returned the RFC 7748 vector 1 answer\n\n");

    /* ── report ── */
    stats_t so = {0}, ss[N_OTH];
    if (root) so = stats_of(ours_smp, X_ROUNDS);
    for (int c = 0; c < N_OTH; c++) ss[c] = stats_of(oth_smp[c], X_ROUNDS);

    printf("  %-20s %9s %9s %9s %9s %8s\n", "contender", "median", "min", "p10", "p90", "/ours");
    if (root) row(OURS_LABEL, so, so.med);
    for (int c = 0; c < N_OTH; c++) row(OTHERS[c].label, ss[c], so.med);
    printf("  (cycles; /ours = median / " OURS_LABEL "'s median, >1 = ours faster)\n\n");

    if (root)
        printf("X25519 " OURS_LABEL " %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
               so.med, so.min, so.p10, so.p90);
    for (int c = 0; c < N_OTH; c++)
        printf("X25519 %s %" PRIu64 " %" PRIu64 " %" PRIu64 " %" PRIu64 "\n",
               OTHERS[c].label, ss[c].med, ss[c].min, ss[c].p10, ss[c].p90);
    printf("DONE x25519\n");
    return 0;
}
