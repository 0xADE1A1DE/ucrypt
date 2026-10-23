/*
 * common.h -- shared by kernel.c and x25519.c: includes, our 5x51 X25519 with
 * both patch sets, the variant this binary runs, timing, statistics and the
 * RFC 7748 correctness gate.
 */
#ifndef BENCH_COMMON_H
#define BENCH_COMMON_H

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stddef.h>
#include <unistd.h>
#include <patch.h>
#include <ucode_macro.h>
#include <misc.h>
#include "../include/bench_core.h"      /* bench_pin(): pin to BENCH_CORE, print PINNED */
#include "../freq_guard.h"              /* freq_guard(): refuse an unpinned core       */
#include "ours/ours.h"

/* ── which patch set this process runs ───────────────────────────────
 * One binary per patch set. Each is built from a short wrapper file
 * (x25519_setcc.c, kernel_adc.c, ...) that sets BENCH_VARIANT and includes
 * the shared benchmark. The process installs that variant's patches once and
 * never swaps them. Two full sweeps that swapped patch sets inside one process
 * each wedged the bench core (2026-10-08 and 2026-10-09). */
#ifndef BENCH_VARIANT
#error "build a wrapper (x25519_setcc.c, kernel_adc.c, ...), not the shared file"
#endif
#define _CAT3(a, b, c)  a##b##c
#define CAT3(a, b, c)   _CAT3(a, b, c)
#define VARIANT_NAME    S(BENCH_VARIANT)                       /* "setcc" */
#define install_variant CAT3(install_, BENCH_VARIANT, _patches)

/* ── timing ──────────────────────────────────────────────────────────
 * cpuid serialises before the start read; rdtscp + cpuid after the end read
 * keep later instructions out of the timed region. RDTSC ticks are core
 * cycles only with turbo off and the core at base (freq_guard). */
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

/* ── statistics: median (the headline), min, p10, p90 ─────────────── */
typedef struct { uint64_t med, min, p10, p90; } stats_t;

static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}
/* Nearest-rank percentile of an ascending array. */
static uint64_t pctl(const uint64_t *sorted, int n, double pct) {
    int i = (int)(pct / 100.0 * (n - 1) + 0.5);
    return sorted[i < 0 ? 0 : i >= n ? n - 1 : i];
}
/* Sorts samples in place. */
static stats_t stats_of(uint64_t *samples, int n) {
    qsort(samples, n, sizeof(uint64_t), cmp_u64);
    stats_t s = { samples[n / 2], samples[0], pctl(samples, n, 10), pctl(samples, n, 90) };
    return s;
}

/* ── hex ─────────────────────────────────────────────────────────── */
static void hex_to_bytes(const char *hex, uint8_t *out, int len) {
    for (int i = 0; i < len; i++) {
        unsigned int v;
        sscanf(hex + 2 * i, "%02x", &v);
        out[i] = (uint8_t)v;
    }
}

/* ── RFC 7748 section 5.2 ────────────────────────────────────────── */
typedef void (*x25519_fn)(uint8_t out[32], const uint8_t scalar[32],
                          const uint8_t point[32]);

#define RFC_V1_SCALAR "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"
#define RFC_V1_POINT  "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c"
#define RFC_V1_OUT    "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
#define RFC_V2_SCALAR "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"
#define RFC_V2_POINT  "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493"
#define RFC_V2_OUT    "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"
#define RFC_IT1_OUT   "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"
#define RFC_IT1000_OUT "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"

/* Vectors 1 and 2, then the iterated test for 1 and (if iter1000) 1000
 * iterations. Prints one line; returns the number of failed checks. */
static int rfc7748_check(const char *label, x25519_fn fn, int iter1000) {
    uint8_t s[32], p[32], r[32], want[32];
    int fail = 0;

    hex_to_bytes(RFC_V1_SCALAR, s, 32); hex_to_bytes(RFC_V1_POINT, p, 32);
    hex_to_bytes(RFC_V1_OUT, want, 32);
    fn(r, s, p); fail += memcmp(r, want, 32) != 0;

    hex_to_bytes(RFC_V2_SCALAR, s, 32); hex_to_bytes(RFC_V2_POINT, p, 32);
    hex_to_bytes(RFC_V2_OUT, want, 32);
    fn(r, s, p); fail += memcmp(r, want, 32) != 0;

    uint8_t k[32] = {9}, u[32] = {9};
    int iters = iter1000 ? 1000 : 1;
    for (int i = 1; i <= iters; i++) {
        fn(r, k, u);
        memcpy(u, k, 32);
        memcpy(k, r, 32);
        if (i == 1) { hex_to_bytes(RFC_IT1_OUT, want, 32); fail += memcmp(k, want, 32) != 0; }
    }
    if (iter1000) { hex_to_bytes(RFC_IT1000_OUT, want, 32); fail += memcmp(k, want, 32) != 0; }

    printf("  RFC 7748 %-20s %s (vectors 1, 2, iterated x1%s)\n", label,
           fail ? "FAIL" : "pass", iter1000 ? " and x1000" : "");
    return fail;
}

/* ── setup / teardown of the microcode hooks ─────────────────────── */
static void ucode_setup(void) {
    init_match_and_patch();
    do_fix_IN_patch();
}
static void ucode_teardown(void) {
    init_match_and_patch();
    do_fix_IN_patch();
}

#endif /* BENCH_COMMON_H */
