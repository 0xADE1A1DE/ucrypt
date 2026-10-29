/*
 * bench_core.h 
 */
#ifndef C25519_BENCH_CORE_H
#define C25519_BENCH_CORE_H

#include <stdlib.h>

static inline int bench_core(void)
{
    const char *e = getenv("BENCH_CORE");
    if (!e || !*e) return 1;
    return (int)strtol(e, NULL, 10);
}

/* Pin to BENCH_CORE and print where we actually landed, so every log carries
 * its own proof of the core it was measured on (the benchmark harness checks it).
 * Needs misc.h's assign_to_core, so include this after misc.h. */
#ifdef MISC_H_
#include <sched.h>
#include <stdio.h>
static inline void bench_pin(void)
{
    int c = bench_core();
    assign_to_core(c);
    printf("PINNED core=%d sched_getcpu=%d\n", c, sched_getcpu());
}
#endif

#endif /* C25519_BENCH_CORE_H */
