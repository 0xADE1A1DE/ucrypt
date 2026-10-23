/*
 * bench_core.h — which physical core a Keccak harness pins itself to.
 *
 *
 *   default                      core 1 
 *   BENCH_CORE=0 ./harness       core 0
 *
 * Nothing else in the patching path is core-specific: patch_ucode() and
 * hook_match_and_patch() act on whichever core executes them, so installing and
 * firing from another core is symmetric — as long as both happen on the SAME
 * core, which is why assign_to_core() runs before the patch is installed.
 */
#ifndef KECCAK_BENCH_CORE_H
#define KECCAK_BENCH_CORE_H

#include <stdlib.h>

static inline int bench_core(void)
{
    const char *e = getenv("BENCH_CORE");
    if (!e || !*e) return 1;
    return (int)strtol(e, NULL, 10);
}

#endif /* KECCAK_BENCH_CORE_H */
