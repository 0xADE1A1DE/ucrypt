/* kernel_floor.c -- LEVEL 1 dispatch floor: the 1-triad no-op patches are
 * installed once and stay for the whole process. The benchmark itself is
 * kernel.c; summarize.py subtracts this floor from Fe_*_setcc / Fe_*_adc. */
#define BENCH_VARIANT floor
#include "kernel.c"
