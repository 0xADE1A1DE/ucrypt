/* x25519_adc.c -- LEVEL 2 for ours/adc: patch_adc.h is installed once and stays
 * for the whole process. The benchmark itself is x25519.c. */
#define BENCH_VARIANT adc
#include "x25519.c"
