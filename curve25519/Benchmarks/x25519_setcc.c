/* x25519_setcc.c -- LEVEL 2 for ours/setcc: patch_setcc.h is installed once and stays
 * for the whole process. The benchmark itself is x25519.c. */
#define BENCH_VARIANT setcc
#include "x25519.c"
