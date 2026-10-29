/*
 * sha3_kc512_shim.c - SHA3-256 through a SUPERCOP keccakc512 package's OWN sponge.
 *
 * keccakc512 is the Keccak team's final SHA-3-256 submission: Keccak[r=1088,
 * c=512], i.e. SHA3-256's rate and capacity, with that package's own sponge
 * (KeccakSponge.c) and its rate-1088 fast absorb path (ProvideFast1088). Its
 * hash.c is exactly this function minus one line: FIPS 202 appends the domain
 * bits "01" to the message before padding, which the pre-standard submission
 * does not. The package's Absorb() takes bit lengths and accepts a final partial
 * byte (KeccakSponge.c, "Only the last call may contain a partial byte"); bits
 * are numbered LSB first, so "01" is the byte 0x02 with length 2. Its own
 * pad10*1 then sets bit 2, giving the 0x06 ... 0x80 padding of SHA3-256.
 *
 * Compiled once per package, inside that package's object (Makefile rule
 * sha3own_<key>.o), with -I<package dir> and SHA3_ENTRY naming the entry point.
 * Identical to the package's hash.c otherwise, so everything timed is the
 * package's own code.
 */
#include "KeccakSponge.h"

#ifndef SHA3_ENTRY
#error "define SHA3_ENTRY to the entry point name"
#endif

int SHA3_ENTRY(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    static const unsigned char sha3_suffix = 0x02;  /* FIPS 202 domain bits "01", LSB first */
    spongeState state;
    InitSponge(&state, 1088, 512);
    Absorb(&state, in, inlen*8);
    Absorb(&state, &sha3_suffix, 2);
    Squeeze(&state, out, 256);
    return 0;
}
