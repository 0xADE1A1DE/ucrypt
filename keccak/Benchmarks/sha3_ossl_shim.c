/*
 * sha3_ossl_shim.c — SHA3-256 through OpenSSL's OWN sponge (crypto/sha/sha3.c)
 * over its x86-64 assembly (SHA3_absorb / SHA3_squeeze, keccak1600-x86_64.pl).
 *
 * This repeats what OpenSSL's provider does for SHA3-256 on x86-64
 * (providers/implementations/digests/sha3_prov.c): ossl_sha3_init() with pad
 * 0x06 and 256-bit output, the generic method sha3_generic_md =
 * {ossl_sha3_absorb_default, ossl_sha3_final_default, NULL}, then
 * ossl_sha3_absorb() (the buffered update) and ossl_sha3_final(). Only the EVP
 * and provider dispatch around those calls is left out; every byte of sponge
 * work is OpenSSL's.
 */
#include <stdlib.h>
#include "internal/sha3.h"

int sha3_256_openssl(unsigned char *out, const unsigned char *in, unsigned long long inlen)
{
    KECCAK1600_CTX ctx;
    ossl_sha3_init(&ctx, '\x06', 256);
    ctx.meth.absorb  = ossl_sha3_absorb_default;
    ctx.meth.final   = ossl_sha3_final_default;
    ctx.meth.squeeze = NULL;
    ossl_sha3_absorb(&ctx, in, (size_t)inlen);
    ossl_sha3_final(&ctx, out, 32);
    return 0;
}

/* sha3.c's ossl_shake256_new() (never called for SHA3-256) references libcrypto's
 * allocator; this is its definition minus the debug bookkeeping, so the object
 * links without the rest of libcrypto. */
void *CRYPTO_zalloc(size_t num, const char *file, int line)
{
    (void)file; (void)line;
    return calloc(1, num);
}
