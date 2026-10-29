# Third-party software

This artifact vendors source from several external projects so that the
benchmarks build and run without a network fetch, and so that the baselines are
exactly the ones the paper measured.

Nothing under `third_party/` was modified. Where a baseline needed adapting to
coexist with the others in one binary such as symbol renaming, a generated `config.h`, and
the SHA3-256 domain-separation byte. The adaptation is done at build time by
the Makefiles (`objcopy --redefine-sym`, `sed`, generated stubs), never by
editing the vendored file. `keccak/Benchmarks/Makefile` documents each case.

| Path | Project | Upstream |
|---|---|---|---|
| `keccak/third_party/openssl/` | OpenSSL | <https://github.com/openssl/openssl>, commit `43e1e98a` (4.1.0-dev), June 2026 | 
| `keccak/third_party/XKCP/` | eXtended Keccak Code Package | <https://github.com/XKCP/XKCP>, commit `78477d2e`, 12 June 2026 | 
| `keccak/third_party/supercop-20260330/` | SUPERCOP | <https://bench.cr.yp.to/supercop.html>, release 20260330 | 
| `keccak/third_party/supercop-data/` | SUPERCOP support headers | same release | 
| `curve25519/third_party/supercop-20260330/` | SUPERCOP | same release |
| `curve25519/third_party/supercop-data/` | SUPERCOP support headers and `libcryptoint.a` | same release | 
| `curve25519/third_party/curvesC/` | Reference C field arithmetic used as a differential oracle | this project | 

`s2n-bignum` appears inside both SUPERCOP trees
(`third_party/supercop-20260330/s2n-bignum/`). It is a snapshot of
<https://github.com/awslabs/s2n-bignum> distributed with SUPERCOP 20260330 see its
`README-supercop.md`. Its Keccak-f[1600] (`x86/sha3/sha3_keccak_f1600.S`) is a Light-verified port of Andy Polyakov's OpenSSL assembly.

**lib-micro**, the microcode patching library this artifact links against, is
not vendored either, but it is pinned rather than left to float:

| Path | Project | Upstream |
|---|---|---|
| `lib-micro/` | lib-micro (git submodule) | <https://github.com/zanderdk/lib-micro>, commit `f3a3a8d`, 15 August 2023 |

The submodule records the commit; it contains no code of ours and we apply no
patches to it. `git clone --recursive` fetches it — see the README for setup.

One further component is **not** included at all:

- **CryptOpt** — `curve25519/cryptopt_mul.asm` and `cryptopt_sq.asm` are output
  we generated with CryptOpt (<https://github.com/0xADE1A1DE/CryptOpt>) on the
  target N3350. CryptOpt itself is not included.

## Attribution

The baselines this work is compared against high performance native implementations.
In particular: the Keccak team (Guido Bertoni,
Joan Daemen, Michaël Peeters, Gilles Van Assche, Ronny Van Keer) for the
reference and optimised Keccak implementations and XKCP, Andy Polyakov for the
OpenSSL x86-64 Keccak and Curve25519 assembly, Daniel J. Bernstein, Niels Duif,
Tanja Lange, Peter Schwabe and Bo-Yin Yang for `amd64-51` and `amd64-64`, Adam
Langley for `curve25519-donna`, and Amazon Web Services for s2n-bignum.
