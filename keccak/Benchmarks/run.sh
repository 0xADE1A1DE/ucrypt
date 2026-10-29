#!/usr/bin/env bash
#
# run.sh -- build, check and run the Keccak benchmark, all three levels.
#
# The counterpart of curve25519/Benchmarks/run.sh. Each level produces one
# table of the paper:
#
#   --perm      Table 1   the 24-round permutation against every SUPERCOP,
#                         XKCP, OpenSSL and s2n-bignum baseline that runs on
#                         this core, swept over the (compiler, -O) grid
#   --speed-up  Table 2   the four kernel variants, each undoing one design
#                         choice, timed against the complete kernel
#   --sha3      Table 3   complete SHA3-256, every native contender running
#                         its own sponge, each built with the configuration
#                         that won it its row of the permutation sweep
#
#   ./run.sh                   all three, in that order (~40 min)
#   ./run.sh --quick           gcc -O3 only for the sweep, ~3 min
#   ./run.sh --perm            one level (combines with --quick)
#   ./run.sh --speed-up --sha3 several levels
#
#   BENCH_CORE=1   measure on this core (default 1)
#   RUNS=3         SHA3-256 repeats (default 3); each is its own process
#
# --sha3 reads the winning configuration of every contender out of RESULTS.md,
# which --perm writes. Run --perm at least once before --sha3, or the SHA3-256
# level aborts rather than guess.
#
# Each level installs the microcode patch itself and refuses to time anything
# that fails its correctness checks. Output: RESULTS.md (the permutation sweep,
# committed as a reference run) and results/ (SHA3-256 logs and summaries).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"           # Benchmarks/

LEVELS=""
export QUICK="${QUICK:-0}"
for arg in "$@"; do
    case "$arg" in
    --quick)     QUICK=1 ;;
    --perm)      LEVELS="$LEVELS perm" ;;
    --speed-up)  LEVELS="$LEVELS speed-up" ;;
    --sha3)      LEVELS="$LEVELS sha3" ;;
    --all)       LEVELS="perm speed-up sha3" ;;
    -h|--help)   sed -n '2,30p' "$0"; exit 0 ;;
    *)           echo "unknown option: $arg (try --help)" >&2; exit 64 ;;
    esac
done
[ -n "$LEVELS" ] || LEVELS="perm speed-up sha3"

export BENCH_CORE="${BENCH_CORE:-1}"
export RUNS="${RUNS:-3}"

# Run this as yourself, never as `sudo ./run.sh`. Every level builds as you and
# sudo's only the steps that need it (wrmsr, taskset, the microcode patch). A
# build under root leaves root-owned objects and generated config directories
# behind, and the next level's `make clean` then cannot remove them.
if [ "$(id -u)" = "0" ]; then
    echo "[ABORT] run as yourself, not under sudo: ./run.sh (it prompts for sudo)" >&2
    exit 1
fi

sudo -v
sudo modprobe msr 2>/dev/null || true

# Repair whatever an earlier sudo run left owned by root, so that `make clean`
# and the result writes below succeed instead of aborting half way through.
sudo chown -R "$(id -un)": \
    scstub xkcpcfg_g64 xkcpcfg_g64lc \
    sha3simple sha3cfg_xkcp_g64 sha3cfg_xkcp_g64lc \
    best results RESULTS.md ./*.o ./*_static 2>/dev/null || true

ran=() failed=()

for level in $LEVELS; do
    echo
    echo "================ $level ================"
    case "$level" in
    perm)
        # Writes RESULTS.md; --sha3 reads the winning configs back out of it.
        # Not under sudo: the sweep sudo's its own wrmsr and taskset steps, and
        # building it as root is what leaves the next level unable to clean.
        if ./bench_keccak_matrix.sh; then ran+=(perm); else failed+=(perm); fi
        ;;
    speed-up)
        # One process installs all five kernels in turn and times them against
        # each other, so the comparison needs no cross-process normalisation.
        if make -s clean &&
           make -s -j"$(nproc)" PROG=bench_speed-up &&
           sudo wrmsr -p "$BENCH_CORE" 0x1e6 0x200 &&
           sudo -E taskset -c "$BENCH_CORE" ./bench_speed-up_static; then
            ran+=(speed-up)
        else
            failed+=(speed-up)
        fi
        ;;
    sha3)
        if [ ! -r RESULTS.md ]; then
            echo "RESULTS.md not found -- run ./run.sh --perm first" >&2
            failed+=(sha3); continue
        fi
        if ./sha3_best.sh; then ran+=(sha3); else failed+=(sha3); fi
        ;;
    esac
done

echo
echo "ran: ${ran[*]:-none}${failed:+; FAILED: ${failed[*]}}"
(( ${#failed[@]} == 0 )) || exit 1
