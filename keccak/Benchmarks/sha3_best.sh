#!/usr/bin/env bash
#
# sha3_best.sh — SHA3-256 head-to-head in which every native contender runs its
# OWN complete SHA3-256 (its own sponge, absorb, padding and squeeze around its own
# permutation; see sha3_own.c), built under the compiler configuration that won
# that implementation its row of the permutation sweep.
#
# Why: `make PROG=sha3_own` links whatever sha3own_*.o happen to be lying in this
# directory (make does not track CFLAGS), so its rows would be built under no
# particular configuration.
#
# What: for each native contender, read its winning config from the "best per
# contender" table of the sweep results (bench_keccak_matrix.sh output), rebuild
# that contender's object (sha3own_<key>.o: sponge + permutation, every C file of
# it) with exactly the flags the sweep used for that config, verify the compiler
# and -O recorded in the debug info of every compiled unit, and link all of them
# into sha3_own_best_static. The harness itself (sha3_own.c, incl. the microcode's
# C sponge) keeps the default harness flags. s2n_bignum has a sweep row but ships
# only a permutation, so it has no SHA3-256 contender.
#
#   ./sha3_best.sh                    build, verify, run RUNS times on BENCH_CORE
#                                     (prompts for sudo; run it as yourself, not under sudo)
#   RUNS=5 ./sha3_best.sh             more repeats (default 3)
#   NO_RUN=1 ./sha3_best.sh           build + verify only
#   RESULTS_FILE=RESULTS.core0.md BENCH_CORE=0 ./sha3_best.sh
#
# Each run is a separate process, so the repeats catch process-level outliers
# (one run once read openssl 3% slow) that a single run's 51 batches cannot.
# summarize.py reduces them as the Curve25519 evaluation does: median of the
# per-run medians, plus the run-to-run spread.
#
# Outputs: best/*.o and best/MANIFEST (contender, config, recorded producer),
#          sha3_own_best_static,
#          results/sha3_best.core<N>.<timestamp>.log          (every run, raw)
#          results/sha3_best.core<N>.<timestamp>.summary.md   (reduced table)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

RESULTS_FILE="${RESULTS_FILE:-RESULTS.md}"
# RESULTS.md was swept on core 1.
BENCH_CORE="${BENCH_CORE:-1}"
RUNS="${RUNS:-3}"

# Under sudo the build would leave root-owned objects, binary and results/ behind,
# which then block the next run as a normal user. The script calls sudo itself
# for the steps that need it.
if [ "$(id -u)" = "0" ]; then
    echo "[ABORT] run as yourself, not under sudo: ./sha3_best.sh (it prompts for sudo)"
    exit 1
fi
if [ "${NO_RUN:-0}" != "1" ]; then
    mkdir -p results
    if [ ! -w results ]; then
        echo "[ABORT] results/ is not writable (left root-owned by an earlier sudo run). Fix with:"
        echo "        sudo chown -R $USER results best sha3_own_best_static"
        exit 1
    fi
fi

# Must match bench_keccak_matrix.sh (SUPERCOP_BASE and the per-compiler suffix in
# run_matrix), so each object is the same build the sweep measured.
SUPERCOP_BASE="-fwrapv -fPIC -fPIE -gdwarf-4 -Wall -march=native"
config_cflags() {   # config_cflags "gcc-11 -Os"
    local cc="${1%% *}" opt="${1##* }" cflags
    cflags="$opt $SUPERCOP_BASE -masm=intel"
    if [[ "$cc" == clang* ]]; then
        cflags="$cflags -Qunused-arguments"
    else
        cflags="$cflags -mtune=native"
    fi
    echo "$cflags"
}

# Native contenders, as in the sweep's "keccak/<key>" rows; object = sha3own_<key>.o.
NATIVE=( x86_64_asm x86_64_shld openssl
         opt64lcu24 opt64lcu24shld opt64lcu6 opt64u6
         sseu2 mmxu1 simple xkcp_g64 xkcp_g64lc )

winning_config() {  # winning_config opt64lcu24  ->  gcc-11 -Os
    awk -F'|' -v k="keccak/$1" '
        /^## best per contender/ { t=1; next }
        /^## /                   { t=0 }
        t { l=$2; gsub(/ /,"",l)
            if (l==k) { c=$7; gsub(/^ +| +$/,"",c); print c; exit } }
    ' "$RESULTS_FILE"
}

producers() {       # every DW_AT_producer of an object, one per compiled unit
    readelf --debug-dump=info "$1" 2>/dev/null \
        | sed -n -E 's/.*DW_AT_producer[[:space:]]*:[[:space:]]*(\(indirect[^)]*\):[[:space:]]*)?//p'
}

# Does a recorded producer match the config? Compiler version always; the -O
# level only where flags are recorded: GCC records its switches, and only clang-18
# here records its command line (with -O spelled -O1). GNU as units (assembly,
# whose code no compiler or -O can change) are skipped by the caller.
producer_matches() {  # producer_matches <cc> <opt> <producer>
    local cc="$1" opt="$2" p="$3" ver="${1#*-}"
    case "$cc" in
        gcc-*)   [[ "$p" == "GNU C"*" $ver."* ]] || return 1 ;;
        clang-*) [[ "$p" == *"clang version $ver."* ]] || return 1
                 [[ "$p" == *" -c "* ]] || return 0 ;;   # no command line recorded
    esac
    [[ " $p " == *" $opt "* || ( "$opt" == "-O" && " $p " == *" -O1 "* ) ]]
}

[ -r "$RESULTS_FILE" ] || { echo "[ABORT] cannot read $RESULTS_FILE"; exit 1; }
echo "Winning configs from: $RESULTS_FILE"

mkdir -p best
rm -f best/*.o
: > best/MANIFEST
objs=()
for key in "${NATIVE[@]}"; do
    cfg=$(winning_config "$key")
    if [ -z "$cfg" ]; then
        echo "[ABORT] no winning config for keccak/$key in $RESULTS_FILE"; exit 1
    fi
    cc="${cfg%% *}"; opt="${cfg##* }"
    command -v "$cc" >/dev/null 2>&1 || { echo "[ABORT] $cc not installed"; exit 1; }

    obj="sha3own_${key}.o"
    rm -f "$obj"
    make -s PROG=sha3_own CC="$cc" CFLAGS="$(config_cflags "$cfg")" "$obj" >/dev/null
    mv "$obj" "best/$obj"
    objs+=("best/$obj")

    # Every contender object holds compiled C (at least its sponge), so it must
    # carry debug info, and every compiled unit in it must match the config.
    nunits=0; first=""
    while IFS= read -r p; do
        [[ "$p" == "GNU AS"* ]] && continue
        if ! producer_matches "$cc" "$opt" "$p"; then
            echo "[ABORT] a unit of best/$obj was not built as $cfg:"; echo "        $p"; exit 1
        fi
        nunits=$((nunits + 1)); [ -n "$first" ] || first="$p"
    done < <(producers "best/$obj")
    if [ "$nunits" -eq 0 ]; then
        echo "[ABORT] best/$obj has no compiled unit with debug info; cannot verify $cfg"; exit 1
    fi
    p="$nunits compiled unit(s): $first"
    if [[ "$cc" == clang* && "$first" != *" -c "* ]]; then
        p="$p (version checked; $cc does not record its flags)"
    fi
    printf '%-15s | %-13s | %s\n' "$key" "$cfg" "$p" >> best/MANIFEST
    printf '  %-15s %-13s ok (%d compiled units)\n' "$key" "$cfg" "$nunits"
done

rm -f sha3_own_best_static
make -s PROG=sha3_own TARGET=sha3_own_best_static EXTRA_OBJS="${objs[*]}"
echo "Linked sha3_own_best_static (manifest: best/MANIFEST)"

if [ "${NO_RUN:-0}" = "1" ]; then
    echo "NO_RUN=1: not running. To run: ./sha3_best.sh  (prompts for sudo)"
    exit 0
fi

# ── Run, same environment checks as the permutation sweep ──
echo "Priming sudo (needed for the frequency check, MSR unlock and microcode patch)..."
sudo -v
source ../lib/freq_guard.sh       # check_cpu_frequency(), uses BENCH_CORE
check_cpu_frequency

stamp="results/sha3_best.core${BENCH_CORE}.$(date +%Y%m%d-%H%M%S)"
log="$stamp.log"
summary="$stamp.summary.md"
{
    echo "# sha3_best.sh  $(date -Is)  core ${BENCH_CORE}  ${RUNS} runs  winning configs from ${RESULTS_FILE}"
    echo "# before: delivered ${DELIVERED_FREQ_MHZ:-n/a} MHz, TSC ${TSC_FREQ_MHZ:-n/a} MHz, f_core/f_TSC ${CYCLE_CORRECTION:-n/a}"
    sed 's/^/# /' best/MANIFEST
} > "$log"

for (( run = 1; run <= RUNS; run++ )); do
    echo "### run $run/$RUNS  $(date -Is)" | tee -a "$log"
    # Re-assert the microcode debug unlock (MSR 0x1E6 bit 9) on the bench core;
    # see bench_keccak_matrix.sh — it can be lost while the core sits in a deep
    # C-state.
    sudo wrmsr -p "$BENCH_CORE" 0x1e6 0x200 || true
    # Full output goes to the log; the terminal gets the result tables and any
    # failure the harness reports. A harness that dies (e.g. SIGSEGV from the
    # microcode) prints nothing to the terminal before its first table, so its
    # exit status is checked here instead of letting set -e end the script
    # silently.
    set +e
    sudo env BENCH_CORE="$BENCH_CORE" taskset -c "$BENCH_CORE" ./sha3_own_best_static \
        | tee -a "$log" \
        | grep -E --line-buffered 'FAIL|FATAL|Abort|RSP-GUARD|^--- SHA3-256, message|^  contender|^  [a-z0-9_]+ +(ucode|asm|C64|xkcp|ref|SSE2|MMX) +[0-9]|fastest native'
    rc=${PIPESTATUS[0]}
    set -e
    if [ "$rc" -ne 0 ]; then
        sig=""; [ "$rc" -gt 128 ] && sig=" (killed by signal $((rc - 128)); 11 = SIGSEGV, see: sudo dmesg | tail)"
        echo "[RUN $run FAILED] harness exited with status $rc$sig" | tee -a "$log"
        echo "  last lines of $log:"; tail -n 4 "$log" | sed 's/^/    /'
        echo "[ABORT] remaining runs skipped; no summary written (it needs every run complete)."
        exit 1
    fi
done

# The frequency must still be the base P-state after the runs, not only before.
check_effective_freq
echo "# after:  delivered ${DELIVERED_FREQ_MHZ:-n/a} MHz, TSC ${TSC_FREQ_MHZ:-n/a} MHz, f_core/f_TSC ${CYCLE_CORRECTION:-n/a}" >> "$log"

python3 summarize.py "$log" > "$summary"
echo
sed -n '/^## per-run speed-up/,$p' "$summary"
echo "Log:     $log"
echo "Summary: $summary"
