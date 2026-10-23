#!/usr/bin/env bash
#
# run.sh -- build and run the curve25519 benchmark, both levels.
#
#   ./run.sh               every (compiler, -O) pair SUPERCOP tries -- gcc 11/12/13
#                          and clang 14/17/18 at -O3/-O2/-Os/-O, 24 in all; each
#                          contender keeps its best (the paper's method), ~17 min
#   ./run.sh --quick       one configuration (gcc -O3), ~1 min
#   ./run.sh --kernels     level 1 only          ./run.sh --x25519   level 2 only
#                          (both combine with --quick: ./run.sh --quick --x25519)
#   ./run.sh --summary DIR rebuild DIR/SUMMARY.md from existing results
#
#   BENCH_CORE=1   measure on core 1 (default 1; IRQs go to the other core)
#   RUNS=1         X25519 runs per variant per configuration (default 1)
#
# Per configuration: clean build, then ours/setcc (kernel_setcc, then
# x25519_setcc RUNS times, default once), then ours/adc (the same), then
# kernel_floor once (the dispatch floor). Every binary installs ONE patch set, once, and never
# swaps it; two sweeps that swapped patch sets inside a process each wedged
# the bench core. Each binary runs under core isolation (lib/isolation.sh: IRQs
# steered away, irqbalance stopped, SCHED_FIFO 99). Before anything runs: the
# ../lib/pin_cpu.sh (turbo off,
# userspace governor at base on every core; left in place afterwards, and
# skipped with ALLOW_UNPINNED=1), the frequency guard (checked again after) and
# the microcode debug unlock, re-asserted before every binary. Each binary
# refuses to time anything that fails its correctness checks and exits
# non-zero; such a run is retried up to 3 times, then that variant (or the
# floor) is dropped from the configuration and reported.
#
# Output: results/<date_time>/<config>/{build.log, kernel_<v>.txt,
# x25519_<v>_<n>.txt} for v = setcc, adc (and kernel_floor.txt),
# results/<date_time>/SUMMARY.md, and results/latest -> the newest run.
# The summary is also copied to RESULTS_<date_time>.md in this folder, one
# file per run, never overwritten. Nothing is committed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"           # Benchmarks/

LEVELS="kernel x25519"
SWEEP=1
for arg in "$@"; do
    case "$arg" in
    --quick)    SWEEP=0 ;;
    --sweep)    SWEEP=1 ;;                  # the default; kept for old habits
    --kernels)  LEVELS="kernel" ;;
    --x25519)   LEVELS="x25519" ;;
    --summary)  exec python3 summarize.py "${2:?usage: ./run.sh --summary results/<dir>}" ;;
    -h|--help)  sed -n '2,30p' "$0"; exit 0 ;;
    *)          echo "unknown option: $arg (try --help)" >&2; exit 64 ;;
    esac
done
RUNS="${RUNS:-1}"
export BENCH_CORE="${BENCH_CORE:-1}"

if (( SWEEP )); then
    CONFIGS=(
        "gcc-11 -O3"   "gcc-11 -O2"   "gcc-11 -Os"   "gcc-11 -O"
        "gcc-12 -O3"   "gcc-12 -O2"   "gcc-12 -Os"   "gcc-12 -O"
        "gcc-13 -O3"   "gcc-13 -O2"   "gcc-13 -Os"   "gcc-13 -O"
        "clang-14 -O3" "clang-14 -O2" "clang-14 -Os" "clang-14 -O"
        "clang-17 -O3" "clang-17 -O2" "clang-17 -Os" "clang-17 -O"
        "clang-18 -O3" "clang-18 -O2" "clang-18 -Os" "clang-18 -O"
    )
else
    CONFIGS=("gcc -O3")
fi

source ../lib/freq_guard.sh       # check_cpu_frequency, recheck_effective_freq
source ../lib/isolation.sh        # setup_isolation, restore_isolation, BENCH_RUN

# Everything this script writes belongs to the user who started it, even when
# that was `sudo ./run.sh`: otherwise build/ and results/ end up root's and the
# next run without sudo cannot clean or write them. Also repairs leftovers.
OWNER="${SUDO_USER:-$(id -un)}"
fix_owner() {
    sudo chown -R "$OWNER": build results RESULTS_*.md ./*_static 2>/dev/null || true
}
sudo -v
fix_owner
trap fix_owner EXIT

STAMP="$(date +%Y-%m-%d_%H%M)"
OUT="results/$STAMP"
mkdir -p "$OUT"
ln -sfn "${OUT#results/}" results/latest

if [[ "${ALLOW_UNPINNED:-0}" != 1 ]]; then
    echo "== pinning the CPU (../lib/pin_cpu.sh) =="
    sudo bash ../lib/pin_cpu.sh | sed 's/^/   /'
fi
sudo modprobe msr 2>/dev/null || true
sudo wrmsr -p "$BENCH_CORE" 0x1e6 0x200 || {
    echo "ERROR: could not set the microcode debug unlock on core $BENCH_CORE" >&2; exit 1; }
check_cpu_frequency
trap 'restore_isolation; fix_owner' EXIT
setup_isolation

# run_bin <binary> <out-file>: run under isolation, retry up to 3 times, and
# accept only an exit 0 on the right core that printed its DONE line.
run_bin() {
    local bin=$1 out=$2 attempt
    for attempt in 1 2 3; do
        sudo wrmsr -p "$BENCH_CORE" 0x1e6 0x200 2>/dev/null || true
        if $BENCH_RUN "./$bin" >"$out" 2>&1 &&
           grep -q "^PINNED core=$BENCH_CORE sched_getcpu=$BENCH_CORE\$" "$out" &&
           grep -q "^DONE " "$out"; then
            return 0
        fi
        echo "   [$bin attempt $attempt failed: $(grep -m1 -E 'FAIL|ERROR|WRONG' "$out" || tail -1 "$out")]"
    done
    return 1
}

ran=() failed=()
for cfg in "${CONFIGS[@]}"; do
    cc=${cfg%% *} opt=${cfg##* }
    tag="${cc}_${opt#-}"
    dir="$OUT/$tag"
    mkdir -p "$dir"
    echo
    echo "== $cfg =="
    if ! command -v "$cc" >/dev/null; then
        echo "   $cc NOT INSTALLED, skipped"; failed+=("$cfg (not installed)"); continue
    fi
    make -s clean
    if ! make -s -j"$(nproc)" CC="$cc" OPT="$opt" >"$dir/build.log" 2>&1; then
        echo "   BUILD FAILED (see $dir/build.log)"; failed+=("$cfg (build)"); continue
    fi
    bad=()                              # what failed in this configuration
    for v in setcc adc; do              # one process per patch set, setcc first
        ok=1
        if [[ " $LEVELS " == *" kernel "* ]]; then
            if run_bin "kernel_${v}_static" "$dir/kernel_$v.txt"; then
                grep -E "^  Fe_(mul|sq)_$v " "$dir/kernel_$v.txt" | sed 's/^/  /'
            else
                echo "   kernel_$v FAILED (see $dir/kernel_$v.txt)"; ok=0
            fi
        fi
        if [[ " $LEVELS " == *" x25519 "* ]]; then
            for (( r = 1; r <= RUNS; r++ )); do
                out="$dir/x25519_${v}_$r.txt"
                if run_bin "x25519_${v}_static" "$out"; then
                    echo "   x25519_$v run $r: $(grep '^X25519 ' "$out" |
                                               awk '{printf "%s %s  ", $2, $3}')"
                else
                    echo "   x25519_$v run $r FAILED (see $out)"; ok=0; break
                fi
            done
        fi
        if (( ! ok )); then bad+=("$v"); rm -f "$dir/kernel_$v.txt" "$dir"/x25519_"$v"_*.txt; fi
    done
    if [[ " $LEVELS " == *" kernel "* ]]; then
        if run_bin kernel_floor_static "$dir/kernel_floor.txt"; then
            grep -E "^  Fe_(mul|sq)_floor " "$dir/kernel_floor.txt" | sed 's/^/  /'
        else
            echo "   kernel_floor FAILED (see $dir/kernel_floor.txt)"
            bad+=("floor"); rm -f "$dir/kernel_floor.txt"
        fi
    fi
    if (( ${#bad[@]} == 0 )); then ran+=("$cfg"); else failed+=("$cfg (${bad[*]})"); fi
done

echo
recheck_effective_freq
restore_isolation
trap fix_owner EXIT

{
    echo "date=$(date '+%Y-%m-%d %H:%M %Z')"
    echo "git=$(git rev-parse --short HEAD 2>/dev/null || echo unknown)$(git diff --quiet -- . 2>/dev/null || echo ' (Benchmarks/ has uncommitted changes)')"
    echo "core=$BENCH_CORE"
    echo "isolation=$ISOLATION_STATUS"
    echo "nohz=$NOHZ_FULL_STATUS"
    echo "freq=delivered ${DELIVERED_FREQ_MHZ:-?} MHz, TSC ${TSC_FREQ_MHZ:-?} MHz, f_core/f_TSC ${CYCLE_CORRECTION:-?}"
    echo "freq_drift=$FREQ_DRIFT_STATUS"
    echo "configs=${#ran[@]} ran: ${ran[*]:-none}${failed:+; FAILED: ${failed[*]}}"
    echo "runs=$RUNS"
} >"$OUT/meta.txt"

echo
python3 summarize.py "$OUT"
cp "$OUT/SUMMARY.md" "RESULTS_$STAMP.md"
echo "Results: Benchmarks/RESULTS_$STAMP.md  (raw outputs: $OUT)"
(( ${#failed[@]} == 0 )) || { echo "FAILED configurations: ${failed[*]}" >&2; exit 1; }
