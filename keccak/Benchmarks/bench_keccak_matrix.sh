#!/usr/bin/env bash
#
# bench_keccak_matrix.sh - the SUPERCOP-style compiler sweep (the Keccak
# counterpart of curve25519/Benchmarks/run.sh), applied to the head-to-head.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Physical core every run is measured on. The harness re-pins itself with
# sched_setaffinity, so BENCH_CORE is exported into the run as well as being
# used for the taskset mask - taskset alone would be overridden.
BENCH_CORE="${BENCH_CORE:-1}"

# Generic helpers shared with the curve matrix (no curve-specific state in them).
source ../lib/freq_guard.sh       # check_cpu_frequency()
source ../lib/parse.sh            # record_result()

# -- Result tables (read by record_result in lib/parse.sh) --
declare -A cell          # "cfg|label" -> min cyc/perm
declare -A cell_med      # "cfg|label" -> median cyc/perm (headline stat)
declare -A cell_p10      # "cfg|label" -> 10th-percentile cyc/perm (dispersion)
declare -A cell_p90      # "cfg|label" -> 90th-percentile cyc/perm (dispersion)
declare -A best_min      # label -> best (smallest) min
declare -A best_med      # label -> best (smallest) median  (headline; SUPERCOP style)
declare -A best_cfg      # label -> config achieving best_min
declare -A best_med_cfg  # label -> config achieving best_med
declare -a ran_cfgs      # configs that produced a benchmark
rsp_fires=0              # microcode firings summed over the sweep (RSP-GUARD line)
rsp_changed=0            # of those, firings that returned a changed RSP

# Same flag base SUPERCOP uses for its gcc/clang lines, minus '-I include/'
# (the keccak sources reference headers by explicit relative path; they need no
# -I). -masm=intel is appended for the harness compile (it contains Intel-syntax
# inline asm); the Makefile re-derives -masm=att for the SUPERCOP .o baselines.
SUPERCOP_BASE="-fwrapv -fPIC -fPIE -gdwarf-4 -Wall -march=native"

# (compiler, -O level) grid - same -O levels SUPERCOP tries (okcompilers/c).
# Any compiler not installed is silently dropped by select_active_configs.
CONFIGS=(
    "gcc-11 -O3"   "gcc-11 -O2"   "gcc-11 -Os"   "gcc-11 -O"
    "gcc-12 -O3"   "gcc-12 -O2"   "gcc-12 -Os"   "gcc-12 -O"
    "gcc-13 -O3"   "gcc-13 -O2"   "gcc-13 -Os"   "gcc-13 -O"
    "clang-14 -O3" "clang-14 -O2" "clang-14 -Os" "clang-14 -O"
    "clang-17 -O3" "clang-17 -O2" "clang-17 -Os" "clang-17 -O"
    "clang-18 -O3" "clang-18 -O2" "clang-18 -Os" "clang-18 -O"
)

# QUICK=1 (run.sh --quick): one configuration instead of the full grid, as
# curve25519/Benchmarks/run.sh --quick does.
if [ "${QUICK:-0}" = 1 ]; then CONFIGS=("gcc -O3"); fi

# Contender labels - must match the "keccak/<key>:" lines asm_op_keccak_vs.c
# prints in its "=== matrix-parse ===" block.
CONTENDERS=(
    "keccak/x86_64_asm"
    "keccak/x86_64_shld"
    "keccak/opt64lcu24"
    "keccak/opt64lcu24shld"
    "keccak/opt64lcu6"
    "keccak/opt64u6"
    "keccak/sseu2"
    "keccak/mmxu1"
    "keccak/simple"
    "keccak/xkcp_g64"
    "keccak/xkcp_g64lc"
    "keccak/openssl"
    "keccak/s2n_bignum"
    "keccak/microcode"
)
# Every native baseline object linked into asm_op_keccak_vs - must match
# EXTRA_OBJS for that PROG in the Makefile. All are deleted and rebuilt per config.
BASELINE_OBJS=(
    keccak_x86_64_asm.o keccak_x86_64_shld.o
    keccak_opt64lcu24.o keccak_opt64lcu24shld.o
    keccak_opt64lcu6.o keccak_opt64u6.o
    keccak_sseu2.o keccak_mmxu1.o keccak_simple.o
    keccak_xkcp_g64.o keccak_xkcp_g64lc.o keccak_openssl.o
    keccak_s2n_bignum.o
)
# Short column headers for the markdown matrix, index-aligned with CONTENDERS.
SHORT=( "asm" "shld" "opt24" "opt24shld" "lcu6" "u6" "sse" "mmx" "simple" "xg64" "xg64lc" "ossl" "s2n" "ucode" )

ACTIVE_CONFIGS=()
select_active_configs() {
    local cfg cc
    for cfg in "${CONFIGS[@]}"; do
        cc="${cfg%% *}"
        if command -v "$cc" >/dev/null 2>&1; then
            ACTIVE_CONFIGS+=("$cfg")
        else
            echo "[skip] $cc not installed - dropping config: $cfg"
        fi
    done
    if [ ${#ACTIVE_CONFIGS[@]} -eq 0 ]; then
        echo "No usable compilers found - abort."
        exit 1
    fi
}

# run_matrix - for each active config: clean-rebuild asm_op_keccak_vs with that
# compiler/flags, run it, scrape each contender's min/median from the
# matrix-parse block, and record. Echoes the per-config human report live.
run_matrix() {
    local cfg cc opt cflags output line label mn md p10 p90
    for cfg in "${ACTIVE_CONFIGS[@]}"; do
        cc="${cfg%% *}"
        opt="${cfg##* }"

        cflags="$opt $SUPERCOP_BASE -masm=intel"
        if [[ "$cc" == clang* ]]; then
            cflags="$cflags -Qunused-arguments"
        else
            cflags="$cflags -mtune=native"
        fi

        echo
        echo "== config $cfg"
        echo "   cflags: $cflags"

        # Force clean rebuild - cached .o files hold the previous config's flags,
        # and make does not track CFLAGS, so EVERY baseline object must go. (This
        # list used to name only 4 of the 12, which left the other 8 frozen at
        # whatever config last built them for the whole sweep.)
        rm -f "${BASELINE_OBJS[@]}" asm_op_keccak_vs_static
        touch .build_stamp

        if ! make -s PROG=asm_op_keccak_vs CC="$cc" CFLAGS="$cflags" \
                  >/dev/null 2>build_err.log; then
            echo "[BUILD FAILED]"
            sed 's/^/    /' build_err.log
            continue
        fi
        rm -f build_err.log

        # Guard: every baseline object must have been rebuilt for THIS config.
        # A stale one would make its "winning config" column meaningless.
        local obj stale=0
        for obj in "${BASELINE_OBJS[@]}"; do
            if [ ! "$obj" -nt .build_stamp ]; then
                echo "[STALE OBJECT] $obj was not rebuilt under $cfg"
                stale=1
            fi
        done
        if [ "$stale" -ne 0 ]; then
            echo "[ABORT] stale baseline objects - sweep results would be invalid."
            exit 1
        fi

        sudo wrmsr -p "$BENCH_CORE" 0x1e6 0x200 || true
        if ! output=$(sudo env BENCH_CORE="$BENCH_CORE" taskset -c "$BENCH_CORE" ./asm_op_keccak_vs_static 2>&1); then
            echo "[RUN FAILED - harness crashed or exited non-zero] skipping config: $cfg"
            echo "$output" | tail -n 8 | sed 's/^/    /'
            continue
        fi

        # Show the human report so the user sees per-config numbers in real time.
        echo "$output" | sed -n '/head-to-head/,/ratios valid/p'

        ran_cfgs+=("$cfg")

        line=$(echo "$output" | grep -oE 'RSP-GUARD: [0-9]+ microcode firings, [0-9]+ returned' || true)
        if [ -n "$line" ]; then
            rsp_fires=$(( rsp_fires + $(echo "$line" | awk '{print $2}') ))
            rsp_changed=$(( rsp_changed + $(echo "$line" | awk '{print $5}') ))
        fi

        for label in "${CONTENDERS[@]}"; do
            line=$(echo "$output" | grep -E "^${label}:" || true)
            [ -z "$line" ] && continue
            mn=$(echo "$line"  | grep -oE 'min[[:space:]]+[0-9]+'    | awk '{print $2}')
            md=$(echo "$line"  | grep -oE 'median[[:space:]]+[0-9]+' | awk '{print $2}')
            p10=$(echo "$line" | grep -oE 'p10[[:space:]]+[0-9]+'    | awk '{print $2}')
            p90=$(echo "$line" | grep -oE 'p90[[:space:]]+[0-9]+'    | awk '{print $2}')
            record_result "$cfg" "$label" "$mn" "$md" "$p10" "$p90"
        done
    done
}

# headline: fastest SUPERCOP baseline (min over the 4 SUPERCOP variants) vs ucode.
# Echoes "<sc_best_label> <sc_best> <uc>" (or empty fields if unavailable).
# Headline is by MEDIAN (best-per-contender across the sweep, SUPERCOP style).
compute_headline() {
    local label v sc_best="" sc_best_label="" uc
    for label in keccak/x86_64_asm keccak/x86_64_shld \
                 keccak/opt64lcu24 keccak/opt64lcu24shld \
                 keccak/opt64lcu6 keccak/opt64u6 \
                 keccak/sseu2 keccak/mmxu1 keccak/simple \
                 keccak/xkcp_g64 keccak/xkcp_g64lc keccak/openssl \
                 keccak/s2n_bignum; do
        v="${best_med[$label]:-}"
        [ -z "$v" ] && continue
        if [ -z "$sc_best" ] || [ "$v" -lt "$sc_best" ]; then
            sc_best="$v"; sc_best_label="$label"
        fi
    done
    uc="${best_med[keccak/microcode]:-}"
    echo "$sc_best_label|$sc_best|$uc"
}

report_terminal() {
    local label hl sc_best_label sc_best uc uc_best rcell bm cfg p10 p90
    uc_best="${best_med[keccak/microcode]:-}"   # microcode's best median, for the ratio column
    echo
    echo "== scoreboard: best median cyc/perm over ${#ran_cfgs[@]} configs"
    printf "  %-24s %8s %8s %8s %8s %10s   %s\n" "contender" "median" "min" "p10" "p90" "this/ucode" "best config"
    printf "  %-24s %8s %8s %8s %8s %10s   %s\n" "------------------------" "--------" "--------" "--------" "--------" "----------" "-----------------"
    for label in "${CONTENDERS[@]}"; do
        # this/ucode = this_contender_median / microcode_median  (>1 => microcode faster)
        rcell="n/a"; bm="${best_med[$label]:-}"; cfg="${best_med_cfg[$label]:-}"
        if [ -n "$uc_best" ] && [[ "$bm" =~ ^[0-9]+$ ]] && [ "$bm" -gt 0 ]; then
            rcell=$(awk -v u="$uc_best" -v b="$bm" 'BEGIN{printf "%.3fx", b/u}')
        fi
        # p10/p90 taken at the best-median config, so the spread matches the headline number.
        p10="${cell_p10[$cfg|$label]:-n/a}"; p90="${cell_p90[$cfg|$label]:-n/a}"
        printf "  %-24s %8s %8s %8s %8s %10s   %s\n" "$label" \
            "${best_med[$label]:-n/a}" "${best_min[$label]:-n/a}" "$p10" "$p90" "$rcell" "${cfg:-n/a}"
    done

    hl=$(compute_headline)
    sc_best_label="${hl%%|*}"; hl="${hl#*|}"
    sc_best="${hl%%|*}";       uc="${hl#*|}"
    echo
    if [ -n "$uc" ] && [ -n "$sc_best_label" ]; then
        echo "  fastest SUPERCOP baseline: $sc_best_label = $sc_best cyc/perm (${best_cfg[$sc_best_label]})"
        echo "  microcode (looped):        $uc cyc/perm (${best_cfg[keccak/microcode]})"
        awk -v u="$uc" -v s="$sc_best" 'BEGIN{
            printf "  ratio microcode / fastest: %.3fx  (%s)\n",
                   u/s, (u<s ? "*** microcode WINS ***" : "microcode loses")
        }'
    else
        echo "  no headline: no configs ran"
    fi
}

# Markdown: a full (config x contender) matrix of mins + a best-per-contender
# table + the headline. No git interaction (unlike the curve script).
emit_results_md() {
    local out="$1" cfg label i hl sc_best_label sc_best uc uc_best rcell bm p10 p90
    {
        echo "# Keccak SUPERCOP-matrix benchmark"
        echo
        echo "Method, as in curve25519/Benchmarks/run.sh. For each (compiler, -O) config"
        echo "SUPERCOP tries: rebuild every runnable SUPERCOP Keccak baseline (hand asm,"
        echo "64-bit C, x86 SIMD, reference) and the head-to-head harness, run them"
        echo "back-to-back in one process, keep the best per contender."
        echo
        echo "Unit: cyc/perm, RDTSC at the TSC rate, cores pinned to base."
        echo "Headline: **median**. Min and the p10-p90 spread are also listed."
        echo "Configs that ran: ${#ran_cfgs[@]} / ${#CONFIGS[@]}"
        echo
        echo "Environment. Core ${BENCH_CORE}, base-pinned, turbo off."
        echo "Delivered core freq ${DELIVERED_FREQ_MHZ:-n/a} MHz, TSC rate ${TSC_FREQ_MHZ:-n/a} MHz,"
        echo "correction f_core/f_TSC = ${CYCLE_CORRECTION:-n/a} (aperf/mperf under load, before the sweep)."
        echo "Ratios are invariant to it. Multiply absolute counts by it for true core cycles."
        echo
        echo "Correctness. One firing is checked against a C reference Keccak-f[1600] at"
        echo "start-up, and every timed batch's end state against the same reference."
        echo "A failed check aborts that config."
        echo "RSP guard: ${rsp_fires} firings, ${rsp_changed} returned a changed RSP."
        echo
        echo "## median cyc/perm per (config x contender)"
        echo
        printf "| config |"; for i in "${SHORT[@]}"; do printf " %s |" "$i"; done; echo
        printf "|---|";       for i in "${SHORT[@]}"; do printf -- "---|"; done; echo
        for cfg in "${ran_cfgs[@]}"; do
            printf "| %s |" "$cfg"
            for label in "${CONTENDERS[@]}"; do
                printf " %s |" "${cell_med[$cfg|$label]:-n/a}"
            done
            echo
        done
        echo
        echo "## best per contender (what SUPERCOP's autotuner would pick)"
        echo
        echo "Best = lowest **median** across the sweep."
        echo "\`this/microcode\` = contender median / microcode median; > 1 means microcode wins."
        echo "p10/p90 are taken at each contender's best-median config."
        echo
        uc_best="${best_med[keccak/microcode]:-}"
        echo "| contender | median | min | p10 | p90 | winning config | this/microcode |"
        echo "|---|---|---|---|---|---|---|"
        for label in "${CONTENDERS[@]}"; do
            rcell="n/a"; bm="${best_med[$label]:-}"; cfg="${best_med_cfg[$label]:-}"
            if [ -n "$uc_best" ] && [[ "$bm" =~ ^[0-9]+$ ]] && [ "$bm" -gt 0 ]; then
                rcell=$(awk -v u="$uc_best" -v b="$bm" 'BEGIN{printf "%.3fx", b/u}')
            fi
            p10="${cell_p10[$cfg|$label]:-n/a}"; p90="${cell_p90[$cfg|$label]:-n/a}"
            echo "| $label | ${best_med[$label]:-n/a} | ${best_min[$label]:-n/a} | $p10 | $p90 | ${cfg:-n/a} | $rcell |"
        done
        echo
        hl=$(compute_headline)
        sc_best_label="${hl%%|*}"; hl="${hl#*|}"
        sc_best="${hl%%|*}";       uc="${hl#*|}"
        if [ -n "$uc" ] && [ -n "$sc_best_label" ]; then
            echo "## headline"
            echo
            echo "- fastest SUPERCOP baseline: **$sc_best_label = $sc_best cyc/perm** (median, ${best_med_cfg[$sc_best_label]})"
            echo "- microcode (looped): **$uc cyc/perm** (median, ${best_med_cfg[keccak/microcode]})"
            awk -v u="$uc" -v s="$sc_best" 'BEGIN{
                printf "- ratio microcode / fastest SUPERCOP: **%.3fx** (%s)\n",
                       u/s, (u<s ? "microcode WINS" : "microcode loses")
            }'
        fi
    } > "$out"
}

# -- Pipeline --
check_cpu_frequency
select_active_configs

echo "Priming sudo (needed for taskset + microcode patch on each run)..."
sudo -v

run_matrix
report_terminal

RESULTS_FILE="${RESULTS_FILE:-RESULTS.md}"
emit_results_md "$RESULTS_FILE"
echo
echo "Markdown written to: $RESULTS_FILE"
echo "Done."
