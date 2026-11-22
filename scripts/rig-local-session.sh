#!/usr/bin/env bash
# One full Phase 0 measurement session on the SYNTHETIC local rig
# (deploy/rig/providers/local.sh). Follows bench/RUNBOOK.md: pre-flight, floor at
# 3 loads x 5 runs in randomized order, capacity-fit grid (rate AND events vary),
# transport/TLS comparison, synthetic-trace replay, teardown with orphan check.
#
#   RIG_PROVIDER=local scripts/rig-local-session.sh [session-name]
#
# Everything is stamped shape-only by envinfo (WSL2/virtualised, shared cores).
# Results: bench/results/<session>-*/ ; session log: bench/sessions/<session>/.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
S="${1:-p0-synth-$(date -u +%Y%m%d)}"
OUT="$ROOT/bench/results"
LOG="$ROOT/bench/sessions/$S"; mkdir -p "$LOG" "$OUT"
PHASES="${PHASES:-pre floor fit tp trace}"
has() { [[ " $PHASES " == *" $1 "* ]]; }
DUR="${DUR:-15s}"; WARM="${WARM:-3s}"; GAP="${GAP:-const:5ms}"
LOADS=(${LOADS:-250 500 1000}); RUNS="${RUNS:-5}"
BIN="$ROOT/.bin"; ST="$ROOT/.rig-local"
WORK="$ST/work"
TLS="$ST/tls"

"$ROOT/deploy/rig/providers/local.sh" up | tee "$LOG/rig-up.txt"
trap '"$ROOT/deploy/rig/providers/local.sh" down | tee "$LOG/rig-down.txt"' EXIT
# shellcheck disable=SC1091
source "$ST/env"
mkdir -p "$WORK" "$ST/pids"

reg() { echo "$1" >"$ST/pids/$2"; }
wait_port() { for _ in $(seq 1 100); do (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null && return 0; sleep 0.1; done; echo "port $1 never opened" >&2; return 1; }

# ---- pre-flight --------------------------------------------------------------
if has pre; then
echo "== pre-flight: timer probe, noise canary, strict self-check (informational on this host) =="
taskset -c "$GEN_CORES" "$BIN/twload" timer 2>&1 | tee "$LOG/timer.txt"
if [[ -f "$ROOT/bench/noise-baseline.json" ]]; then
  taskset -c "$GEN_CORES" "$BIN/twcanary" -baseline "$ROOT/bench/noise-baseline.json" 2>&1 | tee "$LOG/canary.txt" || echo "(canary drift: logged, not fatal on the synthetic rig)"
else
  taskset -c "$GEN_CORES" "$BIN/twcanary" -write -baseline "$ROOT/bench/noise-baseline.json" | tee "$LOG/canary.txt"
fi
( cd "$ROOT" && taskset -c "$GEN_CORES" go test ./internal/load -run SelfCheck -count=1 -v ) >"$LOG/selfcheck-strict.txt" 2>&1 || true
grep -E "^(---|ok|FAIL|PASS)" "$LOG/selfcheck-strict.txt" | tee "$LOG/selfcheck-strict.summary.txt" || true

fi
# ---- services ----------------------------------------------------------------
start_mock() { # fresh process + fresh logs: each run sees only its own ground truth
  [[ -f "$ST/pids/mock" ]] && { kill "$(cat "$ST/pids/mock")" 2>/dev/null || true; while kill -0 "$(cat "$ST/pids/mock")" 2>/dev/null; do sleep 0.05; done; }
  rm -f "$WORK/gt.jsonl" "$WORK/emit.csv"
  taskset -c "$MOCK_CORES" "$BIN/twmock" -listen 127.0.0.1:9300 -admin "" -h2c \
    -ground-truth "$WORK/gt.jsonl" -emit-log "$WORK/emit.csv" -emit-sample 0.05 >>"$LOG/twmock.log" 2>&1 & reg $! mock
  wait_port 9300
}
start_mock
start_null() { # name listen admin extra...
  local n="$1" l="$2" a="$3"; shift 3
  taskset -c "$GW_CORES" "$BIN/twnull" -listen "127.0.0.1:$l" -admin "127.0.0.1:$a" -upstream http://127.0.0.1:9300 "$@" >"$LOG/twnull-$n.log" 2>&1 &
  reg $! "null-$n"; wait_port "$l"
}
start_null h1 9302 9303
start_null h1-uph2c 9306 9307 -upstream-h2c
start_null h2c 9308 9309 -h2c -upstream-h2c
start_null tls 9304 9305 -tls-cert "$TLS/srv.pem" -tls-key "$TLS/srv.key"
echo "services up"

# ---- run helper --------------------------------------------------------------
FIXED=(-duration "$DUR" -warmup "$WARM" -gap "$GAP" -inject PCI.PAN:1 -inject-frac 0.2
       -ground-truth "$WORK/gt.jsonl" -emit-log "$WORK/emit.csv" -emit-sample 0.05 -check-sample 0.05
       -mock-stats http://127.0.0.1:9300/_tw/stats -out "$OUT")
run() { # id target rate events [extra...]
  local id="$1" target="$2" rate="$3" ev="$4"; shift 4
  echo "-- $id"
  taskset -c "$GEN_CORES" "$BIN/twload" run -target "$target" -rate "$rate" -events "$ev" -run-id "$id" "${FIXED[@]}" "$@" >"$LOG/$id.txt" 2>&1 \
    || { rc=$?; [[ $rc == 3 || $rc == 4 ]] || { cat "$LOG/$id.txt"; return $rc; }; }   # 3 = flagged invalid, 4 = pass-through leaks (expected: control)
  start_mock
}
sut() { echo -sut-metrics "http://127.0.0.1:$1/metrics"; }

if has floor; then
# ---- floor: 3 loads x RUNS x {direct, null}, randomized order ------------------
plan=()
for L in "${LOADS[@]}"; do for r in $(seq 1 "$RUNS"); do plan+=("direct $L $r" "null $L $r"); done; done
mapfile -t plan < <(printf '%s\n' "${plan[@]}" | shuf --random-source=<(yes 42))
echo "== floor: ${#plan[@]} runs (randomized) =="
for item in "${plan[@]}"; do
  read -r kind L r <<<"$item"
  if [[ $kind == direct ]]; then run "$S-direct-L$L-r$r" http://127.0.0.1:9300 "$L" 64
  else run "$S-null-L$L-r$r" http://127.0.0.1:9302 "$L" 64 $(sut 9303); fi
done

fi
if has fit; then
# ---- fit grid: rate x events vary independently -------------------------------
echo "== fit grid =="
grid=()
for L in "${LOADS[@]}"; do for e in 16 256; do grid+=("$L $e"); done; done
mapfile -t grid < <(printf '%s\n' "${grid[@]}" | shuf --random-source=<(yes 7))
for item in "${grid[@]}"; do
  read -r L e <<<"$item"
  run "$S-fit-L$L-e$e-r1" http://127.0.0.1:9302 "$L" "$e" $(sut 9303)
done

fi
if has tp; then
# ---- transport / TLS comparison at the middle load ------------------------------
M="${LOADS[1]}"
echo "== transport at $M req/s, events=64 (3 runs each) =="
tp=()
for r in 1 2 3; do for k in ${TP_KINDS:-h1 uph2c tls-h1 tls-h2 h2c-h2c}; do tp+=("$k $r"); done; done
mapfile -t tp < <(printf '%s\n' "${tp[@]}" | shuf --random-source=<(yes 9))
for item in "${tp[@]}"; do
  read -r kind r <<<"$item"; id="$S-tp-$kind-r$r"
  case $kind in
    h1)      run "$id" http://127.0.0.1:9302 "$M" 64 $(sut 9303) ;;
    uph2c)   run "$id" http://127.0.0.1:9306 "$M" 64 $(sut 9307) ;;
    tls-h1)  run "$id" https://localhost:9304 "$M" 64 $(sut 9305) -tls-ca "$TLS/ca.pem" ;;
    tls-h2)  run "$id" https://localhost:9304 "$M" 64 $(sut 9305) -tls-ca "$TLS/ca.pem" -h2 ;;
    h2c-h2c) run "$id" http://127.0.0.1:9308 "$M" 64 $(sut 9309) -h2c ;;
  esac
done

fi
if has trace; then
# ---- synthetic-trace replay (burstiness) ---------------------------------------
echo "== synthetic BurstGPT-shaped trace replay =="
TRACE="$ROOT/bench/data/synthetic-burstgpt.csv"
[[ -f "$TRACE" ]] || "$BIN/twtrace" -rows 30000 >"$TRACE"
run "$S-trace-null-r1" http://127.0.0.1:9302 "$M" 64 $(sut 9303) -trace "$TRACE"
run "$S-trace-poisson-null-r1" http://127.0.0.1:9302 "$M" 64 $(sut 9303)
fi
echo "session $S complete; teardown follows"
