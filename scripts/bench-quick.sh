#!/usr/bin/env bash
# bench-quick: ~60-second single-box sanity run of the Phase 0 harness.
#
#   direct (twload -> twmock)                      baseline
#   via null proxy at 16/64/256 events/response     floor; feeds the capacity fit
#   twload diff                                    "added latency" of the null proxy
#   twfit                                          c_r / c_e
#
# Everything runs on ONE host, so results are SHAPE-ONLY (generator, mock and
# proxy compete for cores). Published numbers come from the 3-VM rig
# (bench/RUNBOOK.md). Results go to $OUT/$TAG-<label>/ (default .bench-quick/).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${OUT:-$ROOT/.bench-quick}"
TAG="${TAG:-bq-$(date -u +%Y%m%dT%H%M%SZ)}"
RATE="${RATE:-200}"
DUR="${DUR:-10s}"
WARM="${WARM:-3s}"
GAP="${GAP:-const:20ms}"
MOCK_ADDR="127.0.0.1:${MOCK_PORT:-9300}"
NULL_ADDR="127.0.0.1:${NULL_PORT:-9302}"
NULL_ADMIN="127.0.0.1:${NULL_ADMIN_PORT:-9303}"
SPIN="${SPIN:-}"            # twload --spin-margin (set from `twload timer` on the rig)
BIN="$ROOT/.bin"

mkdir -p "$BIN" "$OUT"
( cd "$ROOT" && CGO_ENABLED=0 go build -trimpath -o "$BIN/" ./cmd/twmock ./cmd/twnull ./cmd/twload ./cmd/twfit )

WORK="$ROOT/.bench-quick/$TAG-work"; mkdir -p "$WORK"   # bulky ground-truth/emit logs stay out of committed results
pids=()
cleanup() { for p in "${pids[@]:-}"; do kill "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; }
trap cleanup EXIT

"$BIN/twmock" -listen "$MOCK_ADDR" -admin "" -ground-truth "$WORK/gt.jsonl" -emit-log "$WORK/emit.csv" -emit-sample 0.1 >"$WORK/mock.log" 2>&1 &
pids+=($!)
"$BIN/twnull" -listen "$NULL_ADDR" -admin "$NULL_ADMIN" -upstream "http://$MOCK_ADDR" >"$WORK/null.log" 2>&1 &
pids+=($!)
for i in $(seq 1 50); do
  (exec 3<>"/dev/tcp/${MOCK_ADDR%:*}/${MOCK_ADDR#*:}") 2>/dev/null && (exec 3<>"/dev/tcp/${NULL_ADDR%:*}/${NULL_ADDR#*:}") 2>/dev/null && break
  sleep 0.1
done

spin=(); [[ -n "$SPIN" ]] && spin=(-spin-margin "$SPIN")
run() { # label target events [extra...]
  local label="$1" target="$2" events="$3"; shift 3
  "$BIN/twload" run -target "$target" -rate "$RATE" -duration "$DUR" -warmup "$WARM" -events "$events" -gap "$GAP" \
    -inject PCI.PAN:1 -inject-frac 0.2 -ground-truth "$WORK/gt.jsonl" -emit-log "$WORK/emit.csv" -emit-sample 0.1 -check-sample 0.1 \
    -mock-stats "http://$MOCK_ADDR/_tw/stats" -out "$OUT" -run-id "$TAG-$label" "${spin[@]}" "$@" \
    || { rc=$?; [[ $rc == 3 || $rc == 4 ]] || exit $rc; }   # 3 = run flagged invalid, 4 = pass-through leaks (expected here)
}

echo "== direct baseline =="
run direct "http://$MOCK_ADDR" 64
echo; echo "== null proxy, events/response sweep =="
for e in 16 64 256; do
  run "null-e$e" "http://$NULL_ADDR" "$e" -sut-metrics "http://$NULL_ADMIN/metrics"
  echo
done

echo "== added latency of the null proxy (events=64): test - base =="
"$BIN/twload" diff -base "$OUT/$TAG-direct" -test "$OUT/$TAG-null-e64"
echo; echo "== capacity fit (null proxy) =="
"$BIN/twfit" "$OUT/$TAG-null-e16" "$OUT/$TAG-null-e64" "$OUT/$TAG-null-e256" || true
echo; echo "results: $OUT/$TAG-*   (single host: SHAPE ONLY, not publishable)"
