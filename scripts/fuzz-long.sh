#!/usr/bin/env bash
# Phase 1 exit criterion: every fuzz target >= 10 minutes with no findings.
# Runs the targets with limited parallelism and records the outcome per target
# into bench/fuzz/<date>/<target>.log . Seed corpora live in testdata/fuzz (go-managed).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DUR="${FUZZTIME:-10m}"
OUT="$ROOT/bench/fuzz/$(date -u +%Y%m%d)"; mkdir -p "$OUT"
cd "$ROOT"
run() { # pkg target
  local pkg="$1" tgt="$2"
  if go test "./internal/$pkg" -run '^$' -fuzz "^${tgt}\$" -fuzztime "$DUR" -parallel "${PAR:-2}" >"$OUT/$tgt.log" 2>&1; then
    echo "$tgt PASS ($DUR)" >>"$OUT/summary.txt"
  else
    echo "$tgt FAIL" >>"$OUT/summary.txt"
  fi
}
: >"$OUT/summary.txt"
for t in "sse FuzzSSEDecoder" "jsonscan FuzzJSONScan" "jsonscan FuzzJSONScanDiff" "jsonscan FuzzDeltaRewriter"; do
  run $t &
done
wait
for t in "jsonscan FuzzUnescaper" "jsonscan FuzzNavigationNeverPanics" "config FuzzParse" "mock FuzzChunkReassembly"; do
  run $t &
done
wait
cat "$OUT/summary.txt"
