#!/usr/bin/env bash
# fuzz-smoke: run every Fuzz* target for FUZZTIME (default 30s in CI, 10s locally).
# Targets are discovered, so a new parser's fuzz target is picked up automatically
# (IMPLEMENTATION_PLAN §2.7: a parser PR without its fuzz target is incomplete).
set -euo pipefail
cd "$(dirname "$0")/.."
FUZZTIME="${FUZZTIME:-10s}"
n=0
for pkg in $(go list ./...); do
  for t in $(go test -list '^Fuzz' "$pkg" 2>/dev/null | grep '^Fuzz' || true); do
    echo "== fuzz $pkg $t ($FUZZTIME)"
    go test "$pkg" -run '^$' -fuzz "^${t}\$" -fuzztime "$FUZZTIME"
    n=$((n+1))
  done
done
echo "fuzz-smoke: $n target(s) clean"
[[ $n -gt 0 ]] || { echo "no fuzz targets found" >&2; exit 1; }
