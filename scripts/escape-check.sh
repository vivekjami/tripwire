#!/usr/bin/env bash
# escape-check: heap-escape regression gate for the hot packages
# (IMPLEMENTATION_PLAN WP0.1 / ARCHITECTURE §12.3).
#
# For each hot package that exists, records the set of "escapes to heap" /
# "moved to heap" sites (line numbers stripped, so unrelated edits do not
# churn it) and diffs it against the committed baseline in bench/escape/.
# A NEW heap escape fails the check; fix it, or regenerate the baseline with
#   scripts/escape-check.sh --update
# in the same PR with a justification.
#
# Phase 0 has no hot packages yet (internal/{sse,jsonscan,detect} arrive in
# Phases 1-2); the gate is wired now so it is never skipped later.
set -euo pipefail
cd "$(dirname "$0")/.."
HOT=(internal/sse internal/jsonscan internal/detect)
update=0; [[ "${1:-}" == "--update" ]] && update=1
mkdir -p bench/escape
fail=0; checked=0
for pkg in "${HOT[@]}"; do
  [[ -d "$pkg" ]] || { echo "escape-check: $pkg not present yet (skipped)"; continue; }
  checked=$((checked+1))
  name="${pkg//\//_}"
  cur="$(go build -gcflags='-m' "./$pkg" 2>&1 | grep -E 'escapes to heap|moved to heap' | sed -E 's/:[0-9]+:[0-9]+:/:/' | sort -u || true)"
  base="bench/escape/$name.txt"
  if (( update )) || [[ ! -f "$base" ]]; then
    printf '%s\n' "$cur" > "$base"; echo "escape-check: wrote baseline $base"
    continue
  fi
  new="$(comm -13 <(sort -u "$base") <(printf '%s\n' "$cur" | sort -u))"
  if [[ -n "$new" ]]; then
    echo "escape-check: NEW heap escapes in $pkg:"; echo "$new"; fail=1
  fi
done
echo "escape-check: $checked hot package(s) checked"
exit $fail
