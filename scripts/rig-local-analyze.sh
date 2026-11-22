#!/usr/bin/env bash
# Analyse a rig-local session: floor table with CIs, added latency (null - direct),
# capacity fit over every null-proxy run, and the transport/TLS table.
#   scripts/rig-local-analyze.sh <session-name>  ->  bench/sessions/<S>/analysis.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; S="$1"; R="$ROOT/bench/results"; B="$ROOT/.bin"
OUT="$ROOT/bench/sessions/$S/analysis.md"
( cd "$ROOT" && go build -trimpath -o .bin/ ./cmd/twagg ./cmd/twfit ./cmd/twload )
{
echo "# Analysis of session \`$S\` (SYNTHETIC local rig: shape only, not publishable)"
echo
echo "## Per-event delay, direct vs null proxy (merged histograms; p99 CI is across runs)"
"$B/twagg" -metric event_delay "$R"/$S-direct-L* "$R"/$S-null-L*
echo
echo "## Request total latency (open loop, from intended send time)"
"$B/twagg" -metric request_total "$R"/$S-direct-L* "$R"/$S-null-L*
echo
echo "## Dispatch lag (generator health)"
"$B/twagg" -metric dispatch_lag "$R"/$S-direct-L* "$R"/$S-null-L*
echo
echo "## Added event latency of the null proxy (percentile-wise difference of merged histograms)"
echo '```'
for L in $(ls -d "$R"/$S-direct-L*-r1 | sed -E "s/.*-L([0-9]+)-r1/\1/"); do
  echo "load $L req/s:"; "$B/twload" diff -base "$R/$S-direct-L$L-r1" -test "$R/$S-null-L$L-r1" 2>&1 || true
done
echo '```'
echo "(diff above uses run r1 of each point; the merged-histogram table is authoritative.)"
echo
echo "## Capacity fit"
echo "Only UNSATURATED null-proxy runs enter the fit (SUT cores < 1.0): above the knee CPU is no longer proportional to work, and a fit through saturated points is meaningless (the all-runs fit gave R^2 < 0; it is kept below for transparency)."
FIT_MAX_CORES="${FIT_MAX_CORES:-1.0}"
mapfile -t fitdirs < <(python3 - "$R" "$S" "$FIT_MAX_CORES" <<'PY'
import json,glob,sys
R,S,mx=sys.argv[1],sys.argv[2],float(sys.argv[3])
for d in sorted(glob.glob(f"{R}/{S}-null-L*")+glob.glob(f"{R}/{S}-fit-*")):
    s=json.load(open(d+"/summary.json"))
    if s["sut_cpu_seconds"]/s["window_seconds"]<mx: print(d)
PY
)
echo '```'
echo "runs in fit: ${#fitdirs[@]}"
"$B/twfit" "${fitdirs[@]}" 2>&1 || true
echo
echo "--- for transparency: ALL null-proxy runs incl. saturated (do not use) ---"
"$B/twfit" "$R"/$S-null-L* "$R"/$S-fit-* 2>&1 | tail -4 || true
echo '```'
echo
echo "## Transport / TLS at the middle load (events=64)"
"$B/twagg" -metric event_delay "$R"/$S-tp-*
echo
"$B/twagg" -metric request_total "$R"/$S-tp-*
echo
echo "## Synthetic trace vs Poisson at the middle load"
"$B/twagg" -metric request_total "$R/$S-trace-null-r1" "$R/$S-trace-poisson-null-r1"
echo
echo "## Ground-truth control (pass-through must leak everything, alter nothing)"
python3 - "$R" "$S" <<'PY'
import json,glob,sys
R,S=sys.argv[1:3]
tot=dict(inj=0,leak=0,alt=0,checked=0,perr=0,inc=0)
for f in glob.glob(f"{R}/{S}-*/summary.json"):
    g=json.load(open(f)).get("ground_truth") or {}
    tot["inj"]+=g.get("spans_total",0); tot["leak"]+=g.get("spans_leaked",0)
    tot["alt"]+=g.get("benign_altered",0); tot["checked"]+=g.get("checked",0)
    tot["perr"]+=g.get("parse_errors",0); tot["inc"]+=g.get("incomplete",0)
print(f"- streams checked: {tot['checked']}; injected spans: {tot['inj']}; leaked: {tot['leak']}; benign streams altered: {tot['alt']}; parse errors: {tot['perr']}; incomplete: {tot['inc']}")
PY
echo
echo "## Validity"
python3 - "$R" "$S" <<'PY'
import json,glob,sys,collections
R,S=sys.argv[1:3]
n=v=0; why=collections.Counter()
for f in glob.glob(f"{R}/{S}-*/summary.json"):
    s=json.load(open(f)); n+=1; v+=bool(s.get("valid"))
    for r in s.get("invalid_reasons") or []: why[r.split(" (")[0].split(" ")[0:3].__str__()]+=1
print(f"- {v}/{n} runs flagged valid. Invalid reasons: {dict(why)}")
PY
} >"$OUT"
echo "wrote $OUT"
