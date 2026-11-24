#!/usr/bin/env bash
# Analyse a rig-local-gateway session against the Phase 1 performance criteria.
#   scripts/rig-local-gateway-analyze.sh <session>  ->  bench/sessions/<session>/analysis.md
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; S="$1"; R="$ROOT/bench/results"; B="$ROOT/.bin"
OUT="$ROOT/bench/sessions/$S/analysis.md"
( cd "$ROOT" && go build -trimpath -o .bin/ ./cmd/twagg ./cmd/twload )
KNEE="$(tr -d '[:space:]' <"$ROOT/bench/sessions/$S/knee.txt")"; L70=$(( KNEE * 70 / 100 ))
{
echo "# Phase 1 parse-only performance, session \`$S\` (SYNTHETIC local rig: shape only, not publishable)"
echo
echo "Gateway = auth + strict parse + SSE decode + delta scan + request events, **no detectors**. Floor = null proxy. Both pinned to the same 2 cores."
echo
echo "## Knee sweep (3 runs per rate; healthy = merged event_delay p99 <= 5 ms and achieved >= 98 % of offered)"
echo '```'
echo "null proxy:";  "$B/twagg" -knee "$R"/$S-sweep-null-L* 2>&1 || true
echo; echo "gateway:"; "$B/twagg" -knee "$R"/$S-sweep-gw-L* 2>&1 || true
echo '```'
echo
echo "## Comparison at 70 % of the null knee ($L70 req/s) and at the knee ($KNEE req/s), 5 runs per cell"
for m in event_delay request_total; do
  echo; echo "### $m"
  "$B/twagg" -metric $m "$R"/$S-cmp-direct-L$L70-r* "$R"/$S-cmp-null-L$L70-r* "$R"/$S-cmp-gw-L$L70-r* "$R"/$S-cmp-direct-L$KNEE-r* "$R"/$S-cmp-null-L$KNEE-r* "$R"/$S-cmp-gw-L$KNEE-r*
done
echo
echo "### Added latency of the gateway over the null proxy (merged histograms, runs 1-5 pooled by twagg; r1 shown by twload diff)"
echo '```'
for L in $L70 $KNEE; do echo "load $L req/s: gateway - null"; "$B/twload" diff -base "$R/$S-cmp-null-L$L-r1" -test "$R/$S-cmp-gw-L$L-r1" 2>&1 | sed -n 1,6p; done
echo '```'
echo
echo "## Criteria"
python3 - "$R" "$S" "$L70" "$KNEE" "$ROOT/bin" <<'PY'
import json,glob,sys,subprocess
R,S,L70,KNEE=sys.argv[1],sys.argv[2],int(sys.argv[3]),int(sys.argv[4])
def pooled(kind,L,metric):
    out=subprocess.run([".bin/twagg","-metric",metric,"-json","/dev/stdout",*sorted(glob.glob(f"{R}/{S}-cmp-{kind}-L{L}-r*"))],capture_output=True,text=True).stdout
    j=out[out.index("["):]
    return json.loads(j)[0]
n70,g70=pooled("null",L70,"event_delay"),pooled("gw",L70,"event_delay")
add=g70["merged_p99_us"]-n70["merged_p99_us"]
print(f"- p99 added event latency over the null proxy at 70% of knee ({L70} req/s): **{add} us** (gateway {g70['merged_p99_us']} us vs null {n70['merged_p99_us']} us); criterion <= 1000 us -> {'PASS' if add<=1000 else 'FAIL'}")
print(f"- p50 added: {g70['merged_p50_us']-n70['merged_p50_us']} us")
cn,cg=n70["sut_cores_mean"],g70["sut_cores_mean"]
print(f"- SUT CPU at {L70} req/s: null {cn:.2f} cores, gateway {cg:.2f} cores (x{cg/cn:.2f})")
valid=sum(json.load(open(f))["valid"] for f in glob.glob(f"{R}/{S}-*/summary.json")); tot=len(glob.glob(f"{R}/{S}-*/summary.json"))
print(f"- runs flagged valid: {valid}/{tot} (a virtualised host: every number here is shape-only)")
PY
} >"$OUT"
echo "wrote $OUT"
