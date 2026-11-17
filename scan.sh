#!/bin/bash
# Baseline security scan. Makes read-only API calls only.
# Run it through run-readonly.sh so it gets read-only credentials.
#
# Each file in checks/ is one component and may define:
#   cN_global          account-wide checks, run once
#   cN_region <region> per-Region checks, run in parallel by scan-region.sh
#   cN_summary         cross-Region conclusions, run after all Regions finish
#
# Env (optional):
#   REGIONS     space-separated Regions to scan (default: every Region enabled in the account)
#   PARALLEL    Regions scanned at once (default: 4)
#   COMPONENTS  component numbers to run, e.g. "1 6" (default: all)
# Output: reports/<timestamp>/report.md and findings.tsv
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARALLEL="${PARALLEL:-4}"
export COMPONENT_NUMBERS="${COMPONENTS:-1 2 3 4 5 6 7 8}"
export OUT_DIR="$SCRIPT_DIR/reports/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT_DIR"
FINDINGS_FILE="$OUT_DIR/findings-global.tsv"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
# shellcheck source=lib/report.sh
source "$SCRIPT_DIR/lib/report.sh"
for f in "$SCRIPT_DIR"/checks/*.sh; do source "$f"; done
: > "$FINDINGS_FILE"

run_phase() { # <phase name>: calls cN_<phase> for every selected component that defines it
  local n
  for n in $COMPONENT_NUMBERS; do
    if declare -F "c${n}_$1" >/dev/null; then "c${n}_$1"; fi
  done
}

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text) || { echo "ERROR: cannot read caller identity" >&2; exit 1; }
export ACCOUNT_ID
j=$(aws_json C4-REGIONS "$G" ec2 describe-regions --region "$GLOBAL_REGION") || { echo "ERROR: cannot list Regions" >&2; exit 1; }
jq -r --arg only "${REGIONS:-}" '($only | split(" ") | map(select(. != ""))) as $o
  | .Regions[] | select(($o | length) == 0 or (.RegionName as $r | $o | index($r))) | "\(.RegionName) \(.OptInStatus)"' <<<"$j" > "$OUT_DIR/regions.txt"

echo "Scanning account $ACCOUNT_ID, $(wc -l < "$OUT_DIR/regions.txt" | tr -d ' ') Regions, components: $COMPONENT_NUMBERS"
echo "Output in $OUT_DIR"
echo "Account-wide checks..."
run_phase global
echo "Regional checks ($PARALLEL at a time)..."
cut -d' ' -f1 "$OUT_DIR/regions.txt" | xargs -P "$PARALLEL" -I{} "$SCRIPT_DIR/scan-region.sh" {} "$OUT_DIR"
run_phase summary
write_report
rm -rf "$OUT_DIR"/findings-*.tsv "$OUT_DIR/cache"

sed -n '1,/^## /p' "$OUT_DIR/report.md" | sed '$d'
echo "Full report: $OUT_DIR/report.md"
