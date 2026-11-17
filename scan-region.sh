#!/bin/bash
# Runs every component's Region checks (cN_region) for one Region. Called by scan.sh. Read-only API calls only.
# Usage: scan-region.sh <region> <output-dir>
set -uo pipefail

R="$1"
OUT_DIR="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FINDINGS_FILE="$OUT_DIR/findings-$R.tsv"
# shellcheck source=lib/common.sh
source "$SCRIPT_DIR/lib/common.sh"
load_components "$SCRIPT_DIR"
: > "$FINDINGS_FILE"

for n in $COMPONENT_NUMBERS; do
  if declare -F "c${n}_region" >/dev/null; then "c${n}_region" "$R"; fi
done
echo "  scanned $R" >&2
