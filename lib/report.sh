# Builds report.md and findings.tsv from the per-process findings files. Sourced by scan.sh.
# Control IDs and titles come from the component registry (register_component in each checks/ file).

STATUS_ORDER="FAIL WARN ERROR INFO PASS"

write_report() {
  local f="$OUT_DIR/findings.tsv" n c t s
  cat "$OUT_DIR"/findings-*.tsv | sort -t$'\t' -k1,1 -k3,3 > "$f"
  {
    echo "# Baseline security scan"
    echo
    echo "Account $ACCOUNT_ID, scanned $(date -u +%Y-%m-%dT%H:%MZ), $(wc -l < "$OUT_DIR/regions.txt" | tr -d ' ') Regions."
    echo "IDs in brackets map a check to a published catalog: (SRA-IAM-06) to AWS SRA Verify, (ASSB ACCT.04) to the AWS Startup Security Baseline."
    echo
    echo "| Control | FAIL | WARN | PASS | ERROR |"
    echo "|---|---|---|---|---|"
    for n in $COMPONENT_NUMBERS; do
      awk -F'\t' -v c="${COMPONENT_IDS[$n]}" -v t="${COMPONENT_TITLES[$n]}" \
        '$1 == c { k[$2]++ } END { printf "| %s | %d | %d | %d | %d |\n", t, k["FAIL"], k["WARN"], k["PASS"], k["ERROR"] }' "$f"
    done
    for n in $COMPONENT_NUMBERS; do
      c="${COMPONENT_IDS[$n]}"; t="${COMPONENT_TITLES[$n]}"
      echo; echo "## $t"; echo
      for s in $STATUS_ORDER; do
        awk -F'\t' -v c="$c" -v s="$s" '$1 == c && $2 == s { printf "- %s [%s] %s: %s\n", s, $3, $4, $5 }' "$f"
      done
    done
  } > "$OUT_DIR/report.md"
}
