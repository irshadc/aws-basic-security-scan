# Builds report.md and findings.tsv from the per-process findings files. Sourced by scan.sh.

CONTROLS="C1-KEYS C2-PUBLIC C3-DETECT C4-REGIONS C5-WAF C6-IMDS C7-SIR C8-LOGGING"
STATUS_ORDER="FAIL WARN ERROR INFO PASS"

control_title() {
  case "$1" in
    C1-KEYS) echo "1. Remove long-lived access keys" ;;
    C2-PUBLIC) echo "2. Review every public endpoint" ;;
    C3-DETECT) echo "3. GuardDuty, Security Hub, Inspector and Macie" ;;
    C4-REGIONS) echo "4. Block unused Regions" ;;
    C5-WAF) echo "5. AWS WAF on public applications" ;;
    C6-IMDS) echo "6. Enforce IMDSv2" ;;
    C7-SIR) echo "7. AWS Security Incident Response" ;;
    C8-LOGGING) echo "8. Logging and encryption baseline" ;;
  esac
}

write_report() {
  local f="$OUT_DIR/findings.tsv" c s
  cat "$OUT_DIR"/findings-*.tsv | sort -t$'\t' -k1,1 -k3,3 > "$f"
  {
    echo "# Baseline security scan"
    echo
    echo "Account $ACCOUNT_ID, scanned $(date -u +%Y-%m-%dT%H:%MZ), $(wc -l < "$OUT_DIR/regions.txt" | tr -d ' ') Regions."
    echo "IDs in brackets such as (SRA-IAM-06) map a check to the AWS SRA Verify check catalog."
    echo
    echo "| Control | FAIL | WARN | PASS | ERROR |"
    echo "|---|---|---|---|---|"
    for c in $CONTROLS; do
      awk -F'\t' -v c="$c" -v t="$(control_title "$c")" \
        '$1 == c { n[$2]++ } END { printf "| %s | %d | %d | %d | %d |\n", t, n["FAIL"], n["WARN"], n["PASS"], n["ERROR"] }' "$f"
    done
    for c in $CONTROLS; do
      echo; echo "## $(control_title "$c")"; echo
      for s in $STATUS_ORDER; do
        awk -F'\t' -v c="$c" -v s="$s" '$1 == c && $2 == s { printf "- %s [%s] %s: %s\n", s, $3, $4, $5 }' "$f"
      done
    done
  } > "$OUT_DIR/report.md"
}
