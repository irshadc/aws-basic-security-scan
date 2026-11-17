# Shared helpers for the baseline security scan. Sourced by scan.sh and scan-region.sh.
# Callers must set FINDINGS_FILE before sourcing.

# Field separator for jq rows. Non-whitespace, so `read` keeps empty fields.
SEP=$'\x1f'

# emit <control> <status> <region> <resource> <detail>
# Status is one of FAIL, WARN, PASS, INFO, ERROR.
emit() {
  printf '%s\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4" "${5//$'\t'/ }" >> "$FINDINGS_FILE"
}

# aws_json <control> <region-label> <aws args...>
# Prints the JSON response and returns 0 on success.
# On failure: if stderr matches $EXPECT_ERR, prints the message and returns 2 (caller decides);
# otherwise records an ERROR finding and returns 1.
aws_json() {
  local control="$1" label="$2"; shift 2
  local err out msg rc=0
  err="$(mktemp)"
  out="$(aws "$@" --output json 2>"$err" </dev/null)" || rc=$?
  if [ "$rc" -eq 0 ]; then rm -f "$err"; printf '%s' "$out"; return 0; fi
  msg="$(tr '\n' ' ' < "$err" | cut -c1-300)"
  rm -f "$err"
  if [ -n "${EXPECT_ERR:-}" ] && printf '%s' "$msg" | grep -Eq "$EXPECT_ERR"; then
    printf '%s' "$msg"; return 2
  fi
  emit "$control" ERROR "$label" "aws $1 $2" "$msg"
  return 1
}

# rows <jq filter producing arrays>: reads JSON on stdin, prints one SEP-joined line per array.
rows() {
  jq -r "($1) | map(tostring) | join(\"\\u001f\")"
}
