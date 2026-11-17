# Shared helpers for the scan. Sourced by scan.sh and scan-region.sh.
# Callers set FINDINGS_FILE (where findings go) and OUT_DIR (run folder) before calling these.

# Field separator for jq rows. Non-whitespace, so `read` keeps empty fields.
SEP=$'\x1f'
EMPTY_JSON='{}'           # returned when a successful call prints nothing
G="global"
GLOBAL_REGION="us-east-1"   # endpoint for global services (IAM, CloudFront, Organizations, S3 control)
NOT_AVAILABLE_RE='Could not connect|EndpointConnectionError|UnknownEndpoint|not supported|SubscriptionRequiredException'

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
  if [ "$rc" -eq 0 ]; then rm -f "$err"; printf '%s' "${out:-$EMPTY_JSON}"; return 0; fi
  msg="$(tr '\n' ' ' < "$err" | cut -c1-300)"
  rm -f "$err"
  if [ -n "${EXPECT_ERR:-}" ] && printf '%s' "$msg" | grep -Eq "$EXPECT_ERR"; then
    printf '%s' "$msg"; return 2
  fi
  emit "$control" ERROR "$label" "aws $1 $2" "$msg"
  return 1
}

# cached_json <control> <region-label> <cache-key> <aws args...>
# Same as aws_json, but stores the response so other components reuse it instead of calling again.
cached_json() {
  local control="$1" label="$2" key="$3"; shift 3
  local file out
  file=$(cache_file "$label" "$key")
  if [ -f "$file" ]; then cat "$file"; return 0; fi
  out=$(aws_json "$control" "$label" "$@") || return $?
  mkdir -p "$OUT_DIR/cache"
  printf '%s' "$out" > "$file"
  printf '%s' "$out"
}

# rows <jq filter producing arrays> [extra jq args]: reads JSON on stdin, prints one SEP-joined line per array.
rows() {
  local filter="$1"; shift
  jq -r "$@" "($filter) | map(tostring) | join(\"\\u001f\")"
}

# cache_file <region-label> <cache-key>: path of a response stored by cached_json, for jq --slurpfile.
cache_file() { echo "$OUT_DIR/cache/$1-$2.json"; }

# pass_or_fail <condition-result true|false> <control> <region> <resource> <pass-detail> <fail-detail> [fail-status]
pass_or_fail() {
  if [ "$1" = true ]; then emit "$2" PASS "$3" "$4" "$5"
  else emit "$2" "${7:-FAIL}" "$3" "$4" "$6"; fi
}

# has_finding <control> <status-regex> <resource> [region] -> 0 if a matching finding exists in any findings file
has_finding() {
  awk -F'\t' -v c="$1" -v s="$2" -v r="$3" -v g="${4:-}" \
    '$1 == c && $2 ~ s && $4 == r && (g == "" || $3 == g) { f = 1 } END { exit !f }' "$OUT_DIR"/findings-*.tsv
}

# jq definition: age_days turns an AWS timestamp into whole days ago. Accepts "Z" or a "+05:30"-style offset,
# with or without fractional seconds, because services differ.
JQ_AGE='def age_days: capture("^(?<t>[0-9-]+T[0-9:]+)(\\.[0-9]+)?(?<z>.*)$") as $c
  | ($c.z | if test("^[+-][0-9]{2}:[0-9]{2}$") then (if .[0:1] == "-" then -1 else 1 end) * ((.[1:3] | tonumber) * 3600 + (.[4:6] | tonumber) * 60) else 0 end) as $offset
  | (now - (($c.t + "Z" | fromdateiso8601) - $offset)) / 86400 | floor;'

# Component registry. Each checks/NN-*.sh file calls register_component once, so scan.sh and the
# report pick up a new component just by adding its file.
COMPONENT_LIST=""
COMPONENT_IDS=()
COMPONENT_TITLES=()
register_component() { # <number> <control id> <report title>
  COMPONENT_LIST="${COMPONENT_LIST:+$COMPONENT_LIST }$1"
  COMPONENT_IDS[$1]="$2"
  COMPONENT_TITLES[$1]="$3"
}

# load_components <script dir>: sources the inventory and every component file.
load_components() {
  local f
  # shellcheck source=lib/inventory.sh
  source "$1/lib/inventory.sh"
  for f in "$1"/checks/*.sh; do source "$f"; done
}
