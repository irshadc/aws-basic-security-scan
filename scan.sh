#!/bin/bash
# Baseline security scan for 7 controls. Makes read-only API calls only.
# Run it through run-readonly.sh so it gets read-only credentials.
#
# Env (optional):
#   REGIONS   space-separated Regions to scan (default: every Region enabled in the account)
#   PARALLEL  Regions scanned at once (default: 4)
# Output: reports/<timestamp>/report.md and findings.tsv
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PARALLEL="${PARALLEL:-4}"
GLOBAL_REGION="us-east-1"   # endpoint for global services (IAM, CloudFront, Organizations, S3 control)
G="global"
CONTROLS="C1-KEYS C2-PUBLIC C3-DETECT C4-REGIONS C5-WAF C6-IMDS C7-SIR"
OUT_DIR="$SCRIPT_DIR/reports/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT_DIR"
export FINDINGS_FILE="$OUT_DIR/findings-global.tsv"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
: > "$FINDINGS_FILE"

control_title() {
  case "$1" in
    C1-KEYS) echo "1. Remove long-lived access keys" ;;
    C2-PUBLIC) echo "2. Review every public endpoint" ;;
    C3-DETECT) echo "3. GuardDuty, Security Hub and Inspector" ;;
    C4-REGIONS) echo "4. Block unused Regions" ;;
    C5-WAF) echo "5. AWS WAF on public applications" ;;
    C6-IMDS) echo "6. Enforce IMDSv2" ;;
    C7-SIR) echo "7. AWS Security Incident Response" ;;
  esac
}

check_long_lived_keys() {
  local j k l user key status age last found=0
  if j=$(aws_json C1-KEYS "$G" iam get-account-summary); then
    if [ "$(jq '.SummaryMap.AccountAccessKeysPresent' <<<"$j")" = 0 ]; then emit C1-KEYS PASS "$G" root "no root access keys"
    else emit C1-KEYS FAIL "$G" root "root user has access keys; delete them"; fi
    if [ "$(jq '.SummaryMap.AccountMFAEnabled' <<<"$j")" = 1 ]; then emit C1-KEYS PASS "$G" root-mfa "root MFA enabled"
    else emit C1-KEYS FAIL "$G" root-mfa "root user has no MFA"; fi
  fi
  j=$(aws_json C1-KEYS "$G" iam list-users) || return
  while read -r user; do
    [ -z "$user" ] && continue
    k=$(aws_json C1-KEYS "$G" iam list-access-keys --user-name "$user") || continue
    while IFS="$SEP" read -r key status age; do
      [ -z "$key" ] && continue
      found=1
      if [ "$status" != Active ]; then
        emit C1-KEYS WARN "$G" "user:$user/$key" "inactive key, $age days old; delete it"
        continue
      fi
      last="never used"
      if l=$(aws_json C1-KEYS "$G" iam get-access-key-last-used --access-key-id "$key"); then
        last=$(jq -r '.AccessKeyLastUsed | if .LastUsedDate then "last used \(.LastUsedDate[0:10]) on \(.ServiceName)" else "never used" end' <<<"$l")
      fi
      emit C1-KEYS FAIL "$G" "user:$user/$key" "active key, $age days old, $last; replace with a role or IAM Identity Center"
    done < <(rows '.AccessKeyMetadata[] | [.AccessKeyId, .Status, ((now - (.CreateDate | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601)) / 86400 | floor)]' <<<"$k")
  done < <(jq -r '.Users[].UserName' <<<"$j")
  if [ "$found" = 0 ]; then emit C1-KEYS PASS "$G" iam-users "no IAM user access keys"; fi
}

bucket_is_blocked() { # bucket region -> 0 if bucket-level Block Public Access is fully on
  local j
  j=$(EXPECT_ERR='NoSuchPublicAccessBlockConfiguration' aws_json C2-PUBLIC "$2" s3api get-public-access-block --bucket "$1" --region "$2") || return 1
  [ "$(jq '[.PublicAccessBlockConfiguration[]] | all' <<<"$j")" = true ]
}

check_s3_public_access() {
  local j rc b br p a grants checked=0 public=0
  j=$(EXPECT_ERR='NoSuchPublicAccessBlockConfiguration' aws_json C2-PUBLIC "$G" s3control get-public-access-block --account-id "$ACCOUNT_ID" --region "$GLOBAL_REGION"); rc=$?
  [ "$rc" -eq 1 ] && return
  if [ "$rc" -eq 0 ] && [ "$(jq '[.PublicAccessBlockConfiguration[]] | all' <<<"$j")" = true ]; then
    emit C2-PUBLIC PASS "$G" s3-account-block "S3 Block Public Access fully on for the account; no bucket can be public"
    return
  fi
  emit C2-PUBLIC FAIL "$G" s3-account-block "account-level S3 Block Public Access is not fully on"
  j=$(aws_json C2-PUBLIC "$G" s3api list-buckets --region "$GLOBAL_REGION") || return
  while read -r b; do
    [ -z "$b" ] && continue
    checked=$((checked + 1))
    p=$(aws_json C2-PUBLIC "$G" s3api get-bucket-location --bucket "$b" --region "$GLOBAL_REGION") || continue
    br=$(jq -r '.LocationConstraint // "us-east-1" | if . == "EU" then "eu-west-1" else . end' <<<"$p")
    bucket_is_blocked "$b" "$br" && continue
    if p=$(EXPECT_ERR='NoSuchBucketPolicy' aws_json C2-PUBLIC "$br" s3api get-bucket-policy-status --bucket "$b" --region "$br") \
       && [ "$(jq -r '.PolicyStatus.IsPublic' <<<"$p")" = true ]; then
      emit C2-PUBLIC FAIL "$br" "s3:$b" "bucket policy makes the bucket public"; public=$((public + 1))
    fi
    if a=$(aws_json C2-PUBLIC "$br" s3api get-bucket-acl --bucket "$b" --region "$br"); then
      grants=$(jq -r '[.Grants[] | select((.Grantee.URI // "") | test("AllUsers|AuthenticatedUsers")) | .Permission] | join(",")' <<<"$a")
      if [ -n "$grants" ]; then emit C2-PUBLIC FAIL "$br" "s3:$b" "ACL grants $grants to everyone"; public=$((public + 1)); fi
    fi
  done < <(jq -r '.Buckets[].Name' <<<"$j")
  emit C2-PUBLIC INFO "$G" s3-buckets "$checked buckets checked, $public public findings"
}

check_cloudfront() { # C2 inventory, C5 WAF
  local j id domain acl aliases
  j=$(aws_json C2-PUBLIC "$G" cloudfront list-distributions --region "$GLOBAL_REGION") || return
  while IFS="$SEP" read -r id domain acl aliases; do
    [ -z "$id" ] && continue
    emit C2-PUBLIC INFO "$G" "cloudfront:$id" "public distribution: ${aliases:-$domain}"
    if [ -n "$acl" ]; then emit C5-WAF PASS "$G" "cloudfront:$id" "web ACL attached"
    else emit C5-WAF FAIL "$G" "cloudfront:$id" "no AWS WAF web ACL (${aliases:-$domain})"; fi
  done < <(rows '.DistributionList.Items[]? | [.Id, .DomainName, (.WebACLId // ""), ((.Aliases.Items // []) | join(","))]' <<<"$j")
}

check_region_scp() { # C4: is there an SCP that denies Regions?
  local j rc pid pname c found=""
  j=$(EXPECT_ERR='AWSOrganizationsNotInUseException' aws_json C4-REGIONS "$G" organizations describe-organization --region "$GLOBAL_REGION"); rc=$?
  if [ "$rc" -eq 2 ]; then
    emit C4-REGIONS WARN "$G" region-scp "account is not in AWS Organizations, so no SCP can block Regions; disable unused opt-in Regions"
    return
  fi
  [ "$rc" -ne 0 ] && return
  j=$(EXPECT_ERR='AccessDenied' aws_json C4-REGIONS "$G" organizations list-policies --filter SERVICE_CONTROL_POLICY --region "$GLOBAL_REGION"); rc=$?
  if [ "$rc" -eq 2 ]; then
    emit C4-REGIONS WARN "$G" region-scp "member account cannot read SCPs; ask the org admin to confirm an SCP denies unused Regions (aws:RequestedRegion)"
    return
  fi
  [ "$rc" -ne 0 ] && return
  while IFS="$SEP" read -r pid pname; do
    [ -z "$pid" ] && continue
    c=$(aws_json C4-REGIONS "$G" organizations describe-policy --policy-id "$pid" --region "$GLOBAL_REGION") || continue
    if jq -r '.Policy.Content' <<<"$c" | grep -q 'aws:RequestedRegion'; then found="${found:+$found, }$pname"; fi
  done < <(rows '.Policies[] | [.Id, .Name]' <<<"$j")
  if [ -n "$found" ]; then emit C4-REGIONS PASS "$G" region-scp "SCPs using aws:RequestedRegion: $found (confirm they are attached to this account)"
  else emit C4-REGIONS FAIL "$G" region-scp "no SCP uses aws:RequestedRegion to deny unused Regions"; fi
}

has_finding() { # control status resource [region] -> 0 if a matching finding exists
  awk -F'\t' -v c="$1" -v s="$2" -v r="$3" -v g="${4:-}" \
    '$1 == c && $2 ~ s && $4 == r && (g == "" || $3 == g) { f = 1 } END { exit !f }' "$OUT_DIR"/findings-*.tsv
}

summarize_cross_region() {
  local region opt
  has_finding C1-KEYS PASS identity-center \
    || emit C1-KEYS WARN "$G" identity-center "no IAM Identity Center instance found; use it for human access instead of IAM users"
  awk -F'\t' '$1 == "C7-SIR" && $2 == "PASS" { f = 1 } END { exit !f }' "$OUT_DIR"/findings-*.tsv \
    || emit C7-SIR FAIL "$G" security-ir "no AWS Security Incident Response membership found in scanned Regions"
  while read -r region opt; do
    has_finding C4-REGIONS INFO region-unused "$region" || continue
    if [ "$opt" = opted-in ]; then
      emit C4-REGIONS WARN "$region" region-unused "opt-in Region enabled but unused. Disable: aws account disable-region --region-name $region"
    else
      emit C4-REGIONS WARN "$region" region-unused "default Region with no workloads; deny it with an SCP on aws:RequestedRegion"
    fi
  done < "$OUT_DIR/regions.txt"
}

write_report() {
  local f="$OUT_DIR/findings.tsv" c s
  cat "$OUT_DIR"/findings-*.tsv | sort -t$'\t' -k1,1 -k3,3 > "$f"
  {
    echo "# Baseline security scan"
    echo
    echo "Account $ACCOUNT_ID, scanned $(date -u +%Y-%m-%dT%H:%MZ), $(wc -l < "$OUT_DIR/regions.txt" | tr -d ' ') Regions."
    echo
    echo "| Control | FAIL | WARN | PASS | ERROR |"
    echo "|---|---|---|---|---|"
    for c in $CONTROLS; do
      awk -F'\t' -v c="$c" -v t="$(control_title "$c")" \
        '$1 == c { n[$2]++ } END { printf "| %s | %d | %d | %d | %d |\n", t, n["FAIL"], n["WARN"], n["PASS"], n["ERROR"] }' "$f"
    done
    for c in $CONTROLS; do
      echo; echo "## $(control_title "$c")"; echo
      for s in FAIL WARN ERROR INFO PASS; do
        awk -F'\t' -v c="$c" -v s="$s" '$1 == c && $2 == s { printf "- %s [%s] %s: %s\n", s, $3, $4, $5 }' "$f"
      done
    done
  } > "$OUT_DIR/report.md"
}

ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text) || { echo "ERROR: cannot read caller identity" >&2; exit 1; }
j=$(aws_json C4-REGIONS "$G" ec2 describe-regions --region "$GLOBAL_REGION") || { echo "ERROR: cannot list Regions" >&2; exit 1; }
jq -r --arg only "${REGIONS:-}" '($only | split(" ") | map(select(. != ""))) as $o
  | .Regions[] | select(($o | length) == 0 or (.RegionName as $r | $o | index($r))) | "\(.RegionName) \(.OptInStatus)"' <<<"$j" > "$OUT_DIR/regions.txt"

echo "Scanning account $ACCOUNT_ID, $(wc -l < "$OUT_DIR/regions.txt" | tr -d ' ') Regions, output in $OUT_DIR"
echo "Global checks (IAM, S3, CloudFront, Organizations)..."
check_long_lived_keys
check_s3_public_access
check_cloudfront
check_region_scp
echo "Regional checks ($PARALLEL at a time)..."
cut -d' ' -f1 "$OUT_DIR/regions.txt" | xargs -P "$PARALLEL" -I{} "$SCRIPT_DIR/scan-region.sh" {} "$OUT_DIR"
summarize_cross_region
write_report
rm -f "$OUT_DIR"/findings-*.tsv

sed -n '1,/^## /p' "$OUT_DIR/report.md" | sed '$d'
echo "Full report: $OUT_DIR/report.md"
