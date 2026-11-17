#!/bin/bash
# Enforces IMDSv2 (control 6): sets the account default per Region and requires tokens on existing instances.
# Dry run by default; prints what it would change. Set APPLY=1 to make changes.
# Instances that made IMDSv1 calls in the last LOOKBACK_DAYS are skipped unless FORCE=1,
# because enforcing would break software that still uses IMDSv1.
#
# Usage: ./fix-imdsv2.sh                    (dry run, all enabled Regions)
#        APPLY=1 ./fix-imdsv2.sh            (apply)
# Env:   REGIONS (space-separated), APPLY=1, FORCE=1, LOOKBACK_DAYS (default 14), AWS_PROFILE
set -euo pipefail

APPLY="${APPLY:-0}"
FORCE="${FORCE:-0}"
LOOKBACK_DAYS="${LOOKBACK_DAYS:-14}"
DAY_SECONDS=86400
GLOBAL_REGION="us-east-1"

if [ "$APPLY" = 1 ]; then MODE="APPLY"; else MODE="DRY-RUN"; fi
START=$(date -u -v-"${LOOKBACK_DAYS}"d +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -d "$LOOKBACK_DAYS days ago" +%Y-%m-%dT%H:%M:%SZ)
END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
REGIONS="${REGIONS:-$(aws ec2 describe-regions --region "$GLOBAL_REGION" --query 'Regions[].RegionName' --output text)}"
changed=0; skipped=0; already=0

imdsv1_calls() { # instance region -> total MetadataNoToken calls in the lookback window
  aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name MetadataNoToken \
    --dimensions "Name=InstanceId,Value=$1" --start-time "$START" --end-time "$END" \
    --period "$DAY_SECONDS" --statistics Sum --region "$2" --output json \
    | jq '[.Datapoints[].Sum] | add // 0 | floor'
}

fix_account_default() { # region
  local t
  t=$(aws ec2 get-instance-metadata-defaults --region "$1" --query 'AccountLevel.HttpTokens' --output text)
  if [ "$t" = required ]; then return; fi
  echo "[$MODE] $1 account default HttpTokens=$t -> required"
  if [ "$APPLY" = 1 ]; then aws ec2 modify-instance-metadata-defaults --http-tokens required --region "$1" >/dev/null; fi
}

fix_instances() { # region
  local id tokens name calls
  while IFS=$'\t' read -r id tokens name; do
    [ -z "$id" ] && continue
    if [ "$tokens" = required ]; then already=$((already + 1)); continue; fi
    calls=$(imdsv1_calls "$id" "$1")
    if [ "$calls" -gt 0 ] && [ "$FORCE" != 1 ]; then
      echo "[SKIP] $1 $id ($name): $calls IMDSv1 calls in last $LOOKBACK_DAYS days; update its software first or set FORCE=1"
      skipped=$((skipped + 1)); continue
    fi
    echo "[$MODE] $1 $id ($name): HttpTokens=$tokens -> required ($calls IMDSv1 calls in last $LOOKBACK_DAYS days)"
    if [ "$APPLY" = 1 ]; then
      aws ec2 modify-instance-metadata-options --instance-id "$id" --http-tokens required --http-endpoint enabled --region "$1" >/dev/null
    fi
    changed=$((changed + 1))
  done < <(aws ec2 describe-instances --region "$1" --output json \
    | jq -r '.Reservations[].Instances[] | select(.State.Name != "terminated")
      | [.InstanceId, (.MetadataOptions.HttpTokens // "unknown"), ([.Tags[]? | select(.Key == "Name") | .Value][0] // "-")] | @tsv')
}

echo "Mode: $MODE. Identity: $(aws sts get-caller-identity --query Arn --output text)"
for r in $REGIONS; do
  fix_account_default "$r"
  fix_instances "$r"
done
echo "Done. Already IMDSv2: $already. To change: $changed. Skipped (IMDSv1 in use): $skipped."
if [ "$APPLY" != 1 ] && [ "$changed" -gt 0 ]; then echo "Re-run with APPLY=1 to make these changes."; fi
