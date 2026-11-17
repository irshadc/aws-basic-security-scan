# Control 11 (phase 3): data protection. Encrypted EBS and RDS, secrets kept in Secrets Manager and rotated,
# and no secret-looking values in Lambda or ECS environment variables.
# AWS Startup Security Baseline: WKLD.03, WKLD.04, WKLD.08, WKLD.09.
C11=C11-DATA
register_component 11 $C11 "11. Data protection and secrets"
SECRET_UNUSED_DAYS=90
# Variable names that usually hold a secret, and names that only point to one (an ARN, a parameter name, a key ID).
SECRET_NAME_RE='(SECRET|PASSWORD|PASSWD|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY|CREDENTIAL)'
SECRET_REFERENCE_RE='(_ARN|_NAME|_ID|_PARAM|_PARAMETER|_PATH|_URL|_REGION|_PROVIDER|_TABLE|_INDEX|_BUCKET|_TTL|_MINUTES|_SECONDS|_HEADER|_ENABLED)$'
# jq: names of secret-looking variables in an object of NAME: value pairs. Values are tested but never printed.
SECRET_VARS_JQ='to_entries | map(select((.key | ascii_upcase | test($name)) and ((.key | ascii_upcase | test($ref)) | not)
  and ((.value | tostring) | test("^(arn:|\\{\\{resolve:|\\$\\{)") | not) and ((.value | tostring) != ""))) | map(.key) | join(",")'

c11_ebs() { # WKLD.08: existing volumes and snapshots, on top of the encryption-by-default check in control 8
  local R="$1" j vol size attached n
  if j=$(aws_json $C11 "$R" ec2 describe-volumes --filters Name=encrypted,Values=false --region "$R"); then
    while IFS="$SEP" read -r vol size attached; do
      [ -n "$vol" ] && emit $C11 FAIL "$R" "ebs:$vol" "unencrypted ${size} GiB volume${attached:+ on $attached}; copy a snapshot with encryption and swap the volume (ASSB WKLD.08)"
    done < <(rows '.Volumes[] | [.VolumeId, .Size, ([.Attachments[]?.InstanceId] | join(","))]' <<<"$j")
  fi
  if j=$(aws_json $C11 "$R" ec2 describe-snapshots --owner-ids self --filters Name=encrypted,Values=false --region "$R"); then
    n=$(jq '.Snapshots | length' <<<"$j")
    [ "$n" -gt 0 ] && emit $C11 WARN "$R" ebs-snapshots "$n unencrypted EBS snapshots; copy with encryption or delete (ASSB WKLD.08)"
  fi
}

c11_rds() { # WKLD.09: RDS instances (non-Aurora) and Aurora or Multi-AZ DB clusters
  local R="$1" j id engine enc
  if j=$(rds_instances $C11 "$R"); then
    while IFS="$SEP" read -r id engine enc; do
      [ -z "$id" ] && continue
      pass_or_fail "$enc" $C11 "$R" "rds:$id" "$engine storage encrypted" "$engine storage not encrypted; restore an encrypted snapshot copy (ASSB WKLD.09)"
    done < <(rows '.DBInstances[] | select(.DBClusterIdentifier == null) | [.DBInstanceIdentifier, .Engine, .StorageEncrypted]' <<<"$j")
  fi
  j=$(aws_json $C11 "$R" rds describe-db-clusters --region "$R") || return
  while IFS="$SEP" read -r id engine enc; do
    [ -z "$id" ] && continue
    pass_or_fail "$enc" $C11 "$R" "rds-cluster:$id" "$engine cluster storage encrypted" "$engine cluster storage not encrypted (ASSB WKLD.09)"
  done < <(rows '.DBClusters[] | [.DBClusterIdentifier, .Engine, .StorageEncrypted]' <<<"$j")
}

c11_secrets_manager() { # WKLD.03: secrets rotate and are still in use
  local R="$1" j name rotation used
  j=$(aws_json $C11 "$R" secretsmanager list-secrets --region "$R") || return
  while IFS="$SEP" read -r name rotation used; do
    [ -z "$name" ] && continue
    [ "$rotation" = true ] || emit $C11 WARN "$R" "secret:$name" "rotation off; turn on automatic rotation where the service supports it (ASSB WKLD.03)"
    [ -n "$used" ] && [ "$used" -gt "$SECRET_UNUSED_DAYS" ] && emit $C11 WARN "$R" "secret:$name" "not read for $used days; delete it if nothing uses it (ASSB WKLD.03)"
  done < <(rows "$JQ_AGE"' .SecretList[] | [.Name, (.RotationEnabled // false), (if .LastAccessedDate then (.LastAccessedDate | age_days) else "" end)]' <<<"$j")
}

c11_env_secrets() { # WKLD.04: secret-looking environment variables in Lambda functions and ECS task definitions
  local R="$1" j fn names fam t
  if j=$(lambda_functions $C11 "$R"); then
    while IFS="$SEP" read -r fn names; do
      [ -n "$names" ] && emit $C11 WARN "$R" "lambda:$fn" "environment variables that look like secrets: $names; move them to Secrets Manager or Parameter Store (ASSB WKLD.04)"
    done < <(jq -r --arg name "$SECRET_NAME_RE" --arg ref "$SECRET_REFERENCE_RE" \
      ".Functions[] | [.FunctionName, ((.Environment.Variables // {}) | $SECRET_VARS_JQ)] | join(\"\u001f\")" <<<"$j")
  fi
  j=$(aws_json $C11 "$R" ecs list-task-definition-families --status ACTIVE --region "$R") || return
  while read -r fam; do
    [ -z "$fam" ] && continue
    t=$(aws_json $C11 "$R" ecs describe-task-definition --task-definition "$fam" --region "$R") || continue
    names=$(jq -r --arg name "$SECRET_NAME_RE" --arg ref "$SECRET_REFERENCE_RE" \
      "[.taskDefinition.containerDefinitions[].environment[]? | {(.name): .value}] | add // {} | $SECRET_VARS_JQ" <<<"$t")
    [ -n "$names" ] && emit $C11 WARN "$R" "ecs-task:$fam" "environment variables that look like secrets: $names; use the container 'secrets' field instead (ASSB WKLD.04)"
  done < <(jq -r '.families[]' <<<"$j")
}

c11_region() {
  c11_ebs "$1"
  c11_rds "$1"
  c11_secrets_manager "$1"
  c11_env_secrets "$1"
}
