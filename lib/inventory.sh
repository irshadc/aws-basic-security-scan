# Shared resource inventory. Each call is cached per Region for the run, so components that need
# the same list (for example instances for controls 2, 6, 9 and 12) make the API call only once.
# Arguments for every function: <control> <region>. Global lists take only <control>.

# Compute and network
ec2_instances()      { cached_json "$1" "$2" instances ec2 describe-instances --region "$2"; }
owned_vpcs()         { cached_json "$1" "$2" vpcs ec2 describe-vpcs --filters "Name=owner-id,Values=$ACCOUNT_ID" --region "$2"; }
security_groups()    { cached_json "$1" "$2" security-groups ec2 describe-security-groups --region "$2"; }
network_interfaces() { cached_json "$1" "$2" enis ec2 describe-network-interfaces --region "$2"; }
lambda_functions()   { cached_json "$1" "$2" functions lambda list-functions --region "$2"; }
rds_instances()      { cached_json "$1" "$2" rds rds describe-db-instances --region "$2"; }

# Entry points
load_balancers() { cached_json "$1" "$2" elbv2 elbv2 describe-load-balancers --region "$2"; }
classic_lbs()    { cached_json "$1" "$2" elb elb describe-load-balancers --region "$2"; }
rest_apis()      { cached_json "$1" "$2" rest-apis apigateway get-rest-apis --region "$2"; }
http_apis()      { cached_json "$1" "$2" http-apis apigatewayv2 get-apis --region "$2"; }
distributions()  { cached_json "$1" "$G" cloudfront cloudfront list-distributions --region "$GLOBAL_REGION"; }

# Security services
access_analyzers() { cached_json "$1" "$2" analyzers accessanalyzer list-analyzers --region "$2"; }
guardduty_detector_id() { # -> detector id, or empty
  local j
  j=$(cached_json "$1" "$2" gd-detectors guardduty list-detectors --region "$2") || return 1
  jq -r '.DetectorIds[0] // ""' <<<"$j"
}

# IAM: users, groups, roles (with inline policies and instance profiles) and customer managed policies.
iam_authorization_details() {
  cached_json "$1" "$G" iam-authorization iam get-account-authorization-details --filter User Group Role LocalManagedPolicy
}

function_url_rows() { # -> "function SEP url SEP auth-type" lines
  local file="$OUT_DIR/cache/$2-function-urls.txt" j u fn
  if [ ! -f "$file" ]; then
    mkdir -p "$OUT_DIR/cache"; : > "$file"
    j=$(lambda_functions "$1" "$2") || return
    while read -r fn; do
      [ -z "$fn" ] && continue
      u=$(aws_json "$1" "$2" lambda list-function-url-configs --function-name "$fn" --region "$2") || continue
      jq -r --arg fn "$fn" '.FunctionUrlConfigs[] | [$fn, .FunctionUrl, .AuthType] | join("\u001f")' <<<"$u" >> "$file"
    done < <(jq -r '.Functions[].FunctionName' <<<"$j")
  fi
  cat "$file"
}
