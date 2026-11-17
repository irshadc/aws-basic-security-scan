#!/bin/bash
# Per-Region checks for the baseline controls. Called by scan.sh. Read-only API calls only.
# Usage: scan-region.sh <region> <output-dir>
set -uo pipefail

R="$1"
OUT_DIR="$2"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
export FINDINGS_FILE="$OUT_DIR/findings-$R.tsv"
# shellcheck source=lib.sh
source "$SCRIPT_DIR/lib.sh"
: > "$FINDINGS_FILE"

WEB_PORTS_RE='^(80|443)$'
NOT_AVAILABLE_RE='Could not connect|EndpointConnectionError|UnknownEndpoint|not supported'
instance_count=0; lambda_count=0; rds_count=0; vpc_count=0

check_instances() { # C6 IMDSv2 per instance, C2 public IPs
  local j id state ip tokens name label t
  if j=$(aws_json C6-IMDS "$R" ec2 describe-instances --region "$R"); then
    while IFS="$SEP" read -r id state ip tokens name; do
      [ -z "$id" ] && continue
      instance_count=$((instance_count + 1))
      label="$id${name:+ ($name)}"
      if [ "$tokens" = required ]; then
        emit C6-IMDS PASS "$R" "$label" "IMDSv2 required"
      else
        emit C6-IMDS FAIL "$R" "$label" "HttpTokens=$tokens ($state). Fix: aws ec2 modify-instance-metadata-options --instance-id $id --http-tokens required --region $R"
      fi
      if [ -n "$ip" ]; then emit C2-PUBLIC WARN "$R" "$label" "public IP $ip; justify or move behind a load balancer"; fi
    done < <(rows '.Reservations[].Instances[] | select(.State.Name != "terminated") | [.InstanceId, .State.Name, (.PublicIpAddress // ""), (.MetadataOptions.HttpTokens // "unknown"), ([.Tags[]? | select(.Key == "Name") | .Value][0] // "")]' <<<"$j")
  fi
  if j=$(aws_json C6-IMDS "$R" ec2 get-instance-metadata-defaults --region "$R"); then
    t=$(jq -r '.AccountLevel.HttpTokens // "not set"' <<<"$j")
    if [ "$t" = required ]; then
      emit C6-IMDS PASS "$R" account-default "new instances default to IMDSv2"
    else
      emit C6-IMDS WARN "$R" account-default "account default HttpTokens=$t. Fix: aws ec2 modify-instance-metadata-defaults --http-tokens required --region $R"
    fi
  fi
}

check_network() { # C2 open security groups, non-default VPC count for C4
  local j gid gname proto from to ports status
  if j=$(aws_json C2-PUBLIC "$R" ec2 describe-security-groups --region "$R"); then
    while IFS="$SEP" read -r gid gname proto from to; do
      [ -z "$gid" ] && continue
      if [ "$proto" = "-1" ]; then
        ports="all traffic"; status=FAIL
      else
        ports="$proto $from-$to"; status=FAIL
        if [ "$from" = "$to" ] && [[ "$from" =~ $WEB_PORTS_RE ]]; then status=WARN; fi
      fi
      emit C2-PUBLIC "$status" "$R" "$gid ($gname)" "inbound open to 0.0.0.0/0 or ::/0: $ports"
    done < <(rows '.SecurityGroups[] | . as $g | .IpPermissions[] | select(any(.IpRanges[]?; .CidrIp == "0.0.0.0/0") or any(.Ipv6Ranges[]?; .CidrIpv6 == "::/0")) | [$g.GroupId, $g.GroupName, .IpProtocol, (.FromPort // ""), (.ToPort // "")]' <<<"$j")
  fi
  if j=$(aws_json C4-REGIONS "$R" ec2 describe-vpcs --region "$R"); then
    vpc_count=$(jq '[.Vpcs[] | select(.IsDefault | not)] | length' <<<"$j")
  fi
}

check_databases() { # C2 publicly accessible RDS
  local j db engine
  if j=$(aws_json C2-PUBLIC "$R" rds describe-db-instances --region "$R"); then
    rds_count=$(jq '.DBInstances | length' <<<"$j")
    while IFS="$SEP" read -r db engine; do
      [ -z "$db" ] && continue
      emit C2-PUBLIC FAIL "$R" "rds:$db" "$engine instance is PubliclyAccessible"
    done < <(rows '.DBInstances[] | select(.PubliclyAccessible) | [.DBInstanceIdentifier, .Engine]' <<<"$j")
  fi
}

check_load_balancers() { # C2 internet-facing LBs, C5 WAF on ALBs
  local j w arn name type dns acl
  if j=$(aws_json C2-PUBLIC "$R" elbv2 describe-load-balancers --region "$R"); then
    while IFS="$SEP" read -r arn name type dns; do
      [ -z "$arn" ] && continue
      emit C2-PUBLIC INFO "$R" "$type-lb:$name" "internet-facing: $dns"
      if [ "$type" != application ]; then
        emit C5-WAF WARN "$R" "$type-lb:$name" "AWS WAF cannot attach to a $type load balancer; front it with CloudFront + WAF or justify"
        continue
      fi
      w=$(aws_json C5-WAF "$R" wafv2 get-web-acl-for-resource --resource-arn "$arn" --region "$R") || continue
      acl=$(jq -r '.WebACL.Name // ""' <<<"$w")
      if [ -n "$acl" ]; then emit C5-WAF PASS "$R" "alb:$name" "web ACL $acl"
      else emit C5-WAF FAIL "$R" "alb:$name" "no AWS WAF web ACL"; fi
    done < <(rows '.LoadBalancers[] | select(.Scheme == "internet-facing") | [.LoadBalancerArn, .LoadBalancerName, .Type, .DNSName]' <<<"$j")
  fi
  if j=$(aws_json C2-PUBLIC "$R" elb describe-load-balancers --region "$R"); then
    while read -r name; do
      [ -z "$name" ] && continue
      emit C2-PUBLIC WARN "$R" "classic-lb:$name" "internet-facing Classic Load Balancer"
      emit C5-WAF WARN "$R" "classic-lb:$name" "AWS WAF cannot attach to a Classic Load Balancer; migrate to ALB"
    done < <(jq -r '.LoadBalancerDescriptions[] | select(.Scheme == "internet-facing") | .LoadBalancerName' <<<"$j")
  fi
}

check_apis() { # C2 public API Gateway APIs, C5 WAF on REST stages
  local j s id name stage acl proto
  if j=$(aws_json C2-PUBLIC "$R" apigateway get-rest-apis --region "$R"); then
    while IFS="$SEP" read -r id name; do
      [ -z "$id" ] && continue
      emit C2-PUBLIC INFO "$R" "rest-api:$name ($id)" "public REST API endpoint"
      s=$(aws_json C5-WAF "$R" apigateway get-stages --rest-api-id "$id" --region "$R") || continue
      while IFS="$SEP" read -r stage acl; do
        [ -z "$stage" ] && continue
        if [ -n "$acl" ]; then emit C5-WAF PASS "$R" "rest-api:$name/$stage" "web ACL attached"
        else emit C5-WAF FAIL "$R" "rest-api:$name/$stage" "no AWS WAF web ACL on stage"; fi
      done < <(rows '.item[] | [.stageName, (.webAclArn // "")]' <<<"$s")
    done < <(rows '.items[] | select((.endpointConfiguration.types // []) | index("PRIVATE") | not) | [.id, .name]' <<<"$j")
  fi
  if j=$(aws_json C2-PUBLIC "$R" apigatewayv2 get-apis --region "$R"); then
    while IFS="$SEP" read -r id name proto; do
      [ -z "$id" ] && continue
      emit C2-PUBLIC INFO "$R" "$proto-api:$name ($id)" "public API Gateway $proto API"
      emit C5-WAF WARN "$R" "$proto-api:$name ($id)" "$proto APIs do not support AWS WAF directly; front with CloudFront + WAF"
    done < <(rows '.Items[] | [.ApiId, .Name, .ProtocolType]' <<<"$j")
  fi
}

check_function_urls() { # C2 Lambda function URLs
  local j u fn url auth status
  j=$(aws_json C2-PUBLIC "$R" lambda list-functions --region "$R") || return
  lambda_count=$(jq '.Functions | length' <<<"$j")
  while read -r fn; do
    [ -z "$fn" ] && continue
    u=$(aws_json C2-PUBLIC "$R" lambda list-function-url-configs --function-name "$fn" --region "$R") || continue
    while IFS="$SEP" read -r url auth; do
      [ -z "$url" ] && continue
      status=INFO; [ "$auth" = NONE ] && status=FAIL
      emit C2-PUBLIC "$status" "$R" "lambda-url:$fn" "function URL with AuthType $auth: $url"
      emit C5-WAF WARN "$R" "lambda-url:$fn" "function URLs do not support AWS WAF directly; front with CloudFront + WAF"
    done < <(rows '.FunctionUrlConfigs[] | [.FunctionUrl, .AuthType]' <<<"$u")
  done < <(jq -r '.Functions[].FunctionName' <<<"$j")
}

check_detection() { # C3 GuardDuty, Security Hub, Inspector
  local j det st rc ec2 ecr lam hub=""
  if j=$(aws_json C3-DETECT "$R" guardduty list-detectors --region "$R"); then
    det=$(jq -r '.DetectorIds[0] // ""' <<<"$j")
    if [ -z "$det" ]; then
      emit C3-DETECT FAIL "$R" guardduty "GuardDuty not enabled"
    elif j=$(aws_json C3-DETECT "$R" guardduty get-detector --detector-id "$det" --region "$R"); then
      st=$(jq -r '.Status' <<<"$j")
      if [ "$st" = ENABLED ]; then emit C3-DETECT PASS "$R" guardduty "detector $det enabled"
      else emit C3-DETECT FAIL "$R" guardduty "detector $det status $st"; fi
    fi
  fi
  j=$(EXPECT_ERR='not subscribed|ResourceNotFoundException' aws_json C3-DETECT "$R" securityhub describe-security-hub-v2 --region "$R"); rc=$?
  [ "$rc" -eq 0 ] && hub="Security Hub"
  j=$(EXPECT_ERR='not subscribed|InvalidAccessException' aws_json C3-DETECT "$R" securityhub describe-hub --region "$R"); rc=$?
  [ "$rc" -eq 0 ] && hub="${hub:+$hub + }Security Hub CSPM"
  if [ -n "$hub" ]; then emit C3-DETECT PASS "$R" security-hub "$hub enabled"
  else emit C3-DETECT FAIL "$R" security-hub "neither Security Hub nor Security Hub CSPM enabled"; fi
  if j=$(aws_json C3-DETECT "$R" inspector2 batch-get-account-status --region "$R"); then
    IFS="$SEP" read -r st ec2 ecr lam < <(rows '.accounts[0] | [.state.status, (.resourceState.ec2.status // ""), (.resourceState.ecr.status // ""), (.resourceState.lambda.status // "")]' <<<"$j")
    if [ "$st" = ENABLED ] && [ "$ec2" = ENABLED ] && [ "$ecr" = ENABLED ] && [ "$lam" = ENABLED ]; then st=PASS
    elif [ "$st" = ENABLED ]; then st=WARN
    else st=FAIL; fi
    emit C3-DETECT "$st" "$R" inspector "ec2=$ec2 ecr=$ecr lambda=$lam"
  fi
}

check_identity_and_ir() { # C1 Identity Center instance, C7 Security Incident Response membership
  local j arn id status
  if j=$(aws_json C1-KEYS "$R" sso-admin list-instances --region "$R"); then
    while IFS="$SEP" read -r arn status; do
      [ -z "$arn" ] && continue
      emit C1-KEYS PASS "$R" identity-center "IAM Identity Center instance $arn ($status)"
    done < <(rows '.Instances[] | [.InstanceArn, (.Status // "")]' <<<"$j")
  fi
  if j=$(EXPECT_ERR="$NOT_AVAILABLE_RE" aws_json C7-SIR "$R" security-ir list-memberships --region "$R"); then
    while IFS="$SEP" read -r id status; do
      [ -z "$id" ] && continue
      emit C7-SIR PASS "$R" "membership:$id" "status $status"
    done < <(rows '.items[] | [.membershipId, (.membershipStatus // "")]' <<<"$j")
  fi
}

check_instances
check_network
check_databases
check_load_balancers
check_apis
check_function_urls
check_detection
check_identity_and_ir

if [ $((instance_count + lambda_count + rds_count + vpc_count)) -gt 0 ]; then
  emit C4-REGIONS INFO "$R" region-in-use "ec2=$instance_count lambda=$lambda_count rds=$rds_count non-default-vpcs=$vpc_count"
else
  emit C4-REGIONS INFO "$R" region-unused "no EC2, Lambda, RDS or non-default VPCs"
fi
echo "  scanned $R" >&2
