# Control 2: find every internet-facing resource. WAF coverage of these is checked in 05-waf.sh.
C2=C2-PUBLIC
register_component 2 $C2 "2. Review every public endpoint"
WEB_PORTS_RE='^(80|443)$'

c2_s3() {
  local j rc b br p a grants off checked=0 public=0
  j=$(EXPECT_ERR='NoSuchPublicAccessBlockConfiguration' aws_json $C2 "$G" s3control get-public-access-block --account-id "$ACCOUNT_ID" --region "$GLOBAL_REGION"); rc=$?
  [ "$rc" -eq 1 ] && return
  off="all four settings"
  [ "$rc" -eq 0 ] && off=$(jq -r '[.PublicAccessBlockConfiguration | to_entries[] | select(.value != true) | .key] | join(", ")' <<<"$j")
  if [ -z "$off" ]; then
    emit $C2 PASS "$G" s3-account-block "S3 Block Public Access fully on for the account; no bucket can be public (SRA-S3-01..04)"
    return
  fi
  emit $C2 FAIL "$G" s3-account-block "account-level S3 Block Public Access off for: $off (SRA-S3-01..04)"
  j=$(aws_json $C2 "$G" s3api list-buckets --region "$GLOBAL_REGION") || return
  while read -r b; do
    [ -z "$b" ] && continue
    checked=$((checked + 1))
    p=$(aws_json $C2 "$G" s3api get-bucket-location --bucket "$b" --region "$GLOBAL_REGION") || continue
    br=$(jq -r '.LocationConstraint // "us-east-1" | if . == "EU" then "eu-west-1" else . end' <<<"$p")
    p=$(EXPECT_ERR='NoSuchPublicAccessBlockConfiguration' aws_json $C2 "$br" s3api get-public-access-block --bucket "$b" --region "$br") \
      && [ "$(jq '[.PublicAccessBlockConfiguration[]] | all' <<<"$p")" = true ] && continue
    if p=$(EXPECT_ERR='NoSuchBucketPolicy' aws_json $C2 "$br" s3api get-bucket-policy-status --bucket "$b" --region "$br") \
       && [ "$(jq -r '.PolicyStatus.IsPublic' <<<"$p")" = true ]; then
      emit $C2 FAIL "$br" "s3:$b" "bucket policy makes the bucket public"; public=$((public + 1))
    fi
    if a=$(aws_json $C2 "$br" s3api get-bucket-acl --bucket "$b" --region "$br"); then
      grants=$(jq -r '[.Grants[] | select((.Grantee.URI // "") | test("AllUsers|AuthenticatedUsers")) | .Permission] | join(",")' <<<"$a")
      if [ -n "$grants" ]; then emit $C2 FAIL "$br" "s3:$b" "ACL grants $grants to everyone"; public=$((public + 1)); fi
    fi
  done < <(jq -r '.Buckets[].Name' <<<"$j")
  emit $C2 INFO "$G" s3-buckets "$checked buckets checked, $public public findings"
}

c2_cloudfront() {
  local j id domain aliases
  j=$(distributions $C2) || return
  while IFS="$SEP" read -r id domain aliases; do
    [ -z "$id" ] && continue
    emit $C2 INFO "$G" "cloudfront:$id" "public distribution: ${aliases:-$domain}"
  done < <(rows '.DistributionList.Items[]? | [.Id, .DomainName, ((.Aliases.Items // []) | join(","))]' <<<"$j")
}

c2_global() {
  c2_s3
  c2_cloudfront
}

c2_compute() { # public instance IPs, open security groups, public RDS
  local R="$1" j id ip name gid gname proto from to ports status db engine
  if j=$(ec2_instances $C2 "$R"); then
    while IFS="$SEP" read -r id ip name; do
      [ -z "$id" ] && continue
      emit $C2 WARN "$R" "$id${name:+ ($name)}" "public IP $ip; justify or move behind a load balancer"
    done < <(rows '.Reservations[].Instances[] | select(.State.Name != "terminated" and .PublicIpAddress) | [.InstanceId, .PublicIpAddress, ([.Tags[]? | select(.Key == "Name") | .Value][0] // "")]' <<<"$j")
  fi
  if j=$(security_groups $C2 "$R"); then
    while IFS="$SEP" read -r gid gname proto from to; do
      [ -z "$gid" ] && continue
      ports="all traffic"; status=FAIL
      if [ "$proto" != "-1" ]; then
        ports="$proto $from-$to"
        if [ "$from" = "$to" ] && [[ "$from" =~ $WEB_PORTS_RE ]]; then status=WARN; fi
      fi
      emit $C2 "$status" "$R" "$gid ($gname)" "inbound open to 0.0.0.0/0 or ::/0: $ports"
    done < <(rows '.SecurityGroups[] | . as $g | .IpPermissions[] | select(any(.IpRanges[]?; .CidrIp == "0.0.0.0/0") or any(.Ipv6Ranges[]?; .CidrIpv6 == "::/0")) | [$g.GroupId, $g.GroupName, .IpProtocol, (.FromPort // ""), (.ToPort // "")]' <<<"$j")
  fi
  if j=$(rds_instances $C2 "$R"); then
    while IFS="$SEP" read -r db engine; do
      [ -z "$db" ] && continue
      emit $C2 FAIL "$R" "rds:$db" "$engine instance is PubliclyAccessible"
    done < <(rows '.DBInstances[] | select(.PubliclyAccessible) | [.DBInstanceIdentifier, .Engine]' <<<"$j")
  fi
}

c2_entry_points() { # load balancers, API Gateway, Lambda function URLs
  local R="$1" j name type dns id proto fn url auth
  if j=$(load_balancers $C2 "$R"); then
    while IFS="$SEP" read -r name type dns; do
      [ -n "$name" ] && emit $C2 INFO "$R" "$type-lb:$name" "internet-facing: $dns"
    done < <(rows '.LoadBalancers[] | select(.Scheme == "internet-facing") | [.LoadBalancerName, .Type, .DNSName]' <<<"$j")
  fi
  if j=$(classic_lbs $C2 "$R"); then
    jq -r '.LoadBalancerDescriptions[] | select(.Scheme == "internet-facing") | .LoadBalancerName' <<<"$j" \
      | while read -r name; do [ -n "$name" ] && emit $C2 WARN "$R" "classic-lb:$name" "internet-facing Classic Load Balancer"; done
  fi
  if j=$(rest_apis $C2 "$R"); then
    while IFS="$SEP" read -r id name; do
      [ -n "$id" ] && emit $C2 INFO "$R" "rest-api:$name ($id)" "public REST API endpoint"
    done < <(rows '.items[] | select((.endpointConfiguration.types // []) | index("PRIVATE") | not) | [.id, .name]' <<<"$j")
  fi
  if j=$(http_apis $C2 "$R"); then
    while IFS="$SEP" read -r id name proto; do
      [ -n "$id" ] && emit $C2 INFO "$R" "$proto-api:$name ($id)" "public API Gateway $proto API"
    done < <(rows '.Items[] | [.ApiId, .Name, .ProtocolType]' <<<"$j")
  fi
  while IFS="$SEP" read -r fn url auth; do
    [ -z "$fn" ] && continue
    if [ "$auth" = NONE ]; then emit $C2 FAIL "$R" "lambda-url:$fn" "function URL with no auth: $url"
    else emit $C2 INFO "$R" "lambda-url:$fn" "function URL with AuthType $auth: $url"; fi
  done < <(function_url_rows $C2 "$R")
}

c2_region() {
  c2_compute "$1"
  c2_entry_points "$1"
}
