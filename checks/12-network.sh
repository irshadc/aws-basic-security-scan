# Control 12 (phase 3): network hygiene. Unused VPCs and security groups, default security groups,
# subnets that hand out public IPs, VPC endpoints, and Session Manager instead of SSH or RDP.
# AWS Startup Security Baseline: ACCT.09, WKLD.06, WKLD.10, WKLD.11, WKLD.12.
C12=C12-NETWORK
register_component 12 $C12 "12. Network hygiene and remote access"
GATEWAY_ENDPOINT_SERVICES="s3 dynamodb"
# jq: true when a security group rule opens SSH (22) or RDP (3389) to the whole internet.
REMOTE_ADMIN_OPEN_JQ='any(.IpPermissions[]; (any(.IpRanges[]?; .CidrIp == "0.0.0.0/0") or any(.Ipv6Ranges[]?; .CidrIpv6 == "::/0"))
  and (.IpProtocol == "-1" or ((.FromPort // 0) <= 22 and (.ToPort // 0) >= 22) or ((.FromPort // 0) <= 3389 and (.ToPort // 0) >= 3389)))'

c12_unused() { # ACCT.09: VPCs and security groups with no network interfaces; default security groups with rules
  local R="$1" v s enis id name is_default used rules
  v=$(owned_vpcs $C12 "$R") || return
  s=$(security_groups $C12 "$R") || return
  network_interfaces $C12 "$R" >/dev/null || return
  enis=$(cache_file "$R" enis)
  while IFS="$SEP" read -r id is_default used; do
    [ -z "$id" ] && continue
    if [ "$used" = 0 ]; then
      emit $C12 WARN "$R" "vpc:$id" "$([ "$is_default" = true ] && echo 'default ')VPC with no network interfaces; delete it if unused (ASSB ACCT.09)"
    fi
  done < <(rows '.Vpcs[] | .VpcId as $v | [.VpcId, .IsDefault, ([$e[0].NetworkInterfaces[] | select(.VpcId == $v)] | length)]' --slurpfile e "$enis" <<<"$v")
  while IFS="$SEP" read -r id name used rules; do
    [ -z "$id" ] && continue
    if [ "$name" = default ]; then
      [ "$rules" -gt 0 ] && emit $C12 WARN "$R" "$id (default)" "default security group has $rules rules; remove them so nothing relies on it by accident (ASSB WKLD.11)"
    elif [ "$used" = 0 ]; then
      emit $C12 WARN "$R" "$id ($name)" "security group not attached to any network interface; delete it if no launch template or rule refers to it (ASSB ACCT.09)"
    fi
  done < <(rows '([$e[0].NetworkInterfaces[].Groups[]?.GroupId] | unique) as $used | .SecurityGroups[]
      | [.GroupId, .GroupName, (if (.GroupId as $g | $used | index($g)) then 1 else 0 end), ((.IpPermissions | length) + (.IpPermissionsEgress | length))]' \
      --slurpfile e "$enis" <<<"$s")
}

c12_public_subnets() { # WKLD.10: subnets outside the default VPC that give every new instance a public IP
  local R="$1" j id vpc
  owned_vpcs $C12 "$R" >/dev/null || return
  j=$(aws_json $C12 "$R" ec2 describe-subnets --filters Name=map-public-ip-on-launch,Values=true --region "$R") || return
  while IFS="$SEP" read -r id vpc; do
    [ -n "$id" ] && emit $C12 WARN "$R" "subnet:$id" "in $vpc, gives every new instance a public IP; turn off MapPublicIpOnLaunch unless the subnet is only for load balancers or NAT (ASSB WKLD.10)"
  done < <(rows '([$v[0].Vpcs[] | select(.IsDefault) | .VpcId]) as $d
      | .Subnets[] | select(.VpcId as $id | $d | index($id) | not) | [.SubnetId, .VpcId]' --slurpfile v "$(cache_file "$R" vpcs)" <<<"$j")
}

c12_vpc_endpoints() { # WKLD.12: VPCs with workloads have S3 and DynamoDB gateway endpoints
  local R="$1" v p vpc svc missing
  v=$(owned_vpcs $C12 "$R") || return
  network_interfaces $C12 "$R" >/dev/null || return
  p=$(aws_json $C12 "$R" ec2 describe-vpc-endpoints --region "$R") || return
  while read -r vpc; do
    [ -z "$vpc" ] && continue
    missing=""
    for svc in $GATEWAY_ENDPOINT_SERVICES; do
      jq -e --arg v "$vpc" --arg s "com.amazonaws.$R.$svc" 'any(.VpcEndpoints[]; .VpcId == $v and .ServiceName == $s)' <<<"$p" >/dev/null || missing="${missing:+$missing, }$svc"
    done
    pass_or_fail "$([ -z "$missing" ] && echo true)" $C12 "$R" "vpc:$vpc/endpoints" "S3 and DynamoDB gateway endpoints present" \
      "no gateway endpoint for $missing; traffic to these services leaves through the internet or NAT. Gateway endpoints are free (ASSB WKLD.12)" WARN
  done < <(jq -r --slurpfile e "$(cache_file "$R" enis)" '.Vpcs[] | .VpcId as $v | select(any($e[0].NetworkInterfaces[]; .VpcId == $v)) | .VpcId' <<<"$v")
}

c12_remote_access() { # WKLD.06: instances managed by Session Manager, with no key pair and no SSH or RDP open to the internet
  local R="$1" j m s open id name state key groups issues status
  j=$(ec2_instances $C12 "$R") || return
  m=$(aws_json $C12 "$R" ssm describe-instance-information --region "$R") || return
  s=$(security_groups $C12 "$R") || return
  open=$(jq -c "[.SecurityGroups[] | select($REMOTE_ADMIN_OPEN_JQ) | .GroupId]" <<<"$s")
  while IFS="$SEP" read -r id name state key groups; do
    [ -z "$id" ] && continue
    issues=""
    [ "$state" = running ] && ! jq -e --arg i "$id" 'any(.InstanceInformationList[]; .InstanceId == $i)' <<<"$m" >/dev/null && issues="not managed by Systems Manager"
    [ -n "$key" ] && issues="${issues:+$issues; }launched with key pair $key"
    status=WARN
    if jq -e --argjson o "$open" --arg g "$groups" 'any($g | split(",")[]; . as $x | $o | index($x))' -n >/dev/null; then
      issues="${issues:+$issues; }SSH or RDP open to the internet"; status=FAIL
    fi
    pass_or_fail "$([ -z "$issues" ] && echo true)" $C12 "$R" "ec2:$id${name:+ ($name)}" "reachable through Session Manager only" \
      "$issues ($state); connect with Session Manager instead of SSH or RDP (ASSB WKLD.06)" "$status"
  done < <(rows '.Reservations[].Instances[] | select(.State.Name != "terminated")
      | [.InstanceId, ([.Tags[]? | select(.Key == "Name") | .Value][0] // ""), .State.Name, (.KeyName // ""), ([.SecurityGroups[]?.GroupId] | join(","))]' <<<"$j")
}

c12_region() {
  c12_unused "$1"
  c12_public_subnets "$1"
  c12_vpc_endpoints "$1"
  c12_remote_access "$1"
}
