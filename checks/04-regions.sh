# Control 4: find unused Regions and check whether Organizations policies block them.
C4=C4-REGIONS
register_component 4 $C4 "4. Block unused Regions"
REGION_CONDITION_KEY='aws:RequestedRegion'

c4_policies_with_region_key() { # <list-policies JSON> -> names of customer policies containing $REGION_CONDITION_KEY, or "none"
  local j="$1" pid pname c found=""
  while IFS="$SEP" read -r pid pname; do
    [ -z "$pid" ] && continue
    c=$(aws_json $C4 "$G" organizations describe-policy --policy-id "$pid" --region "$GLOBAL_REGION") || continue
    if jq -r '.Policy.Content' <<<"$c" | grep -q "$REGION_CONDITION_KEY"; then found="${found:+$found, }$pname"; fi
  done < <(rows '.Policies[] | select(.AwsManaged | not) | [.Id, .Name]' <<<"$j")
  echo "${found:-none}"
}

c4_global() { # SRA-ORGANIZATIONS-01, 06, 07
  local j rc scps rcps
  j=$(EXPECT_ERR='AWSOrganizationsNotInUseException' aws_json $C4 "$G" organizations describe-organization --region "$GLOBAL_REGION"); rc=$?
  if [ "$rc" -eq 2 ]; then
    emit $C4 WARN "$G" region-scp "account is not in AWS Organizations, so no SCP can block Regions; disable unused opt-in Regions (SRA-ORGANIZATIONS-01)"
    return
  fi
  [ "$rc" -ne 0 ] && return
  pass_or_fail "$(jq '.Organization.FeatureSet == "ALL"' <<<"$j")" $C4 "$G" org-features "all features enabled" "organization runs consolidated billing only, so SCPs are unavailable (SRA-ORGANIZATIONS-05)"
  j=$(EXPECT_ERR='AccessDenied' aws_json $C4 "$G" organizations list-policies --filter SERVICE_CONTROL_POLICY --region "$GLOBAL_REGION"); rc=$?
  if [ "$rc" -eq 2 ]; then
    emit $C4 WARN "$G" region-scp "this account cannot read organization policies; ask the org admin to confirm an SCP denies unused Regions ($REGION_CONDITION_KEY)"
    return
  fi
  [ "$rc" -ne 0 ] && return
  scps=$(c4_policies_with_region_key "$j")
  pass_or_fail "$([ "$scps" != none ] && echo true)" $C4 "$G" region-scp "SCPs using $REGION_CONDITION_KEY: $scps (confirm they are attached to this account)" "no SCP uses $REGION_CONDITION_KEY to deny unused Regions (SRA-ORGANIZATIONS-06)"
  rcps=$(EXPECT_ERR='PolicyTypeNotEnabled' aws_json $C4 "$G" organizations list-policies --filter RESOURCE_CONTROL_POLICY --region "$GLOBAL_REGION") || rcps='{}'
  pass_or_fail "$(jq '[.Policies[]? | select(.AwsManaged | not)] | length > 0' <<<"$rcps")" $C4 "$G" rcp "customer-managed resource control policies exist" "no customer-managed resource control policies (SRA-ORGANIZATIONS-07)" WARN
}

c4_region() { # count workloads so unused Regions can be flagged
  local R="$1" ec2=0 fn=0 db=0 vpc=0 j
  j=$(ec2_instances $C4 "$R") && ec2=$(jq '[.Reservations[].Instances[] | select(.State.Name != "terminated")] | length' <<<"$j")
  j=$(lambda_functions $C4 "$R") && fn=$(jq '.Functions | length' <<<"$j")
  j=$(rds_instances $C4 "$R") && db=$(jq '.DBInstances | length' <<<"$j")
  j=$(owned_vpcs $C4 "$R") && vpc=$(jq '[.Vpcs[] | select(.IsDefault | not)] | length' <<<"$j")
  if [ $((ec2 + fn + db + vpc)) -gt 0 ]; then
    emit $C4 INFO "$R" region-in-use "ec2=$ec2 lambda=$fn rds=$db non-default-vpcs=$vpc"
  else
    emit $C4 INFO "$R" region-unused "no EC2, Lambda, RDS or non-default VPCs"
  fi
}

c4_summary() {
  local region opt
  while read -r region opt; do
    has_finding $C4 INFO region-unused "$region" || continue
    if [ "$opt" = opted-in ]; then
      emit $C4 WARN "$region" region-unused "opt-in Region enabled but unused. Disable: aws account disable-region --region-name $region"
    else
      emit $C4 WARN "$region" region-unused "default Region with no workloads; deny it with an SCP on $REGION_CONDITION_KEY"
    fi
  done < "$OUT_DIR/regions.txt"
}
