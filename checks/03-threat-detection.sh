# Control 3: GuardDuty (with protection plans), Security Hub (standards, finding routing), Inspector, Macie.
C3=C3-DETECT
GD_FOUNDATIONAL="CLOUD_TRAIL DNS_LOGS FLOW_LOGS"
GD_PROTECTION_PLANS="S3_DATA_EVENTS EKS_AUDIT_LOGS EBS_MALWARE_PROTECTION RDS_LOGIN_EVENTS RUNTIME_MONITORING LAMBDA_NETWORK_LOGS"
GD_RUNTIME_AGENTS="EKS_ADDON_MANAGEMENT ECS_FARGATE_AGENT_MANAGEMENT EC2_AGENT_MANAGEMENT"
SH_STANDARDS="aws-foundational-security-best-practices cis-aws-foundations-benchmark ai-security-best-practices"

features_off() { # <detector JSON> <space-separated names> -> names not ENABLED (jq query on .Features)
  jq -r --arg names "$2" '($names | split(" ")) - [.Features[]? | select(.Status == "ENABLED") | .Name] | join(" ")' <<<"$1"
}

c3_guardduty() { # SRA-GUARDDUTY-01, 03-12, 17-19
  local R="$1" det j off agents
  det=$(guardduty_detector_id $C3 "$R") || return
  if [ -z "$det" ]; then emit $C3 FAIL "$R" guardduty "GuardDuty not enabled (SRA-GUARDDUTY-01)"; return; fi
  j=$(aws_json $C3 "$R" guardduty get-detector --detector-id "$det" --region "$R") || return
  if [ "$(jq -r '.Status' <<<"$j")" != ENABLED ]; then emit $C3 FAIL "$R" guardduty "detector $det is suspended (SRA-GUARDDUTY-03)"; return; fi
  emit $C3 PASS "$R" guardduty "detector $det enabled"
  off=$(features_off "$j" "$GD_FOUNDATIONAL")
  pass_or_fail "$([ -z "$off" ] && echo true)" $C3 "$R" guardduty-sources "CloudTrail, DNS and flow log sources on" "data sources off: $off (SRA-GUARDDUTY-04/05/08)"
  off=$(features_off "$j" "$GD_PROTECTION_PLANS")
  pass_or_fail "$([ -z "$off" ] && echo true)" $C3 "$R" guardduty-protection "all protection plans on" "protection plans off: $off; enable those that match your workloads (SRA-GUARDDUTY-06/07/09-12)" WARN
  if [[ " $off " != *" RUNTIME_MONITORING "* ]]; then
    agents=$(jq -r --arg names "$GD_RUNTIME_AGENTS" '($names | split(" ")) - [.Features[]? | select(.Name == "RUNTIME_MONITORING") | .AdditionalConfiguration[]? | select(.Status == "ENABLED") | .Name] | join(" ")' <<<"$j")
    pass_or_fail "$([ -z "$agents" ] && echo true)" $C3 "$R" guardduty-runtime-agents "runtime agent management on for EKS, ECS Fargate and EC2" "runtime agent management off: $agents (SRA-GUARDDUTY-17/18/19)" WARN
  fi
}

c3_finding_routing() { # region label -> 0 if an ENABLED EventBridge rule for aws.securityhub has a target (SRA-SECURITYHUB-20/25)
  local R="$1" j name t
  j=$(aws_json $C3 "$R" events list-rules --region "$R") || return 1
  while read -r name; do
    [ -z "$name" ] && continue
    t=$(aws_json $C3 "$R" events list-targets-by-rule --rule "$name" --region "$R") || continue
    [ "$(jq '.Targets | length' <<<"$t")" -gt 0 ] && return 0
  done < <(jq -r '.Rules[] | select(.State == "ENABLED" and ((.EventPattern // "") | test("aws\\.securityhub"))) | .Name' <<<"$j")
  return 1
}

c3_security_hub() { # SRA-SECURITYHUB-01, 12, 14, 23, 24
  local R="$1" j rc hub="" enabled s
  j=$(EXPECT_ERR='not subscribed|ResourceNotFoundException' aws_json $C3 "$R" securityhub describe-security-hub-v2 --region "$R"); rc=$?
  [ "$rc" -eq 0 ] && hub="Security Hub"
  j=$(EXPECT_ERR='not subscribed|InvalidAccessException' aws_json $C3 "$R" securityhub describe-hub --region "$R"); rc=$?
  [ "$rc" -eq 0 ] && hub="${hub:+$hub + }Security Hub CSPM"
  if [ -z "$hub" ]; then emit $C3 FAIL "$R" security-hub "neither Security Hub nor Security Hub CSPM enabled (SRA-SECURITYHUB-14)"; return; fi
  emit $C3 PASS "$R" security-hub "$hub enabled"
  if [[ "$hub" == *CSPM* ]] && j=$(aws_json $C3 "$R" securityhub get-enabled-standards --region "$R"); then
    enabled=$(jq -r '[.StandardsSubscriptions[] | select(.StandardsStatus == "READY" or .StandardsStatus == "INCOMPLETE") | .StandardsArn] | join(" ")' <<<"$j")
    for s in $SH_STANDARDS; do
      pass_or_fail "$([[ "$enabled" == *"standards/$s/"* ]] && echo true)" $C3 "$R" "standard:$s" "enabled" "not enabled (SRA-SECURITYHUB-01/12/23/24)"
    done
  fi
  if c3_finding_routing "$R"; then emit $C3 PASS "$R" security-hub-routing "EventBridge rule sends Security Hub findings to a target"
  else emit $C3 WARN "$R" security-hub-routing "no enabled EventBridge rule routes Security Hub findings to a target (SNS, ticketing, chat) (SRA-SECURITYHUB-20/25)"; fi
}

c3_inspector() { # SRA-INSPECTOR-01..04
  local R="$1" j st ec2 ecr lam code status
  j=$(aws_json $C3 "$R" inspector2 batch-get-account-status --region "$R") || return
  IFS="$SEP" read -r st ec2 ecr lam code < <(rows '.accounts[0] | [.state.status, (.resourceState.ec2.status // ""), (.resourceState.ecr.status // ""), (.resourceState.lambda.status // ""), (.resourceState.lambdaCode.status // "")]' <<<"$j")
  if [ "$st" != ENABLED ]; then status=FAIL
  elif [ "$ec2" = ENABLED ] && [ "$ecr" = ENABLED ] && [ "$lam" = ENABLED ]; then status=PASS
  else status=WARN; fi
  emit $C3 "$status" "$R" inspector "ec2=$ec2 ecr=$ecr lambda=$lam lambda-code=$code"
}

c3_macie() { # Macie status (SRA-MACIE checks assume Macie is on)
  local R="$1" j rc
  j=$(EXPECT_ERR="AccessDeniedException.*not enabled|Macie is not enabled|$NOT_AVAILABLE_RE" aws_json $C3 "$R" macie2 get-macie-session --region "$R"); rc=$?
  if [ "$rc" -eq 0 ]; then emit $C3 PASS "$R" macie "Macie status $(jq -r '.status' <<<"$j"), publishing $(jq -r '.findingPublishingFrequency' <<<"$j")"
  elif [ "$rc" -eq 2 ]; then emit $C3 WARN "$R" macie "Macie not enabled; it finds sensitive data in S3 (paid)"; fi
}

c3_region() {
  c3_guardduty "$1"
  c3_security_hub "$1"
  c3_inspector "$1"
  c3_macie "$1"
}
