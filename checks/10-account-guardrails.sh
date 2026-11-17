# Control 10 (phase 3): account guardrails that warn you early. Contact details, spend alerts,
# Trusted Advisor, and how much of the estate is deployed from templates.
# AWS Startup Security Baseline: ACCT.01, ACCT.10, ACCT.12, ACCT.16, WKLD.15.
# Cost note: the two Cost Explorer calls (anomaly monitors and subscriptions) cost USD 0.01 each.
C10=C10-GUARDRAILS
register_component 10 $C10 "10. Account guardrails"
STACK_TAG="aws:cloudformation:stack-name"
TRUSTED_ADVISOR_PLAN_RE='support level|SubscriptionRequired'

c10_contact() { # ACCT.01: the primary contact is filled in. Whether emails go to a team list is a manual check.
  local j
  j=$(aws_json $C10 "$G" account get-contact-information --region "$GLOBAL_REGION") || return
  pass_or_fail "$(jq '.ContactInformation | (.FullName // "") != "" and (.PhoneNumber // "") != ""' <<<"$j")" $C10 "$G" primary-contact \
    "primary contact set; confirm the root email and alternate contacts go to team distribution lists, not one person (ASSB ACCT.01)" \
    "primary contact name or phone missing (ASSB ACCT.01)" WARN
}

c10_budgets() { # ACCT.10: at least one budget, and each budget alerts someone
  local j n name count=0
  j=$(aws_json $C10 "$G" budgets describe-budgets --account-id "$ACCOUNT_ID" --region "$GLOBAL_REGION") || return
  while read -r name; do
    [ -z "$name" ] && continue
    count=$((count + 1))
    n=$(aws_json $C10 "$G" budgets describe-notifications-for-budget --account-id "$ACCOUNT_ID" --budget-name "$name" --region "$GLOBAL_REGION") || continue
    pass_or_fail "$(jq '(.Notifications // []) | length > 0' <<<"$n")" $C10 "$G" "budget:$name" "budget with alerts" "budget has no alert, so nobody is told when it is exceeded (ASSB ACCT.10)" WARN
  done < <(jq -r '.Budgets[]?.BudgetName' <<<"$j")
  [ "$count" = 0 ] && emit $C10 FAIL "$G" budgets "no AWS Budgets; unexpected spend (often the first sign of stolen credentials) goes unnoticed. Create a monthly cost budget with an email alert (ASSB ACCT.10)"
}

c10_cost_anomaly() { # ACCT.16: a monitor exists and someone is subscribed to its alerts
  local m s
  m=$(aws_json $C10 "$G" ce get-anomaly-monitors --region "$GLOBAL_REGION") || return
  if [ "$(jq '.AnomalyMonitors | length' <<<"$m")" = 0 ]; then
    emit $C10 FAIL "$G" cost-anomaly "no Cost Anomaly Detection monitor; create one for AWS services (free) (ASSB ACCT.16)"; return
  fi
  s=$(aws_json $C10 "$G" ce get-anomaly-subscriptions --region "$GLOBAL_REGION") || return
  pass_or_fail "$(jq '(.AnomalySubscriptions // []) | any(.Subscribers | length > 0)' <<<"$s")" $C10 "$G" cost-anomaly \
    "Cost Anomaly Detection monitor with alert subscribers: $(jq -r '[.AnomalyMonitors[].MonitorName] | join(", ")' <<<"$m")" \
    "Cost Anomaly Detection monitor exists but no alert subscription, so anomalies are found but nobody is told (ASSB ACCT.16)" WARN
}

c10_trusted_advisor() { # ACCT.12: no open high-risk (red) security recommendations
  local j rc type n found=0
  j=$(EXPECT_ERR="$TRUSTED_ADVISOR_PLAN_RE" aws_json $C10 "$G" trustedadvisor list-recommendations --pillar security --status error --region "$GLOBAL_REGION"); rc=$?
  if [ "$rc" -eq 2 ]; then
    emit $C10 INFO "$G" trusted-advisor "Trusted Advisor API needs a Business or higher support plan; review the free core checks in the console instead (ASSB ACCT.12)"; return
  fi
  [ "$rc" -ne 0 ] && return
  while IFS="$SEP" read -r type n; do
    [ -z "$type" ] && continue
    found=1
    emit $C10 FAIL "$G" "trusted-advisor:$type" "high-risk Trusted Advisor security recommendation, $n resources affected (ASSB ACCT.12)"
  done < <(rows '.recommendationSummaries[] | [.name, (.resourcesAggregates.errorCount // 0)]' <<<"$j")
  [ "$found" = 0 ] && emit $C10 PASS "$G" trusted-advisor "no high-risk Trusted Advisor security recommendations (ASSB ACCT.12)"
}

c10_global() {
  c10_contact
  c10_budgets
  c10_cost_anomaly
  c10_trusted_advisor
}

c10_region() { # WKLD.15: share of instances and databases deployed by CloudFormation or CDK (a rough IaC signal)
  local R="$1" j counts total=0 managed=0 t m
  if j=$(ec2_instances $C10 "$R"); then
    counts=$(jq -r --arg k "$STACK_TAG" '[.Reservations[].Instances[] | select(.State.Name != "terminated")] | "\(length) \([.[] | select(any(.Tags[]?; .Key == $k))] | length)"' <<<"$j")
    read -r t m <<<"$counts"; total=$((total + t)); managed=$((managed + m))
  fi
  if j=$(rds_instances $C10 "$R"); then
    counts=$(jq -r --arg k "$STACK_TAG" '.DBInstances | "\(length) \([.[] | select(any(.TagList[]?; .Key == $k))] | length)"' <<<"$j")
    read -r t m <<<"$counts"; total=$((total + t)); managed=$((managed + m))
  fi
  [ "$total" -gt 0 ] && emit $C10 INFO "$R" iac-coverage "$managed of $total EC2 instances and RDS databases carry the CloudFormation stack tag; the rest were likely created by hand or another tool (ASSB WKLD.15)"
}
