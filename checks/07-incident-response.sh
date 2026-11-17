# Control 7: AWS Security Incident Response membership, proactive triage, and the contacts AWS uses in an incident.
C7=C7-SIR
TRIAGE_ROLE="AWSServiceRoleForSecurityIncidentResponse_Triage"
TRIAGE_RULE_OWNER="triage.security-ir.amazonaws.com"
CONTACT_TYPES="SECURITY OPERATIONS BILLING"

c7_global() { # alternate contacts (SRA-ACCOUNT-01..03), triage service-linked role (SRA-SECURITYINCIDENTRESPONSE-05)
  local t rc status
  for t in $CONTACT_TYPES; do
    EXPECT_ERR='ResourceNotFoundException' aws_json $C7 "$G" account get-alternate-contact --alternate-contact-type "$t" --region "$GLOBAL_REGION" >/dev/null; rc=$?
    [ "$rc" -eq 1 ] && continue
    status=WARN; [ "$t" = SECURITY ] && status=FAIL
    pass_or_fail "$([ "$rc" -eq 0 ] && echo true)" $C7 "$G" "contact:$t" "alternate contact set" \
      "no $t alternate contact; AWS has nobody to reach about $(tr '[:upper:]' '[:lower:]' <<<"$t") issues (SRA-ACCOUNT-0x)" "$status"
  done
  EXPECT_ERR='NoSuchEntity' aws_json $C7 "$G" iam get-role --role-name "$TRIAGE_ROLE" >/dev/null; rc=$?
  [ "$rc" -ne 1 ] && pass_or_fail "$([ "$rc" -eq 0 ] && echo true)" $C7 "$G" triage-role "$TRIAGE_ROLE exists" "$TRIAGE_ROLE missing; proactive triage cannot run (SRA-SECURITYINCIDENTRESPONSE-05)" WARN
}

c7_triage_rules() { # region -> SRA-SECURITYINCIDENTRESPONSE-07
  local R="$1" j
  j=$(aws_json $C7 "$R" events list-rules --region "$R") || return
  jq -r --arg owner "$TRIAGE_RULE_OWNER" '[.Rules[] | select(.ManagedBy == $owner)] as $r
    | if ($r | length) == 0 then "none" elif all($r[]; .State == "ENABLED") then "ok" else ([$r[] | select(.State != "ENABLED") | .Name] | join(",")) end' <<<"$j"
}

c7_region() { # membership (SRA-SECURITYINCIDENTRESPONSE-02), triage opt-in (03)
  local R="$1" j m id status triage rules
  j=$(EXPECT_ERR="$NOT_AVAILABLE_RE" aws_json $C7 "$R" security-ir list-memberships --region "$R") || return
  while IFS="$SEP" read -r id status; do
    [ -z "$id" ] && continue
    pass_or_fail "$([ "$status" = Active ] && echo true)" $C7 "$R" "membership:$id" "status $status" "membership status $status (SRA-SECURITYINCIDENTRESPONSE-02)"
    m=$(aws_json $C7 "$R" security-ir get-membership --membership-id "$id" --region "$R") || continue
    triage=$(jq '[.optInFeatures[]? | select(.featureName == "Triage" and .isEnabled)] | length > 0' <<<"$m")
    pass_or_fail "$triage" $C7 "$R" "membership:$id/triage" "proactive response (triage) on" "proactive response (triage) off (SRA-SECURITYINCIDENTRESPONSE-03)"
    rules=$(c7_triage_rules "$R")
    [ -n "$rules" ] && pass_or_fail "$([ "$rules" = ok ] && echo true)" $C7 "$R" triage-rules "managed triage EventBridge rules enabled" "managed triage EventBridge rules: $rules (SRA-SECURITYINCIDENTRESPONSE-07)"
  done < <(rows '.items[] | [.membershipId, (.membershipStatus // "")]' <<<"$j")
}

c7_summary() {
  awk -F'\t' -v c="$C7" '$1 == c && $4 ~ /^membership:/ { f = 1 } END { exit !f }' "$OUT_DIR"/findings-*.tsv \
    || emit $C7 FAIL "$G" security-ir "no AWS Security Incident Response membership found in scanned Regions (SRA-SECURITYINCIDENTRESPONSE-02)"
}
