# Control 9 (phase 3): who can do what. Root use, console users and MFA, full-admin permissions,
# the roles EC2 instances run with, and resources shared outside the account.
# AWS Startup Security Baseline: ACCT.02, ACCT.03, ACCT.04, ACCT.05, WKLD.01, WKLD.02.
C9=C9-IDENTITY
register_component 9 $C9 "9. Identity and permissions"
ADMIN_POLICY_ARN="arn:aws:iam::aws:policy/AdministratorAccess"
ROOT_RECENT_DAYS=90
CREDENTIAL_REPORT_TRIES=10
CREDENTIAL_REPORT_WAIT_SECONDS=2
SSO_ROLE_PATH="/aws-reserved/sso.amazonaws.com/"
# Services whose roles run application code. A full-admin role trusted by one of these is a workload with admin.
WORKLOAD_SERVICES_RE='^(ec2|lambda|ecs-tasks|eks|batch|codebuild|states|glue|sagemaker|apprunner|build\.apprunner)\.amazonaws\.com$'
admin_profiles_file() { echo "$OUT_DIR/cache/admin-instance-profiles.txt"; }   # written by c9_global, read per Region

# jq: users, groups and roles with full admin, from get-account-authorization-details.
# Full admin = AdministratorAccess, or any attached or inline policy with Allow "*" on "*".
# Output rows: kind, name, path, trusted services, reasons, instance profile ARNs (comma-joined).
ADMIN_ENTITIES_JQ='
  def full_admin: [.Statement] | flatten | any(.[];
    .Effect == "Allow" and ([.Action] | flatten | index("*")) and ([.Resource] | flatten | index("*")));
  ([.Policies[] | select(any(.PolicyVersionList[]; .IsDefaultVersion and (.Document | full_admin))) | .Arn]) as $custom
  | def reasons(inline): [(.AttachedManagedPolicies[]? | select(.PolicyArn == $admin or (.PolicyArn as $a | $custom | index($a))) | .PolicyName),
      (inline[]? | select(.PolicyDocument | full_admin) | "inline policy \(.PolicyName)")];
  ([.GroupDetailList[] | select(reasons(.GroupPolicyList) | length > 0) | .GroupName]) as $admin_groups
  | (.UserDetailList[] | {kind: "user", name: .UserName, path: .Path, services: "", profiles: "",
       why: (reasons(.UserPolicyList) + [.GroupList[]? | select(. as $g | $admin_groups | index($g)) | "group \(.)"])}),
    (.RoleDetailList[] | {kind: "role", name: .RoleName, path: .Path, why: reasons(.RolePolicyList),
       services: ([.AssumeRolePolicyDocument.Statement[]? | .Principal.Service? // empty] | flatten | join(",")),
       profiles: ([.InstanceProfileList[]?.Arn] | join(","))})
  | select(.why | length > 0) | [.kind, .name, .path, .services, (.why | join(", ")), .profiles]'

c9_admin_permissions() { # ACCT.04: no person or workload holds full admin without a reason
  local j kind name path services why profiles workload p found=0
  j=$(iam_authorization_details $C9) || return
  mkdir -p "$OUT_DIR/cache"; : > "$(admin_profiles_file)"
  while IFS="$SEP" read -r kind name path services why profiles; do
    [ -z "$name" ] && continue
    found=1
    for p in ${profiles//,/ }; do printf '%s\n' "$p$SEP$name$SEP$why" >> "$(admin_profiles_file)"; done
    if [ "$kind" = user ]; then
      emit $C9 FAIL "$G" "user:$name" "IAM user with full admin ($why); give people access through IAM Identity Center permission sets (ASSB ACCT.04)"
    elif [ "$path" = "$SSO_ROLE_PATH" ]; then
      emit $C9 INFO "$G" "role:$name" "IAM Identity Center admin permission set ($why); keep its assignments to a few named admins (ASSB ACCT.04)"
    else
      workload=$(tr ',' '\n' <<<"$services" | grep -E "$WORKLOAD_SERVICES_RE" | tr '\n' ',' | sed 's/,$//')
      if [ -n "$workload" ]; then
        emit $C9 FAIL "$G" "role:$name" "workload role with full admin ($why), assumable by $workload; replace with a least-privilege policy (ASSB ACCT.04, WKLD.01)"
      else
        emit $C9 WARN "$G" "role:$name" "role with full admin ($why)${services:+, assumable by $services}; confirm only admins and break-glass users can assume it (ASSB ACCT.04)"
      fi
    fi
  done < <(jq -r --arg admin "$ADMIN_POLICY_ARN" "$ADMIN_ENTITIES_JQ"' | map(tostring) | join("\u001f")' <<<"$j")
  [ "$found" = 0 ] && emit $C9 PASS "$G" admin-permissions "no IAM user, group or role has full admin (ASSB ACCT.04)"
}

c9_credential_report() { # -> report CSV on stdout
  local j i
  for ((i = 0; i < CREDENTIAL_REPORT_TRIES; i++)); do
    j=$(aws_json $C9 "$G" iam generate-credential-report) || return 1
    [ "$(jq -r '.State' <<<"$j")" = COMPLETE ] && break
    sleep "$CREDENTIAL_REPORT_WAIT_SECONDS"
  done
  j=$(aws_json $C9 "$G" iam get-credential-report) || return 1
  jq -r '.Content | @base64d' <<<"$j"
}

c9_sign_in() { # ACCT.02 root use, ACCT.03 console users, ACCT.05 MFA
  local csv user pw last mfa days users=0
  csv=$(c9_credential_report) || return
  while IFS="$SEP" read -r user pw last mfa; do
    [ -z "$user" ] && continue
    days=""
    [[ "$last" == 20* ]] && days=$(jq -rn --arg d "$last" "$JQ_AGE"' $d | age_days')
    if [ "$user" = "<root_account>" ]; then
      pass_or_fail "$([ -z "$days" ] || [ "$days" -gt "$ROOT_RECENT_DAYS" ] && echo true)" $C9 "$G" root-sign-in \
        "root user not signed in within $ROOT_RECENT_DAYS days (last: ${last%%T*})" \
        "root user signed in $days days ago (${last%%T*}); use root only for the few tasks that need it (ASSB ACCT.02)" WARN
      continue
    fi
    [ "$pw" = true ] || continue
    users=$((users + 1))
    if [ "$mfa" = true ]; then
      emit $C9 WARN "$G" "user:$user/console" "console password with MFA, last sign-in ${last%%T*}; move people to IAM Identity Center (ASSB ACCT.03)"
    else
      emit $C9 FAIL "$G" "user:$user/console" "console password without MFA, last sign-in ${last%%T*}; turn on MFA now (ASSB ACCT.05)"
    fi
  done < <(awk -F, -v OFS="$SEP" 'NR == 1 { for (i = 1; i <= NF; i++) col[$i] = i; next }
      { print $col["user"], $col["password_enabled"], $col["password_last_used"], $col["mfa_active"] }' <<<"$csv")
  [ "$users" = 0 ] && emit $C9 PASS "$G" console-users "no IAM users with a console password (ASSB ACCT.03, ACCT.05)"
}

c9_global() {
  c9_sign_in
  c9_admin_permissions
}

c9_instance_roles() { # WKLD.01: every instance runs with a role, and no instance role has full admin
  local R="$1" j id name state profile role why
  if [ ! -f "$(admin_profiles_file)" ]; then
    emit $C9 ERROR "$R" instance-roles "IAM authorization details were not read, so instance roles were not checked"; return
  fi
  j=$(ec2_instances $C9 "$R") || return
  while IFS="$SEP" read -r id name state profile; do
    [ -z "$id" ] && continue
    if [ -z "$profile" ]; then
      emit $C9 WARN "$R" "ec2:$id${name:+ ($name)}" "no instance role ($state); if the software calls AWS, it is likely using stored keys. Attach a role (ASSB WKLD.01)"
      continue
    fi
    role=""; why=""
    IFS="$SEP" read -r _ role why < <(awk -F"$SEP" -v p="$profile" '$1 == p' "$(admin_profiles_file)" 2>/dev/null)
    pass_or_fail "$([ -z "$role" ] && echo true)" $C9 "$R" "ec2:$id${name:+ ($name)}" "instance role without full admin (${profile##*/})" \
      "instance role $role has full admin ($why), $state; replace with ReadOnlyAccess or a least-privilege policy (ASSB ACCT.04, WKLD.01)"
  done < <(rows '.Reservations[].Instances[] | select(.State.Name != "terminated")
      | [.InstanceId, ([.Tags[]? | select(.Key == "Name") | .Value][0] // ""), .State.Name, (.IamInstanceProfile.Arn // "")]' <<<"$j")
}

c9_external_access() { # WKLD.02: active IAM Access Analyzer findings for resources shared outside the account
  local R="$1" j arn type n found=0
  j=$(access_analyzers $C9 "$R") || return
  # EXTERNAL_ANALYZER_TYPES is defined in 01-access-keys.sh, which also reports a missing analyzer.
  arn=$(jq -r --arg t "^($EXTERNAL_ANALYZER_TYPES)$" '[.analyzers[] | select(.status == "ACTIVE" and (.type | test($t))) | .arn][0] // ""' <<<"$j")
  [ -z "$arn" ] && return
  j=$(aws_json $C9 "$R" accessanalyzer list-findings-v2 --analyzer-arn "$arn" --filter '{"status":{"eq":["ACTIVE"]}}' --region "$R") || return
  while IFS="$SEP" read -r type n; do
    [ -z "$type" ] && continue
    found=1
    emit $C9 WARN "$R" "external-access:$type" "$n active Access Analyzer findings: resources shared outside the account. Archive the intended ones and remove the rest (ASSB WKLD.02)"
  done < <(rows '.findings | group_by(.resourceType)[] | [.[0].resourceType, length]' <<<"$j")
  [ "$found" = 0 ] && emit $C9 PASS "$R" external-access "no active external access findings (ASSB WKLD.02)"
}

c9_region() {
  c9_instance_roles "$1"
  c9_external_access "$1"
}

c9_summary() { # how many instances run with a full-admin role, across all Regions
  local admin total
  admin=$(awk -F'\t' -v c="$C9" '$1 == c && $2 == "FAIL" && $4 ~ /^ec2:/' "$OUT_DIR"/findings-*.tsv | wc -l | tr -d ' ')
  total=$(awk -F'\t' -v c="$C9" '$1 == c && $4 ~ /^ec2:/' "$OUT_DIR"/findings-*.tsv | wc -l | tr -d ' ')
  pass_or_fail "$([ "$admin" = 0 ] && echo true)" $C9 "$G" ec2-admin-roles "none of $total instances has a full-admin instance role" \
    "$admin of $total instances have a full-admin instance role; see the ec2: findings (ASSB ACCT.04, WKLD.01)"
}
