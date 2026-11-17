# Control 1: remove long-lived access keys, plus root, IAM user, password policy and Access Analyzer hygiene.
C1=C1-KEYS
register_component 1 $C1 "1. Remove long-lived access keys"
PASSWORD_MIN_LENGTH=14     # CIS / Security Hub IAM.15
PASSWORD_MIN_REUSE=24      # CIS / Security Hub IAM.16
EXTERNAL_ANALYZER_TYPES='ACCOUNT|ORGANIZATION'
UNUSED_ANALYZER_TYPES='ACCOUNT_UNUSED_ACCESS|ORGANIZATION_UNUSED_ACCESS'

c1_root() { # SRA-IAM-05
  local j
  j=$(aws_json $C1 "$G" iam get-account-summary) || return
  pass_or_fail "$(jq '.SummaryMap.AccountAccessKeysPresent == 0' <<<"$j")" $C1 "$G" root "no root access keys" "root user has access keys; delete them (SRA-IAM-05)"
  pass_or_fail "$(jq '.SummaryMap.AccountMFAEnabled == 1' <<<"$j")" $C1 "$G" root-mfa "root MFA enabled" "root user has no MFA"
  pass_or_fail "$(jq '(.SummaryMap.AccountSigningCertificatesPresent // 0) == 0' <<<"$j")" $C1 "$G" root-certificates "no root signing certificates" "root user has signing certificates (SRA-IAM-05)"
}

c1_user_keys() { # access keys per IAM user, SRA-IAM-01
  local j k l user key status age last users=0 found=0
  j=$(cached_json $C1 "$G" iam-users iam list-users) || return
  while read -r user; do
    [ -z "$user" ] && continue
    users=$((users + 1))
    k=$(aws_json $C1 "$G" iam list-access-keys --user-name "$user") || continue
    while IFS="$SEP" read -r key status age; do
      [ -z "$key" ] && continue
      found=1
      if [ "$status" != Active ]; then emit $C1 WARN "$G" "user:$user/$key" "inactive key, $age days old; delete it"; continue; fi
      last="never used"
      if l=$(aws_json $C1 "$G" iam get-access-key-last-used --access-key-id "$key"); then
        last=$(jq -r '.AccessKeyLastUsed | if .LastUsedDate then "last used \(.LastUsedDate[0:10]) on \(.ServiceName)" else "never used" end' <<<"$l")
      fi
      emit $C1 FAIL "$G" "user:$user/$key" "active key, $age days old, $last; replace with a role or IAM Identity Center"
    done < <(rows '.AccessKeyMetadata[] | [.AccessKeyId, .Status, ((now - (.CreateDate | sub("\\.[0-9]+"; "") | sub("\\+00:00$"; "Z") | fromdateiso8601)) / 86400 | floor)]' <<<"$k")
  done < <(jq -r '.Users[].UserName' <<<"$j")
  [ "$found" = 0 ] && emit $C1 PASS "$G" iam-user-keys "no IAM user access keys"
  pass_or_fail "$([ "$users" = 0 ] && echo true)" $C1 "$G" iam-users "no IAM users" "$users IAM users; move people to IAM Identity Center and workloads to roles (SRA-IAM-01)" WARN
}

c1_password_policy() { # SRA-IAM-06
  local j rc problems
  j=$(EXPECT_ERR='NoSuchEntity' aws_json $C1 "$G" iam get-account-password-policy); rc=$?
  if [ "$rc" -eq 2 ]; then emit $C1 FAIL "$G" password-policy "no custom password policy; AWS default applies (SRA-IAM-06)"; return; fi
  [ "$rc" -ne 0 ] && return
  problems=$(jq -r --argjson len "$PASSWORD_MIN_LENGTH" --argjson reuse "$PASSWORD_MIN_REUSE" '.PasswordPolicy as $p | [
      (if ($p.MinimumPasswordLength // 0) < $len then "length \($p.MinimumPasswordLength) < \($len)" else empty end),
      (if ($p.PasswordReusePrevention // 0) < $reuse then "reuse prevention \($p.PasswordReusePrevention // 0) < \($reuse)" else empty end),
      ("RequireUppercaseCharacters", "RequireLowercaseCharacters", "RequireNumbers", "RequireSymbols"
        | select($p[.] != true) | "\(.) off")
    ] | join(", ")' <<<"$j")
  pass_or_fail "$([ -z "$problems" ] && echo true)" $C1 "$G" password-policy "meets baseline (length $PASSWORD_MIN_LENGTH, reuse $PASSWORD_MIN_REUSE, all character classes)" "below baseline: $problems (SRA-IAM-06)"
}

c1_global() {
  c1_root
  c1_user_keys
  c1_password_policy
}

c1_region() { # IAM Identity Center instance, Access Analyzer (SRA-ACCESSANALYZER-01/06/07)
  local R="$1" j arn status ext
  if j=$(aws_json $C1 "$R" sso-admin list-instances --region "$R"); then
    while IFS="$SEP" read -r arn status; do
      [ -z "$arn" ] && continue
      emit $C1 PASS "$R" identity-center "IAM Identity Center instance $arn ($status)"
    done < <(rows '.Instances[] | [.InstanceArn, (.Status // "")]' <<<"$j")
  fi
  j=$(access_analyzers $C1 "$R") || return
  ext=$(jq -r --arg t "^($EXTERNAL_ANALYZER_TYPES)$" '[.analyzers[] | select(.status == "ACTIVE" and (.type | test($t))) | .name] | join(",")' <<<"$j")
  pass_or_fail "$([ -n "$ext" ] && echo true)" $C1 "$R" access-analyzer "external access analyzer active: $ext" "no active external access analyzer; create a free one: aws accessanalyzer create-analyzer --analyzer-name external --type ACCOUNT --region $R (SRA-ACCESSANALYZER-01)"
  jq -r --arg t "^($UNUSED_ANALYZER_TYPES)$" '.analyzers[] | select(.status == "ACTIVE" and (.type | test($t))) | .name' <<<"$j" \
    | while read -r n; do [ -n "$n" ] && emit $C1 PASS "$R" unused-access-analyzer "unused access analyzer $n active"; done
}

c1_summary() {
  has_finding $C1 PASS identity-center \
    || emit $C1 WARN "$G" identity-center "no IAM Identity Center instance found; use it for human access instead of IAM users"
  has_finding $C1 PASS unused-access-analyzer \
    || emit $C1 WARN "$G" unused-access-analyzer "no unused access analyzer in any Region; it finds unused roles, keys and permissions (paid) (SRA-ACCESSANALYZER-07)"
}
