# Control 5: AWS WAF on public applications, web ACL logging, Shield Advanced.
# Uses the public-endpoint inventory from 02-public-endpoints.sh.
C5=C5-WAF
CLOUDFRONT_FRONT="front it with CloudFront + WAF"

waf_acl_for() { # region resource-arn -> web ACL name, or empty
  local j
  j=$(aws_json $C5 "$1" wafv2 get-web-acl-for-resource --resource-arn "$2" --region "$1") || return 1
  jq -r '.WebACL.Name // ""' <<<"$j"
}

report_acl() { # region resource acl-name ref
  pass_or_fail "$([ -n "$3" ] && echo true)" $C5 "$1" "$2" "web ACL $3" "no AWS WAF web ACL ($4)"
}

c5_acl_logging() { # region scope -> SRA-WAF-09
  local R="$1" j rc arn name
  j=$(aws_json $C5 "$R" wafv2 list-web-acls --scope "$2" --region "$R") || return
  while IFS="$SEP" read -r arn name; do
    [ -z "$arn" ] && continue
    EXPECT_ERR='WAFNonexistentItemException' aws_json $C5 "$R" wafv2 get-logging-configuration --resource-arn "$arn" --region "$R" >/dev/null; rc=$?
    [ "$rc" -eq 1 ] && continue
    pass_or_fail "$([ "$rc" -eq 0 ] && echo true)" $C5 "$R" "web-acl:$name" "logging enabled" "web ACL logging off (SRA-WAF-09)"
  done < <(rows '.WebACLs[] | [.ARN, .Name]' <<<"$j")
}

c5_global() { # CloudFront (SRA-WAF-01), Shield Advanced (SRA-SHIELD-01)
  local j rc id domain acl aliases
  if j=$(distributions $C5); then
    while IFS="$SEP" read -r id domain acl aliases; do
      [ -z "$id" ] && continue
      pass_or_fail "$([ -n "$acl" ] && echo true)" $C5 "$G" "cloudfront:$id" "web ACL attached" "no AWS WAF web ACL (${aliases:-$domain}) (SRA-WAF-01)"
    done < <(rows '.DistributionList.Items[]? | [.Id, .DomainName, (.WebACLId // ""), ((.Aliases.Items // []) | join(","))]' <<<"$j")
  fi
  c5_acl_logging "$GLOBAL_REGION" CLOUDFRONT
  j=$(EXPECT_ERR='ResourceNotFoundException' aws_json $C5 "$G" shield get-subscription-state --region "$GLOBAL_REGION"); rc=$?
  [ "$rc" -eq 0 ] && emit $C5 INFO "$G" shield-advanced "Shield Advanced subscription $(jq -r '.SubscriptionState' <<<"$j") (paid; consider for business-critical public apps) (SRA-SHIELD-01)"
}

c5_load_balancers_and_apis() { # SRA-WAF-02, 03
  local R="$1" j s arn name type id stage acl proto fn
  if j=$(load_balancers $C5 "$R"); then
    while IFS="$SEP" read -r arn name type; do
      [ -z "$arn" ] && continue
      if [ "$type" != application ]; then emit $C5 WARN "$R" "$type-lb:$name" "AWS WAF cannot attach to a $type load balancer; $CLOUDFRONT_FRONT or justify"; continue; fi
      acl=$(waf_acl_for "$R" "$arn") && report_acl "$R" "alb:$name" "$acl" SRA-WAF-02
    done < <(rows '.LoadBalancers[] | select(.Scheme == "internet-facing") | [.LoadBalancerArn, .LoadBalancerName, .Type]' <<<"$j")
  fi
  if j=$(classic_lbs $C5 "$R"); then
    jq -r '.LoadBalancerDescriptions[] | select(.Scheme == "internet-facing") | .LoadBalancerName' <<<"$j" \
      | while read -r name; do [ -n "$name" ] && emit $C5 WARN "$R" "classic-lb:$name" "AWS WAF cannot attach to a Classic Load Balancer; migrate to ALB"; done
  fi
  if j=$(rest_apis $C5 "$R"); then
    while IFS="$SEP" read -r id name; do
      [ -z "$id" ] && continue
      s=$(aws_json $C5 "$R" apigateway get-stages --rest-api-id "$id" --region "$R") || continue
      while IFS="$SEP" read -r stage acl; do
        [ -n "$stage" ] && report_acl "$R" "rest-api:$name/$stage" "$acl" SRA-WAF-03
      done < <(rows '.item[] | [.stageName, (.webAclArn // "" | split("/") | .[-2] // "")]' <<<"$s")
    done < <(rows '.items[] | select((.endpointConfiguration.types // []) | index("PRIVATE") | not) | [.id, .name]' <<<"$j")
  fi
  if j=$(http_apis $C5 "$R"); then
    while IFS="$SEP" read -r id name proto; do
      [ -n "$id" ] && emit $C5 WARN "$R" "$proto-api:$name ($id)" "$proto APIs do not support AWS WAF directly; $CLOUDFRONT_FRONT"
    done < <(rows '.Items[] | [.ApiId, .Name, .ProtocolType]' <<<"$j")
  fi
  while IFS="$SEP" read -r fn _; do
    [ -n "$fn" ] && emit $C5 WARN "$R" "lambda-url:$fn" "function URLs do not support AWS WAF directly; $CLOUDFRONT_FRONT"
  done < <(function_url_rows $C5 "$R")
}

c5_other_services() { # Cognito (SRA-WAF-05), AppSync (SRA-WAF-04), App Runner (SRA-WAF-06)
  local R="$1" j id name arn acl
  if j=$(aws_json $C5 "$R" cognito-idp list-user-pools --max-results 60 --region "$R"); then
    while IFS="$SEP" read -r id name; do
      [ -z "$id" ] && continue
      acl=$(waf_acl_for "$R" "arn:aws:cognito-idp:$R:$ACCOUNT_ID:userpool/$id") || continue
      pass_or_fail "$([ -n "$acl" ] && echo true)" $C5 "$R" "cognito:$name" "web ACL $acl" "no AWS WAF web ACL on the user pool's public sign-in endpoints (SRA-WAF-05)" WARN
    done < <(rows '.UserPools[] | [.Id, .Name]' <<<"$j")
  fi
  if j=$(EXPECT_ERR="$NOT_AVAILABLE_RE" aws_json $C5 "$R" appsync list-graphql-apis --region "$R"); then
    while IFS="$SEP" read -r name acl; do
      [ -n "$name" ] && report_acl "$R" "appsync:$name" "$acl" SRA-WAF-04
    done < <(rows '.graphqlApis[] | select(.visibility != "PRIVATE") | [.name, (.wafWebAclArn // "" | split("/") | .[-2] // "")]' <<<"$j")
  fi
  if j=$(EXPECT_ERR="$NOT_AVAILABLE_RE" aws_json $C5 "$R" apprunner list-services --region "$R"); then
    while IFS="$SEP" read -r arn name; do
      [ -z "$arn" ] && continue
      acl=$(waf_acl_for "$R" "$arn") && report_acl "$R" "apprunner:$name" "$acl" SRA-WAF-06
    done < <(rows '.ServiceSummaryList[] | [.ServiceArn, .ServiceName]' <<<"$j")
  fi
}

c5_region() {
  c5_load_balancers_and_apis "$1"
  c5_other_services "$1"
  c5_acl_logging "$1" REGIONAL
}
