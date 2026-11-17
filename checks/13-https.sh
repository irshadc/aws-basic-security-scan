# Control 13 (phase 3): public web endpoints accept HTTPS only, with a current TLS policy.
# API Gateway and Lambda function URLs are HTTPS-only by design, so they are not checked here.
# AWS Startup Security Baseline: WKLD.13.
C13=C13-HTTPS
register_component 13 $C13 "13. HTTPS on public endpoints"
# Load balancer TLS policies that allow only TLS 1.2 or later.
CURRENT_ELB_TLS_RE='TLS13|TLS-1-2|FS-1-2'
CURRENT_CLOUDFRONT_TLS_RE='^TLSv1\.2'

c13_cloudfront() { # viewer protocol on every cache behavior, and minimum TLS version for custom domains
  local j id name policies tls default_cert
  j=$(distributions $C13) || return
  while IFS="$SEP" read -r id name policies tls default_cert; do
    [ -z "$id" ] && continue
    pass_or_fail "$([[ ",$policies," != *",allow-all,"* ]] && echo true)" $C13 "$G" "cloudfront:$id" "viewers redirected to or limited to HTTPS ($name)" \
      "a cache behavior allows plain HTTP ($name); set ViewerProtocolPolicy to redirect-to-https (ASSB WKLD.13)"
    if [ "$default_cert" != true ] && [[ ! "$tls" =~ $CURRENT_CLOUDFRONT_TLS_RE ]]; then
      emit $C13 WARN "$G" "cloudfront:$id/tls" "minimum viewer TLS is $tls ($name); use TLSv1.2_2021 or later (ASSB WKLD.13)"
    fi
  done < <(rows '.DistributionList.Items[]? | [.Id, ((.Aliases.Items // [.DomainName]) | join(",")),
      ([.DefaultCacheBehavior.ViewerProtocolPolicy, (.CacheBehaviors.Items[]?.ViewerProtocolPolicy)] | unique | join(",")),
      (.ViewerCertificate.MinimumProtocolVersion // ""), (.ViewerCertificate.CloudFrontDefaultCertificate // false)]' <<<"$j")
}

c13_load_balancers() { # ALB and NLB listeners: HTTP must redirect to HTTPS; TLS listeners use a current policy
  local R="$1" j l arn name port proto redirect policy
  j=$(load_balancers $C13 "$R") || return
  while IFS="$SEP" read -r arn name; do
    [ -z "$arn" ] && continue
    l=$(aws_json $C13 "$R" elbv2 describe-listeners --load-balancer-arn "$arn" --region "$R") || continue
    while IFS="$SEP" read -r port proto redirect policy; do
      [ -z "$port" ] && continue
      case "$proto" in
        HTTP) pass_or_fail "$redirect" $C13 "$R" "lb:$name:$port" "HTTP listener redirects to HTTPS" "HTTP listener serves traffic without redirecting to HTTPS (ASSB WKLD.13)" ;;
        HTTPS|TLS) pass_or_fail "$([[ "$policy" =~ $CURRENT_ELB_TLS_RE ]] && echo true)" $C13 "$R" "lb:$name:$port" "$proto listener with policy $policy" \
          "$proto listener uses $policy, which allows TLS older than 1.2; switch to ELBSecurityPolicy-TLS13-1-2-2021-06 (ASSB WKLD.13)" WARN ;;
      esac
    done < <(rows '.Listeners[] | [.Port, .Protocol,
        (any(.DefaultActions[]; .Type == "redirect" and .RedirectConfig.Protocol == "HTTPS")), (.SslPolicy // "")]' <<<"$l")
  done < <(rows '.LoadBalancers[] | select(.Scheme == "internet-facing") | [.LoadBalancerArn, .LoadBalancerName]' <<<"$j")
}

c13_classic_lbs() { # Classic Load Balancers cannot redirect, so a public HTTP listener serves plain HTTP
  local R="$1" j name port
  j=$(classic_lbs $C13 "$R") || return
  while IFS="$SEP" read -r name port; do
    [ -n "$name" ] && emit $C13 FAIL "$R" "classic-lb:$name:$port" "plain HTTP listener; Classic Load Balancers cannot redirect to HTTPS, so migrate to an ALB (ASSB WKLD.13)"
  done < <(rows '.LoadBalancerDescriptions[] | select(.Scheme == "internet-facing") | .LoadBalancerName as $n
      | .ListenerDescriptions[] | select(.Listener.Protocol == "HTTP") | [$n, .Listener.LoadBalancerPort]' <<<"$j")
}

c13_global() {
  c13_cloudfront
}

c13_region() {
  c13_load_balancers "$1"
  c13_classic_lbs "$1"
}
