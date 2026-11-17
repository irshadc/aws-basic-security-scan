# Control 6: IMDSv2 required on every instance and as the account default. Fix with fix-imdsv2.sh.
C6=C6-IMDS
register_component 6 $C6 "6. Enforce IMDSv2"

c6_region() {
  local R="$1" j id state tokens name label t
  if j=$(ec2_instances $C6 "$R"); then
    while IFS="$SEP" read -r id state tokens name; do
      [ -z "$id" ] && continue
      label="$id${name:+ ($name)}"
      pass_or_fail "$([ "$tokens" = required ] && echo true)" $C6 "$R" "$label" "IMDSv2 required" \
        "HttpTokens=$tokens ($state). Fix: aws ec2 modify-instance-metadata-options --instance-id $id --http-tokens required --region $R"
    done < <(rows '.Reservations[].Instances[] | select(.State.Name != "terminated") | [.InstanceId, .State.Name, (.MetadataOptions.HttpTokens // "unknown"), ([.Tags[]? | select(.Key == "Name") | .Value][0] // "")]' <<<"$j")
  fi
  j=$(aws_json $C6 "$R" ec2 get-instance-metadata-defaults --region "$R") || return
  t=$(jq -r '.AccountLevel.HttpTokens // "not set"' <<<"$j")
  pass_or_fail "$([ "$t" = required ] && echo true)" $C6 "$R" account-default "new instances default to IMDSv2" \
    "account default HttpTokens=$t. Fix: aws ec2 modify-instance-metadata-defaults --http-tokens required --region $R" WARN
}
