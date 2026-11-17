# Control 8 (phase 2): CloudTrail (with its log bucket and S3 data events), AWS Config, VPC flow logs,
# Route 53 Resolver query logs, EBS default encryption.
C8=C8-LOGGING
register_component 8 $C8 "8. Logging and encryption baseline"
AI_CONFIG_TYPES="AWS::Bedrock::DataSource AWS::BedrockAgentCore::BrowserCustom AWS::BedrockAgentCore::CodeInterpreterCustom AWS::BedrockAgentCore::Gateway AWS::BedrockAgentCore::Memory AWS::BedrockAgentCore::Runtime AWS::SageMaker::FeatureGroup AWS::SageMaker::InferenceExperiment AWS::SageMaker::Model AWS::SageMaker::ModelExplainabilityJobDefinition AWS::SageMaker::ModelQualityJobDefinition AWS::SageMaker::MonitoringSchedule AWS::SageMaker::NotebookInstance"

c8_trail_settings() { # <trail JSON> <label>: static settings (SRA-CLOUDTRAIL-02/03/04/05/06)
  local t="$1" label="$2"
  pass_or_fail "$(jq '.IsMultiRegionTrail' <<<"$t")" $C8 "$G" "$label" "multi-Region" "single-Region trail (SRA-CLOUDTRAIL-04)" WARN
  pass_or_fail "$(jq '.LogFileValidationEnabled' <<<"$t")" $C8 "$G" "$label/validation" "log file validation on" "log file validation off (SRA-CLOUDTRAIL-03)"
  pass_or_fail "$(jq 'has("KmsKeyId")' <<<"$t")" $C8 "$G" "$label/kms" "encrypted with KMS" "not encrypted with a KMS key (SRA-CLOUDTRAIL-02)" WARN
  pass_or_fail "$(jq '.IncludeGlobalServiceEvents' <<<"$t")" $C8 "$G" "$label/global-events" "global service events included" "global service events (IAM, STS) excluded (SRA-CLOUDTRAIL-06)"
  pass_or_fail "$(jq 'has("CloudWatchLogsLogGroupArn")' <<<"$t")" $C8 "$G" "$label/cloudwatch" "sends to CloudWatch Logs" "no CloudWatch Logs delivery, so no metric filters or alarms (SRA-CLOUDTRAIL-05)" WARN
}

c8_trail_runtime() { # <trail ARN> <home region> <label>: logging state and event selectors (SRA-CLOUDTRAIL-07/08/14/15)
  local arn="$1" home="$2" label="$3" s e
  if s=$(aws_json $C8 "$home" cloudtrail get-trail-status --name "$arn" --region "$home"); then
    pass_or_fail "$(jq '.IsLogging' <<<"$s")" $C8 "$G" "$label/logging" "logging" "trail is stopped (SRA-CLOUDTRAIL-07)"
    e=$(jq -r '.LatestDeliveryError // ""' <<<"$s")
    [ -n "$e" ] && emit $C8 FAIL "$G" "$label/delivery" "S3 delivery error: $e (SRA-CLOUDTRAIL-08)"
  fi
  s=$(aws_json $C8 "$home" cloudtrail get-event-selectors --trail-name "$arn" --region "$home") || return
  pass_or_fail "$(jq '(any(.EventSelectors[]?; .IncludeManagementEvents and .ReadWriteType == "All"))
      or (any(.AdvancedEventSelectors[]?; any(.FieldSelectors[]; .Field == "eventCategory" and (.Equals // [] | index("Management")))
        and all(.FieldSelectors[]; .Field != "readOnly")))' <<<"$s")" \
    $C8 "$G" "$label/management-events" "all management events (read and write)" "not logging all read and write management events (SRA-CLOUDTRAIL-15)"
  pass_or_fail "$(jq 'any(.AdvancedEventSelectors[]?; any(.FieldSelectors[]; .Field == "resources.type" and any(.Equals[]?; startswith("AWS::Bedrock"))))' <<<"$s")" \
    $C8 "$G" "$label/bedrock-data-events" "Bedrock or AgentCore data events selected" "no Bedrock or AgentCore data events; model invocations are not audited (SRA-CLOUDTRAIL-14)" WARN
  pass_or_fail "$(jq 'any(.EventSelectors[]?; any(.DataResources[]?; .Type == "AWS::S3::Object"))
      or any(.AdvancedEventSelectors[]?; any(.FieldSelectors[]; .Field == "resources.type" and any(.Equals[]?; . == "AWS::S3::Object")))' <<<"$s")" \
    $C8 "$G" "$label/s3-data-events" "S3 object data events selected" "no S3 data events; reads and deletes of sensitive objects are not audited. Select at least the buckets that hold sensitive data (ASSB WKLD.07)" WARN
}

c8_trail_bucket() { # <trail JSON> <label>: the log bucket is private and keeps old versions (ASSB ACCT.07)
  local t="$1" label="$2" b br j rc
  b=$(jq -r '.S3BucketName // ""' <<<"$t")
  [ -z "$b" ] && return
  j=$(EXPECT_ERR='AccessDenied|NoSuchBucket|AllAccessDisabled' aws_json $C8 "$G" s3api get-bucket-location --bucket "$b" --region "$GLOBAL_REGION"); rc=$?
  if [ "$rc" -eq 2 ]; then
    emit $C8 INFO "$G" "$label/bucket" "log bucket $b is not readable from this account (often a central log-archive account); check its protection there (ASSB ACCT.07)"
    return
  fi
  [ "$rc" -ne 0 ] && return
  br=$(jq -r '.LocationConstraint // "us-east-1" | if . == "EU" then "eu-west-1" else . end' <<<"$j")
  j=$(EXPECT_ERR='NoSuchPublicAccessBlockConfiguration' aws_json $C8 "$br" s3api get-public-access-block --bucket "$b" --region "$br"); rc=$?
  [ "$rc" -ne 1 ] && pass_or_fail "$([ "$rc" -eq 0 ] && jq '[.PublicAccessBlockConfiguration[]] | all' <<<"$j")" $C8 "$G" "$label/bucket-public-access" \
    "log bucket $b blocks all public access" "log bucket $b does not turn on all four bucket-level Block Public Access settings (ASSB ACCT.07)" WARN
  j=$(aws_json $C8 "$br" s3api get-bucket-versioning --bucket "$b" --region "$br") || return
  pass_or_fail "$(jq '.Status == "Enabled"' <<<"$j")" $C8 "$G" "$label/bucket-versioning" "log bucket $b has versioning on" \
    "log bucket $b has versioning off, so deleted or overwritten logs cannot be recovered; turn it on and consider S3 Object Lock (ASSB ACCT.07)" WARN
}

c8_global() {
  local j t arn home name label
  j=$(aws_json $C8 "$G" cloudtrail describe-trails --include-shadow-trails --region "$GLOBAL_REGION") || return
  pass_or_fail "$(jq 'any(.trailList[]; .IsMultiRegionTrail)' <<<"$j")" $C8 "$G" cloudtrail "multi-Region trail exists" "no multi-Region CloudTrail trail; activity in most Regions is not recorded (SRA-CLOUDTRAIL-01/04)"
  while IFS="$SEP" read -r arn home name; do
    [ -z "$arn" ] && continue
    label="trail:$name"
    t=$(jq --arg a "$arn" '[.trailList[] | select(.TrailARN == $a)][0]' <<<"$j")
    [ "$(jq '.IsOrganizationTrail' <<<"$t")" = true ] && label="$label (organization)"
    c8_trail_settings "$t" "$label"
    c8_trail_runtime "$arn" "$home" "$label"
    c8_trail_bucket "$t" "$label"
  done < <(rows '[.trailList[] | {TrailARN, HomeRegion, Name}] | unique_by(.TrailARN)[] | [.TrailARN, .HomeRegion, .Name]' <<<"$j")
}

c8_config() { # region: SRA-CONFIG-01/02/03/10
  local R="$1" j s missing
  j=$(aws_json $C8 "$R" configservice describe-configuration-recorders --region "$R") || return
  if [ "$(jq '.ConfigurationRecorders | length' <<<"$j")" = 0 ]; then emit $C8 FAIL "$R" config "no AWS Config recorder (SRA-CONFIG-01)"; return; fi
  s=$(aws_json $C8 "$R" configservice describe-configuration-recorder-status --region "$R") || return
  pass_or_fail "$(jq 'any(.ConfigurationRecordersStatus[]; .recording)' <<<"$s")" $C8 "$R" config "recorder running" "recorder exists but is stopped (SRA-CONFIG-02)"
  pass_or_fail "$(jq 'any(.ConfigurationRecordersStatus[]; .lastStatus == "SUCCESS")' <<<"$s")" $C8 "$R" config-status "last recording succeeded" "last recording status: $(jq -r '[.ConfigurationRecordersStatus[].lastStatus] | join(",")' <<<"$s") (SRA-CONFIG-03)"
  missing=$(jq -r --arg t "$AI_CONFIG_TYPES" '($t | split(" ")) as $want | [.ConfigurationRecorders[].recordingGroup | 
      if .allSupported then [] elif (.recordingStrategy.useOnly // "") == "EXCLUSION_BY_RESOURCE_TYPES" then ($want - ($want - (.exclusionByResourceTypes.resourceTypes // [])))
      else ($want - (.resourceTypes // [])) end] | min_by(length) | length' <<<"$j")
  pass_or_fail "$([ "$missing" = 0 ] && echo true)" $C8 "$R" config-ai-types "records all Bedrock, AgentCore and SageMaker resource types" "$missing of 13 AI/ML resource types not recorded (SRA-CONFIG-10)" WARN
}

c8_network_logs() { # region: VPC flow logs (SRA-EC2-02), Resolver query logs (SRA-ROUTE53RESOLVER-01)
  local R="$1" v f q vpc default status
  v=$(owned_vpcs $C8 "$R") || return
  f=$(aws_json $C8 "$R" ec2 describe-flow-logs --region "$R") || return
  q=$(EXPECT_ERR="$NOT_AVAILABLE_RE" aws_json $C8 "$R" route53resolver list-resolver-query-log-config-associations --region "$R") || q='{}'
  while IFS="$SEP" read -r vpc default; do
    [ -z "$vpc" ] && continue
    status=FAIL; [ "$default" = true ] && status=WARN
    pass_or_fail "$(jq --arg v "$vpc" 'any(.FlowLogs[]; .ResourceId == $v and .FlowLogStatus == "ACTIVE")' <<<"$f")" $C8 "$R" "vpc:$vpc/flow-logs" "flow logs active" \
      "no active flow log$([ "$default" = true ] && echo ' (default VPC; delete it if unused)') (SRA-EC2-02)" "$status"
    pass_or_fail "$(jq --arg v "$vpc" 'any(.ResolverQueryLogConfigAssociations[]?; .ResourceId == $v and .Status == "ACTIVE")' <<<"$q")" $C8 "$R" "vpc:$vpc/dns-query-logs" "Resolver query logging on" \
      "no Route 53 Resolver query logging (SRA-ROUTE53RESOLVER-01)" WARN
  done < <(rows '.Vpcs[] | [.VpcId, .IsDefault]' <<<"$v")
}

c8_region() {
  local R="$1" j
  c8_config "$R"
  c8_network_logs "$R"
  j=$(aws_json $C8 "$R" ec2 get-ebs-encryption-by-default --region "$R") || return
  pass_or_fail "$(jq '.EbsEncryptionByDefault' <<<"$j")" $C8 "$R" ebs-default-encryption "new EBS volumes encrypted by default" \
    "EBS encryption by default off. Fix: aws ec2 enable-ebs-encryption-by-default --region $R (SRA-EC2-01)"
}
