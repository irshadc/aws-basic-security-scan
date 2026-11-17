#!/bin/bash
# Gets temporary read-only AWS credentials, then runs the baseline scan (or another script) with them.
# Credentials stay in this process's environment only; nothing is written to the AWS config files.
#
# How credentials are obtained depends on the base profile's identity:
#   IAM user      -> sts get-federation-token capped by ReadOnlyAccess.
#                    Federation-token sessions cannot call IAM APIs, so control 1 checks report ERROR.
#   Role session  -> AWS refuses GetFederationToken for session credentials (SSO, assumed roles).
#                    Set READONLY_ROLE_ARN to a role you can assume; the session is capped by ReadOnlyAccess.
#   ALLOW_BASE_CREDENTIALS=1 -> use the base profile unchanged. scan.sh only makes read calls.
#
# Usage: ./run-readonly.sh [script]            (default script: ./scan.sh)
# Env:   BASE_PROFILE (default: default), DURATION seconds (default: 3600), READONLY_ROLE_ARN, ALLOW_BASE_CREDENTIALS
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BASE_PROFILE="${BASE_PROFILE:-default}"
DURATION="${DURATION:-3600}"
READONLY_POLICY_ARN="arn:aws:iam::aws:policy/ReadOnlyAccess"
SESSION_NAME="ReadOnlySession"
TARGET="${1:-$SCRIPT_DIR/scan.sh}"

export_credentials() { # <sts response JSON>
  AWS_ACCESS_KEY_ID=$(jq -r '.Credentials.AccessKeyId' <<<"$1")
  AWS_SECRET_ACCESS_KEY=$(jq -r '.Credentials.SecretAccessKey' <<<"$1")
  AWS_SESSION_TOKEN=$(jq -r '.Credentials.SessionToken' <<<"$1")
  export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
  unset AWS_PROFILE
  echo "Read-only credentials valid until $(jq -r '.Credentials.Expiration' <<<"$1")"
}

REGION=$(aws configure get region --profile "$BASE_PROFILE" || true)
CALLER_ARN=$(aws sts get-caller-identity --profile "$BASE_PROFILE" --query Arn --output text)
echo "Base identity: $CALLER_ARN"

if [[ "$CALLER_ARN" == *":user/"* ]]; then
  echo "Requesting federated read-only credentials..."
  CREDS=$(aws sts get-federation-token --name "$SESSION_NAME" --policy-arns "arn=$READONLY_POLICY_ARN" \
    --duration-seconds "$DURATION" --profile "$BASE_PROFILE" --output json)
  export_credentials "$CREDS"
  echo "WARNING: federation-token sessions cannot call IAM, so control 1 checks will show ERROR." >&2
elif [ -n "${READONLY_ROLE_ARN:-}" ]; then
  echo "Assuming $READONLY_ROLE_ARN with a ReadOnlyAccess session policy..."
  CREDS=$(aws sts assume-role --role-arn "$READONLY_ROLE_ARN" --role-session-name "$SESSION_NAME" \
    --policy-arns "arn=$READONLY_POLICY_ARN" --duration-seconds "$DURATION" --profile "$BASE_PROFILE" --output json)
  export_credentials "$CREDS"
elif [ "${ALLOW_BASE_CREDENTIALS:-0}" = 1 ]; then
  echo "WARNING: running with base profile '$BASE_PROFILE' unrestricted. scan.sh only makes read calls." >&2
  export AWS_PROFILE="$BASE_PROFILE"
else
  echo "ERROR: $CALLER_ARN is a role session, and AWS does not allow GetFederationToken with session credentials." >&2
  echo "Set READONLY_ROLE_ARN=<read-only role you can assume>, or ALLOW_BASE_CREDENTIALS=1 to use this profile as-is." >&2
  exit 1
fi

if [ -n "$REGION" ]; then export AWS_DEFAULT_REGION="$REGION"; fi
aws sts get-caller-identity --output json
"$TARGET"
