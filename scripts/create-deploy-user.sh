#!/usr/bin/env bash
# One-off: create a least-privilege IAM user for local CDK deploys of skylight-mcp.
# Run with the root-session profile (skylight-mcp). Writes the new access key straight
# into a separate AWS CLI profile (skylight-deploy) and never prints the secret.
#
# The user can only (a) assume the CDK bootstrap roles and (b) read the bootstrap
# version parameter / stack status. CDK bootstrap itself (which creates those roles)
# is a separate one-off step done with the admin session.
set -euo pipefail

ADMIN_PROFILE="${ADMIN_PROFILE:-skylight-mcp}"
DEPLOY_PROFILE="${DEPLOY_PROFILE:-skylight-deploy}"
REGION="us-east-2"
USER_NAME="skylight-mcp-deploy"
QUALIFIER="hnb659fds" # CDK default bootstrap qualifier

export AWS_PROFILE="$ADMIN_PROFILE" AWS_REGION="$REGION" AWS_PAGER=""
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

if aws iam get-user --user-name "$USER_NAME" >/dev/null 2>&1; then
  echo "User $USER_NAME already exists; leaving it and its keys alone." >&2
  exit 1
fi

aws iam create-user --user-name "$USER_NAME" \
  --tags Key=project,Value=skylight-mcp >/dev/null

POLICY="$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AssumeCdkBootstrapRoles",
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::${ACCOUNT}:role/cdk-${QUALIFIER}-*-${ACCOUNT}-${REGION}"
    },
    {
      "Sid": "ReadBootstrapVersion",
      "Effect": "Allow",
      "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:${REGION}:${ACCOUNT}:parameter/cdk-bootstrap/${QUALIFIER}/version"
    },
    {
      "Sid": "ReadStackStatus",
      "Effect": "Allow",
      "Action": ["cloudformation:DescribeStacks", "cloudformation:GetTemplate"],
      "Resource": "arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/Skylight*/*"
    }
  ]
}
EOF
)"
aws iam put-user-policy --user-name "$USER_NAME" \
  --policy-name skylight-mcp-cdk-deploy --policy-document "$POLICY"

# Create the key and write it directly to the CLI profile; nothing is echoed.
KEY_JSON="$(aws iam create-access-key --user-name "$USER_NAME" --output json)"
AK="$(printf '%s' "$KEY_JSON" | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["AccessKey"]["AccessKeyId"])')"
SK="$(printf '%s' "$KEY_JSON" | python3 -I -c 'import sys,json;print(json.load(sys.stdin)["AccessKey"]["SecretAccessKey"])')"
unset KEY_JSON
unset AWS_PROFILE
aws configure set aws_access_key_id "$AK" --profile "$DEPLOY_PROFILE"
aws configure set aws_secret_access_key "$SK" --profile "$DEPLOY_PROFILE"
aws configure set region "$REGION" --profile "$DEPLOY_PROFILE"
unset AK SK

echo "Created $USER_NAME in account $ACCOUNT; profile '$DEPLOY_PROFILE' configured."
