#!/usr/bin/env bash
# One-off (admin): let GitHub Actions deploy without stored AWS keys.
#
# Creates (idempotently):
#   - the GitHub Actions OIDC identity provider (token.actions.githubusercontent.com)
#   - role "skylight-mcp-github-deploy", assumable ONLY by a workflow job in
#     logich/skylight-mcp-aws that runs in the "production" environment (whose
#     required reviewer is the owner). Pull requests can never assume it.
#   - an inline policy with the same reach as the skylight-deploy user (assume
#     the CDK bootstrap roles, read the bootstrap version and stack status)
#     plus invoking the live alias for the post-deploy canary.
#
# Prints the role ARN to put in the "production" environment secret
# AWS_DEPLOY_ROLE_ARN (copied to the clipboard; not echoed).
set -euo pipefail
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
REPO="logich/skylight-mcp-aws"
ENVIRONMENT="production"
ROLE="skylight-mcp-github-deploy"
QUALIFIER="hnb659fds"
REGION="us-east-2"
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
PROVIDER_ARN="arn:aws:iam::${ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"

if ! aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$PROVIDER_ARN" >/dev/null 2>&1; then
  # AWS validates GitHub's certificate chain itself; the thumbprint is required
  # by the API but not used for this provider.
  aws iam create-open-id-connect-provider --url https://token.actions.githubusercontent.com \
    --client-id-list sts.amazonaws.com --thumbprint-list ffffffffffffffffffffffffffffffffffffffff \
    --tags Key=project,Value=skylight-mcp >/dev/null
  echo "created the GitHub OIDC provider"
fi

TRUST="$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "${PROVIDER_ARN}" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
        "token.actions.githubusercontent.com:sub": "repo:${REPO}:environment:${ENVIRONMENT}"
      }
    }
  }]
}
EOF
)"

POLICY="$(cat <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    { "Sid": "AssumeCdkBootstrapRoles", "Effect": "Allow", "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::${ACCOUNT}:role/cdk-${QUALIFIER}-*-${ACCOUNT}-${REGION}" },
    { "Sid": "ReadBootstrapVersion", "Effect": "Allow", "Action": "ssm:GetParameter",
      "Resource": "arn:aws:ssm:${REGION}:${ACCOUNT}:parameter/cdk-bootstrap/${QUALIFIER}/version" },
    { "Sid": "ReadStackStatus", "Effect": "Allow",
      "Action": ["cloudformation:DescribeStacks", "cloudformation:GetTemplate"],
      "Resource": "arn:aws:cloudformation:${REGION}:${ACCOUNT}:stack/SkylightMcp/*" },
    { "Sid": "PostDeployCanary", "Effect": "Allow", "Action": "lambda:InvokeFunction",
      "Resource": "arn:aws:lambda:${REGION}:${ACCOUNT}:function:skylight-mcp:live" }
  ]
}
EOF
)"

if aws iam get-role --role-name "$ROLE" >/dev/null 2>&1; then
  aws iam update-assume-role-policy --role-name "$ROLE" --policy-document "$TRUST"
  echo "updated the trust policy of $ROLE"
else
  aws iam create-role --role-name "$ROLE" --assume-role-policy-document "$TRUST" \
    --max-session-duration 3600 --description "skylight-mcp: GitHub Actions deploys (production environment only)" \
    --tags Key=project,Value=skylight-mcp >/dev/null
  echo "created $ROLE"
fi
aws iam put-role-policy --role-name "$ROLE" --policy-name skylight-mcp-github-deploy --policy-document "$POLICY"

ARN="arn:aws:iam::${ACCOUNT}:role/${ROLE}"
if command -v pbcopy >/dev/null; then
  printf '%s' "$ARN" | pbcopy
  echo "role ARN copied to the clipboard: paste it as the production environment secret AWS_DEPLOY_ROLE_ARN"
else
  echo "role ARN: $ARN"
fi
