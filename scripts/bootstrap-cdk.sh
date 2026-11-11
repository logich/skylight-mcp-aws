#!/usr/bin/env bash
# Bootstrap (or re-bootstrap) CDK in us-east-2 with a SCOPED CloudFormation
# execution policy instead of CDK's default AdministratorAccess.
#
# Creates or updates two customer-managed IAM policies from templates in
# infra/bootstrap/ (account id substituted at runtime, never committed):
#   SkylightMcpCfnExec      what CloudFormation may do when deploying this stack
#   SkylightMcpRoleBoundary permissions boundary every stack-created role must carry
#
# Needs admin rights, so it uses the admin session profile (skylight-mcp).
set -euo pipefail
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1
cd "$(dirname "$0")/.."

export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

# The execution policy pins API Gateway and Cognito to this stack's own HTTP
# API and user pool by id. Tags can't do it: HTTP API routes and integrations
# can't carry tags (AWS documents tag inheritance only for REST APIs), and IAM
# Access Analyzer reports aws:ResourceTag has no effect for cognito-idp.
# Before the stack exists there are no ids, so the first deploy gets
# "first-deploy mode": any HTTP API and user pool in the region, plus
# logs:PutResourcePolicy, which API Gateway needs once to set up access-log
# delivery and which can't be scoped to a resource. Re-run this script after
# the first deploy (or after anything replaces the API or pool) to scope down.
output() {
  aws cloudformation describe-stacks --stack-name SkylightMcp \
    --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text 2>/dev/null || true
}
API_ID="$(sed -nE 's#^https://([a-z0-9]+)\.execute-api\.us-east-2\.amazonaws\.com/mcp$#\1#p' <<<"$(output ConnectorUrl)")"
POOL_ID="$(grep -E '^us-east-2_[A-Za-z0-9]+$' <<<"$(output UserPoolId)" || true)"
if [ -n "$API_ID" ] && [ -n "$POOL_ID" ]; then
  FIRST_DEPLOY_EFFECT=Deny
  echo "scoping the execution policy to the stack's own HTTP API and user pool"
else
  API_ID='*' POOL_ID='*'
  FIRST_DEPLOY_EFFECT=Allow
  echo "no deployed SkylightMcp stack: FIRST-DEPLOY MODE (any HTTP API and user pool in us-east-2)."
  echo "Re-run this script after the first deploy to scope the policy down."
fi

render() {
  sed -e "s/\${ACCOUNT}/${ACCOUNT}/g" -e "s/\${API_ID}/${API_ID}/g" -e "s/\${POOL_ID}/${POOL_ID}/g" \
    -e "s/\${FIRST_DEPLOY_EFFECT}/${FIRST_DEPLOY_EFFECT}/g" "$1"
}

# Create the managed policy, or add a new default version (pruning the oldest
# non-default version when IAM's limit of 5 is reached).
upsert_policy() {
  local name="$1" file="$2" arn="arn:aws:iam::${ACCOUNT}:policy/$1" doc
  doc="$(render "$file")"
  if aws iam get-policy --policy-arn "$arn" >/dev/null 2>&1; then
    local versions
    versions="$(aws iam list-policy-versions --policy-arn "$arn" \
      --query 'Versions[?IsDefaultVersion==`false`].VersionId' --output text)"
    if [ "$(wc -w <<<"$versions")" -ge 4 ]; then
      aws iam delete-policy-version --policy-arn "$arn" --version-id "$(tr '\t' '\n' <<<"$versions" | sort -V | head -1)"
    fi
    aws iam create-policy-version --policy-arn "$arn" --policy-document "$doc" --set-as-default >/dev/null
    echo "updated $name"
  else
    aws iam create-policy --policy-name "$name" --policy-document "$doc" \
      --tags Key=project,Value=skylight-mcp >/dev/null
    echo "created $name"
  fi
}

upsert_policy SkylightMcpRoleBoundary infra/bootstrap/role-boundary.json
upsert_policy SkylightMcpCfnExec infra/bootstrap/cfn-exec-policy.json

cd infra
npm ci --silent
# Bootstrap synthesises the app but deploys none of it.
# Deliberately NOT using --custom-permissions-boundary: the bootstrap template
# applies it to the CloudFormation execution role itself, which would cap
# deploys at the narrow role boundary. Instead the execution policy only lets
# CloudFormation create roles that carry SkylightMcpRoleBoundary, and the CDK
# app attaches that boundary to every role it defines.
CDK_DEFAULT_ACCOUNT="$ACCOUNT" npx cdk bootstrap "aws://${ACCOUNT}/us-east-2" \
  --cloudformation-execution-policies "arn:aws:iam::${ACCOUNT}:policy/SkylightMcpCfnExec"
