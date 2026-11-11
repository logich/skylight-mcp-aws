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

render() { sed "s/\${ACCOUNT}/${ACCOUNT}/g" "$1"; }

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
