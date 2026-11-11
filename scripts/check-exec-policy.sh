#!/usr/bin/env bash
# Render the CloudFormation execution policy exactly as bootstrap-cdk.sh would
# (steady state, for the deployed stack) and validate it with IAM Access
# Analyzer. Prints findings only; never prints the rendered policy, which
# contains the account and API ids. Admin profile (read-only calls).
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
URL="$(aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query "Stacks[0].Outputs[?OutputKey=='ConnectorUrl'].OutputValue" --output text)"
API_ID="$(sed -nE 's#^https://([a-z0-9]+)\.execute-api\.us-east-2\.amazonaws\.com/mcp$#\1#p' <<<"$URL")"
POOL_ID="$(aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)"
[ -n "$API_ID" ] && [ -n "$POOL_ID" ] || { echo "could not derive the API or pool id" >&2; exit 1; }
for f in infra/bootstrap/cfn-exec-policy.json infra/bootstrap/role-boundary.json; do
  doc="$(sed -e "s/\${ACCOUNT}/${ACCOUNT}/g" -e "s/\${API_ID}/${API_ID}/g" -e "s/\${POOL_ID}/${POOL_ID}/g" \
    -e "s/\${FIRST_DEPLOY_EFFECT}/Deny/g" "$f")"
  echo "== $f"
  aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY --policy-document "$doc" \
    --query 'findings[].[findingType,issueCode,findingDetails]' --output text
done
