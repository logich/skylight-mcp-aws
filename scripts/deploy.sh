#!/usr/bin/env bash
# Build and deploy the stack with the narrow deploy user.
#
#   SKYLIGHT_ALLOWED_SUB  the one allowed Cognito sub (scripts/get-sub.sh);
#                         without it the server rejects every MCP request
#   SKYLIGHT_USER_EMAIL   transitional only: keeps the Step 0 Cognito user
#                         resource in the template (retained). Omit it to drop
#                         that resource without deleting the user.
#
# Neither value is committed: this repository is public.
set -euo pipefail
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1
cd "$(dirname "$0")/.."

export AWS_PROFILE="${DEPLOY_PROFILE:-skylight-deploy}" AWS_REGION=us-east-2 AWS_PAGER=""
export CDK_DEFAULT_ACCOUNT CDK_DEFAULT_REGION=us-east-2
CDK_DEFAULT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

ctx=(-c "allowedSub=${SKYLIGHT_ALLOWED_SUB:-}")
if [ -n "${SKYLIGHT_USER_EMAIL:-}" ]; then
  ctx+=(-c "userEmail=${SKYLIGHT_USER_EMAIL}")
fi

./scripts/build.sh
cd infra
npm ci --silent
npx cdk deploy --require-approval never "${ctx[@]}" --outputs-file ../dist/outputs.json
