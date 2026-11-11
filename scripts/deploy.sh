#!/usr/bin/env bash
# Build and deploy the stack with the narrow deploy user.
#
#   SKYLIGHT_USER_EMAIL   required: email of the one Cognito user
#   SKYLIGHT_ALLOWED_SUB  optional on first deploy: that user's Cognito sub
#                         (until set, the server rejects every MCP request)
#
# Neither value is committed: this repository is public.
set -euo pipefail
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1
cd "$(dirname "$0")/.."

: "${SKYLIGHT_USER_EMAIL:?set SKYLIGHT_USER_EMAIL}"
export AWS_PROFILE="${DEPLOY_PROFILE:-skylight-deploy}" AWS_REGION=us-east-2 AWS_PAGER=""
export CDK_DEFAULT_ACCOUNT CDK_DEFAULT_REGION=us-east-2
CDK_DEFAULT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

./scripts/build.sh
cd infra
npm ci --silent
npx cdk deploy --require-approval never \
  -c "userEmail=${SKYLIGHT_USER_EMAIL}" \
  -c "allowedSub=${SKYLIGHT_ALLOWED_SUB:-}" \
  --outputs-file ../dist/outputs.json
