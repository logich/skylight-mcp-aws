#!/usr/bin/env bash
# Build and deploy the stack with the narrow deploy user. Takes no personal
# inputs: the allowed Cognito sub is read by CloudFormation from SSM
# (/skylight-mcp/allowed-sub, written once by scripts/set-allowed-sub.sh).
set -euo pipefail
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1
cd "$(dirname "$0")/.."

export AWS_PROFILE="${DEPLOY_PROFILE:-skylight-deploy}" AWS_REGION=us-east-2 AWS_PAGER=""
export CDK_DEFAULT_ACCOUNT CDK_DEFAULT_REGION=us-east-2
CDK_DEFAULT_ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"

./scripts/build.sh
cd infra
npm ci --silent
npx cdk deploy --require-approval never --outputs-file ../dist/outputs.json
