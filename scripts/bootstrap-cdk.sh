#!/usr/bin/env bash
# One-off: bootstrap CDK in us-east-2. Needs admin rights, so it uses the admin
# session profile (skylight-mcp), not the narrow deploy user.
set -euo pipefail
export JSII_SILENCE_WARNING_UNTESTED_NODE_VERSION=1
cd "$(dirname "$0")/../infra"

export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
ACCOUNT="$(aws sts get-caller-identity --query Account --output text)"
npm ci --silent
# Bootstrap synthesises the app but deploys none of it; the placeholder only
# satisfies the app's required context.
npx cdk bootstrap "aws://${ACCOUNT}/us-east-2" -c userEmail=bootstrap-placeholder@example.invalid
