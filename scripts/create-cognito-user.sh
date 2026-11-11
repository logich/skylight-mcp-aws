#!/usr/bin/env bash
# Create the single Cognito user (used when rebuilding the pool; the Step 0
# user already exists). Cognito emails a temporary password; the first sign-in
# on the hosted page sets a new password and enrols TOTP.
set -euo pipefail
: "${SKYLIGHT_USER_EMAIL:?set SKYLIGHT_USER_EMAIL}"
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
POOL="$(aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)"
aws cognito-idp admin-create-user --user-pool-id "$POOL" --username "$SKYLIGHT_USER_EMAIL" \
  --user-attributes Name=email,Value="$SKYLIGHT_USER_EMAIL" Name=email_verified,Value=true \
  --desired-delivery-mediums EMAIL --query 'User.UserStatus' --output text
echo "Then: SKYLIGHT_USER_EMAIL=... ./scripts/get-sub.sh, and deploy with SKYLIGHT_ALLOWED_SUB set."
