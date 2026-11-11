#!/usr/bin/env bash
# Print the Cognito sub (and nothing else) of the pool's user with the given email.
# Needs read access to Cognito, so it uses the admin profile.
set -euo pipefail
: "${SKYLIGHT_USER_EMAIL:?set SKYLIGHT_USER_EMAIL}"
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
POOL="$(aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query "Stacks[0].Outputs[?OutputKey=='UserPoolId'].OutputValue" --output text)"
aws cognito-idp list-users --user-pool-id "$POOL" \
  --filter "email = \"${SKYLIGHT_USER_EMAIL}\"" \
  --query "Users[0].Attributes[?Name=='sub'].Value" --output text
