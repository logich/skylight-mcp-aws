#!/usr/bin/env bash
# One-off (admin): store the one allowed Cognito sub in SSM, where CloudFormation
# reads it on every deploy. After this, routine deploys need only the deploy
# user. Re-run only if the Cognito user is replaced.
#
#   SKYLIGHT_USER_EMAIL=<address of the Cognito user> ./scripts/set-allowed-sub.sh
#
# The sub is not printed. Plain String (not SecureString): it is an identifier,
# not a credential, and CloudFormation parameter types can't read SecureString.
set -euo pipefail
cd "$(dirname "$0")/.."
: "${SKYLIGHT_USER_EMAIL:?set SKYLIGHT_USER_EMAIL}"
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
NAME=/skylight-mcp/allowed-sub

SUB="$(./scripts/get-sub.sh)"
if ! [[ "$SUB" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]]; then
  echo "no Cognito user found for that email (or unexpected sub format); nothing written" >&2
  exit 1
fi
aws ssm put-parameter --name "$NAME" --type String --value "$SUB" --overwrite >/dev/null
aws ssm add-tags-to-resource --resource-type Parameter --resource-id "$NAME" \
  --tags Key=project,Value=skylight-mcp
unset SUB
echo "stored the allowed sub in SSM parameter $NAME"
