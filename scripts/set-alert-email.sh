#!/usr/bin/env bash
# One-off (admin): store the address canary alerts are emailed to, in SSM,
# where CloudFormation reads it at deploy time (never in the repo or in
# GitHub). AWS then sends a confirmation email: click its link, or no alert
# is ever delivered.
#
#   SKYLIGHT_ALERT_EMAIL=<address> ./scripts/set-alert-email.sh
set -euo pipefail
: "${SKYLIGHT_ALERT_EMAIL:?set SKYLIGHT_ALERT_EMAIL}"
if ! [[ "$SKYLIGHT_ALERT_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+\.[^@[:space:]]+$ ]]; then
  echo "that does not look like an email address" >&2
  exit 1
fi
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
NAME=/skylight-mcp/alert-email
aws ssm put-parameter --name "$NAME" --type String --value "$SKYLIGHT_ALERT_EMAIL" --overwrite >/dev/null
aws ssm add-tags-to-resource --resource-type Parameter --resource-id "$NAME" --tags Key=project,Value=skylight-mcp
echo "stored the alert address in SSM parameter $NAME"
