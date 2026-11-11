#!/usr/bin/env bash
# Print the Cognito app client id and secret to paste into claude.ai's custom
# connector "advanced settings". Run it yourself in a terminal: the secret is
# printed once to your screen and is never stored in the repo.
set -euo pipefail
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
out() { aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
POOL="$(out UserPoolId)"; CLIENT="$(out ClientId)"
echo "Connector URL : $(out ConnectorUrl)"
echo "Client ID     : $CLIENT"
printf 'Client secret : '
aws cognito-idp describe-user-pool-client --user-pool-id "$POOL" --client-id "$CLIENT" \
  --query 'UserPoolClient.ClientSecret' --output text
