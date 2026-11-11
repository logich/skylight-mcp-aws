#!/usr/bin/env bash
# Copy one connector setting at a time to the macOS clipboard, so you can paste
# each into claude.ai's custom-connector dialog in turn:
#
#   ./scripts/show-client-secret.sh url      # Remote MCP server URL
#   ./scripts/show-client-secret.sh id       # OAuth Client ID
#   ./scripts/show-client-secret.sh secret   # OAuth Client Secret
#
# With no argument it prints the URL and client id (not secret) and copies
# nothing. The client secret is never printed, so it can't end up in a terminal
# log or an AI session transcript.
set -euo pipefail
export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}" AWS_REGION=us-east-2 AWS_PAGER=""
out() { aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }

case "${1:-}" in
  url)    out ConnectorUrl | tr -d '\n' | pbcopy; echo "Copied: Remote MCP server URL" ;;
  id)     out ClientId | tr -d '\n' | pbcopy; echo "Copied: OAuth Client ID" ;;
  secret)
    aws cognito-idp describe-user-pool-client --user-pool-id "$(out UserPoolId)" --client-id "$(out ClientId)" \
      --query 'UserPoolClient.ClientSecret' --output text | tr -d '\n' | pbcopy
    echo "Copied: OAuth Client Secret (not shown)" ;;
  "")
    echo "Remote MCP server URL : $(out ConnectorUrl)"
    echo "OAuth Client ID       : $(out ClientId)"
    echo "OAuth Client Secret   : run '$0 secret' to copy it (never printed)" ;;
  *) echo "usage: $0 [url|id|secret]" >&2; exit 2 ;;
esac
