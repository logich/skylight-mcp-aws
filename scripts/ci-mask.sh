#!/usr/bin/env bash
# GitHub Actions only: register the account id and every stack identifier as
# log masks before anything prints them (Actions logs of a public repo are
# public). Needs AWS credentials (the deploy role).
set -euo pipefail
export AWS_REGION=us-east-2 AWS_PAGER=""
mask() { [ -n "$1" ] && [ "$1" != "None" ] && echo "::add-mask::$1"; return 0; }
mask "$(aws sts get-caller-identity --query Account --output text)"
outputs="$(aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query 'Stacks[0].Outputs[].OutputValue' --output text 2>/dev/null || true)"
for v in $outputs; do
  mask "$v"
  # Parts that appear on their own elsewhere: API id, pool id, domain prefix.
  mask "$(sed -nE 's#^https://([a-z0-9]+)\.execute-api\..*#\1#p' <<<"$v")"
  mask "$(sed -nE 's#^https://cognito-idp\.[^/]+/(.*)$#\1#p' <<<"$v")"
  mask "$(sed -nE 's#^https://([a-z0-9-]+)\.auth\..*#\1#p' <<<"$v")"
done
echo "masks registered"
