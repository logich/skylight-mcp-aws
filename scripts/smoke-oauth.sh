#!/usr/bin/env bash
# Walk the same OAuth discovery chain a connector client (claude.ai) uses, and
# check the server refuses bad tokens. Run after every deploy and BEFORE asking
# a human to test the connector. Needs no user credentials.
set -uo pipefail
# Only reads stack outputs. In CI the deploy role's credentials are used.
if [ -z "${AWS_ACCESS_KEY_ID:-}" ]; then export AWS_PROFILE="${ADMIN_PROFILE:-skylight-mcp}"; fi
export AWS_REGION=us-east-2 AWS_PAGER=""
SCOPE="skylight-mcp/invoke"
CALLBACK="https://claude.ai/api/mcp/auth_callback"

out() { aws cloudformation describe-stacks --stack-name SkylightMcp \
  --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
MCP="$(out ConnectorUrl)"; CLIENT="$(out ClientId)"
HOST="${MCP%/mcp}"
fails=0
ok()   { printf '  ok    %s\n' "$1"; }
bad()  { printf '  FAIL  %s\n' "$1"; fails=$((fails+1)); }
json() { python3 -I -c "import sys,json; d=json.load(sys.stdin); print($1)" 2>/dev/null; }
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

echo "1. unauthenticated /mcp is refused"
c=$(code -X POST "$MCP" -H 'content-type: application/json' -d '{"jsonrpc":"2.0","id":1,"method":"tools/list"}')
[ "$c" = 401 ] && ok "no token -> 401" || bad "no token -> $c"

echo "2. protected-resource metadata (RFC 9728)"
PR="$(curl -s "$HOST/.well-known/oauth-protected-resource/mcp")"
AS="$(json 'd["authorization_servers"][0]' <<<"$PR")"
[ "$(json 'd["resource"]' <<<"$PR")" = "$MCP" ] && ok "resource = connector URL" || bad "resource mismatch"
[ "$AS" = "$HOST" ] && ok "authorization server = this host" || bad "authorization server = '$AS'"
[ "$(json '" ".join(d.get("scopes_supported",[]))' <<<"$PR")" = "$SCOPE" ] && ok "scope advertised" || bad "scope not advertised"

echo "3. authorization-server metadata (RFC 8414) at the advertised server"
ASM="$(curl -s "$AS/.well-known/oauth-authorization-server")"
[ "$(json 'd["issuer"]' <<<"$ASM")" = "$AS" ] && ok "issuer matches identifier" || bad "issuer mismatch"
AUTHZ="$(json 'd["authorization_endpoint"]' <<<"$ASM")"
[ -n "$AUTHZ" ] && ok "authorization_endpoint present" || bad "no authorization_endpoint"
[ "$(json '"S256" in d["code_challenge_methods_supported"]' <<<"$ASM")" = True ] && ok "PKCE S256" || bad "no S256"
[ "$(code "$HOST/.well-known/openid-configuration")" = 404 ] && ok "no OIDC discovery (by design)" || bad "OIDC discovery still served"

echo "4. Cognito accepts the client, callback and scope (expect redirect to its login page)"
LOC="$(curl -s -o /dev/null -D - -G "$AUTHZ" --data-urlencode "client_id=$CLIENT" \
  --data-urlencode response_type=code --data-urlencode "scope=$SCOPE" \
  --data-urlencode "redirect_uri=$CALLBACK" --data-urlencode state=smoke \
  --data-urlencode "resource=$MCP" \
  --data-urlencode code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM \
  --data-urlencode code_challenge_method=S256 | awk 'tolower($1)=="location:"{print $2}' | tr -d '\r')"
case "$LOC" in
  */login\?*) ok "redirects to hosted login" ;;
  *error=*)   bad "Cognito error: $(sed -E 's/.*(error=[^&]*).*/\1/' <<<"$LOC")" ;;
  *)          bad "unexpected redirect" ;;
esac

echo "5. bad tokens are refused"
h=$(printf '{"alg":"RS256","kid":"x"}' | base64 | tr '+/' '-_' | tr -d '=')
p=$(printf '{"sub":"x","token_use":"access","exp":9999999999}' | base64 | tr '+/' '-_' | tr -d '=')
for t in "garbage" "$h.$p.c2ln" "$h.$p."; do
  c=$(code -X POST "$MCP" -H "authorization: Bearer $t" -H 'content-type: application/json' -d '{}')
  [ "$c" = 401 ] && ok "forged/garbage token -> 401" || bad "forged/garbage token -> $c"
done

echo
[ "$fails" = 0 ] && echo "smoke-oauth: all checks passed" || { echo "smoke-oauth: $fails check(s) FAILED"; exit 1; }
