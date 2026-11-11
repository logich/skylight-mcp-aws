#!/usr/bin/env bash
# Pattern scan of tracked files for things a public repo must never contain.
# Runs in CI on every push and pull request; run it locally before committing.
# Owner-specific identifiers (account id, email, pool/client/API ids) can't be
# listed here without publishing them, so the local pre-commit scan in
# CLAUDE.md stays the control for those.
set -uo pipefail
cd "$(dirname "$0")/.."
fails=0
check() { # description, extended regex, [pathspec...]; $ALLOW: regex of allowed matches
  local desc="$1" re="$2"; shift 2
  local hits
  hits="$(git grep -noIE "$re" -- "$@" ':!scripts/scan-repo.sh' 2>/dev/null | { if [ -n "${ALLOW:-}" ]; then grep -vE "$ALLOW"; else cat; fi; } | cut -c1-160)"
  if [ -n "$hits" ]; then
    echo "FAIL: $desc"; echo "$hits" | sed 's/^/  /'; fails=$((fails+1))
  else
    echo "ok    $desc"
  fi
}
check "AWS access key ids"            '(AKIA|ASIA)[0-9A-Z]{16}'
check "private key blocks"            '-----BEGIN [A-Z ]*PRIVATE KEY-----'
check "ARNs with a real account id"   'arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]{12}:' ':!*.md'
check "emails in fixtures/goldens"    '[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+\.)+(com|net|org|edu|io|us|me)\b' \
  'internal/skylight/testdata' 'internal/server/testdata'
ALLOW=':https://example\.test/' check "URLs in fixtures/goldens" 'https?://[^" ]*' \
  'internal/skylight/testdata' 'internal/server/testdata'
check "Cognito pool ids"              'us-east-2_[A-Za-z0-9]{9}\b'
check "execute-api hostnames"         '[a-z0-9]{10}\.execute-api\.'
[ "$fails" = 0 ] && echo "scan-repo: clean" || { echo "scan-repo: $fails problem(s)"; exit 1; }
