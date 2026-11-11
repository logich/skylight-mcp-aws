#!/usr/bin/env bash
# Run locally what CI's "go" and "infra" jobs run, failing on the first
# problem with a clear message. Run before every commit and push: chaining
# checks by hand with && and ; once let a gofmt failure pass unnoticed.
#   ./scripts/check.sh          # full (includes short fuzz runs and govulncheck)
#   ./scripts/check.sh quick    # skip fuzzing and govulncheck
set -euo pipefail
cd "$(dirname "$0")/.."
step() { printf '\n== %s\n' "$1"; }

step "repo scan";  ./scripts/scan-repo.sh
step "gofmt"
unformatted="$(gofmt -l cmd internal infra/main.go)"
if [ -n "$unformatted" ]; then echo "not gofmt-formatted:"; echo "$unformatted"; exit 1; fi
echo ok
step "go vet";     go vet ./...
step "tests";      go test -race ./...
step "infra vet";  (cd infra && go vet .)
if [ "${1:-}" != quick ]; then
  step "fuzz (short)"
  go test -run x -fuzz FuzzVerify -fuzztime 10s ./internal/auth
  go test -run x -fuzz FuzzAuthorize -fuzztime 10s ./internal/auth
  go test -run x -fuzz FuzzParseEvents -fuzztime 10s ./internal/calendar
  go test -run x -fuzz FuzzExtractCode -fuzztime 5s ./internal/skylight
  step "govulncheck (source)"; go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
  step "build + govulncheck (binary)"
  ./scripts/build.sh
  go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 -mode=binary dist/lambda/bootstrap
fi
printf '\ncheck: all passed\n'
