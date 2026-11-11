# skylight-mcp

Personal, single-user remote MCP server (Go, AWS Lambda `provided.al2023` arm64 + API Gateway HTTP API + Cognito) exposing a family Skylight calendar to Claude via a claude.ai custom connector. Read in this order: `SPEC.md` (requirements, owner-approved), `PLAN.md` (current plan and milestone status), `SKYLIGHT_API.md` (private API notes and unknowns), `docs/RETRO-step0.md` (why things are the way they are).

## Hard rules

- **The repo is public** (`logich/skylight-mcp-aws`). Never commit: credentials or tokens, the AWS account ID, the owner's email, Cognito pool/client IDs, the API hostname, real Skylight data. Personal values are deploy-time inputs only. Before every commit run a secret/identifier scan of the staged files (`git grep --cached` for the account ID, email, IDs, `AKIA…`).
- **Never print secrets** into the terminal or session. Use `scripts/show-client-secret.sh secret` (copies to clipboard). Never ask the owner to paste secrets into chat.
- **Automated tests and CI never call Skylight.** Manual probes by the owner or a session (e.g. `skylight-login`, milestone 3) are fine; their captures become scrubbed fixtures that tests replay. Why:
  - The refresh token rotates and is tied to one device fingerprint. A test refresh rotates the server's grant behind its back: once the test uses its new access token, the token stored in DynamoDB is revoked and the server needs a human re-authorisation. (Probed: a rejected reuse does not revoke the whole chain, but a second holder still breaks the single-holder rule.)
  - The repo is public: CI would need Skylight credentials as secrets, and a failing test could print real family data into public Actions logs.
  - It is a private, unofficial API with unknown rate limits and IP blocking; repeated runs from shared CI runner IPs risk flagging the account.
  - A live calendar changes daily, so assertions would be flaky; fixtures are deterministic.
  - Once v2 writes exist, a live test could change the real family calendar.
  - The production canary is the one scheduled live caller: it runs inside AWS through the same token store and lease as the server.
- **Auth fails closed.** `internal/auth.Check` is the single entry point: bearer token → RS256 signature (Cognito JWKS) → claims (`iss`, `token_use=access`, `client_id`, scope `skylight-mcp/invoke`, `aud` = connector URL when present, `exp`, allowed `sub`). Never trust identity claims from the invocation event. Every auth change gets table tests with real signed tokens, a fuzz run, and a regression test for any attack it closes.
- **Least privilege.** Deploys run through GitHub Actions (`deploy.yml`, OIDC role `skylight-mcp-github-deploy`, trusted only by the `production` environment, which needs the owner's approval). `./scripts/deploy.sh` with the `skylight-deploy` profile is break-glass. Both work only through the CDK bootstrap roles, under the scoped CloudFormation execution policy (`infra/bootstrap/cfn-exec-policy.json`), and every stack role carries `SkylightMcpRoleBoundary`. The admin profile `skylight-mcp` (a root console session) is for bootstrap and one-offs only. Never widen either policy to `*` actions or AdministratorAccess.
- Write commands, AWS changes affecting other projects, pushes, and changes to the owner's connector need the owner's go-ahead.

## Working rules (learned the hard way; see the retro)

1. **Read primary sources before asking design questions.** Code beats docs: the iOS repo's API guide describes paths its own code never calls.
2. **Verify before asserting** facts about the owner's accounts, AWS behaviour or third-party APIs. Check CLI output, schemas (`aws cloudformation describe-type`), templates (`cdk bootstrap --show-template`) and official docs. Say "unverified" otherwise.
3. **For identity resources (Cognito, IAM), read the constraints before deploying.** Don't deploy to find out; replacements can change secrets or lose users.
4. **The owner's connector test is the last check, not the first.** The authorized path can't be machine-tested without weakening single-user auth, so every reconnect is expensive. Before asking: unit tests pass, `scripts/smoke-oauth.sh` passes, logs checked. Batch auth changes into one reconnect.
5. **Smoke tests mirror the real client.** Derive them from observed claude.ai traffic in the gateway access log, not from assumptions (the missing `resource` parameter cost a round trip).
6. **Adversarial review covers code, not just plans.** Before a user-facing test or a security-relevant merge, review the actual diff adversarially (independent subagents only when the owner asks for them). Give reviewers raw evidence (logs, captured responses), not just a summary. Verify their claims before acting.
7. **Every reviewer "if X then Y" warning becomes a test of X** before moving on.
8. **Check with `scripts/check.sh`, never a hand-chained command line.** A chain of `&&` and `;` once let a gofmt failure pass silently and broke the first pipeline run.
9. **Commit before deploy**, so the reported build version maps to a commit (not `-dirty`).
10. **Observability before the first external test.** Gateway access logs exist; read them first when something fails (`aws logs tail /aws/apigateway/skylight-mcp`).
11. **Give the owner exact, field-by-field instructions** with real (non-secret) values, and say what each page or email will look like. The owner may be on Remote Control; restate decisions as questions with choices.

## Commands

```
./scripts/check.sh [quick]                         # what CI runs, fail-fast: run before every commit and push
go vet ./... && go test ./...                      # root module (infra/ is a separate module)
test -z "$(gofmt -l cmd internal infra/main.go)"   # never `gofmt -l .` (crawls infra/node_modules)
(cd infra && go vet .)                             # never `./...` in infra/ (node_modules)
go test -run x -fuzz FuzzVerify -fuzztime 20s ./internal/auth   # also FuzzAuthorize, FuzzParseEvents (calendar), FuzzExtractCode (skylight)
go test ./internal/server -run Contract -update     # regenerate MCP golden files; review the diff
./scripts/build.sh                                 # dist/lambda/bootstrap, version = git describe
./scripts/deploy.sh                                # break-glass only: normal deploys are GitHub Actions (deploy.yml) on push to main, after your approval
./scripts/scan-repo.sh                             # also runs in CI
./scripts/smoke-oauth.sh                           # after every deploy
aws lambda invoke --profile skylight-mcp --region us-east-2 --function-name skylight-mcp:live \
  --cli-binary-format raw-in-base64-out --payload '{"skylight_mcp_canary":true}' /dev/stdout   # Skylight path from AWS: counts only
CDK_DEFAULT_ACCOUNT=000000000000 npx cdk synth -q  # offline synth (in infra/), needs no personal data
```

Admin one-offs: `create-github-deploy-role.sh` (GitHub OIDC provider + role trusted only by the `production` environment), `set-alert-email.sh` (SSM `/skylight-mcp/alert-email`), `scripts/bootstrap-cdk.sh` (re-run after editing `infra/bootstrap/*.json`, after the first deploy, and after anything replaces the HTTP API or user pool; validate first with `scripts/check-exec-policy.sh`), `set-allowed-sub.sh` (writes SSM `/skylight-mcp/allowed-sub`; re-run if the Cognito user is replaced), `create-cognito-user.sh`, `create-deploy-user.sh`. Skylight re-authorisation: `go run ./cmd/skylight-login -force` (browser, catch the code in DevTools), then `go run ./cmd/skylight-store-import -overwrite` (moves it into the `SkylightMcpGrant` table and deletes the local copy). Any time: `show-client-secret.sh [url|id|secret]`.

## Gotchas already paid for

- claude.ai follows `authorization_servers` in the RFC 9728 document and needs RFC 8414 metadata there. Cognito only publishes OIDC discovery, so the server declares **itself** as the authorization server and serves `/.well-known/oauth-authorization-server`, which describes Cognito's endpoints and issues nothing.
- claude.ai sends RFC 8707 `resource` = connector URL, so Cognito sets access-token `aud` to it, and refreshes keep it. The gateway JWT authorizer audience must include the connector URL as well as the client ID.
- Cognito refresh-token rotation forbids `ALLOW_REFRESH_TOKEN_AUTH`; the client has an empty `ExplicitAuthFlows`.
- `cdk bootstrap --custom-permissions-boundary` puts the boundary on the CloudFormation execution role itself, which breaks deploys. Don't use it; the exec policy enforces the boundary instead.
- `cdk bootstrap` synthesises the app. The app requires `CDK_DEFAULT_ACCOUNT` (the Cognito domain prefix derives from it, and a wrong value would replace the domain).
- HTTP API access-log formats must include `$context.requestId`.
- Removing a CloudFormation-managed Cognito user: set `RETAIN` and deploy first, then remove it from the template.
- Lambda account concurrency limit is 10, so no reserved concurrency. Skylight token rotation uses a DynamoDB lease (`internal/grant`).
- Skylight behaves like Doorkeeper `revoke_previous_refresh_token_on_use`: a spent refresh token stays valid until the new access token is first used. **Commit new tokens before using the new access token**; never keep a second live copy of the grant (the table is the only holder).
- Laptop probes (`skylight-probe`) need the local grant file, which `skylight-store-import` deletes. Use the canary for live checks instead.
- The execution policy pins API Gateway and Cognito to this stack's API and pool **by id** (rendered at bootstrap, never committed). Tags can't do it: HTTP API routes/integrations can't be tagged (AWS documents tag inheritance only for REST APIs), and Access Analyzer reports `aws:ResourceTag` has no effect for `cognito-idp`. KMS keys are tag-scoped (`project=skylight-mcp`, set on every resource by the CDK app). `logs:PutResourcePolicy` can't be scoped at all; it is only allowed in first-deploy mode (API Gateway needs it once for access-log delivery). Check tag conditions with `scripts/check-exec-policy.sh` (Access Analyzer), not just the service reference.
- **Actions logs are public** (public repo). `deploy.yml` masks the account id and stack identifiers (`scripts/ci-mask.sh`) before anything prints them; keep new deploy steps behind that, and never echo canary counts or Skylight data in CI.
- This repo's GitHub OIDC tokens use **immutable subject claims** (`repo:logich@<owner id>/skylight-mcp-aws@<repo id>:…`), not the name-based form in most docs. `create-github-deploy-role.sh` reads the format from `GET /repos/{repo}/actions/oidc/customization/sub`; a trust policy on the name-based form makes `configure-aws-credentials` retry and fail.
- The `production` environment's required reviewer is the owner; **"Prevent self-review" must stay off**, or the owner cannot approve deploys of their own pushes. If the environment ever disappears, GitHub recreates it unprotected on the next deploy run.
- Skylight auth is OAuth code + PKCE (`client_id=skylight-mobile`, redirect `https://ourskylight.com/welcome`, codes expire in about 30 s) with a rotating refresh token tied to a device fingerprint. The iOS repo's password flow is obsolete.

## Open follow-ups

- First pipeline deploy of milestone 6 (queued behind a GitHub Actions outage on 2026-11-11): approve it, confirm the SNS subscription email, check the hook and canary ran.
- Owner: enable Dependabot alerts and Dependabot security updates (repo Settings → Code security); both are off and SPEC §9 requires them.
- Then delete the `skylight-deploy` access key (break-glass can be recreated with `create-deploy-user.sh`).
- Not built yet (PLAN §6): rollback on an error alarm / post-traffic check, a one-command manual rollback, an AWS Budget alarm.
- Bump `golang.org/x/sys` past v0.44.0 (Inspector: low severity; `govulncheck`: not called).
- Unknown Skylight behaviour: refresh-token idle expiry, 429 handling (SKYLIGHT_API.md §6). Then v2 (writes) per PLAN §7.
