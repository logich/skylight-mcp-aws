# Implementation plan: skylight-mcp

Read with [SKYLIGHT_API.md](SKYLIGHT_API.md). Decisions: Go 1.27 (toolchain pinned to 1.27.4), CDK in Go, us-east-2, Cognito-native single user, HA-style OAuth refresh token for Skylight, GitHub + Actions, default `execute-api` URL, one Skylight frame.

**Status (2026-11-11):** v1 (milestones 1–5) is live and confirmed by the owner through the claude.ai connector. Milestone 6 is built and pushed (`62ffcc6`) but **not yet deployed**: its first pipeline run is queued behind a GitHub Actions outage, so the live stack still runs `4711e2e` (built with Go 1.27.1) without the canary schedule, alarms or pre-traffic hook. See §6 for what milestone 6 does and does not cover.

## 1. Layout

As built:

```
cmd/server/                 Lambda entrypoint: API Gateway events, canary invokes, and (SKYLIGHT_MCP_MODE=hook) the CodeDeploy pre-traffic hook
cmd/skylight-login/         local: Skylight PKCE sign-in or refresh-token import, saves a 0600 file outside the repo
cmd/skylight-store-import/  local, admin: moves that grant into the DynamoDB table and deletes the local copy
cmd/skylight-probe/         local: read-only live probes (shapes only), -hazards for token reuse/parallel refresh
cmd/skylight-scrub/         local: captures -> committed fixtures, with a leak check
internal/auth/              bearer-token verification and the claims check (auth.Check is the one entry point)
internal/lambdahttp/        API Gateway v2 <-> net/http adapter (ignores event-supplied identity)
internal/server/            HTTP routes, OAuth discovery documents, MCP server (+ contract tests, golden files)
internal/tools/             list_family_members, list_events, get_event
internal/calendar/          strict Skylight parsers and the read client
internal/skylight/          Skylight OAuth/token client, raw API GET, local grant file (+ testdata/ fixtures)
internal/grant/             DynamoDB grant store, lease and refresh protocol
internal/canary/            canary checks (counts and error classes only)
internal/hook/              CodeDeploy pre-traffic checks
internal/scrub/             fixture scrubber
infra/                      CDK app (separate go.mod so CDK's tree never enters the server build); bootstrap/ policies
scripts/  .github/  DEPENDENCIES.md  SKYLIGHT_API.md  PLAN.md  SPEC.md  CLAUDE.md  docs/
```

## 2. Step 0: stub (before any Skylight work)

1. Stub MCP server with one `hello` tool (fixed string + build version), official Go SDK, Streamable HTTP, stateless, JSON responses (no SSE).
2. CDK stack: Lambda `provided.al2023` arm64 (static binary named `bootstrap`), HTTP API, Cognito user pool, CloudWatch logs with short retention.
3. Auth at two layers:
   - **API Gateway JWT authorizer** validates issuer, expiry and the app client. Cheap, and it keeps junk traffic away from the Lambda.
   - **In-Lambda `internal/auth.Authorize(claims) error`**: a single small function that requires `token_use == access`, the exact issuer, the exact client id, unexpired, and `sub` equal to your user's `sub` (from config, not hardcoded). Everything else is rejected. It is the real gate; the authorizer is defence in depth.
4. Cognito: self-signup disabled, one user (you), password + TOTP MFA required, one app client **with a secret** (code grant + PKCE), callback `https://claude.ai/api/mcp/auth_callback`. You enter the client id/secret under the connector's advanced settings.
5. The server serves `/.well-known/oauth-protected-resource` pointing at Cognito.
6. `cdk bootstrap` (one-off, with your admin session), deploy, give you the URL. You add the connector and ask Claude to call `hello`.

**Known risk to test in Step 0, not assume:** Cognito does not do Dynamic Client Registration and publishes OIDC discovery rather than RFC 8414 metadata. If claude.ai refuses the connector, the fallback is a tiny metadata shim in the Lambda (`/.well-known/oauth-authorization-server`, which only describes Cognito's endpoints; it never issues tokens). I will not build it unless the fixed-client path fails.

### Step 0 outcome (2026-11-11): done, `hello` works through the connector

Lessons, now baked into the code:
- claude.ai follows `authorization_servers` in our protected-resource document and wants RFC 8414 metadata at that URL. Cognito only publishes OIDC discovery, so pointing at Cognito's issuer fails silently. **Fix:** the server declares *itself* as the authorization server and serves `/.well-known/oauth-authorization-server` (and OIDC variants) describing Cognito's authorize/token endpoints (the OIDC variants were removed again in §3). Tokens are still issued by Cognito and `auth.Authorize` still checks Cognito's `iss`. The shim only describes; it never issues tokens.
- The JWT authorizer's 401 is a bare `Bearer` (no `resource_metadata`); claude.ai copes by falling back to the well-known path. Gateway access logs (method/path/status only) were added to see these gateway-answered requests.
- Cognito's invitation email has no sign-in link; the temporary password is used on the hosted sign-in page the connector opens.
- `cdk bootstrap` runs the app, so scripts pass a placeholder `userEmail`. Bootstrap used the default `AdministratorAccess` CloudFormation execution policy, so the deploy user can effectively deploy anything via CDK; tighten later. *(Superseded: scoped execution policy and boundary since §3; the app needs no `userEmail`.)*
- Operational scripts: `scripts/bootstrap-cdk.sh` (admin, once), `deploy.sh` (needs `SKYLIGHT_USER_EMAIL`, `SKYLIGHT_ALLOWED_SUB`), `get-sub.sh`, `show-client-secret.sh`, `create-deploy-user.sh`. *(Superseded: `deploy.sh` now takes no inputs; the allowed sub lives in SSM, written once by `set-allowed-sub.sh`.)*

> **Revised 2026-11-11** after the Step 0 retrospective ([docs/RETRO-step0.md](docs/RETRO-step0.md)); you accepted all six of its decisions. §3–§6 below are the revised plan.

## 3. Auth hardening (done before any Skylight code)

- **CDK re-bootstrap** with a scoped CloudFormation execution policy (only the services this stack uses; IAM limited to roles named `SkylightMcp-*`) and a permissions boundary on created roles. Removes the `AdministratorAccess` takeover path.
- **In-Lambda JWT verification:** the Lambda verifies the RS256 signature of the `Authorization` bearer token itself against Cognito's JWKS (fetched once per cold start, stdlib `crypto/rsa`), and only then runs the claims check. Claims passed in the event by API Gateway are no longer trusted, which closes the forged-claims-by-direct-invoke path. The gateway authorizer stays as the first layer.
- **Cognito:** resource server with one custom scope `skylight-mcp/invoke`; no `openid`/`email` scopes (no ID token, so no issuer contradiction); the OIDC discovery routes are removed; `Authorize` requires the scope; client auth flows restricted to refresh only; new app client (fresh id and secret, replacing the one exposed in a transcript); refresh token validity raised to the maximum practical value, with rotation if the pool tier supports it.
- **Cognito user moved out of the CDK template** (created once by script), so synth needs no email and CI logs can't leak it.
- **Scripted OAuth smoke test** run before every connector test: 401 → protected-resource document → authorization-server metadata → authorize redirect → `/mcp` 401 for missing, garbage and tampered tokens.

## 4. v1 build

- **Token store:** one DynamoDB item, encrypted with a customer-managed KMS key, holding `{refresh_token, access_token, access_expires_at, device_fingerprint, frame_id, generation, lease_owner, lease_expires_at}`. Strongly consistent reads. Secrets Manager is not used for rotating tokens (AWS advises against frequent `PutSecretValue`, and it has no compare-and-set).
- **Persist the access token** (HA does), so cold starts reuse it instead of each spending a refresh.
- **Refresh protocol:** acquire the lease with a conditional write on `lease_expires_at`; re-read; if `generation` moved, use the stored token; else refresh with a short deadline (≤4 s), then commit new tokens, bump `generation` and release the lease in **one** conditional `UpdateItem`; retry the commit until the Lambda's own deadline. **Never use the new access token before the commit succeeds** (Skylight revokes the old refresh token when the new access token is first used, so commit-then-use makes a crash between refresh and commit harmless; see SKYLIGHT_API.md, rotation hazards). Rotation happens on every refresh (confirmed live). Losers wait and re-read. On `invalid_grant`, re-read the store and retry once with the stored token if `generation` moved; only then report "re-authorise Skylight", with a clear error.
- **Timeouts:** Lambda timeout ~28 s (HTTP API caps at 30 s); lease TTL = token deadline + commit + margin, below the Lambda timeout.
- **Tools:** `list_family_members`, `list_events(start, end, member?)` (at most 93 days), `get_event(event_id, around?)` (occurrence ids carry their start; plain ids use `around` or a -30/+180-day window); names not ids; drop non-member categories; fail with "upstream API changed" when an event references a category missing from `included`.
- **Robustness, logging, tests:** as before (timeouts, `Retry-After` + jittered backoff, strict parsers, allowlisted slog fields; fixture replay, MCP golden files, fuzzing), plus token-level auth tests with locally generated RSA keys (tampered payload, wrong `kid`, `alg=none`, HS256, expired, wrong pool).

## 5. Dependencies

See [DEPENDENCIES.md](DEPENDENCIES.md) (the current list with reasons): the MCP Go SDK, `aws-lambda-go`, and `aws-sdk-go-v2` (`config`, `dynamodb`, `lambda`, `codedeploy`). No JWT or OAuth libraries.

## 6. Canary, CI/CD and hardening

Built in milestone 6 (in the stack and `.github/`; live once the first pipeline deploy runs):

- **Canary inside AWS:** EventBridge Scheduler (`SkylightMcpCanary`) invokes the live alias **every 6 hours** with `{"skylight_mcp_canary":true}` (direct invoke, not API Gateway, so it cannot reach the MCP tools). Two alarms email via SNS (`SkylightMcp-alerts`, address from SSM `/skylight-mcp/alert-email`): `SkylightMcp-canary-failed` (any failed run in a 6-hour window) and `SkylightMcp-canary-missing` (no success in 24 hours). Shares the token store and lease. No Skylight credential in GitHub.
- **Deploy:** CodeDeploy (`SkylightMcp` application and group), **all at once**, with a **pre-traffic hook** (`skylight-mcp-predeploy-hook`, same binary) that invokes the new version: discovery 200, `/mcp` without a token 401, forged authorizer claims 401, canary ok. A failed hook rolls back automatically.
- **GitHub:** `deploy.yml` on push to `main` runs the full CI, waits for the owner's approval of the `production` environment (required reviewer `logich`, self-review allowed, branch rule `main`), assumes the OIDC role `skylight-mcp-github-deploy` (trust: `repo:logich/skylight-mcp-aws:environment:production`), masks account and stack ids in the public log, deploys, then runs the OAuth smoke test and a pass/fail canary.
- **CI (`ci.yml`, every push except `main` and every PR; `main` runs it through `deploy.yml`):** repo scan, `gofmt`, `go vet`, race tests, short fuzz runs, `govulncheck` on source and on the built binary, infra `go vet`, offline `cdk synth` (dummy account, no credentials), dependency review on PRs. Node 24 in CI. `codeql.yml`: main, PRs, weekly. `dependabot.yml`: weekly, grouped per ecosystem (the CDK npm CLI and the Go `awscdk` module are separate groups, not one).
- **Throttling:** 1 rps (burst 2) on the unauthenticated `.well-known` routes, 5 rps (burst 10) elsewhere (live).
- **Inspector:** Lambda standard scanning enabled and **verified to cover the Go binary** (2026-11-11: it reports the Go 1.27.1 standard-library CVEs in the live function and a low-severity `golang.org/x/sys` v0.41.0 issue). `govulncheck` in CI remains the gate.

Not built (still open):

- **Rollback on an error alarm** and a **post-traffic check**: rollback is triggered only by the pre-traffic hook. The post-deploy smoke test and canary in `deploy.yml` report failure but do not roll back.
- **One-command manual rollback** (today: re-run `deploy.yml` on an earlier commit, or `./scripts/deploy.sh` from a checkout of it).
- **AWS Budget alarm**: no budget exists.

## 7. Milestones (stop for your confirmation at the starred ones)

1. ★ Step 0 stub deployed; you test `hello`. **Done.**
2. ★ Auth hardening (§3); you reconnect the connector once. **Deployed 2026-11-11** (scoped bootstrap + boundary, in-Lambda RS256 verification, custom scope, rotating 365-day refresh tokens, new client, user out of the template, discovery throttles, 28 s timeout); `scripts/smoke-oauth.sh` passes. **Done:** reconnected and `hello` called successfully with in-Lambda verification of real, resource-bound tokens (aud = connector URL, accepted by both gateway and Lambda).
3. `skylight-login` tool (accepts a pasted URL or bare code, exchanges immediately; also imports a refresh token); you authorise once; read-only live calls **from the laptop and from a Lambda** to settle: token response shape and rotation, `expires_in`, old-token reuse behaviour, parallel-refresh behaviour, datacenter-IP blocking, required headers, refresh-token idle expiry, plus the API unknowns in SKYLIGHT_API.md §6. Scrub into fixtures. **Done from the laptop 2026-11-11** (`skylight-login`, `skylight-probe`, `skylight-scrub`; results in SKYLIGHT_API.md §6; fixtures in `internal/skylight/testdata`). Moved to milestone 4: the from-Lambda probe (datacenter-IP blocking), refresh-token idle expiry, 429 behaviour.
4. Token store + lease + Skylight client, with tests. **Done 2026-11-11:** `internal/grant` (DynamoDB store, lease, commit-then-use), `internal/calendar` (strict parsers, client), grant table + KMS key deployed, grant imported (the table is the only holder), canary entry point. From Lambda: reads and refresh work, no IP blocking.
5. Three tools + contract/fuzz tests. **Deployed 2026-11-11 (`4711e2e`):** `internal/tools`; contract tests through an MCP client with golden files; canary green on this version. **Done:** tools verified through the owner's reconnected connector (live data, member filter, both `get_event` lookup paths), and the owner confirmed a Claude client using them.
6. CI, deploy pipeline, canary, Dependabot, Inspector check. **Built and pushed 2026-11-11, first pipeline deploy pending** (queued behind a GitHub Actions outage): `ci.yml` (scan, gofmt, vet, race tests, fuzz, govulncheck source+binary, offline synth, dependency review), `codeql.yml`, `dependabot.yml`, `deploy.yml` (CI → owner-approved `production` environment → OIDC role → deploy → smoke → canary; account and stack ids masked in the public log); stack: canary every 6 h via EventBridge Scheduler, failure and no-success-in-24h alarms emailing via SNS, CodeDeploy all-at-once with a pre-traffic hook (discovery 200, unauthenticated and forged-claims 401, canary) and automatic rollback. Go toolchain pinned to 1.27.4 (govulncheck found 10 reachable stdlib issues in 1.27.1).
7. ★ v1 done end to end. Only then v2 (write tools behind an off-by-default flag, not registered otherwise).

## 8. Decisions (settled)

1. Rotation lock: DynamoDB lease, in the same item as the tokens (revised).
2. AWS SDK v2 rather than hand-rolled SigV4: DynamoDB for the grant store, plus Lambda and CodeDeploy for the pre-traffic hook (no Secrets Manager).
3. Inspector: Lambda standard scanning enabled in us-east-2 on 2026-11-11 (code scanning left off). Verified the same day that it scans the Go binary (stdlib and module CVEs reported).
4. Canary: EventBridge Scheduler inside AWS, SNS email alert (revised; replaces the GitHub-invoked canary).
4a. Retrospective decisions accepted 2026-11-11: in-Lambda JWT verification; DynamoDB token store; in-AWS canary; pre-traffic hook + all-at-once deploy; Cognito custom scope, refresh lifetime and new client; scoped CDK bootstrap.
5. Repo: `https://github.com/logich/skylight-mcp-aws`, **public by decision** (SPEC §9), `main` pushed. GitHub Free; environments with required reviewers and branch rules work on public repos at that tier (verified in GitHub's docs). Settings observed 2026-11-11: secret scanning and push protection **enabled**; **Dependabot alerts and Dependabot security updates disabled** (SPEC §9 wants them on: owner to enable under Settings → Code security). CodeQL and dependency review run as workflows.
   Public-repo rules: no credentials, no AWS account ID in committed files, scrubbed fixtures only, OIDC trust limited to the `production` environment (itself limited to `main` and gated on the owner's approval), Actions logs masked.
6. Cognito user: your own email address, created once by `scripts/create-cognito-user.sh` (not in the template), password + TOTP MFA. The allowlisted Cognito `sub` lives in SSM `/skylight-mcp/allowed-sub` and CloudFormation resolves it at deploy time.
7. Deployers: GitHub Actions through the OIDC role `skylight-mcp-github-deploy` (normal path); AWS profiles `skylight-mcp` (admin session: bootstrap and one-offs) and `skylight-deploy` (IAM user with a long-lived access key, break-glass `./scripts/deploy.sh`; delete the key once the pipeline has deployed).

## 8a. Original open items (answered above)

1. **Lease vs quota:** DynamoDB lease (recommended), or file an AWS quota-increase request (no code, but slow and new accounts are often refused)?
2. **AWS SDK vs hand-rolled SigV4** for Secrets Manager + DynamoDB (recommend SDK).
3. **Inspector:** OK to enable Lambda scanning account-wide in this account?
4. **Canary change** in §5: OK?
5. **Repo:** GitHub repo name and visibility? (Fixtures are scrubbed, but I would default to private.) Directory is not a git repo yet; I will `git init` here.
6. **Cognito user:** the email to create the single user with, and a TOTP app you will use.
