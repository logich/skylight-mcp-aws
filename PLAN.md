# Implementation plan: skylight-mcp

Read with [SKYLIGHT_API.md](SKYLIGHT_API.md). Nothing is built yet. Decisions already made: Go 1.27, CDK in Go, us-east-2, Cognito-native single user, HA-style OAuth refresh token for Skylight, GitHub + Actions, default `execute-api` URL, one Skylight frame.

## 1. Layout

```
cmd/server/            Lambda entrypoint (and local `-http` mode for dev)
internal/auth/         the one authorization function + tests
internal/skylight/     client, token store, parsers (+ testdata/ fixtures)
internal/tools/        MCP tool handlers
internal/lambdahttp/   ~60-line API Gateway v2 <-> net/http adapter
cmd/skylight-login/    one-off local tool: PKCE sign-in, writes secret (never in Lambda)
infra/                 CDK app (separate go.mod so CDK's big tree never enters the server build)
scripts/  .github/workflows/  DEPENDENCIES.md  SKYLIGHT_API.md  PLAN.md
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
- claude.ai follows `authorization_servers` in our protected-resource document and wants RFC 8414 metadata at that URL. Cognito only publishes OIDC discovery, so pointing at Cognito's issuer fails silently. **Fix:** the server declares *itself* as the authorization server and serves `/.well-known/oauth-authorization-server` (and OIDC variants) describing Cognito's authorize/token endpoints. Tokens are still issued by Cognito and `auth.Authorize` still checks Cognito's `iss`. The shim only describes; it never issues tokens.
- The JWT authorizer's 401 is a bare `Bearer` (no `resource_metadata`); claude.ai copes by falling back to the well-known path. Gateway access logs (method/path/status only) were added to see these gateway-answered requests.
- Cognito's invitation email has no sign-in link; the temporary password is used on the hosted sign-in page the connector opens.
- `cdk bootstrap` runs the app, so scripts pass a placeholder `userEmail`. Bootstrap used the default `AdministratorAccess` CloudFormation execution policy, so the deploy user can effectively deploy anything via CDK; tighten later.
- Operational scripts: `scripts/bootstrap-cdk.sh` (admin, once), `deploy.sh` (needs `SKYLIGHT_USER_EMAIL`, `SKYLIGHT_ALLOWED_SUB`), `get-sub.sh`, `show-client-secret.sh`, `create-deploy-user.sh`.

## 3. v1 build (after you confirm `hello` works)

- **Token store:** secret `{refresh_token, device_fingerprint, frame_id}` in Secrets Manager. Access token cached in memory across warm invocations; refresh on 401, once.
- **Rotation safety (changed from my earlier proposal):** reserved concurrency of 1 is **not possible** because the account's Lambda limit is 10 and AWS requires 10 unreserved. Instead: a **DynamoDB lease** (one item, conditional put with ~15 s TTL, on-demand, pennies). The invocation that wins the lease refreshes, writes the new refresh token to Secrets Manager *before using it*, then releases. Losers wait briefly, re-read the secret, and use the fresh token. If refresh is rejected, re-read the secret once in case someone else just rotated, then fail with a clear "re-authorise Skylight" error. This is a few hundred lines of carefully tested code; worth it because a double refresh could burn the grant.
- **Tools:** `list_family_members`, `list_events`, `get_event` exactly as in the spec, with names not ids, drop non-member categories, `get_event(event_id, start?, end?)` unless a live probe finds a real single-event endpoint.
- **Robustness:** timeouts on every outbound call, `Retry-After` plus capped jittered backoff, strict parsers that return "upstream API changed" (never partial data, never silently skipped events).
- **Logging:** `log/slog` JSON through an allowlist of fields; tokens, credentials and event content are not loggable by construction (typed fields, no raw bodies).
- **Tests (all offline in CI):** `httptest` replay of scrubbed fixtures; MCP contract tests with golden files; fuzz targets on every parser; exhaustive auth table tests (missing, malformed, expired, wrong issuer/client/`token_use`, wrong `sub`, `alg=none`, etc.).
- **Live canary:** see §5.

## 4. Dependencies (each justified in DEPENDENCIES.md)

| Module | Why |
|---|---|
| `modelcontextprotocol/go-sdk` | spec requires the official SDK |
| `aws/aws-lambda-go` | Lambda runtime loop; hand-rolling is not worth it |
| `aws-sdk-go-v2` service modules for Secrets Manager + DynamoDB only | SigV4 signing is security-critical; I would rather import it than write it. Alternative is ~100 lines of hand-rolled SigV4 for 3 API calls; your call (see questions). |
| JWT: none | The authorizer does signature checks; my function only validates claims. Decision to revisit: if we also verify signatures in-Lambda, `golang-jwt` or stdlib `crypto` + JWKS fetch. I propose in-Lambda signature verification is skipped because API Gateway already does it and the function is meant to stay tiny. |

Everything else stdlib. `infra/` has its own `go.mod` (CDK, constructs).

## 5. Canary (small deviation from what you chose)

You picked "GitHub Actions schedule + email". A canary that uses its own copy of the Skylight refresh token would fight the Lambda's rotating token chain, and would put a Skylight credential in GitHub. Instead: the daily workflow assumes an **OIDC role** that can invoke only this function with a `{"canary":true}` payload; the Lambda does a real read through the normal token path and returns pass/fail. Failure makes the workflow red and GitHub emails you. Same alerting you asked for, but no Skylight secret outside AWS.

## 6. CI/CD and hardening

- Dependabot for `gomod` (both modules) and GitHub Actions.
- PR checks: `go vet`, `govulncheck`, tests incl. short fuzz, `cdk synth`.
- Merge to main: build arm64 binary, `cdk deploy` via GitHub OIDC role (no long-lived keys in GitHub), new Lambda version → test alias → smoke test → CodeDeploy linear/canary traffic shift with CloudWatch-alarm rollback.
- Least-privilege Lambda role: `GetSecretValue`/`PutSecretValue` on its own secret, read/write its one DynamoDB table, own log group only.
- **Amazon Inspector:** currently `DISABLED` for Lambda in this account. Enabling it is account-wide (affects your other projects' functions and adds cost), so I need your OK. I also have to confirm Inspector's Lambda scanning actually covers Go modules in a `provided.al2023` function; I do not want to claim coverage I have not verified.

## 7. Milestones (stop for your confirmation at the starred ones)

1. ★ Step 0 stub deployed; you test `hello`.
2. `skylight-login` tool; you authorise once; a few read-only live calls from your machine to settle the unknowns in SKYLIGHT_API.md §6, then scrub into fixtures.
3. Skylight client + token store + lease, with tests.
4. Three tools + contract/fuzz/auth tests.
5. CI, auto-deploy, alias/rollback, canary, Dependabot, Inspector.
6. ★ v1 done end to end. Only then v2 (write tools behind an off-by-default flag, not registered otherwise).

## 8. Decisions (settled)

1. Rotation lock: DynamoDB lease.
2. AWS SDK v2 (Secrets Manager + DynamoDB modules only) rather than hand-rolled SigV4.
3. Inspector: Lambda standard scanning enabled in us-east-2 on 2026-11-11 (code scanning left off). Still to verify it covers Go in `provided.al2023`.
4. Canary: Lambda-invoked via GitHub OIDC role (§5).
5. Repo: `https://github.com/logich/skylight-mcp-aws` (created by you, empty, **public by decision**, and SPEC.md §9 now says so). Remote `origin` added locally; nothing pushed yet. Observed on 2026-11-11: secret scanning and push protection already enabled; Dependabot security updates disabled (to enable during CI setup). You confirmed GitHub Free and Copilot Free; everything this project needs from GitHub (Actions, OIDC, environments, branch protection, secret scanning, CodeQL, dependency review, Dependabot) is available on a public repo at that tier. CI adds CodeQL and dependency review.
   Public-repo rules: no credentials, no AWS account ID in committed files, scrubbed fixtures only, OIDC trust limited to `main`, deploy jobs in a protected environment.
6. Cognito user: your own email address (passed at deploy time via CDK context, never committed because the repo is public), password + TOTP MFA. The allowlisted Cognito `sub` is likewise passed at deploy time.
7. AWS profiles: `skylight-mcp` (admin session, bootstrap and one-offs only), `skylight-deploy` (IAM user, normal CDK deploys).

## 8a. Original open items (answered above)

1. **Lease vs quota:** DynamoDB lease (recommended), or file an AWS quota-increase request (no code, but slow and new accounts are often refused)?
2. **AWS SDK vs hand-rolled SigV4** for Secrets Manager + DynamoDB (recommend SDK).
3. **Inspector:** OK to enable Lambda scanning account-wide in this account?
4. **Canary change** in §5: OK?
5. **Repo:** GitHub repo name and visibility? (Fixtures are scrubbed, but I would default to private.) Directory is not a git repo yet; I will `git init` here.
6. **Cognito user:** the email to create the single user with, and a TOTP app you will use.
