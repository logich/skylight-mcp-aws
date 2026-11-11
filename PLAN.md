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
- **Tools:** `list_family_members`, `list_events`, `get_event(event_id, start?, end?)` as specified; names not ids; drop non-member categories; fail with "upstream API changed" when an event references a category missing from `included`.
- **Robustness, logging, tests:** as before (timeouts, `Retry-After` + jittered backoff, strict parsers, allowlisted slog fields; fixture replay, MCP golden files, fuzzing), plus token-level auth tests with locally generated RSA keys (tampered payload, wrong `kid`, `alg=none`, HS256, expired, wrong pool).

## 5. Dependencies (each justified in DEPENDENCIES.md)

| Module | Why |
|---|---|
| `modelcontextprotocol/go-sdk` | spec requires the official SDK |
| `aws/aws-lambda-go` | Lambda runtime loop and event types |
| `aws-sdk-go-v2` DynamoDB (+ core) | SigV4 signing is security-critical; import rather than hand-roll. KMS encryption is server-side, so no KMS client is needed. |
| JWT: none | RS256 verification of a single key type with stdlib `crypto/rsa`, `crypto/sha256`, `encoding/json`, `encoding/base64`; small enough to test exhaustively. |

## 6. Canary, CI/CD and hardening

- **Canary inside AWS:** EventBridge Scheduler invokes the function daily with a canary event (a separate, non-API-Gateway entry point that cannot reach the MCP tools); a CloudWatch alarm on canary failure emails you via SNS. Shares the token store and lease, so it can't race user requests. No Skylight credential or AWS invoke role in GitHub.
- **Deploy:** publish a new Lambda version; a CodeDeploy **pre-traffic hook** runs synthetic smoke tests against that version; shift **all at once**; post-traffic check; automatic rollback if a hook fails or the error alarm fires; one-command manual rollback.
- **GitHub OIDC roles** written against the real `sub` formats (`repo:…:environment:production` for the deploy job), deploy job in a protected environment.
- **CI:** root `go vet ./...`, `gofmt -l cmd internal`, `govulncheck ./...` and `-mode=binary`; infra `go vet .`; tests with short fuzz; `cdk synth` with a dummy account and no credentials; CodeQL; dependency review; secret-pattern scan. Node 24 pinned; Dependabot groups `aws-cdk` (npm) with `awscdk/v2` (gomod).
- **Throttling:** ~1 rps on unauthenticated `.well-known` routes; AWS Budget alarm.
- **Inspector:** enabled, but Go coverage in `provided.al2023` is undocumented; confirm via its coverage API after deploy and treat `govulncheck` as the real control.

## 7. Milestones (stop for your confirmation at the starred ones)

1. ★ Step 0 stub deployed; you test `hello`. **Done.**
2. ★ Auth hardening (§3); you reconnect the connector once. **Deployed 2026-11-11** (scoped bootstrap + boundary, in-Lambda RS256 verification, custom scope, rotating 365-day refresh tokens, new client, user out of the template, discovery throttles, 28 s timeout); `scripts/smoke-oauth.sh` passes. **Done:** reconnected and `hello` called successfully with in-Lambda verification of real, resource-bound tokens (aud = connector URL, accepted by both gateway and Lambda).
3. `skylight-login` tool (accepts a pasted URL or bare code, exchanges immediately; also imports a refresh token); you authorise once; read-only live calls **from the laptop and from a Lambda** to settle: token response shape and rotation, `expires_in`, old-token reuse behaviour, parallel-refresh behaviour, datacenter-IP blocking, required headers, refresh-token idle expiry, plus the API unknowns in SKYLIGHT_API.md §6. Scrub into fixtures. **Done from the laptop 2026-11-11** (`skylight-login`, `skylight-probe`, `skylight-scrub`; results in SKYLIGHT_API.md §6; fixtures in `internal/skylight/testdata`). Moved to milestone 4: the from-Lambda probe (datacenter-IP blocking), refresh-token idle expiry, 429 behaviour.
4. Token store + lease + Skylight client, with tests. **Done 2026-11-11:** `internal/grant` (DynamoDB store, lease, commit-then-use), `internal/calendar` (strict parsers, client), grant table + KMS key deployed, grant imported (the table is the only holder), canary entry point. From Lambda: reads and refresh work, no IP blocking.
5. Three tools + contract/fuzz tests.
6. CI, deploy pipeline, canary, Dependabot, Inspector check.
7. ★ v1 done end to end. Only then v2 (write tools behind an off-by-default flag, not registered otherwise).

## 8. Decisions (settled)

1. Rotation lock: DynamoDB lease, in the same item as the tokens (revised).
2. AWS SDK v2 (DynamoDB only) rather than hand-rolled SigV4 (revised: no Secrets Manager).
3. Inspector: Lambda standard scanning enabled in us-east-2 on 2026-11-11 (code scanning left off). Still to verify it covers Go in `provided.al2023`.
4. Canary: EventBridge Scheduler inside AWS, SNS email alert (revised; replaces the GitHub-invoked canary).
4a. Retrospective decisions accepted 2026-11-11: in-Lambda JWT verification; DynamoDB token store; in-AWS canary; pre-traffic hook + all-at-once deploy; Cognito custom scope, refresh lifetime and new client; scoped CDK bootstrap.
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
