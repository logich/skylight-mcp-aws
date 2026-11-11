# Retrospective: planning and Step 0 (2026-11-11)

Scope: from reading SPEC.md to a working `hello` call through the claude.ai connector (commit `19400de`). Part 1 is what happened in the session. Part 2 is an adversarial review of the plan's next steps, done by three independent reviewers who were asked to break the plan's assumptions with evidence, then checked by me.

## Outcome

Step 0 met its goal: a stub MCP server on Lambda (`provided.al2023`, arm64) behind API Gateway HTTP API, gated by Cognito OAuth and locked to one user, called successfully from Claude. It took three connector attempts by you before it worked.

## Part 1: what the session taught us

### What went well

- **Read the code, not the docs.** Reading the HA integration's code showed Skylight moved to OAuth with rotating refresh tokens in July 2026, and that the iOS repo's own API guide describes paths its code never calls. Following the docs would have built the wrong auth.
- **Checked an assumption before relying on it.** Checking the Lambda account limit (10) killed "reserved concurrency of 1" before any code depended on it.
- **Security defaults held.** Fail-closed `Authorize`, the server deployed with an empty allowlist first, least-privilege Lambda role, no secrets or identifiers committed to a public repo (scanned before commit).
- **Instrumenting the failure found it.** Gateway access logs turned "it never prompts" into a precise diagnosis on the next attempt.

### What went poorly, and the lesson

| # | What happened | Cost | Lesson / rule going forward |
|---|---|---|---|
| 1 | I asked you design questions (Google federation, Skylight email+password) **before** reading the reference repos. Both answers were later overturned (you don't use Google for Claude; the HA approach is OAuth, not password). | Two rounds of rework and confusion. | Read the primary sources first; ask only questions the sources can't answer. |
| 2 | I predicted the Cognito/DCR/RFC 8414 risk in the plan but **handed you an untested connector anyway**. Three attempts were needed: no route for the AS metadata, then the protected-resource document pointing at Cognito's issuer. | Three round trips of your time; the cause was guessable offline. | Before asking you to test, run the client's discovery chain myself: 401 → RFC 9728 doc → follow `authorization_servers` → RFC 8414 metadata → authorize redirect. Make it a scripted smoke test (`scripts/smoke-oauth.sh`). |
| 3 | No gateway-level logging at first, so requests the gateway answered itself (404s, authorizer 401s) were invisible. | One diagnosis round. | Observability first: add access logs before the first external test, not after the first failure. |
| 4 | My connector setup instructions were vague ("add a custom connector… advanced settings"), and I didn't warn that Cognito's invitation email has no sign-in link. | You had to ask twice. | Give exact field-by-field steps with the actual values, and say what each email or page will look like. |
| 5 | The Cognito client secret ended up in this session's transcript: I said "run it in your own terminal" but you ran it through the session's `!` prompt. | Low (local transcript only), but avoidable. | Say explicitly "not via the `!` prompt here". Better: copy secrets to the clipboard (`pbcopy`) instead of printing them. |
| 6 | I wrote your email into PLAN.md, a file bound for a public repo. Caught and removed before commit. | None, but close. | Treat every file as public from the start; keep the pre-commit scan as a CI check (secret-pattern grep plus GitHub push protection). |
| 7 | I told you Dependabot works the same on private repos; that was an unverified claim about your GitHub plan. | Corrected, but it was a confident wrong statement. | Check before asserting facts about your accounts. |
| 8 | Smaller friction: `cdk bootstrap` synthesises the app (needed a placeholder context); API Gateway rejected an access-log format without `$context.requestId`; `gofmt -l .` at the root, and `go vet ./...` / `govulncheck ./...` inside `infra/`, crawl `infra/node_modules` (root `go vet ./...` does not include `infra/`, a separate module). | A failed deploy (rolled back cleanly) and some noise. | These are now in scripts; CI must scope Go commands to our packages. |
| 9 | The Cognito admin API reports no enrolled MFA method for your user, although sign-in required TOTP. Unexplained. | Unknown. | Verify on the next sign-in that a TOTP code is asked for; if not, enforce `SOFTWARE_TOKEN_MFA` explicitly. |
| 10 | The deployed build reports version `dev` because there was no commit at build time. | Minor. | Now that commits exist, deploy from a clean tree so the version is the git SHA. |

| 11 | After the auth hardening, the connector connected but listed **no tools**: claude.ai sends RFC 8707 `resource`, Cognito (since Oct 2025) then sets the access token `aud` to that URL, and the gateway authorizer only accepted the client id. A reviewer had flagged exactly this; the smoke test didn't mirror claude.ai's request. | One more round trip for you. | The smoke test must send exactly what the real client sends (now includes `resource`). Act on reviewer "if X then Y" warnings by testing X. Fixed: gateway accepts the connector URL as audience; the Lambda requires `aud` to equal it whenever present. |

### Process changes adopted

1. Read primary sources before asking design questions.
2. Before any user-facing test, run a scripted end-to-end check of the same path the user will exercise, with logs on.
3. Every file is public: pre-commit scan, no identifiers in code, deploy-time values only.
4. Handling secrets: never print to the session; clipboard or user-run terminal only.

## Part 2: adversarial review of next steps

Three independent reviewers attacked (a) the Skylight token lifecycle, (b) connector OAuth and the auth layer, (c) CI, deployment and operations. I verified the load-bearing claims against the code, the HA reference and the live AWS configuration before accepting them; "verified" below means I checked it myself.

### Critical / high: the plan must change

| # | Finding | Evidence | Status |
|---|---|---|---|
| A1 | **Forged claims via direct Lambda invoke.** `lambdahttp` trusts `authorizer.jwt.claims` from the event; signature checks happen only in API Gateway. Any principal with `lambda:InvokeFunction` can impersonate you. Today only API Gateway (route-scoped) and account admins can invoke, so it is latent, but the planned GitHub canary role would open it. IAM cannot restrict the invoke payload. Found independently by two reviewers. | `internal/lambdahttp/lambdahttp.go:42-44`; live resource policy | Verified |
| A2 | **CDK bootstrap uses `AdministratorAccess`** as the CloudFormation execution policy, so the "narrow" deploy user (and any future CI role) can deploy an IAM admin: full account takeover. | bootstrap output | Verified |
| A3 | **Cold starts would each spend a refresh.** The plan kept the Skylight access token only in memory; HA persists it. Every new Lambda environment would refresh, multiplying rotations and races. | HA `__init__.py:85-93` | Verified |
| A4 | **Secrets Manager is the wrong store for a rotating token.** AWS advises against `PutSecretValue` more than once per 10 min and versions accumulate; there is no compare-and-set. The single atomic "commit new tokens + release lease" the design needs is one conditional DynamoDB `UpdateItem`. | PutSecretValue API reference | Plausible; doc quoted by reviewer, not re-fetched |
| A5 | **Token loss window.** If Skylight rotates and the Lambda dies before persisting, the grant is gone. Mitigate with a short token-call deadline and persist retries; residual risk accepted (recovery = re-authorise). | design | Agreed |
| A6 | **Lease TTL (15 s) > Lambda timeout (10 s);** HA allows 15–20 s per call. | `infra/main.go:142`, HA `api.py:255,346` | Verified |
| A7 | **Canary can't work as planned:** the handler only decodes API Gateway events; GitHub OIDC `sub` can't distinguish a scheduled run from a push to main; environment jobs get `sub=…:environment:<name>`; GitHub disables cron in idle public repos after 60 days. | `cmd/server/main.go`, GitHub OIDC docs | Verified (code); docs per reviewer |
| A8 | **Connector dies at day 30.** Cognito refresh tokens are valid 30 days with rotation off. | live client config | Verified |
| A9 | **SPEC §8.4 auth tests are not met.** Malformed, bad-signature, `alg=none`, wrong-pool tokens are tested nowhere because the gateway does that work. | `internal/auth/auth_test.go` | Verified |
| A10 | **PR `cdk synth` would leak your email** (the Cognito user is in the template) and fails without an account. | `infra/main.go:96-104,223` | Verified |

### Medium / low

- `openid` scope gives an ID token whose `iss` (Cognito) contradicts our advertised issuer; our `openid-configuration` document is incomplete OIDC. Fix: custom resource-server scope (e.g. `mcp/invoke`), drop `openid`/`email`, drop the OIDC routes, check `scope` in `Authorize`, restrict client auth flows (currently Cognito defaults incl. SRP).
- CodeDeploy gradual shifting is feasible but meaningless at single-user traffic (alarms never get data). Proposal: pre-traffic hook smoke test, all-at-once shift, alarm and hook rollback.
- Inspector coverage of Go in `provided.al2023` is undocumented; treat `govulncheck` (source and `-mode=binary`) as the real control and confirm Inspector via its coverage API after deploy.
- Unauthenticated `.well-known` routes share the 10-concurrency account limit; per-route throttle ~1 rps plus an AWS Budget alarm.
- Skylight facts still unproven: rotation on every use, `expires_in`, reuse detection (could revoke the grant), parallel-refresh behaviour, datacenter-IP blocking. These become explicit live checks in milestone 2, run from Lambda as well as the laptop.
- Rotate the Cognito client secret (it is in a local transcript); make `show-client-secret.sh` copy to the clipboard.
- Pin Node 24 in CI; group Dependabot updates for `aws-cdk` (npm) and `awscdk/v2` (gomod).

### Where reviewers were wrong or overstated

- "Root `go vet ./...` crawls `infra/`" was my own claim, corrected: only `gofmt -l .` and `./...` *inside* `infra/` hit `node_modules`.
- "Rotation is unproven" is technically right (no capture) but the HA author observed it; treat it as likely and design for both.

## Decisions needed (they change SPEC.md)

1. **Verify JWT signatures inside the Lambda** (stdlib RSA + cached Cognito JWKS), keeping the gateway authorizer as a first layer. Closes A1 and A9; reverses PLAN §4.
2. **Store Skylight tokens and the lease in one KMS-encrypted DynamoDB item** instead of Secrets Manager (amend SPEC §5).
3. **Canary on EventBridge Scheduler inside AWS, alerting by SNS email**, instead of GitHub Actions (amend the canary choice).
4. **Deploy: pre-traffic hook + all-at-once + rollback** instead of gradual shifting (amend SPEC §9).
5. **Cognito: custom scope, longer or rotating refresh tokens, rotate client secret.** Requires reconnecting the connector once.
6. **Re-bootstrap CDK with a scoped execution policy and permissions boundary** before CI gets any role (A2). No spec change; do first.
