# Skylight MCP Server: Specification

## 0. Step 0: prove the connector path works (do this first)

It is not yet confirmed that a custom connector I add will be usable from Claude Duet. Settle that before any Skylight work:

1. Build a stub MCP server in Go with one tool, `hello`, that returns a fixed string and the server's build version.
2. Deploy it with the same stack the real server will use: Lambda (`provided.al2023`, arm64), API Gateway HTTP API, and the OAuth setup from §6, locked to my account.
3. Stop and tell me it's deployed, with the URL to add. I'll add it as a custom connector in claude.ai and ask Claude Duet to call `hello`.
4. Continue to §2 onward only after I confirm the call worked. If it doesn't, help me diagnose (OAuth flow, transport, CORS, connector settings) before building anything else.

Keep the stub's infrastructure code; the real server reuses it.

## 1. Purpose

Build a remote MCP server that lets Claude read, and later edit, my family's Skylight calendar, including the tags that link each event to family members. Skylight's iCloud sync drops those tags, which is why this exists.

The server will be added to my claude.ai account as a custom connector. It is for personal use by one account only.

## 2. Prior work to reuse

Read these before writing any code:

- **iOS app (Swift/SwiftUI):** https://github.com/logich/Skylight-swift. It fully reimplements the Skylight API client and includes a six-guide documentation package (technical spec, API integration guide, roadmap and others). This is the primary reference.
- **Home Assistant Skylight integration:** https://github.com/logich/skylight_calendar. Secondary reference for the same API.
- **Background only:** `@eaglebyte/skylight-mcp` (unofficial MCP server). Do not copy its code.

Skylight has no public API. Both implementations use its private, reverse-engineered API.

**First deliverable:** `SKYLIGHT_API.md`, covering endpoints, auth and token refresh flow, and data models (events, family members/profiles, and the event-to-member tag). Note any place where the iOS and HA implementations disagree.

## 3. Language and dependencies

- **Go**, current stable release, built as a single static binary.
- Use the official MCP Go SDK with the Streamable HTTP transport, run stateless.
- Prefer the standard library (`net/http`, `crypto/tls`, `encoding/json`) for everything else. Every additional module must be justified in `DEPENDENCIES.md` with why the standard library won't do.
- Goal: the smallest dependency tree that meets the spec, to minimise security maintenance.

## 4. Tools

### v1 (read-only, ship first)

| Tool | Inputs | Returns |
|---|---|---|
| `list_family_members` | none | id, name, colour |
| `list_events` | `start`, `end` (RFC 3339), optional `member` | events with title, start, end, all-day flag, location, notes, and member tags as **names** (not just ids) |
| `get_event` | `event_id` | one event, same shape |

### v2 (behind a config flag, off by default)

- `create_event`, `update_event`, `delete_event`, with members assignable by name.
- Write tools must not be registered at all unless the flag is on.

Later and out of scope for now: chores, lists, tasks.

## 5. AWS hosting

- **Compute:** Lambda on the OS-only runtime (`provided.al2023`, arm64) behind API Gateway (HTTP API).
- **Secrets:** Skylight tokens (refresh token, access token, device fingerprint) in a single DynamoDB item encrypted with a customer-managed KMS key, updated only through conditional writes. Never in environment variables, code or logs. (Revised 2026-11-11: originally Secrets Manager, which suits rarely-changing secrets but not a token that rotates on use and needs compare-and-set.)
- **IAM:** least privilege. The function may read and write only its own token table, use only its own KMS key, and write only its own logs. The CDK bootstrap uses a scoped CloudFormation execution policy and a permissions boundary, never `AdministratorAccess`.
- **Logging:** CloudWatch with structured logs that never contain tokens, credentials or event content.
- **Infrastructure as code:** CDK or Terraform. Pick one and explain why in the plan.

## 6. Authentication to the server

- Claude custom connectors authenticate with OAuth. Put the endpoint behind OAuth 2.1 (Cognito is acceptable).
- Lock access to my account alone. Any other identity is rejected.
- The authorization check is a small package with one entry point (`auth.Check`), simple enough to reason about fully, and exhaustively tested and fuzzed (see §8).
- The function verifies the bearer token's signature itself (against Cognito's published keys), in addition to any API Gateway authorizer. Identity claims supplied in the invocation event are never trusted, so invoking the function directly cannot impersonate the user.
- Tokens carry a dedicated scope for this server, and the check requires it.

## 7. Robustness

- Refresh Skylight tokens automatically, and fail with a clear error when refresh fails.
- Respect rate limits with backoff.
- When Skylight's response shape changes, return a clear "upstream API changed" error rather than partial or wrong data.
- Timeouts on every outbound call.

## 8. Testing

All tests run in CI with no live Skylight calls:

1. **Recorded API tests:** an `httptest` server replays scrubbed Skylight responses (fixtures committed, with personal data replaced).
2. **MCP contract tests:** call every tool through an MCP client and compare output to golden files, so an SDK update cannot silently change what Claude sees.
3. **Fuzz tests:** Go native fuzzing on every response parser. Parsers must never panic.
4. **Auth tests:** prove the authorization check rejects every identity except mine, including missing, expired and malformed tokens, bad signatures, unknown keys, `alg=none` and other algorithms, wrong issuer, client or scope.

Separately, outside CI:

5. **Daily live canary:** a scheduled check inside AWS against the real Skylight API that emails me (via SNS) if it starts failing. This catches Skylight changing its API. It uses the server's own token store and cannot reach the MCP tools.

## 9. Updates and deployment

- The code lives in a **public** GitHub repo, `https://github.com/logich/skylight-mcp-aws`, so GitHub's free security features apply: secret scanning with push protection, CodeQL code scanning, dependency review on PRs, and Dependabot alerts and security updates. Enable and keep them on. Because the repo is public, nothing sensitive may be committed: no credentials or tokens, no AWS account ID, and only scrubbed fixtures (scan them for emails, names, ids and tokens before committing).
- The deploy role trusts GitHub OIDC only for this repo's `main` branch (and the canary role only for the scheduled workflow), so a fork or pull request can never deploy or invoke anything. Deploy jobs run in a protected GitHub environment.
- Dependabot or Renovate opens PRs for Go and module updates.
- CI runs `go vet`, `govulncheck` and all tests on every PR.
- Merging to main builds and deploys automatically.
- Publish a new function version, run smoke tests against it in a pre-traffic hook, then shift all traffic at once, with automatic rollback if a hook fails or the error alarm fires. (Revised 2026-11-11: gradual shifting has no signal at single-user traffic.)
- `cdk synth` in CI needs no real account, credentials or personal values, so pull-request logs leak nothing.
- Enable Amazon Inspector scanning for the function.

## 10. Working agreement

- Before writing code, show me `SKYLIGHT_API.md` and a short implementation plan, and ask me anything unclear.
- Build v1 end to end (including tests and deployment) before starting v2.
- Do not make live calls to Skylight from tests, and do not commit real data or credentials.
