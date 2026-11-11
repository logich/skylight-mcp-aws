# skylight-mcp

A personal, single-user [MCP](https://modelcontextprotocol.io) server that lets Claude read a family's [Skylight](https://www.ourskylight.com) calendar, including which family members each event belongs to.

## Why

Skylight's iCloud calendar sync drops the tags that link events to family members, so "what does each of the kids have this week?" can't be answered from the synced calendar. This server reads Skylight directly and keeps those tags.

## What it does

It runs as a claude.ai custom connector and offers three read-only tools:

| Tool | Returns |
|---|---|
| `list_family_members` | the people events can be tagged with |
| `list_events` | events in a time range, optionally for one member, with members by name |
| `get_event` | one event by id |

Write tools (create, update, delete) are planned, behind a flag that is off by default.

## How it is built

- Go on AWS Lambda (arm64) behind API Gateway, deployed with the AWS CDK.
- **Access:** OAuth through Amazon Cognito, locked to one account. The function verifies every token's signature itself.
- **Skylight sign-in:** stored in one KMS-encrypted DynamoDB item. Skylight rotates its refresh token on every use, so writes are conditional and only one invocation refreshes at a time.
- **Monitoring:** a scheduled canary inside AWS emails the owner if Skylight access breaks.
- **Deploys:** GitHub Actions, after the owner approves each one. A pre-traffic check rolls back a bad version.

Skylight has no public API. This uses its private API, as reverse-engineered by [logich/skylight_calendar](https://github.com/logich/skylight_calendar) and verified live. It can break whenever Skylight changes.

## Documentation

- [SPEC.md](SPEC.md): requirements
- [PLAN.md](PLAN.md): design, status and open items
- [SKYLIGHT_API.md](SKYLIGHT_API.md): what is known about Skylight's private API
- [DEPENDENCIES.md](DEPENDENCIES.md): why each dependency is here
- [CLAUDE.md](CLAUDE.md): working rules and commands

This is a personal project, not affiliated with Skylight. It is public so GitHub's free security tooling applies. It holds no credentials, account identifiers or real calendar data.
