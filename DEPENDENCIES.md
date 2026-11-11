# Dependencies

Every direct dependency of the server module, and why it is here (SPEC §9, PLAN §5). Indirect modules come in through these. `govulncheck` (source and binary mode) is the vulnerability control; Dependabot proposes updates (milestone 6).

| Module | Why | Instead of |
|---|---|---|
| `github.com/modelcontextprotocol/go-sdk` | The spec requires the official MCP SDK (streamable HTTP, stateless, JSON responses). | — |
| `github.com/aws/aws-lambda-go` | Lambda runtime loop and API Gateway v2 event types. | Hand-rolling the Runtime API |
| `github.com/aws/aws-sdk-go-v2` (+ `config`, `service/dynamodb`) | Grant store reads and conditional writes. SigV4 signing and credential handling are security-critical, so they are imported, not hand-rolled. KMS encryption is server-side, so no KMS client. | Raw HTTP + homemade SigV4 |

Deliberately **not** used:

- **JWT libraries.** RS256 verification of one key type is done with the standard library (`internal/auth`), small enough to test and fuzz exhaustively.
- **OAuth libraries** for Skylight. Its token endpoint needs non-standard form fields and must never echo a body into errors; `internal/skylight` is about 300 lines with tests.
- **`feature/dynamodb/attributevalue`.** The item has a handful of fields, mapped by hand in `internal/grant/dynamo.go`.

The CDK app (`infra/`) is a separate module with its own `go.mod` (`aws-cdk-go`, `constructs-go`, `jsii-runtime-go`) and an npm-pinned CDK CLI; none of it ships in the Lambda.
