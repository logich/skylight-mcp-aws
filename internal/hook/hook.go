// Package hook is the CodeDeploy pre-traffic hook: before the "live" alias
// moves to a new Lambda version, it invokes that exact version and checks
//
//  1. the OAuth discovery document answers 200 without a token,
//  2. /mcp without a token answers 401 (auth fails closed),
//  3. a direct invoke carrying forged API Gateway authorizer claims gets 401,
//  4. the canary passes (grant store, token, Skylight reads).
//
// It reports Succeeded or Failed to CodeDeploy; Failed rolls the deployment
// back and traffic never reaches the new version.
package hook

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	cdtypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"
)

// Event is what CodeDeploy sends a lifecycle hook.
type Event struct {
	DeploymentID                  string `json:"DeploymentId"`
	LifecycleEventHookExecutionID string `json:"LifecycleEventHookExecutionId"`
}

// Invoker calls a Lambda function version synchronously.
type Invoker interface {
	Invoke(ctx context.Context, in *lambda.InvokeInput, opts ...func(*lambda.Options)) (*lambda.InvokeOutput, error)
}

// Reporter tells CodeDeploy the outcome.
type Reporter interface {
	PutLifecycleEventHookExecutionStatus(ctx context.Context, in *codedeploy.PutLifecycleEventHookExecutionStatusInput,
		opts ...func(*codedeploy.Options)) (*codedeploy.PutLifecycleEventHookExecutionStatusOutput, error)
}

// Hook runs the checks against Target (a version ARN).
type Hook struct {
	Lambda  Invoker
	CodeDep Reporter
	Target  string
	Host    string // the API's host, for realistic HTTP events (may be empty)
	Logf    func(format string, a ...any)
}

// Handle runs the checks and reports the result. It returns an error only if
// reporting itself fails (CodeDeploy then times the hook out and rolls back).
func (h Hook) Handle(ctx context.Context, ev Event) error {
	if ev.DeploymentID == "" || ev.LifecycleEventHookExecutionID == "" {
		return errors.New("not a CodeDeploy lifecycle event")
	}
	status := cdtypes.LifecycleEventStatusSucceeded
	if err := h.Check(ctx); err != nil {
		status = cdtypes.LifecycleEventStatusFailed
		h.logf("pre-traffic check failed: %v", err)
	} else {
		h.logf("pre-traffic checks passed")
	}
	_, err := h.CodeDep.PutLifecycleEventHookExecutionStatus(ctx, &codedeploy.PutLifecycleEventHookExecutionStatusInput{
		DeploymentId:                  aws.String(ev.DeploymentID),
		LifecycleEventHookExecutionId: aws.String(ev.LifecycleEventHookExecutionID),
		Status:                        status,
	})
	return err
}

func (h Hook) logf(format string, a ...any) {
	if h.Logf != nil {
		h.Logf(format, a...)
	}
}

// Check runs every check against the target version.
func (h Hook) Check(ctx context.Context) error {
	if h.Target == "" {
		return errors.New("no target version configured")
	}
	checks := []struct {
		name   string
		method string
		path   string
		body   string
		claims map[string]string
		want   int
	}{
		{"discovery is public", http.MethodGet, "/.well-known/oauth-protected-resource/mcp", "", nil, 200},
		{"mcp without a token is refused", http.MethodPost, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`, nil, 401},
		{"forged authorizer claims are refused", http.MethodPost, "/mcp", `{"jsonrpc":"2.0","id":1,"method":"tools/list"}`,
			map[string]string{"sub": "forged", "scope": "skylight-mcp/invoke", "token_use": "access"}, 401},
	}
	for _, c := range checks {
		var ev events.APIGatewayV2HTTPRequest
		ev.RawPath = c.path
		ev.Body = c.body
		ev.Headers = map[string]string{"content-type": "application/json", "accept": "application/json, text/event-stream"}
		ev.RequestContext.DomainName = h.Host
		ev.RequestContext.HTTP.Method = c.method
		if c.claims != nil {
			ev.RequestContext.Authorizer = &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
				JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{Claims: c.claims},
			}
		}
		payload, _ := json.Marshal(ev)
		out, err := h.invoke(ctx, payload)
		if err != nil {
			return fmt.Errorf("%s: %w", c.name, err)
		}
		var resp events.APIGatewayV2HTTPResponse
		if err := json.Unmarshal(out, &resp); err != nil || resp.StatusCode != c.want {
			return fmt.Errorf("%s: status %d, want %d", c.name, resp.StatusCode, c.want)
		}
	}
	out, err := h.invoke(ctx, []byte(`{"skylight_mcp_canary":true}`))
	if err != nil {
		return fmt.Errorf("canary: %w", err)
	}
	var r struct {
		OK         bool   `json:"ok"`
		ErrorClass string `json:"error_class"`
		Stage      string `json:"stage"`
	}
	if err := json.Unmarshal(out, &r); err != nil || !r.OK {
		return fmt.Errorf("canary failed at %q (%s)", r.Stage, r.ErrorClass)
	}
	return nil
}

func (h Hook) invoke(ctx context.Context, payload []byte) ([]byte, error) {
	out, err := h.Lambda.Invoke(ctx, &lambda.InvokeInput{FunctionName: aws.String(h.Target), Payload: payload})
	if err != nil {
		return nil, errors.New("invoke failed")
	}
	if out.FunctionError != nil {
		return nil, fmt.Errorf("function error %q", aws.ToString(out.FunctionError))
	}
	return out.Payload, nil
}
