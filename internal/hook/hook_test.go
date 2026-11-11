package hook

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/codedeploy"
	cdtypes "github.com/aws/aws-sdk-go-v2/service/codedeploy/types"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	"github.com/logich/skylight-mcp-aws/internal/canary"
)

// fakeVersion answers like the server would: discovery 200, /mcp 401,
// canary {ok}. Fields let tests break one behaviour at a time.
type fakeVersion struct {
	discovery, mcp, forged int
	canaryOK               bool
	funcErr                bool
	calls                  []string
}

func (f *fakeVersion) Invoke(_ context.Context, in *lambda.InvokeInput, _ ...func(*lambda.Options)) (*lambda.InvokeOutput, error) {
	if aws.ToString(in.FunctionName) != "arn:target:42" {
		return nil, errors.New("wrong target")
	}
	if f.funcErr {
		return &lambda.InvokeOutput{FunctionError: aws.String("Unhandled")}, nil
	}
	if canary.IsCanary(in.Payload) {
		f.calls = append(f.calls, "canary")
		b, _ := json.Marshal(map[string]any{"ok": f.canaryOK, "stage": "token", "error_class": "reauthorize"})
		return &lambda.InvokeOutput{Payload: b}, nil
	}
	var ev events.APIGatewayV2HTTPRequest
	_ = json.Unmarshal(in.Payload, &ev)
	status := f.mcp
	switch {
	case ev.RawPath != "/mcp":
		status = f.discovery
	case ev.RequestContext.Authorizer != nil:
		status = f.forged
	}
	f.calls = append(f.calls, ev.RequestContext.HTTP.Method+" "+ev.RawPath)
	b, _ := json.Marshal(events.APIGatewayV2HTTPResponse{StatusCode: status})
	return &lambda.InvokeOutput{Payload: b}, nil
}

type fakeCD struct{ status cdtypes.LifecycleEventStatus }

func (f *fakeCD) PutLifecycleEventHookExecutionStatus(_ context.Context, in *codedeploy.PutLifecycleEventHookExecutionStatusInput,
	_ ...func(*codedeploy.Options)) (*codedeploy.PutLifecycleEventHookExecutionStatusOutput, error) {
	f.status = in.Status
	return &codedeploy.PutLifecycleEventHookExecutionStatusOutput{}, nil
}

func healthy() *fakeVersion {
	return &fakeVersion{discovery: 200, mcp: 401, forged: 401, canaryOK: true}
}

func TestHookReportsOutcome(t *testing.T) {
	ev := Event{DeploymentID: "d-1", LifecycleEventHookExecutionID: "e-1"}
	cases := map[string]struct {
		v    *fakeVersion
		want cdtypes.LifecycleEventStatus
	}{
		"healthy":                {healthy(), cdtypes.LifecycleEventStatusSucceeded},
		"discovery broken":       {&fakeVersion{discovery: 500, mcp: 401, forged: 401, canaryOK: true}, cdtypes.LifecycleEventStatusFailed},
		"auth open":              {&fakeVersion{discovery: 200, mcp: 200, forged: 401, canaryOK: true}, cdtypes.LifecycleEventStatusFailed},
		"forged claims accepted": {&fakeVersion{discovery: 200, mcp: 401, forged: 200, canaryOK: true}, cdtypes.LifecycleEventStatusFailed},
		"canary fails":           {&fakeVersion{discovery: 200, mcp: 401, forged: 401, canaryOK: false}, cdtypes.LifecycleEventStatusFailed},
		"function errors":        {&fakeVersion{funcErr: true}, cdtypes.LifecycleEventStatusFailed},
	}
	for name, c := range cases {
		cd := &fakeCD{}
		h := Hook{Lambda: c.v, CodeDep: cd, Target: "arn:target:42"}
		if err := h.Handle(context.Background(), ev); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if cd.status != c.want {
			t.Errorf("%s: reported %s, want %s", name, cd.status, c.want)
		}
	}
}

func TestHookRejectsNonLifecycleEvents(t *testing.T) {
	h := Hook{Lambda: healthy(), CodeDep: &fakeCD{}, Target: "arn:target:42"}
	if err := h.Handle(context.Background(), Event{}); err == nil {
		t.Fatal("accepted an empty event")
	}
}

func TestHookWithoutTargetFails(t *testing.T) {
	cd := &fakeCD{}
	_ = Hook{Lambda: healthy(), CodeDep: cd}.Handle(context.Background(), Event{DeploymentID: "d", LifecycleEventHookExecutionID: "e"})
	if cd.status != cdtypes.LifecycleEventStatusFailed {
		t.Fatalf("status %s", cd.status)
	}
}
