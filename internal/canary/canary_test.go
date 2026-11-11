package canary

import (
	"encoding/json"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func TestIsCanary(t *testing.T) {
	if !IsCanary(json.RawMessage(`{"skylight_mcp_canary":true}`)) {
		t.Fatal("canary event not recognised")
	}
	// An API Gateway event can never be mistaken for one, even if the HTTP
	// body or headers carry the field name.
	var ev events.APIGatewayV2HTTPRequest
	ev.RawPath = "/mcp"
	ev.Body = `{"skylight_mcp_canary":true}`
	ev.Headers = map[string]string{"skylight_mcp_canary": "1"}
	ev.RequestContext.HTTP.Method = "POST"
	b, _ := json.Marshal(ev)
	if IsCanary(b) {
		t.Fatal("API Gateway event treated as canary")
	}
	if IsCanary(json.RawMessage(`{"skylight_mcp_canary":true,"requestContext":{}}`)) {
		t.Fatal("event with requestContext treated as canary")
	}
	for _, s := range []string{``, `[]`, `"x"`, `{}`} {
		if IsCanary(json.RawMessage(s)) {
			t.Fatalf("%q treated as canary", s)
		}
	}
}
