package lambdahttp

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"

	"github.com/logich/skylight-mcp-aws/internal/auth"
)

func event(method, path, query, body string, b64 bool) events.APIGatewayV2HTTPRequest {
	var ev events.APIGatewayV2HTTPRequest
	ev.RawPath, ev.RawQueryString, ev.Body, ev.IsBase64Encoded = path, query, body, b64
	ev.Headers = map[string]string{"content-type": "application/json"}
	ev.RequestContext.DomainName = "abc.execute-api.us-east-2.amazonaws.com"
	ev.RequestContext.HTTP.Method = method
	return ev
}

func TestRoundTrip(t *testing.T) {
	var gotHost, gotBody, gotQuery string
	var gotClaims map[string]string
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotHost, gotBody, gotQuery, gotClaims = r.Host, string(b), r.URL.RawQuery, auth.ClaimsFrom(r.Context())
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))

	ev := event("POST", "/mcp", "a=1", base64.StdEncoding.EncodeToString([]byte(`{"x":1}`)), true)
	ev.RequestContext.Authorizer = &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
		JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{Claims: map[string]string{"sub": "s"}},
	}
	resp, err := h(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusCreated || resp.Body != "ok" || resp.Headers["x-test"] != "yes" {
		t.Fatalf("unexpected response: %+v", resp)
	}
	if gotHost != "abc.execute-api.us-east-2.amazonaws.com" || gotBody != `{"x":1}` || gotQuery != "a=1" {
		t.Fatalf("request not translated: host=%q body=%q query=%q", gotHost, gotBody, gotQuery)
	}
	if gotClaims["sub"] != "s" {
		t.Fatalf("claims not propagated: %v", gotClaims)
	}
}

func TestNoAuthorizerMeansNoClaims(t *testing.T) {
	var claims map[string]string
	h := Handler(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { claims = auth.ClaimsFrom(r.Context()) }))
	if _, err := h(context.Background(), event("GET", "/x", "", "", false)); err != nil {
		t.Fatal(err)
	}
	if claims != nil {
		t.Fatalf("expected no claims, got %v", claims)
	}
}

func TestBadBase64Is400(t *testing.T) {
	h := Handler(http.NotFoundHandler())
	resp, _ := h(context.Background(), event("POST", "/mcp", "", "!!not-base64!!", true))
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
}

func TestBinaryBodyIsBase64(t *testing.T) {
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte{0xff, 0xfe, 0x00}) }))
	resp, _ := h(context.Background(), event("GET", "/", "", "", false))
	if !resp.IsBase64Encoded {
		t.Fatal("non-UTF-8 body must be base64 encoded")
	}
}
