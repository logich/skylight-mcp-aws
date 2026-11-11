package lambdahttp

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/aws/aws-lambda-go/events"
)

func event(method, path, query, body string, b64 bool) events.APIGatewayV2HTTPRequest {
	var ev events.APIGatewayV2HTTPRequest
	ev.RawPath, ev.RawQueryString, ev.Body, ev.IsBase64Encoded = path, query, body, b64
	ev.Headers = map[string]string{"content-type": "application/json", "authorization": "Bearer abc"}
	ev.RequestContext.DomainName = "abc.execute-api.us-east-2.amazonaws.com"
	ev.RequestContext.HTTP.Method = method
	return ev
}

func TestRoundTrip(t *testing.T) {
	var gotHost, gotBody, gotQuery, gotAuthz string
	h := Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotHost, gotBody, gotQuery, gotAuthz = r.Host, string(b), r.URL.RawQuery, r.Header.Get("Authorization")
		w.Header().Set("X-Test", "yes")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("ok"))
	}))

	ev := event("POST", "/mcp", "a=1", base64.StdEncoding.EncodeToString([]byte(`{"x":1}`)), true)
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
	if gotAuthz != "Bearer abc" {
		t.Fatalf("Authorization header not passed through: %q", gotAuthz)
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
