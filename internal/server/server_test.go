package server

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/logich/skylight-mcp-aws/internal/auth"
)

const (
	issuer = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_TESTPOOL"
	client = "client-abc"
	sub    = "11111111-2222-3333-4444-555555555555"
)

var now = time.Unix(1_800_000_000, 0)

func goodClaims() map[string]string {
	return map[string]string{
		"iss": issuer, "token_use": "access", "client_id": client, "sub": sub,
		"exp": strconv.FormatInt(now.Unix()+600, 10),
	}
}

// startServer serves the handler and injects claims the way lambdahttp would
// after API Gateway's JWT authorizer has run. A nil claims map simulates a
// request that arrives with no authorizer context.
func startServer(t *testing.T, claims map[string]string) *httptest.Server {
	t.Helper()
	h := New(Options{
		Auth:    auth.Config{Issuer: issuer, ClientID: client, AllowedSub: sub},
		Version: "test-version",
		Now:     func() time.Time { return now },
	})
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if claims != nil {
			r = r.WithContext(auth.WithClaims(r.Context(), claims))
		}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestHelloThroughMCPClient(t *testing.T) {
	ts := startServer(t, goodClaims())
	ctx := context.Background()

	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := c.Connect(ctx, &mcp.StreamableClientTransport{Endpoint: ts.URL + "/mcp"}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "hello"})
	if err != nil {
		t.Fatalf("call hello: %v", err)
	}
	if res.IsError {
		t.Fatalf("hello returned error: %+v", res)
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if !strings.Contains(text, "hello from skylight-mcp") || !strings.Contains(text, "test-version") {
		t.Fatalf("unexpected hello output: %q", text)
	}
}

func TestMCPEndpointRejectsUnauthorized(t *testing.T) {
	bad := map[string]map[string]string{
		"no authorizer context": nil,
		"other user":            func() map[string]string { c := goodClaims(); c["sub"] = "someone-else"; return c }(),
		"expired":               func() map[string]string { c := goodClaims(); c["exp"] = "1"; return c }(),
		"id token":              func() map[string]string { c := goodClaims(); c["token_use"] = "id"; return c }(),
	}
	for name, claims := range bad {
		t.Run(name, func(t *testing.T) {
			ts := startServer(t, claims)
			resp, err := http.Post(ts.URL+"/mcp", "application/json",
				strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("missing resource_metadata in WWW-Authenticate: %q", resp.Header.Get("WWW-Authenticate"))
			}
		})
	}
}

func TestAuthorizationServerMetadata(t *testing.T) {
	h := New(Options{
		Auth:         auth.Config{Issuer: issuer, ClientID: client, AllowedSub: sub},
		AuthorizeURL: "https://example.test/oauth2/authorize",
		TokenURL:     "https://example.test/oauth2/token",
	})
	ts := httptest.NewServer(h) // no claims: must be public
	defer ts.Close()
	for _, p := range []string{
		"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp",
		"/.well-known/openid-configuration", "/.well-known/openid-configuration/mcp",
	} {
		resp, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", p, resp.StatusCode)
		}
		host := strings.TrimPrefix(ts.URL, "http://")
		for _, want := range []string{"https://example.test/oauth2/authorize", "https://example.test/oauth2/token", `"S256"`, `"issuer":"https://` + host + `"`} {
			if !strings.Contains(string(body), want) {
				t.Fatalf("%s: missing %q in %s", p, want, body)
			}
		}
	}
}

func TestAuthorizationServerMetadataUnconfiguredIs404(t *testing.T) {
	ts := startServer(t, nil) // startServer sets no endpoint URLs
	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestProtectedResourceMetadataIsPublic(t *testing.T) {
	ts := startServer(t, nil) // no claims at all
	for _, path := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		host := strings.TrimPrefix(ts.URL, "http://")
		if !strings.Contains(string(body), `"authorization_servers":["https://`+host+`"]`) {
			t.Fatalf("%s: metadata does not name this host as authorization server: %s", path, body)
		}
	}
}
