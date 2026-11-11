package server

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/logich/skylight-mcp-aws/internal/auth"
	"github.com/logich/skylight-mcp-aws/internal/lambdahttp"
)

const (
	issuer = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_TESTPOOL"
	client = "client-abc"
	sub    = "11111111-2222-3333-4444-555555555555"
	scope  = "skylight-mcp/invoke"
	aud    = "https://abc.execute-api.us-east-2.amazonaws.com/mcp"
)

var (
	now     = time.Unix(1_800_000_000, 0)
	keyOnce sync.Once
	key     *rsa.PrivateKey
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func signingKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	keyOnce.Do(func() {
		var err error
		if key, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
	})
	return key
}

func keySet(t *testing.T) *auth.KeySet {
	k := signingKey(t)
	doc, _ := json.Marshal(map[string]any{"keys": []map[string]string{{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": "k1",
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
	}}})
	return &auth.KeySet{
		Fetch:      func(context.Context) ([]byte, error) { return doc, nil },
		MinRefresh: time.Minute,
		Now:        func() time.Time { return now },
	}
}

func token(t *testing.T, mut func(map[string]any)) string {
	t.Helper()
	p := map[string]any{
		"iss": issuer, "token_use": "access", "client_id": client, "sub": sub,
		"scope": scope, "exp": now.Unix() + 600,
	}
	if mut != nil {
		mut(p)
	}
	hb, _ := json.Marshal(map[string]any{"alg": "RS256", "kid": "k1"})
	pb, _ := json.Marshal(p)
	in := b64(hb) + "." + b64(pb)
	d := sha256.Sum256([]byte(in))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signingKey(t), crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return in + "." + b64(sig)
}

func handler(t *testing.T) http.Handler {
	return New(Options{
		Auth:         auth.Config{Issuer: issuer, ClientID: client, AllowedSub: sub, Scope: scope, Audience: aud},
		Keys:         keySet(t),
		AuthorizeURL: "https://example.test/oauth2/authorize",
		TokenURL:     "https://example.test/oauth2/token",
		Version:      "test-version",
		Now:          func() time.Time { return now },
	})
}

// bearerTransport adds an Authorization header to every request.
type bearerTransport struct{ token string }

func (b bearerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return http.DefaultTransport.RoundTrip(r)
}

func TestHelloThroughMCPClient(t *testing.T) {
	ts := httptest.NewServer(handler(t))
	defer ts.Close()
	ctx := context.Background()

	c := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := c.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint: ts.URL + "/mcp",
		// Resource-bound, as claude.ai's tokens are.
		HTTPClient: &http.Client{Transport: bearerTransport{token(t, func(p map[string]any) { p["aud"] = aud })}},
	}, nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer session.Close()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "hello"})
	if err != nil {
		t.Fatalf("call hello: %v", err)
	}
	var text string
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	if res.IsError || !strings.Contains(text, "hello from skylight-mcp") || !strings.Contains(text, "test-version") {
		t.Fatalf("unexpected hello result: %+v %q", res, text)
	}
}

func TestMCPEndpointRejectsUnauthorized(t *testing.T) {
	cases := map[string]string{
		"no header":                 "",
		"garbage":                   "Bearer garbage",
		"other user":                "Bearer " + token(t, func(p map[string]any) { p["sub"] = "someone-else" }),
		"expired":                   "Bearer " + token(t, func(p map[string]any) { p["exp"] = now.Unix() - 1 }),
		"no scope":                  "Bearer " + token(t, func(p map[string]any) { p["scope"] = "openid email" }),
		"bound to another resource": "Bearer " + token(t, func(p map[string]any) { p["aud"] = "https://evil.example/mcp" }),
		"tampered": "Bearer " + func() string {
			p := strings.Split(token(t, nil), ".")
			fake, _ := json.Marshal(map[string]any{"iss": issuer, "token_use": "access", "client_id": client,
				"sub": sub, "scope": scope, "exp": now.Unix() + 9999})
			return p[0] + "." + b64(fake) + "." + p[2]
		}(),
	}
	ts := httptest.NewServer(handler(t))
	defer ts.Close()
	for name, authz := range cases {
		t.Run(name, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp",
				strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
			req.Header.Set("Content-Type", "application/json")
			if authz != "" {
				req.Header.Set("Authorization", authz)
			}
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("status = %d, want 401", resp.StatusCode)
			}
			if !strings.Contains(resp.Header.Get("WWW-Authenticate"), "resource_metadata=") {
				t.Fatalf("missing resource_metadata: %q", resp.Header.Get("WWW-Authenticate"))
			}
		})
	}
}

// The retrospective's top finding: a direct Lambda invoke carrying forged API
// Gateway authorizer claims for the allowed user must get nothing.
func TestDirectInvokeWithForgedAuthorizerClaimsIsRejected(t *testing.T) {
	invoke := lambdahttp.Handler(handler(t))
	var ev events.APIGatewayV2HTTPRequest
	ev.RawPath = "/mcp"
	ev.Body = `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"hello","arguments":{}}}`
	ev.Headers = map[string]string{"content-type": "application/json", "accept": "application/json, text/event-stream"}
	ev.RequestContext.DomainName = "x.execute-api.us-east-2.amazonaws.com"
	ev.RequestContext.HTTP.Method = http.MethodPost
	ev.RequestContext.Authorizer = &events.APIGatewayV2HTTPRequestContextAuthorizerDescription{
		JWT: &events.APIGatewayV2HTTPRequestContextAuthorizerJWTDescription{Claims: map[string]string{
			"iss": issuer, "token_use": "access", "client_id": client, "sub": sub,
			"scope": scope, "exp": "9999999999",
		}},
	}
	resp, err := invoke(context.Background(), ev)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("forged claims got status %d, want 401 (body %q)", resp.StatusCode, resp.Body)
	}
}

func TestDiscoveryDocumentsArePublicAndConsistent(t *testing.T) {
	ts := httptest.NewServer(handler(t)) // no Authorization header anywhere
	defer ts.Close()
	host := strings.TrimPrefix(ts.URL, "http://")
	get := func(path string) (int, string) {
		resp, err := http.Get(ts.URL + path)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp.StatusCode, string(b)
	}
	for _, p := range []string{"/.well-known/oauth-protected-resource", "/.well-known/oauth-protected-resource/mcp"} {
		code, body := get(p)
		if code != http.StatusOK || !strings.Contains(body, `"authorization_servers":["https://`+host+`"]`) ||
			!strings.Contains(body, `"scopes_supported":["`+scope+`"]`) {
			t.Fatalf("%s: %d %s", p, code, body)
		}
	}
	for _, p := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-authorization-server/mcp"} {
		code, body := get(p)
		for _, want := range []string{`"issuer":"https://` + host + `"`, "https://example.test/oauth2/authorize",
			"https://example.test/oauth2/token", `"S256"`, `"scopes_supported":["` + scope + `"]`} {
			if code != http.StatusOK || !strings.Contains(body, want) {
				t.Fatalf("%s: missing %q in %d %s", p, want, code, body)
			}
		}
		if strings.Contains(body, "openid") {
			t.Fatalf("%s advertises openid: %s", p, body)
		}
	}
	// OIDC discovery is intentionally gone.
	if code, _ := get("/.well-known/openid-configuration"); code != http.StatusNotFound {
		t.Fatalf("openid-configuration status %d, want 404", code)
	}
}

func TestAuthorizationServerMetadataUnconfiguredIs404(t *testing.T) {
	h := New(Options{Auth: auth.Config{Issuer: issuer, Scope: scope}})
	ts := httptest.NewServer(h)
	defer ts.Close()
	resp, err := http.Get(ts.URL + "/.well-known/oauth-authorization-server")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", resp.StatusCode)
	}
}

func TestNilKeySetFailsClosed(t *testing.T) {
	h := New(Options{Auth: auth.Config{Issuer: issuer, ClientID: client, AllowedSub: sub, Scope: scope, Audience: aud}})
	ts := httptest.NewServer(h)
	defer ts.Close()
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{}`))
	req.Header.Set("Authorization", "Bearer "+token(t, nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
}
