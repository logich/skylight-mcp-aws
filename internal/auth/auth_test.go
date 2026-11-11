package auth

import (
	"errors"
	"math"
	"testing"
	"time"
)

const (
	testIssuer = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_TESTPOOL"
	testClient = "client-abc"
	testSub    = "11111111-2222-3333-4444-555555555555"
	testScope  = "skylight-mcp/invoke"
	testAud    = "https://abc.execute-api.us-east-2.amazonaws.com/mcp"
)

var testNow = time.Unix(1_800_000_000, 0)

func cfg() Config {
	return Config{Issuer: testIssuer, ClientID: testClient, AllowedSub: testSub, Scope: testScope, Audience: testAud}
}

func good() Claims {
	return Claims{
		Issuer: testIssuer, TokenUse: "access", ClientID: testClient,
		Subject: testSub, Scope: testScope, Exp: float64(testNow.Unix() + 600),
	}
}

func with(mut func(*Claims)) Claims {
	c := good()
	mut(&c)
	return c
}

func TestAuthorizeAccepts(t *testing.T) {
	if err := Authorize(cfg(), good(), testNow); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}
	for name, aud := range map[string][]string{
		"aud absent": nil, "aud ours": {testAud}, "aud list incl ours": {"https://other.example/x", testAud},
	} {
		if err := Authorize(cfg(), with(func(c *Claims) { c.Audience = aud }), testNow); err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
	}
	multi := with(func(c *Claims) { c.Scope = "other/read " + testScope + " x" })
	if err := Authorize(cfg(), multi, testNow); err != nil {
		t.Fatalf("scope among several rejected: %v", err)
	}
}

func TestAuthorizeRejects(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		claims Claims
		want   string
	}{
		{"zero claims", cfg(), Claims{}, "issuer"},
		{"issuer other pool", cfg(), with(func(c *Claims) { c.Issuer = testIssuer + "X" }), "issuer"},
		{"issuer prefix only", cfg(), with(func(c *Claims) { c.Issuer = "https://cognito-idp.us-east-2.amazonaws.com/" }), "issuer"},
		{"issuer missing", cfg(), with(func(c *Claims) { c.Issuer = "" }), "issuer"},
		{"id token", cfg(), with(func(c *Claims) { c.TokenUse = "id" }), "token_use"},
		{"token_use missing", cfg(), with(func(c *Claims) { c.TokenUse = "" }), "token_use"},
		{"token_use case", cfg(), with(func(c *Claims) { c.TokenUse = "Access" }), "token_use"},
		{"client missing", cfg(), with(func(c *Claims) { c.ClientID = "" }), "client_id"},
		{"client other", cfg(), with(func(c *Claims) { c.ClientID = "other" }), "client_id"},
		{"scope missing", cfg(), with(func(c *Claims) { c.Scope = "" }), "scope"},
		{"scope only cognito admin", cfg(), with(func(c *Claims) { c.Scope = "aws.cognito.signin.user.admin" }), "scope"},
		{"scope openid email", cfg(), with(func(c *Claims) { c.Scope = "openid email" }), "scope"},
		{"scope superstring", cfg(), with(func(c *Claims) { c.Scope = testScope + "-admin" }), "scope"},
		{"scope substring", cfg(), with(func(c *Claims) { c.Scope = "skylight-mcp/invok" }), "scope"},
		{"aud other resource", cfg(), with(func(c *Claims) { c.Audience = []string{"https://evil.example/mcp"} }), "audience"},
		{"aud prefix of ours", cfg(), with(func(c *Claims) { c.Audience = []string{testAud[:20]} }), "audience"},
		{"aud ours with suffix", cfg(), with(func(c *Claims) { c.Audience = []string{testAud + "/x"} }), "audience"},
		{"aud empty string", cfg(), with(func(c *Claims) { c.Audience = []string{""} }), "audience"},
		{"aud is client id", cfg(), with(func(c *Claims) { c.Audience = []string{testClient} }), "audience"},
		{"exp missing", cfg(), with(func(c *Claims) { c.Exp = 0 }), "exp_invalid"},
		{"exp negative", cfg(), with(func(c *Claims) { c.Exp = -5 }), "exp_invalid"},
		{"exp NaN", cfg(), with(func(c *Claims) { c.Exp = math.NaN() }), "exp_invalid"},
		{"exp Inf", cfg(), with(func(c *Claims) { c.Exp = math.Inf(1) }), "exp_invalid"},
		{"expired", cfg(), with(func(c *Claims) { c.Exp = float64(testNow.Unix() - 1) }), "expired"},
		{"expires exactly now", cfg(), with(func(c *Claims) { c.Exp = float64(testNow.Unix()) }), "expired"},
		{"sub missing", cfg(), with(func(c *Claims) { c.Subject = "" }), "subject"},
		{"sub other user", cfg(), with(func(c *Claims) { c.Subject = "99999999-2222-3333-4444-555555555555" }), "subject"},
		{"sub prefix of allowed", cfg(), with(func(c *Claims) { c.Subject = testSub[:10] }), "subject"},
		{"sub has suffix", cfg(), with(func(c *Claims) { c.Subject = testSub + "0" }), "subject"},
		{"unconfigured issuer", Config{ClientID: testClient, AllowedSub: testSub, Scope: testScope, Audience: testAud}, good(), "not_configured"},
		{"unconfigured client", Config{Issuer: testIssuer, AllowedSub: testSub, Scope: testScope, Audience: testAud}, good(), "not_configured"},
		{"unconfigured sub", Config{Issuer: testIssuer, ClientID: testClient, Scope: testScope, Audience: testAud}, good(), "not_configured"},
		{"unconfigured scope", Config{Issuer: testIssuer, ClientID: testClient, AllowedSub: testSub, Audience: testAud}, good(), "not_configured"},
		{"unconfigured audience", Config{Issuer: testIssuer, ClientID: testClient, AllowedSub: testSub, Scope: testScope}, good(), "not_configured"},
		{"all unconfigured, empty claims", Config{}, Claims{}, "not_configured"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Authorize(tt.cfg, tt.claims, testNow)
			if err == nil {
				t.Fatal("expected rejection, got nil")
			}
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("error is not ErrUnauthorized: %v", err)
			}
			if got := Reason(err); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReasonNeverContainsClaimValues(t *testing.T) {
	err := Authorize(cfg(), with(func(c *Claims) { c.Subject = "secret-sub-value" }), testNow)
	if err == nil || err.Error() != "unauthorized: subject" {
		t.Fatalf("unexpected error %v", err)
	}
}

func FuzzAuthorize(f *testing.F) {
	f.Add(testIssuer, "access", testClient, testSub, testScope, float64(testNow.Unix()+600))
	f.Add("", "", "", "", "", 0.0)
	f.Fuzz(func(t *testing.T, iss, use, client, sub, scope string, exp float64) {
		c := Claims{Issuer: iss, TokenUse: use, ClientID: client, Subject: sub, Scope: scope, Exp: exp}
		if Authorize(cfg(), c, testNow) == nil {
			if iss != testIssuer || use != "access" || client != testClient || sub != testSub ||
				!hasScope(scope, testScope) || exp <= float64(testNow.Unix()) {
				t.Fatalf("accepted unexpected claims: %+v", c)
			}
		}
	})
}
