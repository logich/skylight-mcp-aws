package auth

import (
	"errors"
	"strconv"
	"testing"
	"time"
)

const (
	testIssuer = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_TESTPOOL"
	testClient = "client-abc"
	testSub    = "11111111-2222-3333-4444-555555555555"
)

var testNow = time.Unix(1_800_000_000, 0)

func cfg() Config { return Config{Issuer: testIssuer, ClientID: testClient, AllowedSub: testSub} }

func good() map[string]string {
	return map[string]string{
		"iss":       testIssuer,
		"token_use": "access",
		"client_id": testClient,
		"exp":       strconv.FormatInt(testNow.Unix()+600, 10),
		"sub":       testSub,
	}
}

func with(mut func(map[string]string)) map[string]string {
	c := good()
	mut(c)
	return c
}

func TestAuthorizeAccepts(t *testing.T) {
	if err := Authorize(cfg(), good(), testNow); err != nil {
		t.Fatalf("valid claims rejected: %v", err)
	}
	// API Gateway may stringify numbers in scientific notation.
	c := with(func(c map[string]string) { c["exp"] = "1.8000006e+09" })
	if err := Authorize(cfg(), c, testNow); err != nil {
		t.Fatalf("scientific-notation exp rejected: %v", err)
	}
}

func TestAuthorizeRejects(t *testing.T) {
	tests := []struct {
		name   string
		cfg    Config
		claims map[string]string
		want   string
	}{
		{"nil claims", cfg(), nil, "no_claims"},
		{"empty claims", cfg(), map[string]string{}, "no_claims"},
		{"issuer missing", cfg(), with(func(c map[string]string) { delete(c, "iss") }), "issuer"},
		{"issuer other pool", cfg(), with(func(c map[string]string) { c["iss"] = testIssuer + "X" }), "issuer"},
		{"issuer prefix only", cfg(), with(func(c map[string]string) { c["iss"] = "https://cognito-idp.us-east-2.amazonaws.com/" }), "issuer"},
		{"id token", cfg(), with(func(c map[string]string) { c["token_use"] = "id" }), "token_use"},
		{"token_use missing", cfg(), with(func(c map[string]string) { delete(c, "token_use") }), "token_use"},
		{"token_use case", cfg(), with(func(c map[string]string) { c["token_use"] = "Access" }), "token_use"},
		{"client missing", cfg(), with(func(c map[string]string) { delete(c, "client_id") }), "client_id"},
		{"client other", cfg(), with(func(c map[string]string) { c["client_id"] = "other" }), "client_id"},
		{"exp missing", cfg(), with(func(c map[string]string) { delete(c, "exp") }), "exp_invalid"},
		{"exp empty", cfg(), with(func(c map[string]string) { c["exp"] = "" }), "exp_invalid"},
		{"exp garbage", cfg(), with(func(c map[string]string) { c["exp"] = "soon" }), "exp_invalid"},
		{"exp NaN", cfg(), with(func(c map[string]string) { c["exp"] = "NaN" }), "exp_invalid"},
		{"exp Inf", cfg(), with(func(c map[string]string) { c["exp"] = "+Inf" }), "exp_invalid"},
		{"expired", cfg(), with(func(c map[string]string) { c["exp"] = strconv.FormatInt(testNow.Unix()-1, 10) }), "expired"},
		{"expires exactly now", cfg(), with(func(c map[string]string) { c["exp"] = strconv.FormatInt(testNow.Unix(), 10) }), "expired"},
		{"sub missing", cfg(), with(func(c map[string]string) { delete(c, "sub") }), "subject"},
		{"sub empty", cfg(), with(func(c map[string]string) { c["sub"] = "" }), "subject"},
		{"sub other user", cfg(), with(func(c map[string]string) { c["sub"] = "99999999-2222-3333-4444-555555555555" }), "subject"},
		{"sub prefix of allowed", cfg(), with(func(c map[string]string) { c["sub"] = testSub[:10] }), "subject"},
		{"sub has suffix", cfg(), with(func(c map[string]string) { c["sub"] = testSub + "0" }), "subject"},
		{"sub different case", cfg(), with(func(c map[string]string) { c["sub"] = "AAAAAAAA" }), "subject"},
		{"unconfigured issuer", Config{ClientID: testClient, AllowedSub: testSub}, good(), "not_configured"},
		{"unconfigured client", Config{Issuer: testIssuer, AllowedSub: testSub}, good(), "not_configured"},
		{"unconfigured sub", Config{Issuer: testIssuer, ClientID: testClient}, good(), "not_configured"},
		{"all unconfigured, empty sub claim", Config{}, map[string]string{"sub": ""}, "not_configured"},
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

// A single failing claim among otherwise valid ones must always reject: mutate
// each required claim to a bad value and confirm nothing slips through.
func TestAuthorizeEveryClaimIsRequired(t *testing.T) {
	for _, key := range []string{"iss", "token_use", "client_id", "exp", "sub"} {
		c := good()
		delete(c, key)
		if err := Authorize(cfg(), c, testNow); err == nil {
			t.Errorf("accepted claims with %q removed", key)
		}
	}
}

func TestReasonNeverContainsClaimValues(t *testing.T) {
	c := with(func(c map[string]string) { c["sub"] = "secret-sub-value" })
	err := Authorize(cfg(), c, testNow)
	if err == nil {
		t.Fatal("expected rejection")
	}
	if msg := err.Error(); msg != "unauthorized: subject" {
		t.Fatalf("unexpected error text %q", msg)
	}
}

func FuzzAuthorize(f *testing.F) {
	f.Add("iss", "access", "client-abc", "1800000600", testSub)
	f.Add("", "", "", "", "")
	f.Fuzz(func(t *testing.T, iss, use, client, exp, sub string) {
		claims := map[string]string{"iss": iss, "token_use": use, "client_id": client, "exp": exp, "sub": sub}
		err := Authorize(cfg(), claims, testNow)
		if err == nil {
			// Acceptance is only legal for exactly the valid shape.
			if iss != testIssuer || use != "access" || client != testClient || sub != testSub {
				t.Fatalf("accepted unexpected claims: %q %q %q %q", iss, use, client, sub)
			}
		}
	})
}
