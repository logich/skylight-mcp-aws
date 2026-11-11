package skylight

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPKCE(t *testing.T) {
	p, err := NewPKCE()
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Verifier) < 43 || len(p.Verifier) > 128 {
		t.Fatalf("verifier length %d outside RFC 7636 range", len(p.Verifier))
	}
	// RFC 7636 Appendix B test vector.
	if got := challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge = %s", got)
	}
	q, _ := NewPKCE()
	if p.Verifier == q.Verifier {
		t.Fatal("verifiers repeat")
	}
}

func TestAuthorizationURL(t *testing.T) {
	u, err := url.Parse(AuthorizationURL("chal"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	want := map[string]string{"client_id": ClientID, "response_type": "code", "scope": Scope,
		"redirect_uri": RedirectURI, "code_challenge": "chal", "code_challenge_method": "S256", "prompt": "login"}
	for k, v := range want {
		if q.Get(k) != v {
			t.Errorf("%s = %q, want %q", k, q.Get(k), v)
		}
	}
	if u.Scheme+"://"+u.Host+u.Path != AuthorizeURL {
		t.Errorf("endpoint %s", u)
	}
}

func TestExtractCode(t *testing.T) {
	ok := map[string]string{
		"https://ourskylight.com/welcome?code=abc123":              "abc123",
		"  https://ourskylight.com/welcome?code=abc123&state=x \n": "abc123",
		"'https://ourskylight.com/welcome?code=abc123'":            "abc123",
		"abc123":       "abc123",
		"code=abc123":  "abc123",
		"CODE=abc123&": "abc123",
	}
	for in, want := range ok {
		if got, err := ExtractCode(in); err != nil || got != want {
			t.Errorf("ExtractCode(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	bad := []string{
		"", "   ",
		"https://evil.example/welcome?code=abc",        // not the registered redirect
		"http://ourskylight.com/welcome?code=abc",      // wrong scheme
		"https://ourskylight.com/other?code=abc",       // wrong path
		"https://ourskylight.com/welcome",              // no code
		"https://ourskylight.com/welcome?error=denied", // OAuth error
		"two words",
		strings.Repeat("a", 513),
	}
	for _, in := range bad {
		if got, err := ExtractCode(in); err == nil {
			t.Errorf("ExtractCode(%q) = %q, want error", in, got)
		}
	}
}

// tokenServer records the last form it received and answers with status/body.
func tokenServer(t *testing.T, status int, body string, got *url.Values) *httptest.Server {
	t.Helper()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Errorf("bad request: %s %s", r.Method, r.Header.Get("Content-Type"))
		}
		b, _ := io.ReadAll(r.Body)
		v, _ := url.ParseQuery(string(b))
		if got != nil {
			*got = v
		}
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(ts.Close)
	return ts
}

func TestExchangeSendsHAFields(t *testing.T) {
	var form url.Values
	ts := tokenServer(t, 200, `{"access_token":"AT","refresh_token":"RT","expires_in":7200,"token_type":"Bearer","created_at":1}`, &form)
	r, err := TokenClient{Endpoint: ts.URL}.Exchange(context.Background(), "CODE", "VERIFIER", "fp")
	if err != nil {
		t.Fatal(err)
	}
	if r.AccessToken != "AT" || r.RefreshToken != "RT" || r.ExpiresIn != 7200 {
		t.Fatalf("parsed %+v", r)
	}
	if strings.Join(r.Shape, ",") != "access_token:string,created_at:number,expires_in:number,refresh_token:string,token_type:string" {
		t.Fatalf("shape %v", r.Shape)
	}
	want := map[string]string{"grant_type": "authorization_code", "code": "CODE", "code_verifier": "VERIFIER",
		"client_id": ClientID, "redirect_uri": RedirectURI, "scope": Scope, "source": "js-mobile",
		"skylight_api_client_device_fingerprint": "fp", "skylight_api_client_device_platform": "web"}
	for k, v := range want {
		if form.Get(k) != v {
			t.Errorf("form %s = %q, want %q", k, form.Get(k), v)
		}
	}
}

func TestRefreshWithoutRotation(t *testing.T) {
	var form url.Values
	ts := tokenServer(t, 200, `{"access_token":"AT2"}`, &form)
	r, err := TokenClient{Endpoint: ts.URL}.Refresh(context.Background(), "RT", "fp")
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "RT" || form.Get("source") != "web" {
		t.Fatalf("form %v", form)
	}
	s := Saved{RefreshToken: "RT", DeviceFingerprint: "fp"}
	s.Apply(r, time.Unix(0, 0))
	if s.RefreshToken != "RT" || s.AccessToken != "AT2" || !s.AccessExpiresAt.IsZero() {
		t.Fatalf("apply without rotation: %+v", s)
	}
	s.Apply(TokenResponse{AccessToken: "AT3", RefreshToken: "RT3", ExpiresIn: 60}, time.Unix(0, 0))
	if s.RefreshToken != "RT3" || !s.AccessExpiresAt.Equal(time.Unix(60, 0)) {
		t.Fatalf("apply with rotation: %+v", s)
	}
}

func TestExchangeRequiresRefreshToken(t *testing.T) {
	ts := tokenServer(t, 200, `{"access_token":"AT"}`, nil)
	if _, err := (TokenClient{Endpoint: ts.URL}).Exchange(context.Background(), "c", "v", "f"); err == nil {
		t.Fatal("want error")
	}
}

func TestTokenErrorsClassifiedAndNeverEchoBody(t *testing.T) {
	cases := []struct {
		status int
		want   error
	}{
		{400, ErrReauthorize}, {401, ErrReauthorize}, {403, ErrReauthorize},
		{429, ErrUnavailable}, {500, ErrUnavailable}, {503, ErrUnavailable},
	}
	for _, c := range cases {
		ts := tokenServer(t, c.status, `{"error":"invalid_grant","error_description":"token SECRET-RT is revoked"}`, nil)
		_, err := TokenClient{Endpoint: ts.URL}.Refresh(context.Background(), "SECRET-RT", "fp")
		if !errors.Is(err, c.want) {
			t.Errorf("%d: err %v, want %v", c.status, err, c.want)
		}
		if err != nil && strings.Contains(err.Error(), "SECRET") {
			t.Errorf("%d: error leaks body: %v", c.status, err)
		}
	}
	for _, body := range []string{`not json`, `{"access_token":5}`, `{"refresh_token":"x"}`, `[]`} {
		ts := tokenServer(t, 200, body, nil)
		if _, err := (TokenClient{Endpoint: ts.URL}).Refresh(context.Background(), "r", "f"); !errors.Is(err, ErrUnavailable) {
			t.Errorf("body %s: err %v", body, err)
		}
	}
}

func TestTokenFile(t *testing.T) {
	p := filepath.Join(t.TempDir(), "sub", "tok.json")
	if err := SaveFile(p, Saved{RefreshToken: "", DeviceFingerprint: "f"}); err == nil {
		t.Fatal("saved a bundle without refresh token")
	}
	in := Saved{RefreshToken: "R", AccessToken: "A", DeviceFingerprint: "F", UpdatedAt: time.Unix(5, 0).UTC()}
	if err := SaveFile(p, in); err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(p)
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("mode %v", fi.Mode().Perm())
	}
	di, _ := os.Stat(filepath.Dir(p))
	if di.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %v", di.Mode().Perm())
	}
	out, err := LoadFile(p)
	if err != nil || out != in {
		t.Fatalf("round trip: %+v %v", out, err)
	}
	os.Chmod(p, 0o644)
	if _, err := LoadFile(p); err == nil {
		t.Fatal("loaded a world-readable token file")
	}
	entries, _ := os.ReadDir(filepath.Dir(p))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %v", entries)
	}
}

func FuzzExtractCode(f *testing.F) {
	for _, s := range []string{"abc", "code=x", "https://ourskylight.com/welcome?code=y", "https://ourskylight.com/welcome?error=z"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		c, err := ExtractCode(s)
		if err == nil && (c == "" || len(c) > 512 || strings.ContainsAny(c, " \t\r\n")) {
			t.Fatalf("accepted bad code %q from %q", c, s)
		}
	})
}
