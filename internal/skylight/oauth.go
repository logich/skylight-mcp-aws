// Package skylight is a client for Skylight's private API. This file holds the
// OAuth parts: PKCE, the authorize URL, parsing what the owner pastes back,
// and the token endpoint (code exchange and refresh).
//
// Request fields follow the Home Assistant integration (SKYLIGHT_API.md §2.1),
// which works against the live API. Nothing here logs or formats a token.
package skylight

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	BaseURL      = "https://app.ourskylight.com"
	AuthorizeURL = BaseURL + "/oauth/authorize"
	TokenURL     = BaseURL + "/oauth/token"
	RedirectURI  = "https://ourskylight.com/welcome" // the only registered URI
	ClientID     = "skylight-mobile"
	Scope        = "everything"
	APIVersion   = "2026-05-01"
	// Browser-style UA, as HA sends. Whether it is required is an open question
	// (SKYLIGHT_API.md §6.4).
	UserAgent  = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
	DeviceName = "skylight-mcp"
)

// ErrReauthorize means Skylight rejected the credential (HTTP 400/401/403 from
// the token endpoint): only a human redoing the browser step can fix it.
var ErrReauthorize = errors.New("skylight: credential rejected; re-run skylight-login")

// ErrUnavailable means the token endpoint failed in a way that says nothing
// about the credential (5xx, 429, network). Never treat it as signed out.
var ErrUnavailable = errors.New("skylight: token endpoint unavailable")

// PKCE is an RFC 7636 S256 verifier/challenge pair.
type PKCE struct{ Verifier, Challenge string }

// NewPKCE returns a fresh pair: 64 random bytes as base64url (86 characters,
// inside RFC 7636's 43-128).
func NewPKCE() (PKCE, error) {
	b := make([]byte, 64)
	if _, err := rand.Read(b); err != nil {
		return PKCE{}, err
	}
	v := base64.RawURLEncoding.EncodeToString(b)
	return PKCE{Verifier: v, Challenge: challenge(v)}, nil
}

func challenge(verifier string) string {
	d := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(d[:])
}

// NewFingerprint returns a device fingerprint: 16 random bytes as hex, like HA.
// A refresh token may be bound to it, so it is stored with the token forever.
func NewFingerprint() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// AuthorizationURL is the page the owner opens to sign in to Skylight.
func AuthorizationURL(codeChallenge string) string {
	q := url.Values{
		"client_id":             {ClientID},
		"response_type":         {"code"},
		"scope":                 {Scope},
		"redirect_uri":          {RedirectURI},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"login"},
	}
	return AuthorizeURL + "?" + q.Encode()
}

// ExtractCode accepts what the owner pastes after signing in: the whole
// redirect URL from the address bar, "code=…", or the bare code. A URL must be
// the registered redirect; an OAuth error in it is returned as an error.
func ExtractCode(raw string) (string, error) {
	s := strings.Trim(strings.TrimSpace(raw), `'"`)
	if s == "" {
		return "", errors.New("nothing pasted")
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", errors.New("not a valid URL")
		}
		want, _ := url.Parse(RedirectURI)
		if u.Scheme != want.Scheme || u.Host != want.Host || u.Path != want.Path {
			return "", errors.New("that URL is not the Skylight redirect (" + RedirectURI + ")")
		}
		q := u.Query()
		if e := q.Get("error"); e != "" {
			return "", fmt.Errorf("Skylight returned an error: %s", sanitize(e))
		}
		s = q.Get("code")
	} else if strings.HasPrefix(strings.ToLower(s), "code=") {
		s = s[len("code="):]
		if i := strings.IndexByte(s, '&'); i >= 0 {
			s = s[:i]
		}
	}
	if s == "" {
		return "", errors.New("no code found")
	}
	if len(s) > 512 || strings.ContainsAny(s, " \t\r\n") {
		return "", errors.New("that does not look like an authorization code")
	}
	return s, nil
}

// sanitize keeps a server-supplied string printable and short.
func sanitize(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 80 {
		s = s[:80]
	}
	return s
}

// TokenResponse is the token endpoint's answer. Shape lists the top-level keys
// and their JSON types (never values), for the live probes.
type TokenResponse struct {
	AccessToken  string
	RefreshToken string // empty if the server did not rotate it
	ExpiresIn    int64  // seconds; 0 if absent
	Shape        []string
}

// TokenClient calls the token endpoint.
type TokenClient struct {
	HTTP     *http.Client // nil: a client with a 15 s timeout (as HA)
	Endpoint string       // empty: TokenURL
}

func (c TokenClient) httpClient() *http.Client {
	if c.HTTP != nil {
		return c.HTTP
	}
	return &http.Client{Timeout: 15 * time.Second}
}

func deviceFields(v url.Values, fingerprint string) {
	v.Set("skylight_api_client_device_fingerprint", fingerprint)
	v.Set("skylight_api_client_device_platform", "web")
	v.Set("skylight_api_client_device_name", DeviceName)
	v.Set("skylight_api_client_device_os_version", "unknown")
	v.Set("skylight_api_client_device_app_version", "unknown")
	v.Set("skylight_api_client_device_hardware", "3")
}

// Exchange trades an authorization code for tokens. Codes expire in about 30
// seconds, so call it as soon as the owner pastes.
func (c TokenClient) Exchange(ctx context.Context, code, verifier, fingerprint string) (TokenResponse, error) {
	v := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {ClientID},
		"redirect_uri":  {RedirectURI},
		"code_verifier": {verifier},
		"scope":         {Scope},
		"source":        {"js-mobile"},
	}
	deviceFields(v, fingerprint)
	r, err := c.post(ctx, v)
	if err == nil && r.RefreshToken == "" {
		return TokenResponse{}, fmt.Errorf("%w: code exchange returned no refresh_token", ErrUnavailable)
	}
	return r, err
}

// Refresh spends a refresh token. Skylight rotates refresh tokens, so the old
// one must be treated as gone once this is sent, whatever the outcome.
func (c TokenClient) Refresh(ctx context.Context, refreshToken, fingerprint string) (TokenResponse, error) {
	v := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {refreshToken},
		"client_id":     {ClientID},
		"scope":         {Scope},
		"source":        {"web"},
	}
	deviceFields(v, fingerprint)
	return c.post(ctx, v)
}

func (c TokenClient) post(ctx context.Context, form url.Values) (TokenResponse, error) {
	ep := c.Endpoint
	if ep == "" {
		ep = TokenURL
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep, strings.NewReader(form.Encode()))
	if err != nil {
		return TokenResponse{}, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", UserAgent)
	resp, err := c.httpClient().Do(req)
	if err != nil {
		// The URL error carries no form data, but keep the message generic anyway.
		return TokenResponse{}, fmt.Errorf("%w: request failed", ErrUnavailable)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return TokenResponse{}, fmt.Errorf("%w: reading response", ErrUnavailable)
	}
	if resp.StatusCode != http.StatusOK {
		return TokenResponse{}, statusError(resp.StatusCode, body)
	}
	return parseTokenResponse(body)
}

// statusError classifies a failed token call. Only the OAuth "error" code is
// kept from the body: an error body might echo request fields.
func statusError(status int, body []byte) error {
	var e struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &e)
	detail := fmt.Sprintf("HTTP %d", status)
	if e.Error != "" {
		detail += " " + sanitize(e.Error)
	}
	switch status {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Errorf("%w (%s)", ErrReauthorize, detail)
	default:
		return fmt.Errorf("%w (%s)", ErrUnavailable, detail)
	}
}

func parseTokenResponse(body []byte) (TokenResponse, error) {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return TokenResponse{}, fmt.Errorf("%w: token response is not a JSON object", ErrUnavailable)
	}
	var r TokenResponse
	for k, v := range raw {
		r.Shape = append(r.Shape, k+":"+jsonType(v))
	}
	sort.Strings(r.Shape)
	str := func(k string) (string, error) {
		v, ok := raw[k]
		if !ok {
			return "", nil
		}
		var s string
		if err := json.Unmarshal(v, &s); err != nil {
			return "", fmt.Errorf("%w: %s is not a string", ErrUnavailable, k)
		}
		return s, nil
	}
	var err error
	if r.AccessToken, err = str("access_token"); err != nil {
		return TokenResponse{}, err
	}
	if r.RefreshToken, err = str("refresh_token"); err != nil {
		return TokenResponse{}, err
	}
	if r.AccessToken == "" {
		return TokenResponse{}, fmt.Errorf("%w: no access_token in response", ErrUnavailable)
	}
	if v, ok := raw["expires_in"]; ok {
		var n json.Number
		d := json.NewDecoder(strings.NewReader(string(v)))
		d.UseNumber()
		if d.Decode(&n) == nil {
			r.ExpiresIn, _ = n.Int64()
		}
	}
	return r, nil
}

func jsonType(v json.RawMessage) string {
	s := strings.TrimSpace(string(v))
	switch {
	case s == "null":
		return "null"
	case s == "true" || s == "false":
		return "bool"
	case strings.HasPrefix(s, `"`):
		return "string"
	case strings.HasPrefix(s, "{"):
		return "object"
	case strings.HasPrefix(s, "["):
		return "array"
	default:
		return "number"
	}
}
