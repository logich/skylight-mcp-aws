// Package auth holds the server's authorization decision.
//
// A request is allowed only if its bearer token (1) is a well-formed JWS
// signed with RS256 by a key from the configured Cognito pool's JWKS (Verify),
// and (2) carries exactly the expected claims for the one allowed user
// (Authorize). Identity claims supplied in the Lambda invocation event are never
// used: a direct invoke with a forged API Gateway event gets nothing.
//
// Everything fails closed: any missing, malformed or unexpected value, or an
// unconfigured field, is a rejection.
package auth

import (
	"crypto/subtle"
	"errors"
	"math"
	"strings"
	"time"
)

// Config is the fixed expectation a token is checked against. All fields are
// required; an empty field rejects every request.
type Config struct {
	Issuer     string // exact "iss"
	ClientID   string // exact "client_id"
	AllowedSub string // the one permitted "sub"
	Scope      string // a scope that must appear in the space-separated "scope"
	// Audience is this server's resource URL (the connector URL). When a token
	// carries "aud" (RFC 8707 resource binding: Cognito sets it to the
	// requested resource), it must contain exactly this value.
	Audience string
}

// Claims are the token claims Authorize looks at, as decoded by Verify.
type Claims struct {
	Issuer   string
	TokenUse string
	ClientID string
	Subject  string
	Scope    string
	Audience []string // "aud", if present (string or array in the token)
	Exp      float64  // seconds since the epoch; 0 means absent
}

// ErrUnauthorized is returned for every rejection. Reasons are deliberately
// coarse and never include token or claim values, so they are safe to log.
var ErrUnauthorized = errors.New("unauthorized")

type reasonError struct{ reason string }

func (e reasonError) Error() string        { return "unauthorized: " + e.reason }
func (e reasonError) Is(target error) bool { return target == ErrUnauthorized }

// Reason returns a short, non-sensitive label for why err was a rejection.
func Reason(err error) string {
	var r reasonError
	if errors.As(err, &r) {
		return r.reason
	}
	return ""
}

func reject(reason string) error { return reasonError{reason} }

// Authorize returns nil only if c describes an unexpired Cognito access token,
// issued by the configured pool for the configured app client, with the
// required scope, for the one allowed user. It assumes c came from a token
// whose signature Verify has already checked.
func Authorize(cfg Config, c Claims, now time.Time) error {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.AllowedSub == "" || cfg.Scope == "" || cfg.Audience == "" {
		return reject("not_configured")
	}
	if c.Issuer != cfg.Issuer {
		return reject("issuer")
	}
	if c.TokenUse != "access" {
		return reject("token_use")
	}
	if c.ClientID != cfg.ClientID {
		return reject("client_id")
	}
	if !hasScope(c.Scope, cfg.Scope) {
		return reject("scope")
	}
	// A token bound to some other resource must not be accepted here. A token
	// with no binding at all is still pinned by issuer, client_id and scope.
	if c.Audience != nil && !contains(c.Audience, cfg.Audience) {
		return reject("audience")
	}
	if c.Exp <= 0 || math.IsNaN(c.Exp) || math.IsInf(c.Exp, 0) {
		return reject("exp_invalid")
	}
	if float64(now.Unix()) >= c.Exp {
		return reject("expired")
	}
	if c.Subject == "" || subtle.ConstantTimeCompare([]byte(c.Subject), []byte(cfg.AllowedSub)) != 1 {
		return reject("subject")
	}
	return nil
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// hasScope reports whether want is one of the space-separated scopes, compared
// exactly (so "x/invoke-admin" does not satisfy "x/invoke").
func hasScope(scopes, want string) bool {
	for _, s := range strings.Fields(scopes) {
		if s == want {
			return true
		}
	}
	return false
}
