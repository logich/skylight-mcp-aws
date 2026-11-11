// Package auth holds the single authorization decision for the server.
//
// API Gateway's JWT authorizer has already verified the token signature,
// issuer and expiry by the time a request reaches us. Authorize is the real
// gate: it independently re-checks the claims that matter and then requires the
// token to belong to exactly one Cognito user. It fails closed: any missing,
// malformed or unexpected claim, or an unconfigured allowlist, is a rejection.
package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"math"
	"strconv"
	"time"
)

// Config is the fixed expectation a token is checked against. All fields are
// required; an empty field rejects every request.
type Config struct {
	Issuer     string // exact value of the "iss" claim
	ClientID   string // exact value of the "client_id" claim
	AllowedSub string // the one permitted "sub"
}

// ErrUnauthorized is returned for every rejection. Reasons are deliberately
// coarse and never include claim values, so they are safe to log.
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

// Authorize returns nil only if claims describe an unexpired Cognito access
// token, issued by the configured pool for the configured app client, for the
// one allowed user.
func Authorize(cfg Config, claims map[string]string, now time.Time) error {
	if cfg.Issuer == "" || cfg.ClientID == "" || cfg.AllowedSub == "" {
		return reject("not_configured")
	}
	if len(claims) == 0 {
		return reject("no_claims")
	}
	if claims["iss"] != cfg.Issuer {
		return reject("issuer")
	}
	if claims["token_use"] != "access" {
		return reject("token_use")
	}
	if claims["client_id"] != cfg.ClientID {
		return reject("client_id")
	}
	exp, err := strconv.ParseFloat(claims["exp"], 64)
	if err != nil || math.IsNaN(exp) || math.IsInf(exp, 0) {
		return reject("exp_invalid")
	}
	if float64(now.Unix()) >= exp {
		return reject("expired")
	}
	sub := claims["sub"]
	if sub == "" || subtle.ConstantTimeCompare([]byte(sub), []byte(cfg.AllowedSub)) != 1 {
		return reject("subject")
	}
	return nil
}

type claimsKey struct{}

// WithClaims attaches verified-by-the-gateway claims to a context.
func WithClaims(ctx context.Context, claims map[string]string) context.Context {
	return context.WithValue(ctx, claimsKey{}, claims)
}

// ClaimsFrom returns the claims attached with WithClaims, or nil.
func ClaimsFrom(ctx context.Context) map[string]string {
	c, _ := ctx.Value(claimsKey{}).(map[string]string)
	return c
}
