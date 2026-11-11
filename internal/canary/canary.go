// Package canary is the non-HTTP entry point that checks the Skylight path
// end to end from inside AWS: grant store, token refresh, and read calls.
// It is reached only by a direct Lambda invoke (IAM-authorised: the owner's
// admin session now, EventBridge Scheduler in milestone 6), never through API
// Gateway, and it returns counts and error classes only, never data.
package canary

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/calendar"
	"github.com/logich/skylight-mcp-aws/internal/grant"
	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

// Field is the top-level key that marks a canary event. API Gateway events
// never have it (their request body is a nested string).
const Field = "skylight_mcp_canary"

// IsCanary reports whether a raw invocation payload is a canary event.
func IsCanary(raw json.RawMessage) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(raw, &m) != nil {
		return false
	}
	_, isCanary := m[Field]
	_, hasCtx := m["requestContext"]
	return isCanary && !hasCtx
}

// Result is safe to log and return: no tokens, names or event content.
type Result struct {
	OK          bool   `json:"ok"`
	Version     string `json:"version"`
	Stage       string `json:"stage,omitempty"` // where it failed
	ErrorClass  string `json:"error_class,omitempty"`
	Error       string `json:"error,omitempty"`
	Categories  int    `json:"categories"`
	Members     int    `json:"members"`
	Events7Days int    `json:"events_7_days"`
	TokenMs     int64  `json:"token_ms"`
	TotalMs     int64  `json:"total_ms"`
}

// Run performs the checks.
func Run(ctx context.Context, tokens *grant.Manager, cal *calendar.Client, version string, now time.Time) Result {
	start := time.Now()
	r := Result{Version: version}
	fail := func(stage string, err error) Result {
		r.Stage, r.ErrorClass, r.Error = stage, Class(err), err.Error()
		r.TotalMs = time.Since(start).Milliseconds()
		return r
	}
	t0 := time.Now()
	if _, err := tokens.AccessToken(ctx, ""); err != nil {
		return fail("token", err)
	}
	r.TokenMs = time.Since(t0).Milliseconds()
	cats, err := cal.Categories(ctx)
	if err != nil {
		return fail("categories", err)
	}
	r.Categories, r.Members = len(cats), len(calendar.Members(cats))
	evs, err := cal.Events(ctx, now, now.AddDate(0, 0, 6))
	if err != nil {
		return fail("events", err)
	}
	r.Events7Days = len(evs)
	r.OK = true
	r.TotalMs = time.Since(start).Milliseconds()
	return r
}

// Class names the kind of failure for alarms and logs.
func Class(err error) string {
	switch {
	case errors.Is(err, skylight.ErrReauthorize):
		return "reauthorize"
	case errors.Is(err, grant.ErrNotFound):
		return "no_grant"
	case errors.Is(err, calendar.ErrAPIChanged):
		return "api_changed"
	case errors.Is(err, calendar.ErrUpstream):
		return "upstream"
	case errors.Is(err, skylight.ErrUnavailable):
		return "unavailable"
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	}
	return "other"
}
