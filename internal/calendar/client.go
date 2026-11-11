package calendar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/grant"
	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

// Tokens supplies access tokens (grant.Manager in production).
type Tokens interface {
	AccessToken(ctx context.Context, stale string) (grant.Token, error)
}

// Client reads the calendar. Safe for concurrent use.
type Client struct {
	API    skylight.APIClient
	Tokens Tokens
	// MaxAttempts per request for 429/5xx (default 3). Retries stop early
	// when the context deadline would be passed.
	MaxAttempts int
	Sleep       func(context.Context, time.Duration) error // tests

	tzOnce sync.Mutex
	tz     *time.Location
}

// ErrUpstream wraps a non-success status that retries did not fix.
var ErrUpstream = errors.New("Skylight API error")

func (c *Client) sleep(ctx context.Context, d time.Duration) error {
	if c.Sleep != nil {
		return c.Sleep(ctx, d)
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// get fetches path(frameID) with retries, one forced token refresh on 401,
// and a check of the API version the server echoes.
func (c *Client) get(ctx context.Context, path func(frameID string) string, q url.Values) ([]byte, error) {
	tok, err := c.Tokens.AccessToken(ctx, "")
	if err != nil {
		return nil, err
	}
	attempts := c.MaxAttempts
	if attempts <= 0 {
		attempts = 3
	}
	refreshed := false
	for attempt := 1; ; attempt++ {
		r, err := c.API.Get(ctx, tok.AccessToken, path(url.PathEscape(tok.FrameID)), q, skylight.GetOptions{OmitUserAgent: true})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", skylight.ErrUnavailable, err)
		}
		if v := r.Header.Get("Skylight-Api-Version"); v != "" && v != skylight.APIVersion {
			return nil, changed("server answered with API version %q, expected %q", v, skylight.APIVersion)
		}
		switch {
		case r.Status == http.StatusOK:
			return r.Body, nil
		case r.Status == http.StatusUnauthorized && !refreshed:
			refreshed = true
			if tok, err = c.Tokens.AccessToken(ctx, tok.AccessToken); err != nil {
				return nil, err
			}
			continue
		case r.Status == http.StatusTooManyRequests || r.Status >= 500:
			if attempt >= attempts {
				return nil, fmt.Errorf("%w: HTTP %d after %d attempts", ErrUpstream, r.Status, attempt)
			}
			wait := backoff(attempt, r.Header.Get("Retry-After"))
			if dl, ok := ctx.Deadline(); ok && time.Until(dl) < wait+time.Second {
				return nil, fmt.Errorf("%w: HTTP %d, no time left to retry", ErrUpstream, r.Status)
			}
			if err := c.sleep(ctx, wait); err != nil {
				return nil, err
			}
		default:
			return nil, fmt.Errorf("%w: HTTP %d", ErrUpstream, r.Status)
		}
	}
}

// backoff honours Retry-After (seconds, capped at 10 s), else capped
// exponential backoff with full jitter.
func backoff(attempt int, retryAfter string) time.Duration {
	if s, err := strconv.Atoi(retryAfter); err == nil && s >= 0 {
		return min(time.Duration(s)*time.Second, 10*time.Second)
	}
	ceiling := min(250*time.Millisecond<<attempt, 4*time.Second)
	return time.Duration(rand.Int64N(int64(ceiling))) + 100*time.Millisecond
}

func framePath(suffix string) func(string) string {
	return func(fid string) string { return "/api/frames/" + fid + suffix }
}

// Categories returns all categories (members and others).
func (c *Client) Categories(ctx context.Context) ([]Category, error) {
	b, err := c.get(ctx, framePath("/categories"), url.Values{"include_profiles": {"true"}})
	if err != nil {
		return nil, err
	}
	return ParseCategories(b)
}

// Location returns the frame's timezone (cached for the life of the client).
func (c *Client) Location(ctx context.Context) (*time.Location, error) {
	c.tzOnce.Lock()
	defer c.tzOnce.Unlock()
	if c.tz != nil {
		return c.tz, nil
	}
	// The frames list (verified live) rather than GET /api/frames/{id}.
	var frameID string
	b, err := c.get(ctx, func(fid string) string { frameID = fid; return "/api/frames" }, nil)
	if err != nil {
		return nil, err
	}
	var doc struct {
		Data *[]struct {
			ID         string `json:"id"`
			Attributes struct {
				Timezone string `json:"timezone"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(b, &doc); err != nil || doc.Data == nil {
		return nil, changed("frames list is not a JSON:API document")
	}
	tz := ""
	for _, f := range *doc.Data {
		if url.PathEscape(f.ID) == frameID {
			tz = f.Attributes.Timezone
		}
	}
	if tz == "" {
		return nil, changed("stored frame not in the frames list, or it has no timezone")
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		return nil, changed("frame timezone is not a known IANA name")
	}
	c.tz = loc
	return loc, nil
}

// Events returns events touching the dates [from, to] (inclusive, in the
// frame's timezone). Skylight's date_max is exclusive, so to+1 day is sent.
func (c *Client) Events(ctx context.Context, from, to time.Time) ([]Event, error) {
	loc, err := c.Location(ctx)
	if err != nil {
		return nil, err
	}
	f, t := from.In(loc), to.In(loc)
	if t.Before(f) {
		return nil, errors.New("end date is before start date")
	}
	q := url.Values{
		"date_min": {f.Format(time.DateOnly)},
		"date_max": {t.AddDate(0, 0, 1).Format(time.DateOnly)},
		"timezone": {loc.String()},
		"include":  {"categories"},
	}
	b, err := c.get(ctx, framePath("/calendar_events"), q)
	if err != nil {
		return nil, err
	}
	return ParseEvents(b)
}
