package grant

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

// Refresher spends a refresh token (skylight.TokenClient in production).
type Refresher interface {
	Refresh(ctx context.Context, refreshToken, fingerprint string) (skylight.TokenResponse, error)
}

// Manager hands out access tokens. Safe for concurrent use; any number of
// Managers (Lambda instances) may share one Store.
type Manager struct {
	Store     Store
	Refresher Refresher
	Now       func() time.Time

	LeaseTTL       time.Duration // default 10 s: refresh deadline + commit + margin
	RefreshTimeout time.Duration // default 4 s
	ExpiryMargin   time.Duration // default 5 min: refresh this long before expiry
	PollInterval   time.Duration // default 250 ms: while another holder refreshes
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

func orDefault(d, def time.Duration) time.Duration {
	if d > 0 {
		return d
	}
	return def
}

// Token is an access token with the frame it belongs to.
type Token struct {
	AccessToken string
	FrameID     string
}

// AccessToken returns a usable access token. stale, if non-empty, is a token
// the API just rejected with 401: a different stored token is returned, or a
// refresh is forced. Errors wrap skylight.ErrReauthorize when only a human
// can fix the grant, and skylight.ErrUnavailable for transient failures.
func (m *Manager) AccessToken(ctx context.Context, stale string) (Token, error) {
	owner, err := newOwner()
	if err != nil {
		return Token{}, err
	}
	leaseTTL := orDefault(m.LeaseTTL, 10*time.Second)
	margin := orDefault(m.ExpiryMargin, 5*time.Minute)
	poll := orDefault(m.PollInterval, 250*time.Millisecond)

	for {
		g, err := m.Store.Load(ctx)
		if err != nil {
			return Token{}, err
		}
		if usable(g, stale, m.now(), margin) {
			return Token{g.AccessToken, g.FrameID}, nil
		}
		ok, err := m.Store.AcquireLease(ctx, owner, m.now(), leaseTTL)
		if err != nil {
			return Token{}, err
		}
		if !ok {
			// Someone else is refreshing: wait for their commit (or their
			// lease to expire), then look again.
			if err := sleep(ctx, poll); err != nil {
				return Token{}, fmt.Errorf("%w: waiting for another refresh: %v", skylight.ErrUnavailable, err)
			}
			continue
		}
		tok, again, err := m.refreshHolding(ctx, owner, g.Generation)
		if err != nil {
			return Token{}, err
		}
		if again {
			continue
		}
		return tok, nil
	}
}

// refreshHolding runs with the lease held. again=true means "start over":
// another invocation's commit landed first.
func (m *Manager) refreshHolding(ctx context.Context, owner string, seenGen int64) (tok Token, again bool, err error) {
	release := func() { _ = m.Store.Release(context.WithoutCancel(ctx), owner) }

	g, err := m.Store.Load(ctx)
	if err != nil {
		release()
		return Token{}, false, err
	}
	if g.Generation != seenGen {
		release() // someone refreshed between our read and our lease
		return Token{}, true, nil
	}

	rctx, cancel := context.WithTimeout(ctx, orDefault(m.RefreshTimeout, 4*time.Second))
	r, err := m.Refresher.Refresh(rctx, g.RefreshToken, g.DeviceFingerprint)
	cancel()
	if err != nil {
		release()
		if errors.Is(err, skylight.ErrReauthorize) {
			// invalid_grant most likely means another holder refreshed with
			// this token and has used its new access token. If the store moved
			// on, use that; otherwise the grant really is gone.
			if g2, lerr := m.Store.Load(ctx); lerr == nil && g2.Generation != g.Generation {
				return Token{}, true, nil
			}
		}
		return Token{}, false, err
	}

	now := m.now()
	var exp time.Time
	if r.ExpiresIn > 0 {
		exp = now.Add(time.Duration(r.ExpiresIn) * time.Second)
	}
	// Commit before the new access token is used. Retry transient failures
	// until the context ends; on a lost lease, discard the tokens unused (the
	// old refresh token is still valid because they were never used).
	for attempt := 0; ; attempt++ {
		err = m.Store.Commit(ctx, owner, g.Generation, r.RefreshToken, r.AccessToken, exp, now)
		if err == nil {
			return Token{r.AccessToken, g.FrameID}, false, nil
		}
		if errors.Is(err, ErrLeaseLost) {
			return Token{}, true, nil
		}
		if serr := sleep(ctx, time.Duration(50*(1<<min(attempt, 5)))*time.Millisecond); serr != nil {
			return Token{}, false, fmt.Errorf("%w: could not store refreshed tokens: %v", skylight.ErrUnavailable, err)
		}
	}
}

func usable(g Grant, stale string, now time.Time, margin time.Duration) bool {
	if g.AccessToken == "" || g.AccessToken == stale {
		return false
	}
	return g.AccessExpiresAt.IsZero() || now.Add(margin).Before(g.AccessExpiresAt)
}

func newOwner() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
