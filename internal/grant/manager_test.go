package grant

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

// doorkeeper mimics Skylight's token endpoint as probed live: every refresh
// rotates; a spent refresh token stays valid until the access token issued
// with its successor is used; then it gets invalid_grant (ErrReauthorize).
type doorkeeper struct {
	mu       sync.Mutex
	n        int
	valid    map[string]bool   // live refresh tokens
	parentOf map[string]string // access token -> refresh token spent to get it
	revoked  map[string]bool
	calls    atomic.Int64
	fail     error // returned once if set
	delay    time.Duration
}

func newDoorkeeper(initial string) *doorkeeper {
	return &doorkeeper{valid: map[string]bool{initial: true}, parentOf: map[string]string{}, revoked: map[string]bool{}}
}

func (d *doorkeeper) Refresh(ctx context.Context, rt, fp string) (skylight.TokenResponse, error) {
	d.calls.Add(1)
	if d.delay > 0 {
		time.Sleep(d.delay)
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail != nil {
		err := d.fail
		d.fail = nil
		return skylight.TokenResponse{}, err
	}
	if fp != "fp" || !d.valid[rt] || d.revoked[rt] {
		return skylight.TokenResponse{}, fmt.Errorf("%w (HTTP 400 invalid_grant)", skylight.ErrReauthorize)
	}
	d.n++
	nrt, nat := fmt.Sprintf("rt%d", d.n), fmt.Sprintf("at%d", d.n)
	d.valid[nrt] = true
	d.parentOf[nat] = rt
	return skylight.TokenResponse{AccessToken: nat, RefreshToken: nrt, ExpiresIn: 86400}, nil
}

// use is an API call with an access token: it revokes the token's parent.
func (d *doorkeeper) use(at string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if p, ok := d.parentOf[at]; ok {
		d.revoked[p] = true
	}
}

var t0 = time.Date(2030, 1, 7, 12, 0, 0, 0, time.UTC)

func seeded(access string, exp time.Time) *MemStore {
	return NewMemStore(&Grant{RefreshToken: "rt0", AccessToken: access, AccessExpiresAt: exp, DeviceFingerprint: "fp", FrameID: "f1"})
}

func mgr(st Store, r Refresher, now time.Time) *Manager {
	return &Manager{Store: st, Refresher: r, Now: func() time.Time { return now }, PollInterval: time.Millisecond}
}

func TestValidTokenIsReusedWithoutRefresh(t *testing.T) {
	dk := newDoorkeeper("rt0")
	tok, err := mgr(seeded("at0", t0.Add(time.Hour)), dk, t0).AccessToken(context.Background(), "")
	if err != nil || tok.AccessToken != "at0" || tok.FrameID != "f1" || dk.calls.Load() != 0 {
		t.Fatalf("tok %+v err %v calls %d", tok, err, dk.calls.Load())
	}
}

func TestExpiringTokenIsRefreshedAndCommittedFirst(t *testing.T) {
	dk := newDoorkeeper("rt0")
	st := seeded("at0", t0.Add(time.Minute)) // inside the 5 min margin
	tok, err := mgr(st, dk, t0).AccessToken(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	g := st.Snapshot()
	if tok.AccessToken != "at1" || g.AccessToken != "at1" || g.RefreshToken != "rt1" || g.Generation != 1 || g.LeaseOwner != "" {
		t.Fatalf("tok %+v stored %+v", tok, g)
	}
	if !g.AccessExpiresAt.Equal(t0.Add(24 * time.Hour)) {
		t.Fatalf("expiry %v", g.AccessExpiresAt)
	}
}

func TestStaleTokenForcesRefreshOnce(t *testing.T) {
	dk := newDoorkeeper("rt0")
	st := seeded("at0", t0.Add(time.Hour))
	m := mgr(st, dk, t0)
	tok, err := m.AccessToken(context.Background(), "at0")
	if err != nil || tok.AccessToken != "at1" {
		t.Fatalf("%+v %v", tok, err)
	}
	// A second caller holding the same stale token gets the new one, no refresh.
	tok, err = m.AccessToken(context.Background(), "at0")
	if err != nil || tok.AccessToken != "at1" || dk.calls.Load() != 1 {
		t.Fatalf("%+v %v calls %d", tok, err, dk.calls.Load())
	}
}

// Many concurrent invocations share one store: exactly one refresh, everyone
// gets a token that works, and the stored refresh token stays valid even
// after every returned access token has been used.
func TestConcurrentInvocationsRefreshOnce(t *testing.T) {
	dk := newDoorkeeper("rt0")
	dk.delay = 5 * time.Millisecond
	st := seeded("at0", t0.Add(-time.Hour))
	var wg sync.WaitGroup
	toks := make([]string, 20)
	errs := make([]error, 20)
	for i := range toks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tk, err := mgr(st, dk, t0).AccessToken(context.Background(), "")
			toks[i], errs[i] = tk.AccessToken, err
		}()
	}
	wg.Wait()
	for i := range toks {
		if errs[i] != nil || toks[i] != "at1" {
			t.Fatalf("caller %d: %q %v", i, toks[i], errs[i])
		}
		dk.use(toks[i])
	}
	if dk.calls.Load() != 1 {
		t.Fatalf("refresh calls %d, want 1", dk.calls.Load())
	}
	// The stored refresh token must still work.
	if _, err := dk.Refresh(context.Background(), st.Snapshot().RefreshToken, "fp"); err != nil {
		t.Fatalf("stored refresh token is dead: %v", err)
	}
}

// A commit that fails (lease lost) must discard the new tokens unused, so the
// old refresh token survives.
func TestLostLeaseDiscardsTokensUnused(t *testing.T) {
	dk := newDoorkeeper("rt0")
	st := seeded("at0", t0.Add(-time.Hour))
	st.Fail["Commit"] = ErrLeaseLost
	tok, err := mgr(st, dk, t0).AccessToken(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	// First refresh produced at1 (discarded); the retry produced at2 from rt0.
	if tok.AccessToken != "at2" || st.Snapshot().RefreshToken != "rt2" {
		t.Fatalf("tok %+v stored %+v", tok, st.Snapshot())
	}
	dk.use(tok.AccessToken)
	if _, err := dk.Refresh(context.Background(), "rt2", "fp"); err != nil {
		t.Fatalf("grant lost: %v", err)
	}
}

func TestTransientCommitFailureIsRetried(t *testing.T) {
	dk := newDoorkeeper("rt0")
	st := seeded("at0", t0.Add(-time.Hour))
	st.Fail["Commit"] = errors.New("grant store commit: ProvisionedThroughputExceededException")
	tok, err := mgr(st, dk, t0).AccessToken(context.Background(), "")
	if err != nil || tok.AccessToken != "at1" || st.Snapshot().Generation != 1 || dk.calls.Load() != 1 {
		t.Fatalf("%+v %v %+v calls %d", tok, err, st.Snapshot(), dk.calls.Load())
	}
}

func TestCommitThatNeverSucceedsReturnsUnavailableAndNoToken(t *testing.T) {
	dk := newDoorkeeper("rt0")
	st := &alwaysFailCommit{MemStore: seeded("at0", t0.Add(-time.Hour))}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	tok, err := mgr(st, dk, t0).AccessToken(ctx, "")
	if !errors.Is(err, skylight.ErrUnavailable) || tok.AccessToken != "" {
		t.Fatalf("tok %+v err %v", tok, err)
	}
	if _, err := dk.Refresh(context.Background(), "rt0", "fp"); err != nil {
		t.Fatalf("old refresh token must still be valid: %v", err)
	}
}

type alwaysFailCommit struct{ *MemStore }

func (a *alwaysFailCommit) Commit(context.Context, string, int64, string, string, time.Time, time.Time) error {
	return errors.New("grant store commit: InternalServerError")
}

func TestRevokedGrantReportsReauthorize(t *testing.T) {
	dk := newDoorkeeper("other")
	st := seeded("at0", t0.Add(-time.Hour))
	_, err := mgr(st, dk, t0).AccessToken(context.Background(), "")
	if !errors.Is(err, skylight.ErrReauthorize) {
		t.Fatalf("err %v", err)
	}
	if st.Snapshot().LeaseOwner != "" {
		t.Fatal("lease not released")
	}
}

// invalid_grant because another holder already refreshed and used its token:
// the store has moved on, so use the stored token rather than failing.
func TestInvalidGrantAfterSomeoneElseRefreshedRecovers(t *testing.T) {
	st := seeded("at0", t0.Add(-time.Hour))
	r := refresherFunc(func(ctx context.Context, rt, fp string) (skylight.TokenResponse, error) {
		// Simulate the other holder committing while our refresh is in flight.
		g := st.Snapshot()
		st.mu.Lock()
		st.g.RefreshToken, st.g.AccessToken, st.g.AccessExpiresAt, st.g.Generation = "rtX", "atX", t0.Add(time.Hour), g.Generation+1
		st.mu.Unlock()
		return skylight.TokenResponse{}, fmt.Errorf("%w (HTTP 400 invalid_grant)", skylight.ErrReauthorize)
	})
	tok, err := mgr(st, r, t0).AccessToken(context.Background(), "")
	if err != nil || tok.AccessToken != "atX" {
		t.Fatalf("%+v %v", tok, err)
	}
}

func TestUnavailableIsNotReauthorize(t *testing.T) {
	dk := newDoorkeeper("rt0")
	dk.fail = fmt.Errorf("%w (HTTP 503)", skylight.ErrUnavailable)
	st := seeded("", time.Time{})
	_, err := mgr(st, dk, t0).AccessToken(context.Background(), "")
	if !errors.Is(err, skylight.ErrUnavailable) || errors.Is(err, skylight.ErrReauthorize) {
		t.Fatalf("err %v", err)
	}
	if g := st.Snapshot(); g.RefreshToken != "rt0" || g.LeaseOwner != "" {
		t.Fatalf("store changed: %+v", g)
	}
}

func TestExpiredLeaseOfCrashedHolderIsTakenOver(t *testing.T) {
	dk := newDoorkeeper("rt0")
	st := seeded("at0", t0.Add(-time.Hour))
	st.g.LeaseOwner, st.g.LeaseExpiresAt = "crashed", t0.Add(-time.Second)
	tok, err := mgr(st, dk, t0).AccessToken(context.Background(), "")
	if err != nil || tok.AccessToken != "at1" {
		t.Fatalf("%+v %v", tok, err)
	}
}

func TestLiveLeaseMakesCallersWaitUntilDeadline(t *testing.T) {
	dk := newDoorkeeper("rt0")
	st := seeded("at0", t0.Add(-time.Hour))
	st.g.LeaseOwner, st.g.LeaseExpiresAt = "busy", t0.Add(time.Hour)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err := mgr(st, dk, t0).AccessToken(ctx, "")
	if !errors.Is(err, skylight.ErrUnavailable) || dk.calls.Load() != 0 {
		t.Fatalf("err %v calls %d", err, dk.calls.Load())
	}
}

func TestMissingGrant(t *testing.T) {
	_, err := mgr(NewMemStore(nil), newDoorkeeper("x"), t0).AccessToken(context.Background(), "")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("err %v", err)
	}
}

type refresherFunc func(context.Context, string, string) (skylight.TokenResponse, error)

func (f refresherFunc) Refresh(ctx context.Context, rt, fp string) (skylight.TokenResponse, error) {
	return f(ctx, rt, fp)
}
