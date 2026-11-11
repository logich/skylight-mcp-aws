// Package grant keeps the one Skylight OAuth grant (rotating refresh token,
// current access token, device fingerprint, frame id) and hands out valid
// access tokens to concurrent Lambda invocations without losing the grant.
//
// Skylight's token endpoint behaves like Doorkeeper with
// revoke_previous_refresh_token_on_use (SKYLIGHT_API.md §6): a spent refresh
// token stays valid until the NEW access token is first used. So the one rule
// that keeps the grant safe is: commit the new tokens to the store before the
// new access token is used. The lease only stops invocations from refreshing
// at the same time and committing divergent tokens.
package grant

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Grant is the stored state.
type Grant struct {
	RefreshToken      string
	AccessToken       string
	AccessExpiresAt   time.Time // zero: unknown (treat as valid until a 401)
	DeviceFingerprint string
	FrameID           string
	Generation        int64 // bumped by every committed refresh
	LeaseOwner        string
	LeaseExpiresAt    time.Time
}

// ErrNotFound means the store has no grant: seed it with skylight-store-import.
var ErrNotFound = errors.New("grant: no Skylight grant stored; run the store import")

// ErrLeaseLost means a commit or release found the lease held by someone else
// (or the generation moved). The caller's new tokens must be discarded unused.
var ErrLeaseLost = errors.New("grant: lease lost")

// Store is the persistence the Manager needs. All reads are strongly
// consistent; every write is conditional.
type Store interface {
	Load(ctx context.Context) (Grant, error)
	// AcquireLease takes the lease if it is free, expired, or already ours.
	AcquireLease(ctx context.Context, owner string, now time.Time, ttl time.Duration) (bool, error)
	// Commit stores refreshed tokens, bumps the generation and frees the lease,
	// only if owner holds the lease and the generation is still gen. An empty
	// refreshToken keeps the stored one (a non-rotating response).
	Commit(ctx context.Context, owner string, gen int64, refreshToken, accessToken string, accessExpiresAt, now time.Time) error
	// Release frees the lease if owner holds it.
	Release(ctx context.Context, owner string) error
}

// MemStore is an in-memory Store with the same conditional semantics, for
// tests.
type MemStore struct {
	mu sync.Mutex
	g  *Grant
	// Fail, if set, is returned by the next call to the named method
	// ("Load", "AcquireLease", "Commit", "Release") and then cleared.
	Fail map[string]error
}

// NewMemStore returns a store holding g (nil: empty).
func NewMemStore(g *Grant) *MemStore {
	m := &MemStore{Fail: map[string]error{}}
	if g != nil {
		c := *g
		m.g = &c
	}
	return m
}

func (m *MemStore) fail(name string) error {
	if err, ok := m.Fail[name]; ok {
		delete(m.Fail, name)
		return err
	}
	return nil
}

func (m *MemStore) Load(context.Context) (Grant, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Load"); err != nil {
		return Grant{}, err
	}
	if m.g == nil {
		return Grant{}, ErrNotFound
	}
	return *m.g, nil
}

func (m *MemStore) AcquireLease(_ context.Context, owner string, now time.Time, ttl time.Duration) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AcquireLease"); err != nil {
		return false, err
	}
	if m.g == nil {
		return false, ErrNotFound
	}
	if m.g.LeaseOwner != "" && m.g.LeaseOwner != owner && !m.g.LeaseExpiresAt.Before(now) {
		return false, nil
	}
	m.g.LeaseOwner, m.g.LeaseExpiresAt = owner, now.Add(ttl)
	return true, nil
}

func (m *MemStore) Commit(_ context.Context, owner string, gen int64, rt, at string, exp, _ time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Commit"); err != nil {
		return err
	}
	if m.g == nil || m.g.LeaseOwner != owner || m.g.Generation != gen {
		return ErrLeaseLost
	}
	if rt != "" {
		m.g.RefreshToken = rt
	}
	m.g.AccessToken, m.g.AccessExpiresAt = at, exp
	m.g.Generation++
	m.g.LeaseOwner, m.g.LeaseExpiresAt = "", time.Time{}
	return nil
}

func (m *MemStore) Release(_ context.Context, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("Release"); err != nil {
		return err
	}
	if m.g != nil && m.g.LeaseOwner == owner {
		m.g.LeaseOwner, m.g.LeaseExpiresAt = "", time.Time{}
	}
	return nil
}

// Snapshot returns a copy of the stored grant (tests).
func (m *MemStore) Snapshot() Grant {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.g == nil {
		return Grant{}
	}
	return *m.g
}
