package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

// hazards probes the two refresh-token behaviours the DynamoDB lease is
// designed around (PLAN §4), with the owner's go-ahead: they may make
// Skylight revoke the grant, which then needs a fresh skylight-login.
//
//  1. Reuse: spend T1 (get T2), then send T1 again. Is it rejected, honoured
//     within a grace period, and does a reuse revoke T2's chain?
//  2. Parallel: send the current token twice at the same instant.
//
// Every successful refresh is saved before the next step runs. Tokens are
// only compared, never printed.
func hazards(ctx context.Context, path string, s *skylight.Saved, reuseDelay time.Duration, useFirst bool) {
	tc := skylight.TokenClient{}
	fp := s.DeviceFingerprint
	save := func(r skylight.TokenResponse) {
		s.Apply(r, time.Now())
		must(skylight.SaveFile(path, *s))
	}

	section("hazard 1: reuse of a spent refresh token")
	t1 := s.RefreshToken
	r2, err := tc.Refresh(ctx, t1, fp)
	if err != nil {
		fail(fmt.Errorf("initial refresh failed: %w", err))
	}
	save(r2)
	t2 := r2.RefreshToken
	fmt.Println("  T1 -> T2: ok (saved T2)")

	if useFirst {
		// Doorkeeper's revoke_previous_refresh_token_on_use revokes T1 only
		// once T2's access token is used.
		fmt.Printf("  used T2's access token first: GET /api/frames -> %d\n", frames(ctx, r2.AccessToken))
	}
	fmt.Printf("  waiting %s before reusing T1\n", reuseDelay)
	time.Sleep(reuseDelay)
	rr, err := tc.Refresh(ctx, t1, fp)
	var reuseToken string
	switch {
	case err == nil:
		reuseToken = rr.RefreshToken
		fmt.Printf("  T1 again: ACCEPTED; returned refresh token equals T2: %v, is new: %v\n",
			rr.RefreshToken == t2, rr.RefreshToken != "" && rr.RefreshToken != t2 && rr.RefreshToken != t1)
	default:
		fmt.Printf("  T1 again: rejected, %s\n", describe(err))
	}

	fmt.Printf("  T2's access token after the reuse: GET /api/frames -> %d\n", frames(ctx, r2.AccessToken))

	// Does T2 still refresh? (If the reuse returned a new token, try that too.)
	live := ""
	for _, c := range []struct{ name, tok string }{{"T2", t2}, {"reuse result", reuseToken}} {
		if c.tok == "" || c.tok == live {
			continue
		}
		r, err := tc.Refresh(ctx, c.tok, fp)
		if err != nil {
			fmt.Printf("  refresh with %s: rejected, %s\n", c.name, describe(err))
			continue
		}
		fmt.Printf("  refresh with %s: ok (saved)\n", c.name)
		save(r)
		live = r.RefreshToken
		break
	}
	if live == "" {
		fmt.Println("\n  RESULT: the reuse revoked the chain. Run skylight-login again (-force).")
		return
	}

	section("hazard 2: two refreshes of the same token at the same instant")
	tp := s.RefreshToken
	var wg sync.WaitGroup
	res := make([]skylight.TokenResponse, 2)
	errs := make([]error, 2)
	start := make(chan struct{})
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res[i], errs[i] = tc.Refresh(ctx, tp, fp)
		}()
	}
	close(start)
	wg.Wait()
	var winners []skylight.TokenResponse
	for i := range 2 {
		if errs[i] != nil {
			fmt.Printf("  request %d: rejected, %s\n", i+1, describe(errs[i]))
		} else {
			fmt.Printf("  request %d: ok\n", i+1)
			winners = append(winners, res[i])
		}
	}
	if len(winners) == 2 {
		fmt.Printf("  both succeeded; same refresh token returned: %v\n", winners[0].RefreshToken == winners[1].RefreshToken)
	}
	// Find a surviving token among the winners and save it.
	ok := false
	for i, w := range winners {
		r, err := tc.Refresh(ctx, w.RefreshToken, fp)
		if err != nil {
			fmt.Printf("  winner %d's token: rejected on next refresh, %s\n", i+1, describe(err))
			continue
		}
		fmt.Printf("  winner %d's token: refreshes ok (saved)\n", i+1)
		save(r)
		ok = true
		break
	}
	if !ok {
		fmt.Println("\n  RESULT: the parallel refresh revoked the chain. Run skylight-login again (-force).")
		return
	}
	fmt.Printf("\n  saved grant check: GET /api/frames -> %d\n", frames(ctx, s.AccessToken))
}

func frames(ctx context.Context, accessToken string) int {
	r, err := api.Get(ctx, accessToken, "/api/frames", nil, skylight.GetOptions{})
	if err != nil {
		return -1
	}
	return r.Status
}

// describe gives the error class and OAuth error code (never a token).
func describe(err error) string {
	kind := "other"
	switch {
	case errors.Is(err, skylight.ErrReauthorize):
		kind = "credential rejected"
	case errors.Is(err, skylight.ErrUnavailable):
		kind = "unavailable"
	}
	msg := err.Error()
	if i := strings.Index(msg, "(HTTP"); i >= 0 {
		return kind + " " + msg[i:]
	}
	return kind
}
