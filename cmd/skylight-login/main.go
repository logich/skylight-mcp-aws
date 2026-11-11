// Command skylight-login does the one human step of Skylight's OAuth flow and
// saves the resulting grant to a local 0600 file outside the repository. It
// never prints a token.
//
// Sign in (default):
//
//	go run ./cmd/skylight-login
//
// It opens Skylight's sign-in page. After you sign in, the browser lands on
// https://ourskylight.com/welcome?code=… (the page itself may look blank or
// like Skylight's home page). Copy the whole address and paste it here within
// about 30 seconds; the code is exchanged at once.
//
// Import an existing refresh token instead (from stdin, bare or as JSON with
// refresh_token and optionally device_fingerprint); it is spent once to check
// it works, and the rotated result is saved:
//
//	pbpaste | go run ./cmd/skylight-login -import
//
// Run it in your own terminal, not through a chat session's shell prompt, so
// nothing you paste lands in a transcript.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

func main() {
	def, err := skylight.DefaultTokenPath()
	if err != nil {
		fail(err)
	}
	out := flag.String("out", def, "where to save the grant (mode 0600)")
	imp := flag.Bool("import", false, "read a refresh token from stdin instead of signing in")
	force := flag.Bool("force", false, "replace an existing saved grant")
	noOpen := flag.Bool("no-open", false, "print the sign-in URL without opening a browser")
	flag.Parse()

	if _, err := os.Stat(*out); err == nil && !*force {
		fail(fmt.Errorf("%s already holds a grant; pass -force to replace it (the old refresh token stays valid at Skylight until it is used or revoked)", *out))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	tc := skylight.TokenClient{}

	var saved skylight.Saved
	var resp skylight.TokenResponse
	if *imp {
		saved, resp, err = importToken(ctx, tc, os.Stdin)
	} else {
		saved, resp, err = signIn(ctx, tc, *noOpen)
	}
	if err != nil {
		fail(err)
	}
	if err := skylight.SaveFile(*out, saved); err != nil {
		fail(fmt.Errorf("tokens were issued but could not be saved: %w", err))
	}
	fmt.Printf("\nSaved the Skylight grant to %s (mode 0600).\n", *out)
	fmt.Printf("Token response fields: %s\n", strings.Join(resp.Shape, ", "))
	if resp.ExpiresIn > 0 {
		fmt.Printf("Access token lifetime: %s\n", time.Duration(resp.ExpiresIn)*time.Second)
	} else {
		fmt.Println("Access token lifetime: not stated (no expires_in)")
	}
}

func signIn(ctx context.Context, tc skylight.TokenClient, noOpen bool) (skylight.Saved, skylight.TokenResponse, error) {
	p, err := skylight.NewPKCE()
	if err != nil {
		return skylight.Saved{}, skylight.TokenResponse{}, err
	}
	fp, err := skylight.NewFingerprint()
	if err != nil {
		return skylight.Saved{}, skylight.TokenResponse{}, err
	}
	u := skylight.AuthorizationURL(p.Challenge)
	fmt.Println("1. Sign in to Skylight on this page (opening it now):")
	fmt.Println()
	fmt.Println("   " + u)
	fmt.Println()
	fmt.Println("2. The browser then lands on https://ourskylight.com/welcome?code=…")
	fmt.Println("   Copy the WHOLE address from the address bar and paste it below.")
	fmt.Println("   The code expires in about 30 seconds, so paste right away.")
	if !noOpen && runtime.GOOS == "darwin" {
		_ = exec.Command("open", u).Start()
	}
	fmt.Print("\nPaste here: ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return skylight.Saved{}, skylight.TokenResponse{}, errors.New("nothing pasted")
	}
	code, err := skylight.ExtractCode(line)
	if err != nil {
		return skylight.Saved{}, skylight.TokenResponse{}, err
	}
	resp, err := tc.Exchange(ctx, code, p.Verifier, fp)
	if err != nil {
		if errors.Is(err, skylight.ErrReauthorize) {
			err = fmt.Errorf("%v; the code was probably too old or already used: run this again and paste faster", err)
		}
		return skylight.Saved{}, skylight.TokenResponse{}, err
	}
	s := skylight.Saved{DeviceFingerprint: fp}
	s.Apply(resp, time.Now())
	return s, resp, nil
}

func importToken(ctx context.Context, tc skylight.TokenClient, r io.Reader) (skylight.Saved, skylight.TokenResponse, error) {
	b, err := io.ReadAll(io.LimitReader(r, 16<<10))
	if err != nil {
		return skylight.Saved{}, skylight.TokenResponse{}, err
	}
	text := strings.Trim(strings.TrimSpace(string(b)), `'"`)
	var in struct {
		RefreshToken      string `json:"refresh_token"`
		DeviceFingerprint string `json:"device_fingerprint"`
	}
	if strings.HasPrefix(text, "{") {
		if err := json.Unmarshal([]byte(text), &in); err != nil {
			return skylight.Saved{}, skylight.TokenResponse{}, errors.New("stdin looks like JSON but does not parse")
		}
	} else {
		in.RefreshToken = text
	}
	if len(in.RefreshToken) < 20 || strings.ContainsAny(in.RefreshToken, " \t\r\n") {
		return skylight.Saved{}, skylight.TokenResponse{}, errors.New("stdin does not look like a refresh token")
	}
	if in.DeviceFingerprint == "" {
		// The token may be bound to the fingerprint it was issued with; without
		// it, a new one is tried and Skylight may reject the refresh.
		fmt.Fprintln(os.Stderr, "no device_fingerprint given; generating one (Skylight may reject the token if it is bound to another)")
		if in.DeviceFingerprint, err = skylight.NewFingerprint(); err != nil {
			return skylight.Saved{}, skylight.TokenResponse{}, err
		}
	}
	resp, err := tc.Refresh(ctx, in.RefreshToken, in.DeviceFingerprint)
	if err != nil {
		return skylight.Saved{}, skylight.TokenResponse{}, err
	}
	s := skylight.Saved{RefreshToken: in.RefreshToken, DeviceFingerprint: in.DeviceFingerprint}
	s.Apply(resp, time.Now())
	if resp.RefreshToken == "" {
		fmt.Println("note: the refresh did not return a new refresh token (no rotation)")
	}
	return s, resp, nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "skylight-login:", err)
	os.Exit(1)
}
