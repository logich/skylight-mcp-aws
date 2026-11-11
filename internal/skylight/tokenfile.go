package skylight

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Saved is the credential bundle for one Skylight grant. The refresh token
// rotates, so exactly one place may hold the live bundle at a time: this local
// file during milestone 3, the DynamoDB item from milestone 4 on.
type Saved struct {
	RefreshToken      string    `json:"refresh_token"`
	AccessToken       string    `json:"access_token,omitempty"`
	AccessExpiresAt   time.Time `json:"access_expires_at,omitzero"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// Apply records a token response, keeping the old refresh token only if the
// server did not send a new one.
func (s *Saved) Apply(r TokenResponse, now time.Time) {
	s.AccessToken = r.AccessToken
	if r.RefreshToken != "" {
		s.RefreshToken = r.RefreshToken
	}
	s.AccessExpiresAt = time.Time{}
	if r.ExpiresIn > 0 {
		s.AccessExpiresAt = now.Add(time.Duration(r.ExpiresIn) * time.Second).UTC()
	}
	s.UpdatedAt = now.UTC()
}

// DefaultTokenPath is outside the repository, under the user's config dir.
func DefaultTokenPath() (string, error) {
	d, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "skylight-mcp", "skylight-token.json"), nil
}

// SaveFile writes the bundle atomically (temp file, fsync, rename) with mode
// 0600 in a 0700 directory, so a crash never leaves a half-written token.
func SaveFile(path string, s Saved) error {
	if s.RefreshToken == "" || s.DeviceFingerprint == "" {
		return errors.New("refusing to save a bundle without refresh token and fingerprint")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".skylight-token-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp) // no-op after a successful rename
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// LoadFile reads a bundle and refuses files other users could read.
func LoadFile(path string) (Saved, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return Saved{}, err
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return Saved{}, fmt.Errorf("%s is readable by other users (mode %v); chmod 600 it", path, fi.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return Saved{}, err
	}
	var s Saved
	if err := json.Unmarshal(b, &s); err != nil {
		return Saved{}, errors.New("token file is not valid JSON")
	}
	if s.RefreshToken == "" || s.DeviceFingerprint == "" {
		return Saved{}, errors.New("token file lacks refresh_token or device_fingerprint")
	}
	return s, nil
}
