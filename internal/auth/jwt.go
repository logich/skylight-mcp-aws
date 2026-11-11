package auth

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"time"
)

const minRSABits = 2048

// KeySet holds the pool's RSA signing keys by key id. Keys are fetched lazily
// and re-fetched on an unknown key id (Cognito rotates keys), at most once per
// MinRefresh, so a stream of junk key ids cannot hammer the JWKS endpoint.
type KeySet struct {
	// Fetch returns the raw JWKS document.
	Fetch      func(context.Context) ([]byte, error)
	MinRefresh time.Duration
	Now        func() time.Time

	mu        sync.Mutex
	keys      map[string]*rsa.PublicKey
	lastFetch time.Time
}

func (k *KeySet) key(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if pk, ok := k.keys[kid]; ok {
		return pk, nil
	}
	now := time.Now
	if k.Now != nil {
		now = k.Now
	}
	if !k.lastFetch.IsZero() && now().Sub(k.lastFetch) < k.MinRefresh {
		return nil, reject("unknown_kid")
	}
	k.lastFetch = now()
	if k.Fetch == nil {
		return nil, reject("no_keys")
	}
	raw, err := k.Fetch(ctx)
	if err != nil {
		return nil, reject("jwks_fetch")
	}
	keys, err := parseJWKS(raw)
	if err != nil {
		return nil, reject("jwks_invalid")
	}
	k.keys = keys
	if pk, ok := k.keys[kid]; ok {
		return pk, nil
	}
	return nil, reject("unknown_kid")
}

// parseJWKS accepts only RSA signing keys of at least minRSABits.
func parseJWKS(raw []byte) (map[string]*rsa.PublicKey, error) {
	var doc struct {
		Keys []struct {
			Kty string `json:"kty"`
			Alg string `json:"alg"`
			Use string `json:"use"`
			Kid string `json:"kid"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	out := map[string]*rsa.PublicKey{}
	for _, k := range doc.Keys {
		if k.Kty != "RSA" || k.Kid == "" || (k.Alg != "" && k.Alg != "RS256") || (k.Use != "" && k.Use != "sig") {
			continue
		}
		nb, err1 := base64.RawURLEncoding.DecodeString(k.N)
		eb, err2 := base64.RawURLEncoding.DecodeString(k.E)
		if err1 != nil || err2 != nil || len(eb) == 0 || len(eb) > 4 {
			continue
		}
		e := int(new(big.Int).SetBytes(eb).Int64())
		n := new(big.Int).SetBytes(nb)
		if e < 3 || e%2 == 0 || n.BitLen() < minRSABits {
			continue
		}
		out[k.Kid] = &rsa.PublicKey{N: n, E: e}
	}
	if len(out) == 0 {
		return nil, errors.New("no usable keys")
	}
	return out, nil
}

// BearerToken extracts the token from an Authorization header value.
func BearerToken(header string) (string, error) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", reject("no_bearer")
	}
	token = strings.TrimSpace(token)
	if token == "" || strings.ContainsAny(token, " \t") {
		return "", reject("no_bearer")
	}
	return token, nil
}

// Verify checks the JWS structure and RS256 signature of token against ks and
// returns its claims. It does not judge the claims; pass them to Authorize.
func Verify(ctx context.Context, ks *KeySet, token string) (Claims, error) {
	if ks == nil {
		return Claims{}, reject("no_keys")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return Claims{}, reject("malformed")
	}
	hb, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return Claims{}, reject("malformed")
	}
	var hdr struct {
		Alg  string `json:"alg"`
		Kid  string `json:"kid"`
		Crit any    `json:"crit"`
	}
	if err := json.Unmarshal(hb, &hdr); err != nil {
		return Claims{}, reject("malformed")
	}
	// Exactly RS256: no "none", no HMAC, no other RSA/EC variants.
	if hdr.Alg != "RS256" {
		return Claims{}, reject("alg")
	}
	if hdr.Kid == "" || hdr.Crit != nil {
		return Claims{}, reject("malformed")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, reject("malformed")
	}
	pk, err := ks.key(ctx, hdr.Kid)
	if err != nil {
		return Claims{}, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if rsa.VerifyPKCS1v15(pk, crypto.SHA256, digest[:], sig) != nil {
		return Claims{}, reject("signature")
	}
	pb, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return Claims{}, reject("malformed")
	}
	return decodeClaims(pb)
}

// decodeClaims is strict about types: a claim that is present with the wrong
// JSON type is malformed, rather than silently treated as absent.
func decodeClaims(b []byte) (Claims, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var m map[string]any
	if err := dec.Decode(&m); err != nil || dec.More() {
		return Claims{}, reject("malformed")
	}
	str := func(k string) (string, bool) {
		v, present := m[k]
		if !present {
			return "", true
		}
		s, ok := v.(string)
		return s, ok
	}
	var c Claims
	var ok [5]bool
	c.Issuer, ok[0] = str("iss")
	c.TokenUse, ok[1] = str("token_use")
	c.ClientID, ok[2] = str("client_id")
	c.Subject, ok[3] = str("sub")
	c.Scope, ok[4] = str("scope")
	for _, good := range ok {
		if !good {
			return Claims{}, reject("malformed")
		}
	}
	// "aud" may be a string or an array of strings (RFC 7519 §4.1.3). Present
	// but empty or of any other type is malformed, so it can't be used to
	// sidestep the audience check.
	if v, present := m["aud"]; present {
		switch a := v.(type) {
		case string:
			c.Audience = []string{a}
		case []any:
			for _, x := range a {
				s, isStr := x.(string)
				if !isStr {
					return Claims{}, reject("malformed")
				}
				c.Audience = append(c.Audience, s)
			}
		default:
			return Claims{}, reject("malformed")
		}
		if len(c.Audience) == 0 {
			return Claims{}, reject("malformed")
		}
	}
	if v, present := m["exp"]; present {
		n, isNum := v.(json.Number)
		if !isNum {
			return Claims{}, reject("malformed")
		}
		f, err := n.Float64()
		if err != nil {
			return Claims{}, reject("malformed")
		}
		c.Exp = f
	}
	return c, nil
}

// Check is the whole decision for one request: bearer token present, signature
// valid, claims acceptable.
func Check(ctx context.Context, cfg Config, ks *KeySet, authorizationHeader string, now time.Time) error {
	token, err := BearerToken(authorizationHeader)
	if err != nil {
		return err
	}
	claims, err := Verify(ctx, ks, token)
	if err != nil {
		return err
	}
	return Authorize(cfg, claims, now)
}
