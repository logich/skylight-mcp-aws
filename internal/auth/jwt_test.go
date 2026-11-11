package auth

import (
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	keysOnce          sync.Once
	poolKey, otherKey *rsa.PrivateKey
	smallKey          *rsa.PrivateKey
)

func testKeys(t testing.TB) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if poolKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if otherKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
			panic(err)
		}
		if smallKey, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
			panic(err)
		}
	})
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func jwk(kid string, k *rsa.PublicKey) map[string]string {
	return map[string]string{
		"kty": "RSA", "alg": "RS256", "use": "sig", "kid": kid,
		"n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes()),
	}
}

func jwks(keys ...map[string]string) []byte {
	b, _ := json.Marshal(map[string]any{"keys": keys})
	return b
}

// keySet serves the pool key as "pool-kid" and counts fetches.
func keySet(t testing.TB, extra ...map[string]string) (*KeySet, *int) {
	testKeys(t)
	fetches := 0
	doc := jwks(append([]map[string]string{jwk("pool-kid", &poolKey.PublicKey)}, extra...)...)
	return &KeySet{
		Fetch:      func(context.Context) ([]byte, error) { fetches++; return doc, nil },
		MinRefresh: time.Minute,
		Now:        func() time.Time { return testNow },
	}, &fetches
}

func goodPayload() map[string]any {
	return map[string]any{
		"iss": testIssuer, "token_use": "access", "client_id": testClient, "sub": testSub,
		"scope": testScope, "exp": testNow.Unix() + 600, "iat": testNow.Unix() - 10,
		"username": testSub, "jti": "j",
	}
}

func sign(t testing.TB, key *rsa.PrivateKey, header, payload map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	pb, _ := json.Marshal(payload)
	input := b64(hb) + "." + b64(pb)
	d := sha256.Sum256([]byte(input))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatal(err)
	}
	return input + "." + b64(sig)
}

func rs256(kid string) map[string]any { return map[string]any{"alg": "RS256", "kid": kid} }

func validToken(t testing.TB) string {
	testKeys(t)
	return sign(t, poolKey, rs256("pool-kid"), goodPayload())
}

func check(t *testing.T, ks *KeySet, header string) error {
	t.Helper()
	return Check(context.Background(), cfg(), ks, header, testNow)
}

func TestCheckAcceptsValidToken(t *testing.T) {
	ks, _ := keySet(t)
	if err := check(t, ks, "Bearer "+validToken(t)); err != nil {
		t.Fatalf("valid token rejected: %v", err)
	}
	if err := check(t, ks, "bearer "+validToken(t)); err != nil {
		t.Fatalf("lower-case scheme rejected: %v", err)
	}
	// Resource-bound tokens, as Cognito issues when the client sends RFC 8707
	// "resource" (claude.ai does): aud is our connector URL.
	for _, aud := range []any{testAud, []string{testAud}} {
		p := goodPayload()
		p["aud"] = aud
		if err := check(t, ks, "Bearer "+sign(t, poolKey, rs256("pool-kid"), p)); err != nil {
			t.Fatalf("resource-bound token (aud %v) rejected: %v", aud, err)
		}
	}
}

func TestCheckRejectsTokens(t *testing.T) {
	testKeys(t)
	valid := validToken(t)
	parts := strings.Split(valid, ".")

	payloadWith := func(mut func(map[string]any)) map[string]any { p := goodPayload(); mut(p); return p }
	tamperedPayload := b64([]byte(`{"iss":"` + testIssuer + `","token_use":"access","client_id":"` + testClient +
		`","sub":"attacker","scope":"` + testScope + `","exp":9999999999}`))
	hs256 := func() string {
		h, _ := json.Marshal(map[string]any{"alg": "HS256", "kid": "pool-kid"})
		p, _ := json.Marshal(goodPayload())
		in := b64(h) + "." + b64(p)
		m := hmac.New(sha256.New, poolKey.PublicKey.N.Bytes()) // classic key-confusion attempt
		m.Write([]byte(in))
		return in + "." + b64(m.Sum(nil))
	}()
	none := func() string {
		h, _ := json.Marshal(map[string]any{"alg": "none", "kid": "pool-kid"})
		p, _ := json.Marshal(goodPayload())
		return b64(h) + "." + b64(p) + "."
	}()
	noneWithSig := func() string {
		h, _ := json.Marshal(map[string]any{"alg": "none", "kid": "pool-kid"})
		return b64(h) + "." + parts[1] + "." + parts[2]
	}()

	tests := []struct {
		name, header, want string
	}{
		{"no header", "", "no_bearer"},
		{"basic scheme", "Basic " + valid, "no_bearer"},
		{"bearer no token", "Bearer ", "no_bearer"},
		{"token without scheme", valid, "no_bearer"},
		{"two tokens", "Bearer " + valid + " " + valid, "no_bearer"},
		{"garbage", "Bearer not-a-jwt", "malformed"},
		{"two parts", "Bearer " + parts[0] + "." + parts[1], "malformed"},
		{"four parts", "Bearer " + valid + ".x", "malformed"},
		{"empty signature", "Bearer " + parts[0] + "." + parts[1] + ".", "malformed"},
		{"header not base64", "Bearer !!!." + parts[1] + "." + parts[2], "malformed"},
		{"header not json", "Bearer " + b64([]byte("nope")) + "." + parts[1] + "." + parts[2], "malformed"},
		{"signature not base64", "Bearer " + parts[0] + "." + parts[1] + ".!!!", "malformed"},
		{"tampered payload", "Bearer " + parts[0] + "." + tamperedPayload + "." + parts[2], "signature"},
		{"tampered signature", "Bearer " + parts[0] + "." + parts[1] + "." + b64([]byte("x"+parts[2])), "signature"},
		{"signed by other key, pool kid", "Bearer " + sign(t, otherKey, rs256("pool-kid"), goodPayload()), "signature"},
		{"unknown kid", "Bearer " + sign(t, otherKey, rs256("attacker-kid"), goodPayload()), "unknown_kid"},
		{"missing kid", "Bearer " + sign(t, poolKey, map[string]any{"alg": "RS256"}, goodPayload()), "malformed"},
		{"crit header", "Bearer " + sign(t, poolKey, map[string]any{"alg": "RS256", "kid": "pool-kid", "crit": []string{"x"}}, goodPayload()), "malformed"},
		{"alg none (empty signature, caught as malformed first)", "Bearer " + none, "malformed"},
		{"alg none with real signature", "Bearer " + noneWithSig, "alg"},
		{"alg HS256 key confusion", "Bearer " + hs256, "alg"},
		{"alg RS512", "Bearer " + sign(t, poolKey, map[string]any{"alg": "RS512", "kid": "pool-kid"}, goodPayload()), "alg"},
		{"alg lower case", "Bearer " + sign(t, poolKey, map[string]any{"alg": "rs256", "kid": "pool-kid"}, goodPayload()), "alg"},
		{"payload not json", "Bearer " + func() string {
			h, _ := json.Marshal(rs256("pool-kid"))
			in := b64(h) + "." + b64([]byte("not json"))
			d := sha256.Sum256([]byte(in))
			s, _ := rsa.SignPKCS1v15(rand.Reader, poolKey, crypto.SHA256, d[:])
			return in + "." + b64(s)
		}(), "malformed"},
		{"exp as string", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["exp"] = "9999999999" })), "malformed"},
		{"sub as number", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["sub"] = 5 })), "malformed"},
		{"scope as array", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["scope"] = []string{testScope} })), "malformed"},
		{"expired", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["exp"] = testNow.Unix() - 1 })), "expired"},
		{"exp missing", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { delete(p, "exp") })), "exp_invalid"},
		{"id token", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["token_use"] = "id" })), "token_use"},
		{"wrong pool issuer", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["iss"] = "https://cognito-idp.us-east-2.amazonaws.com/us-east-2_OTHER" })), "issuer"},
		{"other client", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["client_id"] = "other-client" })), "client_id"},
		{"no scope", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { delete(p, "scope") })), "scope"},
		{"other user", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["sub"] = "someone-else" })), "subject"},
		{"aud other resource", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["aud"] = "https://evil.example/mcp" })), "audience"},
		{"aud array other", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["aud"] = []string{"https://evil.example/mcp"} })), "audience"},
		{"aud empty array", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["aud"] = []string{} })), "malformed"},
		{"aud number", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["aud"] = 7 })), "malformed"},
		{"aud array with number", "Bearer " + sign(t, poolKey, rs256("pool-kid"), payloadWith(func(p map[string]any) { p["aud"] = []any{testAud, 7} })), "malformed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ks, _ := keySet(t)
			err := check(t, ks, tt.header)
			if err == nil {
				t.Fatal("expected rejection, got nil")
			}
			if !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("not ErrUnauthorized: %v", err)
			}
			if got := Reason(err); got != tt.want {
				t.Fatalf("reason = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJWKSRejectsWeakAndForeignKeys(t *testing.T) {
	testKeys(t)
	ks := &KeySet{
		Fetch: func(context.Context) ([]byte, error) {
			bad := jwk("small", &smallKey.PublicKey)
			hs := map[string]string{"kty": "oct", "kid": "hmac", "k": "c2VjcmV0"}
			wrongAlg := jwk("rs512", &poolKey.PublicKey)
			wrongAlg["alg"] = "RS512"
			enc := jwk("enc", &poolKey.PublicKey)
			enc["use"] = "enc"
			return jwks(bad, hs, wrongAlg, enc, jwk("pool-kid", &poolKey.PublicKey)), nil
		},
		MinRefresh: time.Minute,
	}
	for _, kid := range []string{"small", "hmac", "rs512", "enc"} {
		tok := sign(t, poolKey, rs256(kid), goodPayload())
		if kid == "small" {
			tok = sign(t, smallKey, rs256(kid), goodPayload())
		}
		if err := check(t, ks, "Bearer "+tok); Reason(err) != "unknown_kid" {
			t.Errorf("kid %q: got %v, want unknown_kid", kid, err)
		}
	}
}

func TestKeySetRefetchIsRateLimited(t *testing.T) {
	ks, fetches := keySet(t)
	for i := 0; i < 20; i++ {
		_ = check(t, ks, "Bearer "+sign(t, otherKey, rs256("junk-kid"), goodPayload()))
	}
	if *fetches != 1 {
		t.Fatalf("JWKS fetched %d times for junk kids, want 1", *fetches)
	}
	// Still accepts the real key from the cached set.
	if err := check(t, ks, "Bearer "+validToken(t)); err != nil {
		t.Fatalf("valid token rejected after junk: %v", err)
	}
}

func TestKeySetFetchFailureFailsClosed(t *testing.T) {
	ks := &KeySet{Fetch: func(context.Context) ([]byte, error) { return nil, errors.New("down") }, MinRefresh: time.Minute}
	if err := check(t, ks, "Bearer "+validToken(t)); Reason(err) != "jwks_fetch" {
		t.Fatalf("got %v, want jwks_fetch", err)
	}
	if err := check(t, &KeySet{}, "Bearer "+validToken(t)); Reason(err) != "no_keys" {
		t.Fatalf("nil fetch: got %v, want no_keys", err)
	}
}

func FuzzVerify(f *testing.F) {
	testKeys(f)
	f.Add(sign(f, poolKey, rs256("pool-kid"), goodPayload()))
	f.Add("a.b.c")
	f.Add("")
	ks, _ := keySet(f)
	f.Fuzz(func(t *testing.T, tok string) {
		c, err := Verify(context.Background(), ks, tok)
		if err == nil && Authorize(cfg(), c, testNow) == nil {
			// Only a token actually signed by the pool key may pass; the fuzzer
			// cannot forge RSA signatures, so a pass means a parsing bug.
			parts := strings.Split(tok, ".")
			d := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
			sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
			if rsa.VerifyPKCS1v15(&poolKey.PublicKey, crypto.SHA256, d[:], sig) != nil {
				t.Fatalf("accepted a token without a valid signature: %q", tok)
			}
		}
	})
}
