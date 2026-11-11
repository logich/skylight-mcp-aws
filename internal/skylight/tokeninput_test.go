package skylight

import "testing"

func TestParseTokenInput(t *testing.T) {
	const tok = "rt_0123456789abcdefghij"
	ok := []struct{ in, tok, fp string }{
		{tok, tok, ""},
		{"  '" + tok + "'\n", tok, ""},
		{`{"refresh_token":"` + tok + `","device_fingerprint":"fp1"}`, tok, "fp1"},
		// Skylight web app Local Storage "auth-storage" (Zustand persist shape).
		{`{"state":{"accessToken":"AT-ignored","refreshToken":"` + tok + `","uniqueId":"dev9"},"version":1}`, tok, "dev9"},
		// With the storage key in front, as some devtools copy it.
		{"auth-storage\t" + `{"state":{"refreshToken":"` + tok + `","uniqueId":"dev9"},"version":1}`, tok, "dev9"},
		{`{"refreshToken":"` + tok + `","unique_id":"u"}`, tok, "u"},
	}
	for _, c := range ok {
		rt, fp, err := ParseTokenInput(c.in)
		if err != nil || rt != c.tok || fp != c.fp {
			t.Errorf("ParseTokenInput(%q) = %q, %q, %v", c.in, rt, fp, err)
		}
	}
	bad := []string{"", "short", "two words that are long enough", `{"state":{"accessToken":"only-access-token-here"}}`,
		`{not json}`, `}{`, "https://ourskylight.com/welcome?code=abc def"}
	for _, in := range bad {
		if _, _, err := ParseTokenInput(in); err == nil {
			t.Errorf("ParseTokenInput(%q) accepted", in)
		}
	}
}
