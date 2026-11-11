package skylight

import (
	"encoding/json"
	"errors"
	"strings"
)

// ParseTokenInput reads what the owner pastes for an import, following the
// HA integration's token_input.py: the bare refresh token; a JSON object with
// refresh_token and device_fingerprint; or the Skylight web app's saved sign-in
// state as copied from browser developer tools (Local Storage "auth-storage":
// {"state":{"refreshToken":…,"uniqueId":…},"version":1}), optionally with the
// storage key in front. Keys may be snake_case or camelCase, at the top level
// or under "state". Access tokens are ignored on purpose. The fingerprint is
// "" when absent.
func ParseTokenInput(raw string) (refreshToken, fingerprint string, err error) {
	text := strings.Trim(strings.TrimSpace(raw), `'"`)
	if text == "" {
		return "", "", errors.New("nothing pasted")
	}
	if strings.Contains(text, "{") {
		start, end := strings.Index(text, "{"), strings.LastIndex(text, "}")
		if end < start {
			return "", "", errors.New("pasted text is not valid JSON")
		}
		var top map[string]any
		if json.Unmarshal([]byte(text[start:end+1]), &top) != nil {
			return "", "", errors.New("pasted text is not valid JSON")
		}
		levels := []map[string]any{top}
		if st, ok := top["state"].(map[string]any); ok {
			levels = append(levels, st)
		}
		for _, l := range levels {
			if refreshToken == "" {
				refreshToken = first(l, "refresh_token", "refreshToken")
			}
			if fingerprint == "" {
				fingerprint = first(l, "device_fingerprint", "deviceFingerprint", "fingerprint", "unique_id", "uniqueId")
			}
		}
	} else {
		refreshToken = text
	}
	// A token never contains whitespace; this catches half-pasted URLs and sentences.
	if len(refreshToken) < 20 || strings.ContainsAny(refreshToken, " \t\r\n") {
		return "", "", errors.New("that does not look like a refresh token")
	}
	return refreshToken, fingerprint, nil
}

func first(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && strings.TrimSpace(s) != "" {
			return strings.TrimSpace(s)
		}
	}
	return ""
}
