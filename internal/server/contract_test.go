package server

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/logich/skylight-mcp-aws/internal/auth"
	"github.com/logich/skylight-mcp-aws/internal/calendar"
	"github.com/logich/skylight-mcp-aws/internal/grant"
	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

var update = flag.Bool("update", false, "rewrite golden files")

// fixtureSkylight replays the scrubbed fixtures (SPEC §8.1).
func fixtureSkylight(t *testing.T) *httptest.Server {
	read := func(name string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "skylight", "testdata", name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Skylight-Api-Version", skylight.APIVersion)
		switch {
		case r.URL.Path == "/api/frames":
			w.Write(read("frames.json"))
		case r.URL.Path == "/api/frames/9000001/categories":
			w.Write(read("categories.json"))
		case r.URL.Path == "/api/frames/9000001/calendar_events" && r.URL.Query().Get("include") == "categories":
			w.Write(read("events.json"))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(ts.Close)
	return ts
}

type fixedTokens struct{}

func (fixedTokens) AccessToken(context.Context, string) (grant.Token, error) {
	return grant.Token{AccessToken: "fixture-token", FrameID: "9000001"}, nil
}

func contractSession(t *testing.T) *mcp.ClientSession {
	t.Helper()
	cal := &calendar.Client{API: skylight.APIClient{BaseURL: fixtureSkylight(t).URL}, Tokens: fixedTokens{}}
	h := New(Options{
		Auth:     auth.Config{Issuer: issuer, ClientID: client, AllowedSub: sub, Scope: scope, Audience: aud},
		Keys:     keySet(t),
		Version:  "test-version",
		Now:      func() time.Time { return now },
		Calendar: cal,
	})
	ts := httptest.NewServer(h)
	t.Cleanup(ts.Close)
	c := mcp.NewClient(&mcp.Implementation{Name: "contract", Version: "0"}, nil)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   ts.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearerTransport{token(t, func(p map[string]any) { p["aud"] = aud })}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// golden compares v (as indented JSON) with testdata/golden/<name>.json.
func golden(t *testing.T, name string, v any) {
	t.Helper()
	got, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	path := filepath.Join("testdata", "golden", name+".json")
	if *update {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (run go test ./internal/server -run Contract -update)", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("%s differs from golden file %s (if intended, rerun with -update and review the diff)\n%s", name, path, firstDiff(got, want))
	}
}

func firstDiff(a, b []byte) string {
	al, bl := strings.Split(string(a), "\n"), strings.Split(string(b), "\n")
	for i := 0; i < len(al) && i < len(bl); i++ {
		if al[i] != bl[i] {
			return "line " + itoa(i+1) + ":\n got  " + al[i] + "\n want " + bl[i]
		}
	}
	return "lengths differ"
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func call(t *testing.T, s *mcp.ClientSession, name string, args map[string]any) *mcp.CallToolResult {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return res
}

func TestContractToolList(t *testing.T) {
	s := contractSession(t)
	res, err := s.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	golden(t, "tools_list", res.Tools)
}

func TestContractToolResults(t *testing.T) {
	s := contractSession(t)
	members := call(t, s, "list_family_members", nil)
	golden(t, "list_family_members", members)

	var mo struct {
		Members []struct{ Name string } `json:"members"`
	}
	b, _ := json.Marshal(members.StructuredContent)
	if err := json.Unmarshal(b, &mo); err != nil || len(mo.Members) != 11 {
		t.Fatalf("members %s %v", b, err)
	}
	week := map[string]any{"start": "2033-04-13T00:00:00-05:00", "end": "2033-04-20T00:00:00-05:00"}
	golden(t, "list_events_week", call(t, s, "list_events", week))
	golden(t, "list_events_member", call(t, s, "list_events", map[string]any{
		"start": week["start"], "end": week["end"], "member": strings.ToUpper(mo.Members[0].Name),
	}))

	// get_event: a recurring occurrence (id carries its start) and a plain id
	// with an 'around' hint, both taken from the fixture.
	var occ, plain, around string
	var ev struct {
		Data []struct {
			ID         string `json:"id"`
			Attributes struct {
				StartsAt string `json:"starts_at"`
			} `json:"attributes"`
		} `json:"data"`
	}
	raw, _ := os.ReadFile(filepath.Join("..", "skylight", "testdata", "events.json"))
	_ = json.Unmarshal(raw, &ev)
	for _, e := range ev.Data {
		if strings.Contains(e.ID, "-") && occ == "" {
			occ = e.ID
		}
		if !strings.Contains(e.ID, "-") && plain == "" {
			plain, around = e.ID, e.Attributes.StartsAt
		}
	}
	golden(t, "get_event_occurrence", call(t, s, "get_event", map[string]any{"event_id": occ}))
	golden(t, "get_event_plain_around", call(t, s, "get_event", map[string]any{"event_id": plain, "around": around}))
}

func TestContractErrorsAreToolErrors(t *testing.T) {
	s := contractSession(t)
	cases := []struct {
		tool string
		args map[string]any
		want string
	}{
		{"list_events", map[string]any{"start": "tomorrow", "end": "2033-04-20T00:00:00-05:00"}, "RFC 3339"},
		{"list_events", map[string]any{"start": "2033-04-20T00:00:00-05:00", "end": "2033-04-13T00:00:00-05:00"}, "end must be after start"},
		{"list_events", map[string]any{"start": "2033-01-01T00:00:00Z", "end": "2033-06-01T00:00:00Z"}, "93 days"},
		{"list_events", map[string]any{"start": "2033-04-13T00:00:00Z", "end": "2033-04-14T00:00:00Z", "member": "Nobody"}, "no family member named"},
		{"get_event", map[string]any{"event_id": ""}, "event_id is required"},
		{"get_event", map[string]any{"event_id": "9999999999999", "around": "2033-04-13T00:00:00Z"}, "no event with id"},
	}
	for _, c := range cases {
		res := call(t, s, c.tool, c.args)
		var text string
		for _, ct := range res.Content {
			if tc, ok := ct.(*mcp.TextContent); ok {
				text += tc.Text
			}
		}
		if !res.IsError || !strings.Contains(text, c.want) {
			t.Errorf("%s %v: IsError=%v text %q, want %q", c.tool, c.args, res.IsError, text, c.want)
		}
	}
	// Missing required arguments are rejected by schema validation.
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: "list_events", Arguments: map[string]any{}})
	if err == nil && !res.IsError {
		t.Error("list_events without start/end accepted")
	}
}

func TestToolsWithoutCalendarReportNotConfigured(t *testing.T) {
	ts := httptest.NewServer(handler(t)) // no Calendar
	defer ts.Close()
	c := mcp.NewClient(&mcp.Implementation{Name: "t", Version: "0"}, nil)
	s, err := c.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   ts.URL + "/mcp",
		HTTPClient: &http.Client{Transport: bearerTransport{token(t, nil)}},
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	res := call(t, s, "list_family_members", nil)
	if !res.IsError {
		t.Fatal("want a tool error")
	}
}
