package calendar

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/grant"
	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("../skylight/testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseFixtures(t *testing.T) {
	cats, err := ParseCategories(fixture(t, "categories.json"))
	if err != nil {
		t.Fatal(err)
	}
	members := Members(cats)
	if len(cats) != 17 || len(members) != 11 {
		t.Fatalf("%d categories, %d members", len(cats), len(members))
	}
	evs, err := ParseEvents(fixture(t, "events.json"))
	if err != nil {
		t.Fatal(err)
	}
	withMembers, allDay := 0, 0
	for _, e := range evs {
		if len(e.Members) > 0 {
			withMembers++
		}
		if e.AllDay {
			allDay++
		}
		if e.Start.IsZero() || e.End.Before(e.Start) {
			t.Fatalf("bad times %+v", e)
		}
	}
	if len(evs) != 106 || withMembers != 101 || allDay != 9 {
		t.Fatalf("events %d, with members %d, all-day %d", len(evs), withMembers, allDay)
	}
}

// mutate applies f to the events fixture and returns the re-encoded body.
func mutate(t *testing.T, f func(doc map[string]any)) []byte {
	var doc map[string]any
	if err := json.Unmarshal(fixture(t, "events.json"), &doc); err != nil {
		t.Fatal(err)
	}
	f(doc)
	b, _ := json.Marshal(doc)
	return b
}

func first(doc map[string]any) map[string]any {
	return doc["data"].([]any)[0].(map[string]any)
}

func attrs(doc map[string]any) map[string]any { return first(doc)["attributes"].(map[string]any) }

func TestParseEventsRejectsShapeChanges(t *testing.T) {
	cases := map[string]func(map[string]any){
		"no data":                func(d map[string]any) { delete(d, "data") },
		"missing starts_at":      func(d map[string]any) { delete(attrs(d), "starts_at") },
		"starts_at not a string": func(d map[string]any) { attrs(d)["starts_at"] = 5 },
		"bad time":               func(d map[string]any) { attrs(d)["starts_at"] = "tomorrow" },
		"end before start":       func(d map[string]any) { attrs(d)["ends_at"] = "2000-01-01T00:00:00Z" },
		"all_day missing":        func(d map[string]any) { delete(attrs(d), "all_day") },
		"wrong event type":       func(d map[string]any) { first(d)["type"] = "event" },
		"no categories relation": func(d map[string]any) { delete(first(d)["relationships"].(map[string]any), "categories") },
		"unresolved category":    func(d map[string]any) { d["included"] = []any{} },
		"rrule not list":         func(d map[string]any) { attrs(d)["rrule"] = "RRULE:FREQ=DAILY" },
		"summary not a string":   func(d map[string]any) { attrs(d)["summary"] = 1 },
		"included label not string": func(d map[string]any) {
			d["included"].([]any)[0].(map[string]any)["attributes"].(map[string]any)["label"] = 3
		},
	}
	for name, f := range cases {
		if _, err := ParseEvents(mutate(t, f)); !errors.Is(err, ErrAPIChanged) {
			t.Errorf("%s: err %v, want ErrAPIChanged", name, err)
		}
	}
	if _, err := ParseCategories([]byte(`{"data":[{"id":"1","type":"category","attributes":{"label":"x","linked_to_profile":true}}]}`)); !errors.Is(err, ErrAPIChanged) {
		t.Error("categories endpoint type change not detected")
	}
}

func FuzzParseEvents(f *testing.F) {
	b, _ := os.ReadFile("../skylight/testdata/events.json")
	f.Add(b)
	f.Add([]byte(`{"data":[]}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		evs, err := ParseEvents(body)
		if err == nil {
			for _, e := range evs {
				if e.End.Before(e.Start) || e.ID == "" {
					t.Fatalf("accepted invalid event %+v", e)
				}
			}
		}
	})
}

// --- client ---

type fakeTokens struct {
	mu    sync.Mutex
	cur   string
	stale []string
}

func (f *fakeTokens) AccessToken(_ context.Context, stale string) (grant.Token, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if stale != "" {
		f.stale = append(f.stale, stale)
		if stale == f.cur {
			f.cur += "+"
		}
	}
	return grant.Token{AccessToken: f.cur, FrameID: "f1"}, nil
}

type fakeSkylight struct {
	t         *testing.T
	statuses  []int // per request, then 200
	version   string
	requests  []*http.Request
	validTok  string
	retryAfer string
}

func (s *fakeSkylight) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.requests = append(s.requests, r)
	if r.Header.Get("Skylight-Api-Version") != skylight.APIVersion {
		s.t.Errorf("request without API version header")
	}
	v := s.version
	if v == "" {
		v = skylight.APIVersion
	}
	w.Header().Set("Skylight-Api-Version", v)
	if s.validTok != "" && r.Header.Get("Authorization") != "Bearer "+s.validTok {
		w.WriteHeader(401)
		return
	}
	if len(s.statuses) > 0 {
		st := s.statuses[0]
		s.statuses = s.statuses[1:]
		if s.retryAfer != "" {
			w.Header().Set("Retry-After", s.retryAfer)
		}
		w.WriteHeader(st)
		return
	}
	switch {
	case r.URL.Path == "/api/frames":
		fmt.Fprint(w, `{"data":[{"id":"f0","attributes":{"timezone":"UTC"}},{"id":"f1","attributes":{"timezone":"America/Chicago"}}]}`)
	case strings.HasSuffix(r.URL.Path, "/calendar_events"):
		w.Write(fixture(s.t, "events.json"))
	case strings.HasSuffix(r.URL.Path, "/categories"):
		w.Write(fixture(s.t, "categories.json"))
	default:
		w.WriteHeader(404)
	}
}

func newClient(t *testing.T, fs *fakeSkylight, tok *fakeTokens) *Client {
	ts := httptest.NewServer(fs)
	t.Cleanup(ts.Close)
	return &Client{API: skylight.APIClient{BaseURL: ts.URL}, Tokens: tok,
		Sleep: func(context.Context, time.Duration) error { return nil }}
}

func TestEventsWindowAndTimezone(t *testing.T) {
	fs := &fakeSkylight{t: t}
	c := newClient(t, fs, &fakeTokens{cur: "a"})
	loc, _ := time.LoadLocation("America/Chicago")
	from := time.Date(2030, 3, 1, 23, 30, 0, 0, time.UTC) // already Mar 1 evening in Chicago
	evs, err := c.Events(context.Background(), from, from.AddDate(0, 0, 6))
	if err != nil || len(evs) != 106 {
		t.Fatalf("%d %v", len(evs), err)
	}
	q := fs.requests[len(fs.requests)-1].URL.Query()
	if q.Get("date_min") != from.In(loc).Format(time.DateOnly) || q.Get("date_max") != "2030-03-08" ||
		q.Get("timezone") != "America/Chicago" || q.Get("include") != "categories" {
		t.Fatalf("query %v", q)
	}
	if !strings.HasPrefix(fs.requests[len(fs.requests)-1].URL.Path, "/api/frames/f1/") {
		t.Fatalf("path %s", fs.requests[len(fs.requests)-1].URL.Path)
	}
}

func TestUnauthorizedForcesOneRefresh(t *testing.T) {
	tok := &fakeTokens{cur: "a"}
	fs := &fakeSkylight{t: t, validTok: "a+"}
	c := newClient(t, fs, tok)
	if _, err := c.Categories(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(tok.stale) != 1 || tok.stale[0] != "a" {
		t.Fatalf("stale reports %v", tok.stale)
	}
	// A 401 that persists after the refresh is an error, not a loop.
	fs.validTok = "never"
	if _, err := c.Categories(context.Background()); !errors.Is(err, ErrUpstream) {
		t.Fatalf("err %v", err)
	}
}

func TestRetriesThenGivesUp(t *testing.T) {
	fs := &fakeSkylight{t: t, statuses: []int{429, 503}, retryAfer: "1"}
	c := newClient(t, fs, &fakeTokens{cur: "a"})
	if _, err := c.Categories(context.Background()); err != nil {
		t.Fatalf("should recover after two retries: %v", err)
	}
	fs.statuses = []int{500, 500, 500}
	if _, err := c.Categories(context.Background()); !errors.Is(err, ErrUpstream) {
		t.Fatalf("err %v", err)
	}
	fs.statuses = []int{404}
	if _, err := c.Categories(context.Background()); !errors.Is(err, ErrUpstream) {
		t.Fatalf("404 err %v", err)
	}
}

func TestVersionChangeDetected(t *testing.T) {
	fs := &fakeSkylight{t: t, version: "2027-01-01"}
	c := newClient(t, fs, &fakeTokens{cur: "a"})
	if _, err := c.Categories(context.Background()); !errors.Is(err, ErrAPIChanged) {
		t.Fatalf("err %v", err)
	}
}

func TestBackoff(t *testing.T) {
	if backoff(1, "3") != 3*time.Second || backoff(1, "999") != 10*time.Second {
		t.Fatal("Retry-After not honoured or not capped")
	}
	for i := 1; i < 8; i++ {
		if d := backoff(i, ""); d <= 0 || d > 4100*time.Millisecond {
			t.Fatalf("backoff(%d) = %v", i, d)
		}
	}
}
