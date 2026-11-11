// Command skylight-probe makes read-only calls to the live Skylight API to
// settle the unknowns in SKYLIGHT_API.md §6. It runs on the owner's laptop
// only (never in tests or CI).
//
// Output is shapes only: status codes, counts, key names, and value formats
// with every digit replaced by 9. Raw responses are saved, mode 0600, under the
// git-ignored captures/ directory, to be scrubbed into fixtures later.
//
//	go run ./cmd/skylight-probe            # uses the saved access token
//	go run ./cmd/skylight-probe -refresh   # first spends the refresh token once
//	                                       # (saved before use) to see rotation
//	go run ./cmd/skylight-probe -hazards   # token reuse and parallel refresh;
//	                                       # may revoke the grant (owner's OK)
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/logich/skylight-mcp-aws/internal/skylight"
)

var (
	api     skylight.APIClient
	capDir  string
	access  string
	digitRE = regexp.MustCompile(`[0-9]`)
)

func main() {
	def, _ := skylight.DefaultTokenPath()
	tokPath := flag.String("token", def, "saved grant")
	doRefresh := flag.Bool("refresh", false, "spend the refresh token once first (rotation probe)")
	doHazards := flag.Bool("hazards", false, "only run the reuse and parallel-refresh probes (may revoke the grant)")
	reuseDelay := flag.Duration("reuse-delay", 2*time.Second, "with -hazards: wait this long before reusing the spent token")
	useFirst := flag.Bool("use-first", false, "with -hazards: use the new access token before reusing the spent refresh token")
	flag.Parse()

	capDir = filepath.Join("captures", time.Now().UTC().Format("20060102T150405Z"))
	must(os.MkdirAll(capDir, 0o700))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	saved, err := skylight.LoadFile(*tokPath)
	must(err)
	if *doHazards {
		hazards(ctx, *tokPath, &saved, *reuseDelay, *useFirst)
		return
	}
	expired := !saved.AccessExpiresAt.IsZero() && time.Now().After(saved.AccessExpiresAt.Add(-time.Minute))
	if *doRefresh || expired || saved.AccessToken == "" {
		refreshProbe(ctx, *tokPath, &saved)
	}
	access = saved.AccessToken

	section("headers")
	for _, o := range []struct {
		name string
		opt  skylight.GetOptions
	}{{"all headers", skylight.GetOptions{}}, {"no browser User-Agent", skylight.GetOptions{OmitUserAgent: true}},
		{"no Skylight-Api-Version", skylight.GetOptions{OmitAPIVersion: true}}} {
		r := get(ctx, "/api/frames", nil, o.opt, "")
		fmt.Printf("  %-26s -> %d, echoed version %q\n", o.name, r.Status, r.Header.Get("Skylight-Api-Version"))
	}

	section("frames")
	fr := get(ctx, "/api/frames", nil, skylight.GetOptions{}, "frames")
	var frames struct {
		Data []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
	}
	must(json.Unmarshal(fr.Body, &frames))
	if len(frames.Data) != 1 {
		fail(fmt.Errorf("expected one frame, got %d", len(frames.Data)))
	}
	fid := frames.Data[0].ID
	tz, _ := frames.Data[0].Attributes["timezone"].(string)
	fmt.Printf("  frame id format %q, timezone present: %v\n", pattern(fid), tz != "")
	if tz == "" {
		tz = "America/New_York"
	}
	if _, err := time.LoadLocation(tz); err != nil {
		fmt.Println("  frame timezone is not an IANA name Go knows")
	}

	section("categories")
	cr := get(ctx, "/api/frames/"+fid+"/categories", url.Values{"include_profiles": {"true"}}, skylight.GetOptions{}, "categories")
	categories(cr.Body)

	section("events (today-7 .. today+30, include=categories)")
	loc, err := time.LoadLocation(tz)
	if err != nil {
		loc = time.UTC
	}
	today := time.Now().In(loc)
	q := url.Values{"date_min": {today.AddDate(0, 0, -7).Format("2006-01-02")},
		"date_max": {today.AddDate(0, 0, 30).Format("2006-01-02")}, "timezone": {tz}, "include": {"categories"}}
	er := get(ctx, "/api/frames/"+fid+"/calendar_events", q, skylight.GetOptions{}, "events")
	evs := events(er.Body)

	section("events without include=categories")
	q2 := url.Values{"date_min": q["date_min"], "date_max": q["date_max"], "timezone": {tz}}
	r2 := get(ctx, "/api/frames/"+fid+"/calendar_events", q2, skylight.GetOptions{}, "events-no-include")
	var noInc struct {
		Data []struct {
			Relationships map[string]any `json:"relationships"`
		} `json:"data"`
		Included []any `json:"included"`
	}
	_ = json.Unmarshal(r2.Body, &noInc)
	withRel := 0
	for _, e := range noInc.Data {
		if _, ok := e.Relationships["categories"]; ok {
			withRel++
		}
	}
	fmt.Printf("  status %d, %d events, %d with relationships.categories, %d included\n", r2.Status, len(noInc.Data), withRel, len(noInc.Included))

	if len(evs) > 0 {
		section("single-day window (is date_max inclusive?)")
		var timed *event
		for i := range evs {
			if !evs[i].AllDay && evs[i].StartDate != "" {
				timed = &evs[i]
				break
			}
		}
		if timed != nil {
			d := timed.StartDate
			r := get(ctx, "/api/frames/"+fid+"/calendar_events",
				url.Values{"date_min": {d}, "date_max": {d}, "timezone": {tz}, "include": {"categories"}}, skylight.GetOptions{}, "events-one-day")
			fmt.Printf("  date_min=date_max=<a day with a timed event>: status %d, event found: %v\n", r.Status, strings.Contains(string(r.Body), `"`+timed.ID+`"`))
		}

		section("single event GET")
		r := get(ctx, "/api/frames/"+fid+"/calendar_events/"+evs[0].ID, nil, skylight.GetOptions{}, "event-single")
		fmt.Printf("  GET .../calendar_events/{id} -> %d (%s)\n", r.Status, topKeys(r.Body))
		if r.Status == 200 {
			r = get(ctx, "/api/frames/"+fid+"/calendar_events/"+evs[0].ID, url.Values{"include": {"categories"}}, skylight.GetOptions{}, "event-single-include")
			fmt.Printf("  ...with include=categories -> %d (%s)\n", r.Status, topKeys(r.Body))
		}
	}
	fmt.Printf("\nraw responses saved under %s (git-ignored, mode 0600)\n", capDir)
}

func refreshProbe(ctx context.Context, path string, s *skylight.Saved) {
	section("refresh (rotation probe)")
	old := s.RefreshToken
	r, err := skylight.TokenClient{}.Refresh(ctx, old, s.DeviceFingerprint)
	if err != nil {
		fail(err)
	}
	s.Apply(r, time.Now())
	// Save before anything else: the old refresh token may already be dead.
	must(skylight.SaveFile(path, *s))
	fmt.Printf("  fields: %s\n", strings.Join(r.Shape, ", "))
	fmt.Printf("  new refresh token returned: %v; differs from old: %v\n", r.RefreshToken != "", r.RefreshToken != "" && r.RefreshToken != old)
	fmt.Printf("  expires_in: %s\n", time.Duration(r.ExpiresIn)*time.Second)
}

type event struct {
	ID, StartDate string
	AllDay        bool
}

func events(body []byte) []event {
	var doc struct {
		Data []struct {
			ID            string         `json:"id"`
			Type          string         `json:"type"`
			Attributes    map[string]any `json:"attributes"`
			Relationships struct {
				Categories struct {
					Data []struct{ ID, Type string } `json:"data"`
				} `json:"categories"`
			} `json:"relationships"`
		} `json:"data"`
		Included []struct {
			ID, Type   string
			Attributes map[string]any `json:"attributes"`
		} `json:"included"`
		Meta  map[string]any `json:"meta"`
		Links map[string]any `json:"links"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		fmt.Println("  body is not the expected JSON:API document")
		return nil
	}
	fmt.Printf("  %d events, %d included; meta keys %v; links keys %v\n", len(doc.Data), len(doc.Included), keys(doc.Meta), keys(doc.Links))
	attrKeys, types, startFmt, endFmt := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	inc := map[string]map[string]any{}
	incTypes := map[string]int{}
	for _, c := range doc.Included {
		inc[c.Type+"/"+c.ID] = c.Attributes
		incTypes[c.Type]++
	}
	ids := map[string]int{}
	var out []event
	allDay, recurring, rrule, tagged, memberTagged, unresolved, nonMemberTags := 0, 0, 0, 0, 0, 0, 0
	for _, e := range doc.Data {
		types[e.Type]++
		ids[e.ID]++
		for k := range e.Attributes {
			attrKeys[k]++
		}
		ad, _ := e.Attributes["all_day"].(bool)
		if ad {
			allDay++
		}
		if b, _ := e.Attributes["recurring"].(bool); b {
			recurring++
		}
		if v, ok := e.Attributes["rrule"]; ok && v != nil {
			rrule++
		}
		s, _ := e.Attributes["starts_at"].(string)
		en, _ := e.Attributes["ends_at"].(string)
		kind := "timed"
		if ad {
			kind = "all-day"
		}
		startFmt[kind+" "+pattern(s)]++
		endFmt[kind+" "+pattern(en)]++
		ev := event{ID: e.ID, AllDay: ad}
		if len(s) >= 10 {
			ev.StartDate = s[:10]
		}
		out = append(out, ev)
		if len(e.Relationships.Categories.Data) > 0 {
			tagged++
		}
		member := false
		for _, c := range e.Relationships.Categories.Data {
			a, ok := inc[c.Type+"/"+c.ID]
			if !ok {
				unresolved++
				continue
			}
			if b, _ := a["linked_to_profile"].(bool); b {
				member = true
			} else {
				nonMemberTags++
			}
		}
		if member {
			memberTagged++
		}
	}
	dups := 0
	for _, n := range ids {
		if n > 1 {
			dups++
		}
	}
	fmt.Printf("  event types %v\n  attribute keys (count of events having each): %v\n", types, attrKeys)
	fmt.Printf("  included types %v\n", incTypes)
	fmt.Printf("  all-day %d, recurring=true %d, rrule non-null %d, ids repeated %d\n", allDay, recurring, rrule, dups)
	fmt.Printf("  starts_at formats %v\n  ends_at formats %v\n", startFmt, endFmt)
	fmt.Printf("  with any category %d, with a family member %d, non-member tags %d, unresolved category refs %d\n", tagged, memberTagged, nonMemberTags, unresolved)
	return out
}

func categories(body []byte) {
	var doc struct {
		Data []struct {
			ID, Type   string
			Attributes map[string]any `json:"attributes"`
		} `json:"data"`
		Included []struct{ Type string } `json:"included"`
		Meta     map[string]any          `json:"meta"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		fmt.Println("  body is not the expected JSON:API document")
		return
	}
	attr, types, inc := map[string]int{}, map[string]int{}, map[string]int{}
	members, colorFmt := 0, map[string]int{}
	for _, c := range doc.Data {
		types[c.Type]++
		for k := range c.Attributes {
			attr[k]++
		}
		if b, _ := c.Attributes["linked_to_profile"].(bool); b {
			members++
		}
		if s, ok := c.Attributes["color"].(string); ok {
			colorFmt[regexp.MustCompile(`[0-9a-fA-F]`).ReplaceAllString(s, "x")]++
		}
	}
	for _, i := range doc.Included {
		inc[i.Type]++
	}
	fmt.Printf("  %d categories, types %v, linked_to_profile=true %d\n", len(doc.Data), types, members)
	fmt.Printf("  attribute keys %v\n  included types %v; meta keys %v; color formats %v\n", attr, inc, keys(doc.Meta), colorFmt)
}

// get performs a call, saves the raw body if name is set, and fails on
// anything but 200 for named (essential) calls.
func get(ctx context.Context, path string, q url.Values, o skylight.GetOptions, name string) skylight.Response {
	r, err := api.Get(ctx, access, path, q, o)
	if err != nil {
		fail(err)
	}
	if name != "" {
		must(os.WriteFile(filepath.Join(capDir, name+".json"), r.Body, 0o600))
		if r.Status != 200 && !strings.HasPrefix(name, "event-single") {
			fail(fmt.Errorf("%s: HTTP %d", name, r.Status))
		}
	}
	if ra := r.Header.Get("Retry-After"); ra != "" || r.Status == 429 {
		fmt.Printf("  (HTTP %d, Retry-After %q)\n", r.Status, ra)
	}
	return r
}

func pattern(s string) string { return digitRE.ReplaceAllString(s, "9") }

func topKeys(b []byte) string {
	var m map[string]any
	if json.Unmarshal(b, &m) != nil {
		return "non-JSON body"
	}
	return "keys " + strings.Join(keys(m), ",")
}

func keys(m map[string]any) []string {
	var k []string
	for x := range m {
		k = append(k, x)
	}
	sort.Strings(k)
	return k
}

func section(s string) { fmt.Printf("\n== %s\n", s) }

func must(err error) {
	if err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "skylight-probe:", err)
	os.Exit(1)
}
