package skylight

import (
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// These tests pin the live-API facts recorded in SKYLIGHT_API.md against the
// scrubbed fixtures (testdata/, produced by cmd/skylight-scrub), so parser
// work starts from verified shapes.

type jsonAPIDoc struct {
	Data []struct {
		ID            string         `json:"id"`
		Type          string         `json:"type"`
		Attributes    map[string]any `json:"attributes"`
		Relationships map[string]struct {
			Data json.RawMessage `json:"data"`
		} `json:"relationships"`
	} `json:"data"`
	Included []struct {
		ID         string         `json:"id"`
		Type       string         `json:"type"`
		Attributes map[string]any `json:"attributes"`
	} `json:"included"`
}

func load(t *testing.T, name string) jsonAPIDoc {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	var d jsonAPIDoc
	if err := json.Unmarshal(b, &d); err != nil {
		t.Fatal(err)
	}
	return d
}

type ref struct{ ID, Type string }

func refs(t *testing.T, raw json.RawMessage) []ref {
	var r []ref
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatalf("relationship data is not a list: %s", raw)
	}
	return r
}

func TestFixtureCategories(t *testing.T) {
	d := load(t, "categories.json")
	members, labels := 0, map[string]bool{}
	for _, c := range d.Data {
		if c.Type != "category_detail" {
			t.Errorf("categories endpoint type %q, want category_detail", c.Type)
		}
		if b, _ := c.Attributes["linked_to_profile"].(bool); b {
			members++
			l, _ := c.Attributes["label"].(string)
			if strings.TrimSpace(l) == "" || labels[l] {
				t.Errorf("member label empty or duplicate: %q", l)
			}
			labels[l] = true
		}
	}
	if members == 0 || members == len(d.Data) {
		t.Errorf("want a mix of members and non-members, got %d of %d", members, len(d.Data))
	}
}

var compositeRE = regexp.MustCompile(`^([0-9]+)-([0-9]+)$`)

func TestFixtureEvents(t *testing.T) {
	d := load(t, "events.json")
	cats := map[string]map[string]any{}
	for _, c := range load(t, "categories.json").Data {
		cats[c.ID] = c.Attributes
	}
	inc := map[string]bool{}
	for _, i := range d.Included {
		if i.Type != "category" {
			t.Errorf("with include=categories, included type %q", i.Type)
		}
		inc[i.ID] = true
	}
	seen := map[string]bool{}
	recurring := 0
	for _, e := range d.Data {
		if seen[e.ID] {
			t.Errorf("duplicate id %s", e.ID)
		}
		seen[e.ID] = true
		rel, ok := e.Relationships["categories"]
		if !ok {
			t.Fatalf("event without relationships.categories")
		}
		for _, r := range refs(t, rel.Data) {
			if r.Type != "category" || !inc[r.ID] || cats[r.ID] == nil {
				t.Errorf("category ref %+v does not resolve", r)
			}
		}
		start, err := time.Parse(time.RFC3339, e.Attributes["starts_at"].(string))
		if err != nil {
			t.Fatal(err)
		}
		end, _ := time.Parse(time.RFC3339, e.Attributes["ends_at"].(string))
		if e.Attributes["all_day"] == true {
			if start.Hour() != 0 || end.Hour() != 0 || end.Sub(start) < 23*time.Hour {
				t.Errorf("all-day event not midnight to midnight: %v %v", start, end)
			}
		}
		// Recurring occurrences: "<id>-<unix start>".
		if m := compositeRE.FindStringSubmatch(e.ID); m != nil {
			recurring++
			if m[2] != strconv.FormatInt(start.Unix(), 10) {
				t.Errorf("occurrence id %s does not encode its start %d", e.ID, start.Unix())
			}
		}
	}
	if recurring == 0 {
		t.Error("fixture has no recurring occurrences")
	}
}

func TestFixtureEventsWithoutIncludeUseSingularKey(t *testing.T) {
	for _, e := range load(t, "events-no-include.json").Data {
		if _, ok := e.Relationships["categories"]; ok {
			t.Fatal("without include=categories the key was expected to be 'category'")
		}
		if _, ok := e.Relationships["category"]; !ok {
			t.Fatal("missing relationships.category")
		}
	}
}
