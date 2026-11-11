package scrub

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// Synthetic input shaped like a Skylight events response (no real data).
const sample = `{
 "data": [
  {"id": "12345678901-1762871400", "type": "calendar_event",
   "attributes": {"summary": "Dentist Bob", "description": "bring forms", "location": "12 Elm St",
     "all_day": false, "starts_at": "2025-11-11T09:30:00.000-05:00", "ends_at": "2025-11-11T10:30:00.000-05:00",
     "timezone": "America/New_York", "rrule": ["RRULE:FREQ=WEEKLY;BYDAY=TU;UNTIL=20261231T045959Z;X-SECRET=abc"],
     "recurring": true, "uid": "abc-uid-123@icloud.com", "owner_email": "alice@realmail.com",
     "invited_emails": ["bob@realmail.com", "alice@realmail.com"], "lat": 40.1, "lng": -74.2,
     "kind": "standard", "source": "caldav", "master_event_id": null, "calendar_id": 4455667},
   "relationships": {"categories": {"data": [{"id": "778899", "type": "category"}]}}},
  {"id": "5550001", "type": "calendar_event",
   "attributes": {"summary": "Dentist Bob", "all_day": true, "starts_at": "2025-11-12T00:00:00.000-05:00",
     "ends_at": "2025-11-13T00:00:00.000-05:00", "uid": "abc-uid-123@icloud.com", "rrule": null},
   "relationships": {"categories": {"data": [{"id": "778899", "type": "category"}]}}}
 ],
 "included": [{"id": "778899", "type": "category",
   "attributes": {"label": "Alice", "color": "#aabbcc", "linked_to_profile": true,
     "profile_picture_urls": {"small": "https://cdn.real.example/alice.jpg"}}}]
}`

func TestScrubKeepsStructureAndRemovesData(t *testing.T) {
	s, err := NewWithShift(7 * 200)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.Document([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if leaks := s.Check(out); len(leaks) > 0 {
		t.Fatalf("leaks: %v\n%s", leaks, out)
	}
	for _, real := range []string{"Dentist", "Bob", "Elm", "realmail", "icloud", "cdn.real", "New_York", "X-SECRET", "40.1", "74.2"} {
		if strings.Contains(string(out), real) {
			t.Errorf("output still contains %q", real)
		}
	}
	var doc struct {
		Data []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
			Rel        struct {
				Categories struct {
					Data []struct{ ID, Type string } `json:"data"`
				} `json:"categories"`
			} `json:"relationships"`
		} `json:"data"`
		Included []struct {
			ID         string         `json:"id"`
			Attributes map[string]any `json:"attributes"`
		} `json:"included"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatal(err)
	}
	e0, e1, c := doc.Data[0], doc.Data[1], doc.Included[0]

	// Cross-references survive.
	if e0.Rel.Categories.Data[0].ID != c.ID || e1.Rel.Categories.Data[0].ID != c.ID || c.ID == "778899" || len(c.ID) != 6 {
		t.Errorf("category id mapping broken: %q %q %q", e0.Rel.Categories.Data[0].ID, e1.Rel.Categories.Data[0].ID, c.ID)
	}
	// Equal inputs stay equal; enumerations, flags and colours are kept.
	if e0.Attributes["summary"] != e1.Attributes["summary"] || e0.Attributes["uid"] != e1.Attributes["uid"] {
		t.Error("consistent mapping broken")
	}
	if e0.Attributes["kind"] != "standard" || e0.Attributes["source"] != "caldav" || c.Attributes["color"] != "#aabbcc" ||
		c.Attributes["linked_to_profile"] != true || e0.Attributes["recurring"] != true || e0.Attributes["master_event_id"] != nil {
		t.Errorf("kept fields changed: %v %v", e0.Attributes, c.Attributes)
	}
	if e0.Attributes["lat"] != nil || e0.Attributes["calendar_id"] == float64(4455667) {
		t.Error("coordinates or numeric id kept")
	}
	// Times: whole weeks, wall clock kept, fake zone, composite id follows start.
	st, err := time.Parse(timeLayout, e0.Attributes["starts_at"].(string))
	if err != nil {
		t.Fatal(err)
	}
	if st.Weekday() != time.Tuesday || st.Hour() != 9 || st.Minute() != 30 || e0.Attributes["timezone"] != FakeZone {
		t.Errorf("start %v tz %v", st, e0.Attributes["timezone"])
	}
	base, suffix, ok := strings.Cut(e0.ID, "-")
	if !ok || len(base) != 11 || base == "12345678901" || suffix != itoa(st.Unix()) {
		t.Errorf("composite id %q vs start %d", e0.ID, st.Unix())
	}
	as, _ := time.Parse(timeLayout, e1.Attributes["starts_at"].(string))
	ae, _ := time.Parse(timeLayout, e1.Attributes["ends_at"].(string))
	if as.Hour() != 0 || ae.Hour() != 0 || ae.Sub(as) < 23*time.Hour {
		t.Errorf("all-day midnight boundaries lost: %v %v", as, ae)
	}
	// rrule: dates shifted, unknown parts dropped.
	r := e0.Attributes["rrule"].([]any)[0].(string)
	if !strings.HasPrefix(r, "RRULE:FREQ=WEEKLY;BYDAY=TU;UNTIL=") || strings.Contains(r, "20261231") {
		t.Errorf("rrule %q", r)
	}
	// Emails become example.test addresses, consistently.
	inv := e0.Attributes["invited_emails"].([]any)
	if inv[1] != e0.Attributes["owner_email"] || !strings.HasSuffix(inv[0].(string), "@example.test") {
		t.Errorf("emails %v %v", inv, e0.Attributes["owner_email"])
	}
}

func TestCheckCatchesShortNamesAsWords(t *testing.T) {
	s, _ := NewWithShift(7)
	s.originals["Ann"] = true
	s.originals["Bob"] = true
	if got := s.Check([]byte(`{"a":"Planning", "b":"meet Bob at 3"}`)); len(got) != 1 || got[0] != "Bob" {
		t.Fatalf("Check = %v, want [Bob]", got)
	}
}

func TestShiftMustBeWholeWeeks(t *testing.T) {
	if _, err := NewWithShift(10); err == nil {
		t.Fatal("accepted a non-week shift")
	}
}

func itoa(n int64) string { b, _ := json.Marshal(n); return string(b) }
