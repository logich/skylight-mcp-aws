// Package calendar is the read side of the Skylight calendar: strict parsers
// for the API's JSON:API documents and a client that fetches them with a
// managed access token. Shapes follow the live probes (SKYLIGHT_API.md §6).
package calendar

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrAPIChanged means a response did not have the shape the parsers were
// built against. Surfaced to the caller instead of dropping data silently.
var ErrAPIChanged = errors.New("Skylight's API response changed shape")

func changed(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrAPIChanged}, a...)...)
}

// Category is a Skylight category; family members have IsMember set.
type Category struct {
	ID       string
	Label    string
	Color    string
	IsMember bool
}

// Event is one calendar event (one occurrence for recurring events).
type Event struct {
	ID          string
	Title       string
	Description string
	Location    string
	Start, End  time.Time
	AllDay      bool
	Timezone    string
	Recurring   bool
	RRule       []string
	Members     []string // family-member names, in Skylight's order, de-duplicated
}

type resource struct {
	ID            *string                    `json:"id"`
	Type          *string                    `json:"type"`
	Attributes    map[string]json.RawMessage `json:"attributes"`
	Relationships map[string]struct {
		Data json.RawMessage `json:"data"`
	} `json:"relationships"`
}

type document struct {
	Data     *[]resource `json:"data"`
	Included []resource  `json:"included"`
}

func decodeDoc(body []byte) (document, error) {
	var d document
	if err := json.Unmarshal(body, &d); err != nil {
		return d, changed("not a JSON:API document")
	}
	if d.Data == nil {
		return d, changed("no data array")
	}
	return d, nil
}

// attr helpers: missing or mistyped attributes are errors unless optional.

func attrString(r resource, k string, optional bool) (string, error) {
	raw, ok := r.Attributes[k]
	if !ok || string(raw) == "null" {
		if optional {
			return "", nil
		}
		return "", changed("attribute %s missing", k)
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", changed("attribute %s is not a string", k)
	}
	return s, nil
}

func attrBool(r resource, k string, optional bool) (bool, error) {
	raw, ok := r.Attributes[k]
	if !ok || string(raw) == "null" {
		if optional {
			return false, nil
		}
		return false, changed("attribute %s missing", k)
	}
	var b bool
	if err := json.Unmarshal(raw, &b); err != nil {
		return false, changed("attribute %s is not a boolean", k)
	}
	return b, nil
}

func idType(r resource) (string, string, error) {
	if r.ID == nil || r.Type == nil || *r.ID == "" {
		return "", "", changed("resource without id or type")
	}
	return *r.ID, *r.Type, nil
}

// ParseCategories parses GET /api/frames/{fid}/categories.
func ParseCategories(body []byte) ([]Category, error) {
	d, err := decodeDoc(body)
	if err != nil {
		return nil, err
	}
	out := make([]Category, 0, len(*d.Data))
	for _, r := range *d.Data {
		id, typ, err := idType(r)
		if err != nil {
			return nil, err
		}
		if typ != "category_detail" {
			return nil, changed("categories endpoint returned type %q", typ)
		}
		c, err := category(id, r)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

func category(id string, r resource) (Category, error) {
	label, err := attrString(r, "label", false)
	if err != nil {
		return Category{}, err
	}
	color, err := attrString(r, "color", true)
	if err != nil {
		return Category{}, err
	}
	member, err := attrBool(r, "linked_to_profile", false)
	if err != nil {
		return Category{}, err
	}
	return Category{ID: id, Label: strings.TrimSpace(label), Color: color, IsMember: member}, nil
}

// Members returns the family members (member categories with a non-empty
// label), de-duplicated by name, in Skylight's order.
func Members(cs []Category) []Category {
	seen := map[string]bool{}
	var out []Category
	for _, c := range cs {
		if c.IsMember && c.Label != "" && !seen[c.Label] {
			seen[c.Label] = true
			out = append(out, c)
		}
	}
	return out
}

// ParseEvents parses GET .../calendar_events?include=categories. Every
// category an event references must be in "included"; events missing
// start or end are errors, never skipped.
func ParseEvents(body []byte) ([]Event, error) {
	d, err := decodeDoc(body)
	if err != nil {
		return nil, err
	}
	cats := map[string]Category{}
	for _, r := range d.Included {
		id, typ, err := idType(r)
		if err != nil {
			return nil, err
		}
		if typ != "category" {
			continue // other included types are not used
		}
		c, err := category(id, r)
		if err != nil {
			return nil, err
		}
		cats[id] = c
	}
	out := make([]Event, 0, len(*d.Data))
	for _, r := range *d.Data {
		e, err := event(r, cats)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, nil
}

func event(r resource, cats map[string]Category) (Event, error) {
	id, typ, err := idType(r)
	if err != nil {
		return Event{}, err
	}
	if typ != "calendar_event" {
		return Event{}, changed("event has type %q", typ)
	}
	e := Event{ID: id}
	if e.Title, err = attrString(r, "summary", true); err != nil {
		return Event{}, err
	}
	if e.Description, err = attrString(r, "description", true); err != nil {
		return Event{}, err
	}
	if e.Location, err = attrString(r, "location", true); err != nil {
		return Event{}, err
	}
	if e.Timezone, err = attrString(r, "timezone", true); err != nil {
		return Event{}, err
	}
	if e.AllDay, err = attrBool(r, "all_day", false); err != nil {
		return Event{}, err
	}
	if e.Recurring, err = attrBool(r, "recurring", true); err != nil {
		return Event{}, err
	}
	for k, dst := range map[string]*time.Time{"starts_at": &e.Start, "ends_at": &e.End} {
		s, err := attrString(r, k, false)
		if err != nil {
			return Event{}, err
		}
		t, err := time.Parse(time.RFC3339, s)
		if err != nil {
			return Event{}, changed("attribute %s is not an RFC 3339 time", k)
		}
		*dst = t
	}
	if e.End.Before(e.Start) {
		return Event{}, changed("event ends before it starts")
	}
	if raw, ok := r.Attributes["rrule"]; ok && string(raw) != "null" {
		if err := json.Unmarshal(raw, &e.RRule); err != nil {
			return Event{}, changed("attribute rrule is not a list of strings")
		}
	}
	rel, ok := r.Relationships["categories"]
	if !ok {
		return Event{}, changed("event without relationships.categories (was include=categories sent?)")
	}
	var refs []struct{ ID, Type string }
	if err := json.Unmarshal(rel.Data, &refs); err != nil {
		return Event{}, changed("relationships.categories.data is not a list")
	}
	seen := map[string]bool{}
	for _, ref := range refs {
		c, ok := cats[ref.ID]
		if !ok || ref.Type != "category" {
			return Event{}, changed("event references a category missing from included")
		}
		if c.IsMember && c.Label != "" && !seen[c.Label] {
			seen[c.Label] = true
			e.Members = append(e.Members, c.Label)
		}
	}
	return e, nil
}
