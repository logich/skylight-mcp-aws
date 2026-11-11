// Package scrub turns captured Skylight responses into fixtures that are safe
// to commit to a public repository, while keeping what the parsers depend on:
// document structure, key names, JSON types, id formats and cross-references,
// boolean flags, colours, recurrence rules, all-day midnight boundaries and
// the composite "<id>-<unix start>" occurrence ids.
//
// It is fail-safe: a string is kept only if its key is on a short allowlist of
// enumerations; every other string is replaced by a synthetic value (the same
// input always maps to the same output, so equality and uniqueness survive).
// Numbers not on the allowlist become 0. Dates are moved by a whole number of
// weeks (weekdays survive) chosen at random per run and not recorded, and
// re-expressed, wall clock unchanged, in a fixed timezone.
//
// After scrubbing, Check verifies that no original string or id appears
// anywhere in the output.
package scrub

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// FakeZone replaces the household timezone everywhere.
const FakeZone = "America/Chicago"

// keepString lists keys whose string values are enumerations, not personal
// data, and are kept verbatim.
var keepString = map[string]bool{
	"type": true, "kind": true, "status": true, "source": true, "color": true,
	"role": true, "locale": true, "token_type": true,
}

// keepNumber lists keys whose numbers are kept (none needed so far).
var keepNumber = map[string]bool{}

const timeLayout = "2006-01-02T15:04:05.000-07:00"

var (
	compositeID = regexp.MustCompile(`^([0-9]+)-([0-9]{9,11})$`)
	digitsOnly  = regexp.MustCompile(`^[0-9]+$`)
	clockOnly   = regexp.MustCompile(`^[0-9]{2}:[0-9]{2}(:[0-9]{2})?$`)
	untilRE     = regexp.MustCompile(`^UNTIL=([0-9]{8})(T[0-9]{6}Z?)?$`)
	rrulePart   = map[string]bool{"FREQ": true, "INTERVAL": true, "BYDAY": true, "BYMONTHDAY": true,
		"BYMONTH": true, "COUNT": true, "WKST": true, "UNTIL": true, "BYSETPOS": true}
)

// Scrubber holds the per-run mappings, so several documents scrubbed by one
// Scrubber stay consistent with each other (ids in events match categories).
type Scrubber struct {
	shiftDays int
	loc       *time.Location
	ids       map[string]string
	strs      map[string]string // key+"\x00"+value -> synthetic
	counters  map[string]int
	originals map[string]bool // values that must not survive
	kept      map[string]bool // values deliberately kept (allowlisted keys)
}

// New returns a Scrubber with a random shift of 150-350 whole weeks.
func New() (*Scrubber, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(200))
	if err != nil {
		return nil, err
	}
	return NewWithShift(int(n.Int64()+150) * 7)
}

// NewWithShift is New with a fixed shift (tests only). shiftDays must be a
// multiple of 7.
func NewWithShift(shiftDays int) (*Scrubber, error) {
	if shiftDays%7 != 0 || shiftDays == 0 {
		return nil, fmt.Errorf("shift must be a non-zero multiple of 7 days")
	}
	loc, err := time.LoadLocation(FakeZone)
	if err != nil {
		return nil, err
	}
	return &Scrubber{shiftDays: shiftDays, loc: loc, ids: map[string]string{},
		strs: map[string]string{}, counters: map[string]int{}, originals: map[string]bool{}, kept: map[string]bool{}}, nil
}

// Document scrubs one JSON document.
func (s *Scrubber) Document(in []byte) ([]byte, error) {
	var v any
	d := json.NewDecoder(strings.NewReader(string(in)))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	// Pass 1 rewrites everything except composite occurrence ids, whose time
	// part must follow the rewritten starts_at of the same resource.
	out := s.walk("", v)
	s.fixComposites(out)
	return json.MarshalIndent(out, "", "  ")
}

func (s *Scrubber) walk(key string, v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, val := range x {
			m[k] = s.walk(k, val)
		}
		return m
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			out[i] = s.walk(key, val)
		}
		return out
	case string:
		return s.str(key, x)
	case json.Number:
		if keepNumber[key] {
			return x
		}
		s.originals[x.String()] = true
		if key == "lat" || key == "lng" {
			return nil
		}
		if (key == "id" || strings.HasSuffix(key, "_id")) && digitsOnly.MatchString(x.String()) {
			return json.Number(s.id(x.String()))
		}
		return json.Number("0")
	default: // bool, nil
		return x
	}
}

func (s *Scrubber) str(key, v string) any {
	if v == "" {
		return v
	}
	if keepString[key] {
		s.kept[v] = true
		return v
	}
	s.originals[v] = true
	switch {
	case key == "id" || strings.HasSuffix(key, "_id"):
		if m := compositeID.FindStringSubmatch(v); m != nil {
			s.originals[m[1]] = true
			return "composite:" + s.id(m[1]) // finished in fixComposites
		}
		return s.id(v)
	case strings.HasSuffix(key, "_at"):
		if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
			return s.shift(t).Format(timeLayout)
		}
		if t, err := time.Parse("2006-01-02", v); err == nil {
			return t.AddDate(0, 0, s.shiftDays).Format("2006-01-02")
		}
		if clockOnly.MatchString(v) {
			return "12:00" // a time of day (e.g. the frame's sleep schedule): real but not needed
		}
	case key == "timezone":
		return FakeZone
	case key == "rrule":
		return s.rrule(v)
	case strings.Contains(key, "email"):
		// One namespace for all email keys, so an owner who is also invited
		// stays the same person.
		return s.synthetic("email", v, func(n int) string { return fmt.Sprintf("person%d@example.test", n) })
	case strings.Contains(key, "url") || strings.HasPrefix(v, "http"):
		return s.synthetic("url", v, func(n int) string { return fmt.Sprintf("https://example.test/image/%d.png", n) })
	case key == "lat" || key == "lng":
		return nil
	}
	return s.synthetic(key, v, func(n int) string { return fmt.Sprintf("%s %d", label(key), n) })
}

func label(key string) string {
	switch key {
	case "label":
		return "Member"
	case "summary":
		return "Event"
	}
	return strings.ReplaceAll(key, "_", "-")
}

func (s *Scrubber) synthetic(key, v string, mk func(int) string) string {
	k := key + "\x00" + v
	if out, ok := s.strs[k]; ok {
		return out
	}
	s.counters[key]++
	out := mk(s.counters[key])
	s.strs[k] = out
	return out
}

// id maps an id to a synthetic one with the same number of digits (or a
// generic token for non-numeric ids). Mapping is global per Scrubber, so
// references across documents still match.
func (s *Scrubber) id(v string) string {
	if out, ok := s.ids[v]; ok {
		return out
	}
	var out string
	if digitsOnly.MatchString(v) {
		n := len(s.ids) + 1
		out = fmt.Sprintf("%0*d", len(v), n)
		out = "9" + out[1:] // leading 9: never a real-looking small id, keeps length
	} else {
		out = fmt.Sprintf("id-%d", len(s.ids)+1)
	}
	s.ids[v] = out
	return out
}

// shift moves t by the run's whole-week shift, keeping its wall clock, and
// re-expresses it in FakeZone.
func (s *Scrubber) shift(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), s.loc).
		AddDate(0, 0, s.shiftDays)
}

func (s *Scrubber) rrule(v string) string {
	body, ok := strings.CutPrefix(v, "RRULE:")
	if !ok {
		return s.synthetic("rrule", v, func(n int) string { return fmt.Sprintf("RRULE:FREQ=WEEKLY;X-SCRUBBED=%d", n) })
	}
	var parts []string
	for p := range strings.SplitSeq(body, ";") {
		name, _, _ := strings.Cut(p, "=")
		if !rrulePart[name] {
			continue
		}
		if m := untilRE.FindStringSubmatch(p); m != nil {
			d, err := time.Parse("20060102", m[1])
			if err != nil {
				continue
			}
			p = "UNTIL=" + d.AddDate(0, 0, s.shiftDays).Format("20060102") + m[2]
		}
		parts = append(parts, p)
	}
	out := "RRULE:" + strings.Join(parts, ";")
	if out == v {
		// A rule with no dates and no unknown parts ("weekly on Tuesday") is
		// structure, not personal data: kept deliberately.
		s.kept[v] = true
	}
	return out
}

// fixComposites finishes "composite:<id>" values using the scrubbed starts_at
// of the same resource.
func (s *Scrubber) fixComposites(v any) {
	switch x := v.(type) {
	case map[string]any:
		if id, ok := x["id"].(string); ok && strings.HasPrefix(id, "composite:") {
			start := ""
			if a, ok := x["attributes"].(map[string]any); ok {
				start, _ = a["starts_at"].(string)
			}
			t, err := time.Parse(timeLayout, start)
			suffix := "0"
			if err == nil {
				suffix = strconv.FormatInt(t.Unix(), 10)
			}
			x["id"] = strings.TrimPrefix(id, "composite:") + "-" + suffix
		}
		for _, val := range x {
			s.fixComposites(val)
		}
	case []any:
		for _, val := range x {
			s.fixComposites(val)
		}
	}
}

// Check returns the original values (length >= 3) that still appear in
// any string or number value of out (key names are not data). Values also
// kept verbatim under an allowlisted key are enumerations and are skipped.
// Call it on every scrubbed document; anything returned is a leak.
func (s *Scrubber) Check(out []byte) []string {
	var v any
	d := json.NewDecoder(strings.NewReader(string(out)))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		return []string{"<output is not JSON>"}
	}
	var vals []string
	var collect func(any)
	collect = func(x any) {
		switch t := x.(type) {
		case map[string]any:
			for _, e := range t {
				collect(e)
			}
		case []any:
			for _, e := range t {
				collect(e)
			}
		case string:
			vals = append(vals, t)
		case json.Number:
			vals = append(vals, t.String())
		}
	}
	collect(v)
	text := strings.Join(vals, "\x00")
	// Short originals (names like "Ann") must match a whole word, so they
	// are not flagged inside unrelated synthetic words; longer ones match
	// anywhere.
	words := map[string]bool{}
	for _, w := range strings.FieldsFunc(text, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9')
	}) {
		words[strings.ToLower(w)] = true
	}
	var leaks []string
	for o := range s.originals {
		if len(o) < 3 || s.kept[o] {
			continue
		}
		if (len(o) < 6 && words[strings.ToLower(o)]) || (len(o) >= 6 && strings.Contains(text, o)) {
			leaks = append(leaks, o)
		}
	}
	sort.Strings(leaks)
	return leaks
}
