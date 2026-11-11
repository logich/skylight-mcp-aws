// Package tools registers the v1 read-only MCP tools (SPEC §4):
// list_family_members, list_events and get_event.
package tools

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/logich/skylight-mcp-aws/internal/calendar"
	"github.com/logich/skylight-mcp-aws/internal/canary"
)

// Calendar is what the tools read from (*calendar.Client in production).
type Calendar interface {
	Categories(ctx context.Context) ([]calendar.Category, error)
	Events(ctx context.Context, from, to time.Time) ([]calendar.Event, error)
	Location(ctx context.Context) (*time.Location, error)
}

// Limits.
const (
	MaxRange       = 93 * 24 * time.Hour // list_events window
	getEventBefore = 30 * 24 * time.Hour // get_event default window without a hint
	getEventAfter  = 180 * 24 * time.Hour
)

// Member is one family member.
type Member struct {
	ID    string `json:"id" jsonschema:"Skylight category id of the member"`
	Name  string `json:"name" jsonschema:"display name"`
	Color string `json:"color,omitempty" jsonschema:"colour as #rrggbb"`
}

// MembersOut is list_family_members' result.
type MembersOut struct {
	Members []Member `json:"members"`
}

// Event is one event (one occurrence of a recurring event).
type Event struct {
	ID        string   `json:"id" jsonschema:"event id; recurring occurrences have ids like <event>-<unix start>"`
	Title     string   `json:"title"`
	Start     string   `json:"start" jsonschema:"RFC 3339, in the household's timezone"`
	End       string   `json:"end" jsonschema:"RFC 3339; for all-day events, midnight after the last day (exclusive)"`
	AllDay    bool     `json:"all_day"`
	Location  string   `json:"location,omitempty"`
	Notes     string   `json:"notes,omitempty"`
	Members   []string `json:"members" jsonschema:"family members tagged on the event, by name"`
	Recurring bool     `json:"recurring,omitempty"`
}

// EventsOut is list_events' result.
type EventsOut struct {
	Timezone string  `json:"timezone" jsonschema:"the household's IANA timezone"`
	Events   []Event `json:"events"`
}

// ListEventsIn is list_events' input.
type ListEventsIn struct {
	Start  string `json:"start" jsonschema:"start of the range, RFC 3339 (e.g. 2026-11-11T00:00:00-06:00)"`
	End    string `json:"end" jsonschema:"end of the range (exclusive), RFC 3339; at most 93 days after start"`
	Member string `json:"member,omitempty" jsonschema:"optional family member name; only events tagged with them"`
}

// GetEventIn is get_event's input.
type GetEventIn struct {
	EventID string `json:"event_id" jsonschema:"an id returned by list_events"`
	Around  string `json:"around,omitempty" jsonschema:"optional RFC 3339 time near the event's start; speeds up and widens the lookup for non-recurring events"`
}

// EventOut is get_event's result.
type EventOut struct {
	Timezone string `json:"timezone"`
	Event    Event  `json:"event"`
}

// Register adds the v1 tools to s.
func Register(s *mcp.Server, cal Calendar, logger *slog.Logger) {
	if logger == nil {
		logger = slog.New(slog.DiscardHandler)
	}
	h := handlers{cal: cal, log: logger}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "list_family_members",
		Description: "List the family members on the Skylight calendar (the people events can be tagged with).",
	}, logged(h, "list_family_members", h.listMembers))
	mcp.AddTool(s, &mcp.Tool{
		Name: "list_events",
		Description: "List Skylight calendar events overlapping a time range (at most 93 days), with the family " +
			"members each event is tagged with. Optionally only events tagged with one member.",
	}, logged(h, "list_events", h.listEvents))
	mcp.AddTool(s, &mcp.Tool{
		Name:        "get_event",
		Description: "Get one Skylight calendar event by the id list_events returned.",
	}, logged(h, "get_event", h.getEvent))
}

type handlers struct {
	cal Calendar
	log *slog.Logger
}

// logged wraps a handler with an allowlisted log line (tool, outcome class,
// duration; never arguments or results) and user-facing error messages.
func logged[In, Out any](h handlers, name string, f func(context.Context, In) (Out, error)) mcp.ToolHandlerFor[In, Out] {
	return func(ctx context.Context, _ *mcp.CallToolRequest, in In) (*mcp.CallToolResult, Out, error) {
		start := time.Now()
		var zero Out
		if h.cal == nil {
			return nil, zero, errors.New("the Skylight connection is not configured on the server")
		}
		out, err := f(ctx, in)
		class := "ok"
		if err != nil {
			var ue userError
			if errors.As(err, &ue) {
				class = "bad_input"
			} else {
				class = canary.Class(err)
				err = friendly(err)
			}
		}
		h.log.Info("tool", "tool", name, "outcome", class, "ms", time.Since(start).Milliseconds())
		if err != nil {
			return nil, zero, err
		}
		return nil, out, nil
	}
}

// userError is a problem with the caller's input; its message is shown as is.
type userError struct{ msg string }

func (e userError) Error() string { return e.msg }

func badInput(format string, a ...any) error { return userError{fmt.Sprintf(format, a...)} }

func friendly(err error) error {
	switch canary.Class(err) {
	case "reauthorize":
		return errors.New("Skylight sign-in has expired or was revoked. The server owner must sign in again " +
			"(skylight-login, then skylight-store-import).")
	case "no_grant":
		return errors.New("the server has no Skylight sign-in stored yet (owner: run skylight-store-import)")
	case "api_changed":
		return fmt.Errorf("upstream API changed: Skylight's response no longer has the expected shape, so no data was returned (%v)", err)
	case "upstream", "unavailable", "timeout":
		return fmt.Errorf("Skylight is unavailable or rate-limiting right now; try again shortly (%v)", err)
	}
	return errors.New("internal error reading the Skylight calendar")
}

func (h handlers) listMembers(ctx context.Context, _ struct{}) (MembersOut, error) {
	cats, err := h.cal.Categories(ctx)
	if err != nil {
		return MembersOut{}, err
	}
	out := MembersOut{Members: []Member{}}
	for _, c := range calendar.Members(cats) {
		out.Members = append(out.Members, Member{ID: c.ID, Name: c.Label, Color: c.Color})
	}
	return out, nil
}

func parseTime(field, v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(v))
	if err != nil {
		return time.Time{}, badInput("%s must be an RFC 3339 time such as 2026-11-11T09:00:00-06:00", field)
	}
	return t, nil
}

func (h handlers) listEvents(ctx context.Context, in ListEventsIn) (EventsOut, error) {
	start, err := parseTime("start", in.Start)
	if err != nil {
		return EventsOut{}, err
	}
	end, err := parseTime("end", in.End)
	if err != nil {
		return EventsOut{}, err
	}
	if !end.After(start) {
		return EventsOut{}, badInput("end must be after start")
	}
	if end.Sub(start) > MaxRange {
		return EventsOut{}, badInput("the range may be at most 93 days; split it into several calls")
	}
	member := strings.TrimSpace(in.Member)
	if member != "" {
		if member, err = h.resolveMember(ctx, member); err != nil {
			return EventsOut{}, err
		}
	}
	loc, err := h.cal.Location(ctx)
	if err != nil {
		return EventsOut{}, err
	}
	evs, err := h.cal.Events(ctx, start, end.Add(-time.Nanosecond))
	if err != nil {
		return EventsOut{}, err
	}
	out := EventsOut{Timezone: loc.String(), Events: []Event{}}
	for _, e := range sorted(evs) {
		if !overlaps(e, start, end) || (member != "" && !hasMember(e, member)) {
			continue
		}
		out.Events = append(out.Events, toEvent(e, loc))
	}
	return out, nil
}

// resolveMember matches a name case-insensitively against the member list.
func (h handlers) resolveMember(ctx context.Context, name string) (string, error) {
	cats, err := h.cal.Categories(ctx)
	if err != nil {
		return "", err
	}
	var names []string
	for _, m := range calendar.Members(cats) {
		if strings.EqualFold(m.Label, name) {
			return m.Label, nil
		}
		names = append(names, m.Label)
	}
	return "", badInput("no family member named %q; members are: %s", name, strings.Join(names, ", "))
}

var occurrenceID = regexp.MustCompile(`^[0-9]+-([0-9]{9,11})$`)

func (h handlers) getEvent(ctx context.Context, in GetEventIn) (EventOut, error) {
	id := strings.TrimSpace(in.EventID)
	if id == "" || len(id) > 64 {
		return EventOut{}, badInput("event_id is required (an id from list_events)")
	}
	var from, to time.Time
	switch m := occurrenceID.FindStringSubmatch(id); {
	case m != nil:
		sec, _ := strconv.ParseInt(m[1], 10, 64)
		at := time.Unix(sec, 0)
		from, to = at.Add(-24*time.Hour), at.Add(24*time.Hour)
	case strings.TrimSpace(in.Around) != "":
		at, err := parseTime("around", in.Around)
		if err != nil {
			return EventOut{}, err
		}
		from, to = at.Add(-7*24*time.Hour), at.Add(7*24*time.Hour)
	default:
		now := time.Now()
		from, to = now.Add(-getEventBefore), now.Add(getEventAfter)
	}
	loc, err := h.cal.Location(ctx)
	if err != nil {
		return EventOut{}, err
	}
	evs, err := h.cal.Events(ctx, from, to)
	if err != nil {
		return EventOut{}, err
	}
	for _, e := range evs {
		if e.ID == id {
			return EventOut{Timezone: loc.String(), Event: toEvent(e, loc)}, nil
		}
	}
	return EventOut{}, badInput("no event with id %q found between %s and %s; pass 'around' with a time near its start",
		id, from.In(loc).Format(time.DateOnly), to.In(loc).Format(time.DateOnly))
}

func overlaps(e calendar.Event, start, end time.Time) bool {
	if e.End.Equal(e.Start) {
		return !e.Start.Before(start) && e.Start.Before(end)
	}
	return e.Start.Before(end) && e.End.After(start)
}

func hasMember(e calendar.Event, name string) bool {
	for _, m := range e.Members {
		if m == name {
			return true
		}
	}
	return false
}

func sorted(evs []calendar.Event) []calendar.Event {
	out := append([]calendar.Event(nil), evs...)
	sort.SliceStable(out, func(i, j int) bool {
		if !out[i].Start.Equal(out[j].Start) {
			return out[i].Start.Before(out[j].Start)
		}
		if out[i].Title != out[j].Title {
			return out[i].Title < out[j].Title
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func toEvent(e calendar.Event, loc *time.Location) Event {
	members := e.Members
	if members == nil {
		members = []string{}
	}
	return Event{
		ID: e.ID, Title: e.Title, AllDay: e.AllDay, Location: e.Location, Notes: e.Description,
		Start: e.Start.In(loc).Format(time.RFC3339), End: e.End.In(loc).Format(time.RFC3339),
		Members: members, Recurring: e.Recurring,
	}
}
