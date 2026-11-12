package scangov

import (
	"context"
	"slices"
	"strings"
	"time"
)

// Origin is how a scan action reached the platform: the condition
// "origins" of a rule matches it.
type Origin string

// Origins.
const (
	// OriginUI: a person's session (the web console, or a script using a
	// session token).
	OriginUI Origin = "ui"
	// OriginAPIKey: a person's `oct_` API key.
	OriginAPIKey Origin = "api_key"
	// OriginServiceAccount: an `oct_` API key of a service account.
	OriginServiceAccount Origin = "service_account"
	// OriginMCP: the MCP endpoint (an `oct_` key or an MCP OAuth grant).
	OriginMCP Origin = "mcp"
	// OriginCI: a CI run token.
	OriginCI Origin = "ci"
	// OriginSystem: no caller (the scheduler, an automation).
	OriginSystem Origin = "system"
)

// Origins lists the origins a rule may name.
var Origins = []Origin{OriginUI, OriginAPIKey, OriginServiceAccount, OriginMCP, OriginCI, OriginSystem}

// Valid reports whether o is a known origin.
func (o Origin) Valid() bool { return slices.Contains(Origins, o) }

type originKey struct{}

// WithOrigin records on ctx how the request authenticated (set by the
// authentication middleware, never from the request's content).
func WithOrigin(ctx context.Context, o Origin) context.Context {
	return context.WithValue(ctx, originKey{}, o)
}

// OriginFrom returns the origin WithOrigin recorded.
func OriginFrom(ctx context.Context) (Origin, bool) {
	if ctx == nil {
		return "", false
	}
	o, ok := ctx.Value(originKey{}).(Origin)
	return o, ok && o.Valid()
}

// Requester is what the requester conditions read: who asks for the scan
// (or starts the run) and through what. Every field comes from the
// organization's own data (its roles, groups and service accounts).
type Requester struct {
	UserID string `json:"user_id,omitempty"`
	Origin Origin `json:"origin"`
	// Roles: the effective organization role (owner, admin, member,
	// viewer) and the ids of every role held.
	Roles []string `json:"roles,omitempty"`
	// GroupIDs: the active groups the requester belongs to.
	GroupIDs []string `json:"group_ids,omitempty"`
	// ServiceAccount: the requester is one of the organization's service
	// accounts.
	ServiceAccount bool `json:"service_account,omitempty"`
}

// Requester roles a rule may name by name (custom roles by id).
var requesterRoleNames = []string{RoleOwner, RoleAdmin, "member", "viewer"}

// Hours is a weekly schedule: Match "outside" (the default) catches scans
// outside every window, "inside" scans inside one. Times are wall-clock
// in Timezone (the organization's timezone when empty), so the windows
// follow daylight-saving changes.
type Hours struct {
	Match    string   `json:"match,omitempty"`
	Timezone string   `json:"timezone,omitempty"`
	Windows  []Window `json:"windows"`
}

// Window is a daily time range on some weekdays: [Start, End), "HH:MM",
// End may be "24:00".
type Window struct {
	Days  []string `json:"days"`
	Start string   `json:"start"`
	End   string   `json:"end"`
}

// Hours matches.
const (
	HoursOutside = "outside"
	HoursInside  = "inside"
)

// MaxWindows bounds a schedule.
const MaxWindows = 14

var weekdays = map[string]time.Weekday{
	"sun": time.Sunday, "mon": time.Monday, "tue": time.Tuesday, "wed": time.Wednesday,
	"thu": time.Thursday, "fri": time.Friday, "sat": time.Saturday,
}

// clockMinutes parses "HH:MM" (allow24: "24:00" too) to minutes.
func clockMinutes(s string, allow24 bool) (int, bool) {
	if len(s) != 5 || s[2] != ':' {
		return 0, false
	}
	h, m := 0, 0
	for _, c := range s[:2] {
		if c < '0' || c > '9' {
			return 0, false
		}
		h = h*10 + int(c-'0')
	}
	for _, c := range s[3:] {
		if c < '0' || c > '9' {
			return 0, false
		}
		m = m*10 + int(c-'0')
	}
	switch {
	case m > 59:
		return 0, false
	case h == 24 && m == 0 && allow24:
		return 24 * 60, true
	case h > 23:
		return 0, false
	}
	return h*60 + m, true
}

func loadZone(tz string) (*time.Location, bool) {
	if tz == "" || strings.EqualFold(tz, "local") {
		return nil, false
	}
	loc, err := time.LoadLocation(tz)
	return loc, err == nil
}

func (h *Hours) normalized() (*Hours, error) {
	if h == nil {
		return nil, nil
	}
	out := &Hours{Match: strings.ToLower(strings.TrimSpace(h.Match)), Timezone: strings.TrimSpace(h.Timezone)}
	switch out.Match {
	case "":
		out.Match = HoursOutside
	case HoursOutside, HoursInside:
	default:
		return nil, invalid("hours.match must be outside or inside")
	}
	if out.Timezone != "" {
		if _, ok := loadZone(out.Timezone); !ok {
			return nil, invalid("hours.timezone is not a known IANA timezone")
		}
	}
	if len(h.Windows) == 0 || len(h.Windows) > MaxWindows {
		return nil, invalid("hours: 1 to %d windows", MaxWindows)
	}
	for i, w := range h.Windows {
		days, err := cleanList(w.Days, true, "hours.days")
		if err != nil {
			return nil, err
		}
		if len(days) == 0 {
			return nil, invalid("hours window %d: at least one day", i+1)
		}
		for _, d := range days {
			if _, ok := weekdays[d]; !ok {
				return nil, invalid("hours window %d: days are mon, tue, wed, thu, fri, sat, sun", i+1)
			}
		}
		start, ok1 := clockMinutes(strings.TrimSpace(w.Start), false)
		end, ok2 := clockMinutes(strings.TrimSpace(w.End), true)
		if !ok1 || !ok2 || start >= end {
			return nil, invalid("hours window %d: start and end are HH:MM with start before end (end may be 24:00)", i+1)
		}
		out.Windows = append(out.Windows, Window{Days: days, Start: strings.TrimSpace(w.Start), End: strings.TrimSpace(w.End)})
	}
	return out, nil
}

// inside reports whether instant at falls inside a window, in zone loc.
func (h *Hours) inside(at time.Time, loc *time.Location) bool {
	local := at.In(loc)
	day, minute := local.Weekday(), local.Hour()*60+local.Minute()
	for _, w := range h.Windows {
		start, _ := clockMinutes(w.Start, false)
		end, _ := clockMinutes(w.End, true)
		if minute < start || minute >= end {
			continue
		}
		for _, d := range w.Days {
			if weekdays[d] == day {
				return true
			}
		}
	}
	return false
}

// matches reports whether the schedule catches instant at; orgTZ is the
// organization's timezone. An unknown instant or zone catches (fail
// closed: the rule asks for approval).
func (h *Hours) matches(at time.Time, orgTZ string) bool {
	if at.IsZero() {
		return true
	}
	tz := h.Timezone
	if tz == "" {
		tz = orgTZ
	}
	if tz == "" {
		tz = "UTC"
	}
	loc, ok := loadZone(tz)
	if !ok {
		return true
	}
	in := h.inside(at, loc)
	if h.Match == HoursInside {
		return in
	}
	return !in
}

// requesterMatches applies the requester conditions to r (nil: unknown,
// which every requester condition catches, fail closed). A trusted service
// account is never caught by the rule.
func (c Conditions) requesterMatches(r *Requester) bool {
	if r != nil && r.ServiceAccount && slices.Contains(c.TrustedServiceAccountIDs, strings.ToLower(r.UserID)) {
		return false
	}
	if r == nil {
		return true
	}
	if len(c.Origins) > 0 && !slices.Contains(c.Origins, string(r.Origin)) {
		return false
	}
	if len(c.RequesterRoles) > 0 && !anyIn(c.RequesterRoles, r.Roles, true) {
		return false
	}
	if len(c.RequesterGroupIDs) > 0 && !anyIn(c.RequesterGroupIDs, r.GroupIDs, true) {
		return false
	}
	return true
}

// NeedsRequester reports whether an enabled rule reads the requester.
func NeedsRequester(rules []Rule) bool {
	for _, r := range rules {
		c := r.Conditions
		if r.Enabled && (len(c.Origins) > 0 || len(c.RequesterRoles) > 0 || len(c.RequesterGroupIDs) > 0 ||
			len(c.TrustedServiceAccountIDs) > 0) {
			return true
		}
	}
	return false
}

// NeedsClock reports whether an enabled rule reads the time of the scan.
func NeedsClock(rules []Rule) bool {
	for _, r := range rules {
		if r.Enabled && r.Conditions.Hours != nil {
			return true
		}
	}
	return false
}

func (c Conditions) normalizedRequester() (Conditions, error) {
	var err error
	if c.RequesterRoles, err = cleanList(c.RequesterRoles, true, "requester_roles"); err != nil {
		return c, err
	}
	for _, r := range c.RequesterRoles {
		if !slices.Contains(requesterRoleNames, r) && !isUUID(r) {
			return c, invalid("requester_roles: owner, admin, member, viewer or a role id")
		}
	}
	if c.RequesterGroupIDs, err = cleanUUIDs(c.RequesterGroupIDs, "requester_group_ids"); err != nil {
		return c, err
	}
	if c.TrustedServiceAccountIDs, err = cleanUUIDs(c.TrustedServiceAccountIDs, "trusted_service_account_ids"); err != nil {
		return c, err
	}
	if c.Origins, err = cleanList(c.Origins, true, "origins"); err != nil {
		return c, err
	}
	for _, o := range c.Origins {
		if !Origin(o).Valid() {
			return c, invalid("origins: ui, api_key, service_account, mcp, ci or system")
		}
	}
	if c.Hours, err = c.Hours.normalized(); err != nil {
		return c, err
	}
	return c, nil
}
