package notifymsg

import (
	"fmt"
	"strings"

	"github.com/openctemio/openctem/server/pkg/safetext"
)

// Grouped messages: one card for several alerts of the same kind
// (docs/architecture/notification-system.md, "Grouped alerts"). The
// headline gives the count, the objects are listed by asset, one compact
// line each, at most MaxGroupLines, then "+N more"; the action opens the
// list of exactly those objects.

// MaxGroupLines caps the object lines of a grouped message.
const MaxGroupLines = 10

// Rune caps of the parts of one object line, so a full message stays well
// under the smallest provider limit (Telegram, 4096 characters).
const (
	maxGroupWhatRunes    = 110
	maxGroupReasonRunes  = 80
	maxGroupSectionRunes = 120
)

// GroupEntry is one listed object of a grouped message.
type GroupEntry struct {
	// Facts of the object (title, CVE, KEV, EPSS, asset); nil when unknown.
	Facts    *Facts
	Severity string
	// Title is the producer's text, used when there are no facts.
	Title string
	// Reason is the producer's one reason (a priority rule), used when the
	// facts give none.
	Reason string
}

// GroupInput is everything a grouped card is built from.
type GroupInput struct {
	EventType    string
	Level        Level
	Locale       string
	Organization string
	URL          string
	// Count is how many objects the message announces.
	Count int
	// Severities counts the announced objects by severity.
	Severities map[string]int
	// Entries are the listed objects, most important first. Only the first
	// MaxGroupLines are listed.
	Entries []GroupEntry
}

// severityOrder lists severities most urgent first.
var severityOrder = []string{severityCritical, severityHigh, severityMedium, severityLow, severityInfo}

// Severity names.
const (
	severityCritical = "critical"
	severityHigh     = "high"
	severityMedium   = "medium"
	severityLow      = "low"
	severityInfo     = "info"
)

// NormalizeSeverityName maps a severity to critical, high, medium, low or
// info.
func NormalizeSeverityName(s string) string { return normalizeSeverity(s) }

// SeverityRank orders severities, most urgent first (unknown last).
func SeverityRank(s string) int {
	s = normalizeSeverity(s)
	for i, v := range severityOrder {
		if v == s {
			return i
		}
	}
	return len(severityOrder)
}

// BuildGroup makes the card of a grouped message. What the channel's level
// excludes (asset and object names below standard) is never put in it.
func BuildGroup(in GroupInput) Card {
	loc := NormalizeLocale(in.Locale)
	level := in.Level
	if _, err := ParseLevel(string(level)); err != nil {
		level = LevelMinimal
	}
	top, target := groupSeverities(in.Severities)
	c := Card{
		Locale:       loc,
		Level:        level,
		EventType:    in.EventType,
		Severity:     top,
		Headline:     groupHeadline(loc, in.EventType, in.Count, target),
		Organization: in.Organization,
		Action:       Action{Label: T(loc, "action.group"), URL: in.URL},
	}
	if target == "" {
		c.What = severityBreakdown(loc, in.Severities)
	}
	if !level.Includes(LevelStandard) {
		return c.Map(stripIDs)
	}
	listed := in.Entries
	if len(listed) > MaxGroupLines {
		listed = listed[:MaxGroupLines]
	}
	c.Sections = groupSections(loc, listed)
	c.More = max(in.Count-len(listed), 0)
	return c.Map(stripIDs)
}

// groupSeverities returns the most urgent severity and, when every object
// has the same one, that severity (the headline says "raised to High").
func groupSeverities(counts map[string]int) (top, target string) {
	top = severityInfo
	n := 0
	for _, s := range severityOrder {
		if counts[s] > 0 {
			if n == 0 {
				top = s
			}
			n++
		}
	}
	if n == 1 {
		target = top
	}
	return top, target
}

func severityBreakdown(loc string, counts map[string]int) string {
	parts := make([]string, 0, len(severityOrder))
	for _, s := range severityOrder {
		if counts[s] > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", counts[s], SeverityWord(loc, s)))
		}
	}
	return strings.Join(parts, ", ")
}

// groupHeadline is "6 findings raised to High"; with mixed severities the
// ".mixed" form ("6 findings raised in priority"); an event type without a
// grouped form says "6 alerts: <event headline>".
func groupHeadline(loc, eventType string, count int, target string) string {
	n := fmt.Sprintf("%d", count)
	if target != "" {
		if _, ok := text(loc, "group."+eventType); ok {
			return T(loc, "group."+eventType, n, SeverityWord(loc, target))
		}
	} else if _, ok := text(loc, "group."+eventType+".mixed"); ok {
		return T(loc, "group."+eventType+".mixed", n)
	}
	return T(loc, "group.default", n, Headline(loc, eventType))
}

// groupSections lists the entries by asset, in the order of each asset's
// first (most important) entry.
func groupSections(loc string, entries []GroupEntry) []Section {
	var out []Section
	index := map[string]int{}
	for _, e := range entries {
		title := T(loc, "group.no_asset")
		if e.Facts != nil && strings.TrimSpace(e.Facts.AssetName) != "" {
			title = Card{Subject: Subject{Name: e.Facts.AssetName, Type: e.Facts.AssetType}}.SubjectText()
		}
		title = safetext.Truncate(title, maxGroupSectionRunes)
		i, ok := index[title]
		if !ok {
			i = len(out)
			index[title] = i
			out = append(out, Section{Title: title})
		}
		out[i].Items = append(out[i].Items, groupLine(loc, e))
	}
	return out
}

// groupLine is "CVE-2024-4577: PHP 8.1 argument injection, Critical, known
// exploited": what, the severity, the one reason.
func groupLine(loc string, e GroupEntry) string {
	var whatText, reason string
	if e.Facts != nil {
		whatText = what(loc, e.Facts)
		if w := why(loc, e.Facts); w != "" {
			reason = strings.SplitN(w, "; ", 2)[0]
		}
	}
	if whatText == "" {
		whatText = stripSeverityWords(e.Title)
	}
	if reason == "" {
		reason = strings.TrimSpace(e.Reason)
	}
	parts := []string{safetext.Truncate(safetext.Clean(whatText), maxGroupWhatRunes), SeverityWord(loc, e.Severity)}
	if reason != "" {
		parts = append(parts, safetext.Truncate(safetext.Clean(reason), maxGroupReasonRunes))
	}
	if parts[0] == "" {
		parts = parts[1:]
	}
	return strings.Join(parts, ", ")
}
