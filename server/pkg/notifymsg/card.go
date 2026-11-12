package notifymsg

import (
	"fmt"
	"strings"
)

// Level is how much of an event a channel receives. Chat and webhook
// receivers are third parties: the level decides what leaves the platform.
type Level string

const (
	// LevelMinimal: what happened, its severity, the organization and a
	// link back. No asset, finding or exposure names.
	LevelMinimal Level = "minimal"
	// LevelStandard adds the asset, what it is, why it matters and the
	// next step. The default for a new channel.
	LevelStandard Level = "standard"
	// LevelFull adds the description, capped. Secrets, evidence,
	// credentials and internal IDs are never part of any level.
	LevelFull Level = "full"
)

// DefaultLevel is the level of a new channel.
const DefaultLevel = LevelStandard

// Levels lists every level, least first.
func Levels() []Level { return []Level{LevelMinimal, LevelStandard, LevelFull} }

// ParseLevel parses a stored or requested level.
func ParseLevel(s string) (Level, error) {
	l := Level(strings.ToLower(strings.TrimSpace(s)))
	for _, k := range Levels() {
		if k == l {
			return l, nil
		}
	}
	return "", fmt.Errorf("unknown detail level %q (want minimal, standard or full)", s)
}

func (l Level) rank() int {
	switch l {
	case LevelStandard:
		return 1
	case LevelFull:
		return 2
	default:
		return 0
	}
}

// Includes reports whether l carries what other carries.
func (l Level) Includes(other Level) bool { return l.rank() >= other.rank() }

// maxDescriptionRunes caps the description a full channel receives.
const maxDescriptionRunes = 600

// Card is one channel message. Renderers lay it out per provider; every
// value in it is untrusted text (an asset name or a title may come from a
// scan target) and is escaped by the renderer, the catalog labels too.
type Card struct {
	Locale    string
	Level     Level
	EventType string
	// Severity is critical, high, medium, low or info. It is shown once,
	// as the severity line, plus a marker the renderer picks (emoji or
	// color); never a template variable.
	Severity string
	// Headline says what happened, once: no severity, no object name.
	Headline string
	Subject  Subject
	What     string
	Why      string
	NextStep string
	// Description is set for LevelFull only.
	Description  string
	Organization string
	Action       Action
	// Items lists the objects of an event about several (new addresses of
	// one discovery, the members of a burst), at most MaxItems, most
	// important first; More counts the ones not listed.
	Items []string
	More  int
	// Custom holds the lines of the channel's template, already rendered;
	// nil means the default layout (Lines).
	Custom []string
}

// MaxItems caps the objects one message lists.
const MaxItems = 5

// Subject is the asset the event is about.
type Subject struct {
	Name string
	Type string
}

// Action is the single link of a message: a button where the channel has
// one, a plain link otherwise. Never repeated in the text.
type Action struct {
	Label string
	URL   string
}

// Line is one labeled line of the default layout. Label is empty for a
// template line.
type Line struct {
	Key   string // severity, asset, what, why, next_step, description, organization
	Label string
	Value string
}

// SubjectText is "name (type)", or the name alone.
func (c Card) SubjectText() string {
	if c.Subject.Name == "" {
		return ""
	}
	if c.Subject.Type == "" {
		return c.Subject.Name
	}
	return c.Subject.Name + " (" + strings.ReplaceAll(c.Subject.Type, "_", " ") + ")"
}

// SeverityText is the localized severity word.
func (c Card) SeverityText() string { return SeverityWord(c.Locale, c.Severity) }

// Lines is the body of the card in display order: the template lines when
// the channel has a template, else the labeled default lines. Empty values
// are left out, so no line ends in a bare label.
func (c Card) Lines() []Line {
	if c.Custom != nil {
		out := make([]Line, 0, len(c.Custom)+len(c.Items)+1)
		for _, l := range c.Custom {
			out = append(out, Line{Value: l})
		}
		return c.appendItems(out)
	}
	all := []Line{
		{Key: "severity", Label: T(c.Locale, "label.severity"), Value: c.SeverityText()},
		{Key: "asset", Label: T(c.Locale, "label.asset"), Value: c.SubjectText()},
		{Key: "what", Label: T(c.Locale, "label.what"), Value: c.What},
		{Key: "why", Label: T(c.Locale, "label.why"), Value: c.Why},
		{Key: "next_step", Label: T(c.Locale, "label.next"), Value: c.NextStep},
		{Key: "description", Label: T(c.Locale, "label.description"), Value: c.Description},
		{Key: "organization", Label: T(c.Locale, "label.organization"), Value: c.Organization},
	}
	out := make([]Line, 0, len(all)+len(c.Items)+1)
	for _, l := range all {
		if strings.TrimSpace(l.Value) != "" {
			out = append(out, l)
		}
	}
	return c.appendItems(out)
}

// appendItems adds one "- item" line per listed object and "+N more".
func (c Card) appendItems(out []Line) []Line {
	for _, it := range c.Items {
		if strings.TrimSpace(it) != "" {
			out = append(out, Line{Key: "item", Value: "- " + it})
		}
	}
	if c.More > 0 {
		out = append(out, Line{Key: "more", Value: T(c.Locale, "list.more", fmt.Sprintf("%d", c.More))})
	}
	return out
}

// Text is the plain-text body: one line per Line, "Label: value".
func (c Card) Text() string {
	var b strings.Builder
	for i, l := range c.Lines() {
		if i > 0 {
			b.WriteByte('\n')
		}
		if l.Label != "" {
			b.WriteString(l.Label + ": ")
		}
		b.WriteString(l.Value)
	}
	return b.String()
}

// Subjectline is the e-mail subject: the headline and the asset (standard
// and full) or the severity (minimal).
func (c Card) Subjectline() string {
	if s := c.SubjectText(); s != "" {
		return c.Headline + ": " + s
	}
	return c.Headline + " (" + c.SeverityText() + ")"
}

// Map applies f to every text value of the card (cleaning, scrubbing).
func (c Card) Map(f func(string) string) Card {
	c.Headline = f(c.Headline)
	c.Subject.Name = f(c.Subject.Name)
	c.Subject.Type = f(c.Subject.Type)
	c.What = f(c.What)
	c.Why = f(c.Why)
	c.NextStep = f(c.NextStep)
	c.Description = f(c.Description)
	c.Organization = f(c.Organization)
	c.Action.Label = f(c.Action.Label)
	if c.Items != nil {
		items := make([]string, len(c.Items))
		for i, it := range c.Items {
			items[i] = f(it)
		}
		c.Items = items
	}
	if c.Custom != nil {
		custom := make([]string, len(c.Custom))
		for i, l := range c.Custom {
			custom[i] = f(l)
		}
		c.Custom = custom
	}
	return c
}
