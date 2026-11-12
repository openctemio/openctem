package notifymsg

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/safetext"
)

// Facts are what the platform knows about the event's object, resolved at
// send time from the organization's own rows. Every field is optional.
type Facts struct {
	// Title of the finding or exposure.
	Title string
	// Class is the exposure class (exposure event_type, e.g. port_open).
	Class     string
	AssetName string
	AssetType string
	CVE       string
	KEV       bool
	// EPSS is the exploit prediction score in [0,1]; nil when unknown.
	EPSS        *float64
	Description string

	// Count is how many objects the event is about (several new assets);
	// Items names the first of them ("address from name"), standard and up.
	Count int
	Items []string
	// SharedCount of the objects sit on a shared provider edge or front end
	// (pkg/domain/edgeaddr), SharedProvider names it when there is one.
	SharedCount    int
	SharedProvider string
}

// AssetRef is one asset of a multi-asset event, with the name it was
// resolved from.
type AssetRef struct {
	ID, Name, Type string
	// From is the domain or subdomain that resolves to the asset, empty
	// when none does.
	From string
	// SharedProvider names the provider when the address is a shared edge
	// or front end (pkg/domain/edgeaddr), empty otherwise.
	SharedProvider string
}

// Text is "name from source" (or the name alone).
func (a AssetRef) Text(locale string) string {
	if a.From == "" || a.From == a.Name {
		return a.Name
	}
	return T(locale, "list.from", a.Name, a.From)
}

// Input is everything a card is built from.
type Input struct {
	EventType     string
	AggregateType string
	Severity      string
	Level         Level
	Locale        string
	Organization  string
	URL           string
	// ProducerTitle and ProducerBody are the text the producer stored with
	// the event. They are used for event types without Facts (scans,
	// sensors, CI, digests); for findings and exposures the facts win.
	ProducerTitle string
	ProducerBody  string
	Facts         *Facts
}

// Event and aggregate types the builder knows.
const (
	eventNewAsset = "new_asset"
	aggFinding    = "finding"
	aggExposure   = "exposure"
)

// epssNotable is the EPSS score from which "why it matters" names it.
const epssNotable = 0.1

// Build makes the card of one delivery. What the channel's level excludes is
// never put in the card.
func Build(in Input) Card {
	loc := NormalizeLocale(in.Locale)
	level := in.Level
	if _, err := ParseLevel(string(level)); err != nil {
		level = LevelMinimal
	}
	c := Card{
		Locale:       loc,
		Level:        level,
		EventType:    in.EventType,
		Severity:     normalizeSeverity(in.Severity),
		Headline:     Headline(loc, in.EventType),
		Organization: in.Organization,
		Action:       Action{Label: actionLabel(loc, in.AggregateType), URL: in.URL},
		NextStep:     T(loc, "next.default"),
	}
	if in.Facts != nil && in.EventType == eventNewAsset {
		c.Headline = assetHeadline(loc, in.Facts)
	}
	if !level.Includes(LevelStandard) {
		return c
	}
	return withFacts(c, in).Map(stripIDs)
}

func withFacts(c Card, in Input) Card {
	loc, level := c.Locale, c.Level
	f := in.Facts
	if f == nil {
		// No object facts: the producer's own title says what it is.
		c.What = stripSeverityWords(in.ProducerTitle)
		if c.What == c.Headline {
			c.What = ""
		}
		if level.Includes(LevelFull) {
			c.Description = capDescription(in.ProducerBody)
		}
		return c
	}
	if in.EventType == eventNewAsset {
		return assetCard(c, f)
	}
	c.Subject = Subject{Name: f.AssetName, Type: f.AssetType}
	c.What = what(loc, f)
	c.Why = why(loc, f)
	c.NextStep = nextStep(loc, in.AggregateType, f)
	if level.Includes(LevelFull) {
		desc := f.Description
		if desc == "" {
			desc = in.ProducerBody
		}
		c.Description = capDescription(desc)
	}
	return c
}

func normalizeSeverity(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	switch s {
	case "critical", "high", "medium", "low":
		return s
	default:
		return "info"
	}
}

func actionLabel(loc, aggregateType string) string {
	switch aggregateType {
	case aggFinding, aggExposure, "approval":
		return T(loc, "action."+aggregateType)
	default:
		return T(loc, "action.default")
	}
}

func what(loc string, f *Facts) string {
	title := strings.TrimSpace(f.Title)
	if f.CVE != "" && !strings.Contains(strings.ToUpper(title), strings.ToUpper(f.CVE)) {
		if title == "" {
			title = f.CVE
		} else {
			title = f.CVE + ": " + title
		}
	}
	if label := ClassLabel(loc, f.Class); label != "" && !strings.EqualFold(label, title) {
		if title == "" {
			return label
		}
		return title + " (" + label + ")"
	}
	return title
}

func why(loc string, f *Facts) string {
	var parts []string
	if f.KEV {
		parts = append(parts, T(loc, "why.kev"))
	}
	if f.EPSS != nil && *f.EPSS >= epssNotable && *f.EPSS <= 1 {
		parts = append(parts, T(loc, "why.epss", fmt.Sprintf("%.0f%%", *f.EPSS*100)))
	}
	if f.Class != "" {
		if v, ok := text(loc, "why.exposure."+f.Class); ok {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, "; ")
}

func nextStep(loc, aggregateType string, f *Facts) string {
	if f.KEV {
		return T(loc, "next.finding.kev")
	}
	switch aggregateType {
	case aggExposure:
		if v, ok := text(loc, "next.exposure."+f.Class); ok && f.Class != "" {
			return v
		}
		return T(loc, "next.exposure")
	case aggFinding:
		return T(loc, "next.finding")
	default:
		return T(loc, "next.default")
	}
}

// severityWordsRE matches the severity words producers used to bake into
// titles: a "New high " prefix word or a trailing " (high)".
var severityWordsRE = regexp.MustCompile(`(?i)\s*\((critical|high|medium|low|info)\)\s*$|\b(critical|high|medium|low|info)\s+(?:(exposure|finding)s?)\b`)

// stripSeverityWords removes the severity from a producer title so the
// card shows it once.
func stripSeverityWords(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return ""
	}
	out := severityWordsRE.ReplaceAllStringFunc(title, func(m string) string {
		sub := severityWordsRE.FindStringSubmatch(m)
		if sub[3] != "" {
			return sub[3]
		}
		return ""
	})
	return strings.TrimSpace(out)
}

// uuidRE matches an internal identifier. Visible text never carries one:
// the action link is the only place an object is referenced.
var uuidRE = regexp.MustCompile(`(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b`)

func stripIDs(s string) string {
	if !uuidRE.MatchString(s) {
		return s
	}
	return strings.Join(strings.Fields(uuidRE.ReplaceAllString(s, "")), " ")
}

func capDescription(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	return safetext.Truncate(safetext.Clean(s), maxDescriptionRunes)
}

// assetHeadline counts what a discovery found, and says so when the
// addresses are a provider's shared edge rather than the organization's.
func assetHeadline(loc string, f *Facts) string {
	n := max(f.Count, 1)
	switch {
	case f.SharedCount > 0 && f.SharedCount >= n:
		return T(loc, "event.new_asset.shared", fmt.Sprintf("%d", n))
	case n > 1:
		return T(loc, "event.new_asset.many", fmt.Sprintf("%d", n))
	default:
		return T(loc, "event.new_asset")
	}
}

func assetCard(c Card, f *Facts) Card {
	loc := c.Locale
	n := max(f.Count, 1)
	if n == 1 && len(f.Items) <= 1 {
		c.Subject = Subject{Name: f.AssetName, Type: f.AssetType}
		if len(f.Items) == 1 {
			c.What = f.Items[0]
		}
	} else {
		items := f.Items
		if len(items) > MaxItems {
			items = items[:MaxItems]
		}
		c.Items = items
		c.More = max(n-len(items), 0)
	}
	provider := f.SharedProvider
	if provider == "" {
		provider = T(loc, "provider.unknown")
	}
	switch {
	case f.SharedCount >= n:
		c.Why = T(loc, "why.asset.shared", provider)
		c.NextStep = T(loc, "next.asset.shared")
	case f.SharedCount > 0:
		c.Why = T(loc, "why.asset.some_shared", fmt.Sprintf("%d", f.SharedCount), provider)
		c.NextStep = T(loc, "next.asset")
	default:
		c.Why = T(loc, "why.asset")
		c.NextStep = T(loc, "next.asset")
	}
	return c
}
