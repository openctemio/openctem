package sensor

// Scanner content (docs/rfcs/RFC-031-managed-sensor-updates.md): the data a
// tool scans with apart from its binary (trivy's vulnerability database, the
// nuclei templates, the semgrep rules). A sensor reports on its heartbeat what
// it has, per tool (tools[].content); the tenant's content policy says how old
// content may get and which versions are pinned; the platform shows staleness
// as a health reason and can ask a sensor to refresh (the refresh_content
// command).
//
// The policy never names a content SOURCE (registry, mirror, URL, directory):
// sources are the sensor host's configuration, so a compromised platform
// cannot point a fleet at other content.

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Content names the platform knows.
const (
	ContentTrivyDB         = "trivy-db"
	ContentTrivyJavaDB     = "trivy-java-db"
	ContentNucleiTemplates = "nuclei-templates"
	ContentSemgrepRules    = "semgrep-rules"
)

// KnownContentNames lists the content names a policy may configure, in display
// order.
func KnownContentNames() []string {
	return []string{ContentTrivyDB, ContentTrivyJavaDB, ContentNucleiTemplates, ContentSemgrepRules}
}

// IsKnownContentName reports whether name is a content name the platform knows.
func IsKnownContentName(name string) bool {
	return slices.Contains(KnownContentNames(), name)
}

// contentLabel is the human name used in health messages.
func contentLabel(name string) (label string, plural bool) {
	switch name {
	case ContentTrivyDB:
		return "trivy DB", false
	case ContentTrivyJavaDB:
		return "trivy Java DB", false
	case ContentNucleiTemplates:
		return "nuclei templates", true
	case ContentSemgrepRules:
		return "semgrep rules", true
	default:
		return name, false
	}
}

// Limits on reported content: it comes from an untrusted sensor process.
const (
	MaxReportedContentPerTool = 8
	MaxReportedContent        = 64
	maxContentNameLen         = 64
	maxContentVersionLen      = 128
	maxContentSourceLen       = 256
	maxContentErrorLen        = 256
	maxContentToolLen         = 50
)

var (
	contentNameRE   = regexp.MustCompile(`^[a-z0-9-]{1,64}$`)
	contentDigestRE = regexp.MustCompile(`^sha256:[0-9a-f]{1,64}$`)
)

// ReportedContent is one piece of scanner content a sensor reported, for one
// of its tools. Display and health data only; dispatch never reads it.
type ReportedContent struct {
	// Tool is the tool the content belongs to ("trivy", "nuclei"). Empty
	// while stored inside its ReportedTool; set by Sensor.ReportedContent.
	Tool      string     `json:"tool,omitempty"`
	Name      string     `json:"name"`
	Version   string     `json:"version,omitempty"`
	UpdatedAt *time.Time `json:"updated_at,omitempty"`
	FetchedAt *time.Time `json:"fetched_at,omitempty"`
	// CheckedAt is when the sensor last confirmed with its source that this
	// is still the newest (or pinned) version: old content is not stale
	// while it keeps being confirmed (sdk-go ContentInfo.Stale).
	CheckedAt *time.Time `json:"checked_at,omitempty"`
	Source    string     `json:"source,omitempty"`
	Digest    string     `json:"digest,omitempty"`
	// Managed is true when the sensor controls the content (it refreshes,
	// verifies and swaps it); false when the tool fetches it by itself.
	Managed bool `json:"managed"`
	// Error is the last refresh failure (the sensor keeps the old version).
	Error string `json:"error,omitempty"`
}

// sanitizeToolContent sanitizes one tool's reported content (the tool's name
// is already sanitized) for storage inside its ReportedTool: Tool is left
// empty. nil stays nil.
func sanitizeToolContent(tool string, items []ReportedContent, now time.Time) []ReportedContent {
	if items == nil {
		return nil
	}
	for i := range items {
		items[i].Tool = tool
	}
	out := SanitizeReportedContent(items, now)
	for i := range out {
		out[i].Tool = ""
	}
	return out
}

// SanitizeReportedContent returns the content worth keeping from a heartbeat:
// valid names only, bounded strings, a digest only when well-formed,
// timestamps no later than a day after now, at most MaxReportedContentPerTool
// per tool and MaxReportedContent overall. It never returns nil for a non-nil
// input, so "reported, none" stays distinct from "not reported".
func SanitizeReportedContent(items []ReportedContent, now time.Time) []ReportedContent {
	if items == nil {
		return nil
	}
	out := make([]ReportedContent, 0, min(len(items), MaxReportedContent))
	perTool := map[string]int{}
	seen := map[string]bool{}
	for _, c := range items {
		if len(out) >= MaxReportedContent {
			break
		}
		tool := cleanText(c.Tool, maxContentToolLen)
		if tool == "" || !contentNameRE.MatchString(c.Name) {
			continue
		}
		key := tool + "\x00" + c.Name
		if seen[key] || perTool[tool] >= MaxReportedContentPerTool {
			continue
		}
		seen[key] = true
		perTool[tool]++
		c.Tool = tool
		c.Version = cleanText(c.Version, maxContentVersionLen)
		c.Source = cleanText(c.Source, maxContentSourceLen)
		c.Error = cleanText(c.Error, maxContentErrorLen)
		if !contentDigestRE.MatchString(c.Digest) {
			c.Digest = ""
		}
		c.UpdatedAt = saneTime(c.UpdatedAt, now)
		c.FetchedAt = saneTime(c.FetchedAt, now)
		c.CheckedAt = saneTime(c.CheckedAt, now)
		out = append(out, c)
	}
	return out
}

// cleanText drops control characters and cuts s to max bytes on a rune
// boundary.
func cleanText(s string, maxLen int) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	s = strings.TrimSpace(s)
	if len(s) <= maxLen {
		return s
	}
	cut := maxLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// saneTime drops a timestamp later than a day after now (a wrong clock or a
// lie) and normalizes it to UTC.
func saneTime(t *time.Time, now time.Time) *time.Time {
	if t == nil || t.IsZero() || t.After(now.Add(24*time.Hour)) {
		return nil
	}
	u := t.UTC()
	return &u
}

// Age returns how old the content is at now (from UpdatedAt, else FetchedAt).
func (c ReportedContent) Age(now time.Time) (time.Duration, bool) {
	switch {
	case c.UpdatedAt != nil:
		return max(now.Sub(*c.UpdatedAt), 0), true
	case c.FetchedAt != nil:
		return max(now.Sub(*c.FetchedAt), 0), true
	default:
		return 0, false
	}
}

// ReportedContent is the scanner content of every reported tool, flattened,
// with Tool set. nil when the sensor reported none.
func (a *Sensor) ReportedContent() []ReportedContent {
	var out []ReportedContent
	for _, t := range a.Reported.Tools {
		for _, c := range t.Content {
			c.Tool = t.Name
			out = append(out, c)
		}
	}
	return out
}

// SupportsContentRefresh reports whether the sensor accepts refresh_content
// commands: it reports at least one piece of content it manages.
func (a *Sensor) SupportsContentRefresh() bool {
	for _, c := range a.ReportedContent() {
		if c.Managed {
			return true
		}
	}
	return false
}

// ContentView is one reported content item judged against the tenant policy.
type ContentView struct {
	ReportedContent
	// AgeSeconds is nil when the age is unknown.
	AgeSeconds *int64
	// MaxAgeHours is the policy limit (0: no limit).
	MaxAgeHours int
	// Stale: managed content older than the limit that the sensor has not
	// confirmed as the newest version within the limit either.
	Stale bool
	// Unconfirmed is how long ago the sensor last confirmed the content
	// (nil: never), for the health message.
	Unconfirmed *time.Duration
	// PinnedVersion is the version the policy pins ("" when none).
	PinnedVersion string
	// PinMismatch: a version is pinned and the sensor reports another.
	PinMismatch bool
}

// ContentViews judges every reported content item against the policy at now.
// Never nil.
func (a *Sensor) ContentViews(now time.Time, policy ContentPolicy) []ContentView {
	content := a.ReportedContent()
	out := make([]ContentView, 0, len(content))
	for _, c := range content {
		out = append(out, viewContent(c, now, policy))
	}
	return out
}

func viewContent(c ReportedContent, now time.Time, policy ContentPolicy) ContentView {
	pin := policy.Pin(c.Name)
	v := ContentView{ReportedContent: c, MaxAgeHours: pin.MaxAgeHours, PinnedVersion: pin.Version}
	maxAge := time.Duration(pin.MaxAgeHours) * time.Hour
	if c.CheckedAt != nil {
		d := max(now.Sub(*c.CheckedAt), 0)
		v.Unconfirmed = &d
	}
	if age, ok := c.Age(now); ok {
		secs := int64(age / time.Second)
		v.AgeSeconds = &secs
		// The same rule as sdk-go ContentInfo.Stale: older than the limit
		// AND not confirmed current within it. The newest release of a
		// template set may itself be older than the limit.
		if c.Managed && pin.MaxAgeHours > 0 && age > maxAge &&
			(v.Unconfirmed == nil || *v.Unconfirmed > maxAge) {
			v.Stale = true
		}
	} else if c.Managed && pin.MaxAgeHours > 0 && c.Version == "" {
		// Managed content the sensor has no version of yet is as stale as it
		// gets (its first fetch failed).
		v.Stale = true
	}
	if pin.Version != "" && c.Managed {
		v.PinMismatch = pin.Version != c.Version && pin.Version != c.Digest
	}
	return v
}

// ContentPolicy is a tenant's scanner content policy (the policy member of a
// refresh_content command). See the package comment: it has no sources.
type ContentPolicy struct {
	// RefreshIntervalHours is how often sensors check for new content.
	RefreshIntervalHours int `json:"refresh_interval_hours,omitempty"`
	// Content is the per-content policy, keyed by content name.
	Content map[string]ContentPin `json:"content,omitempty"`
}

// ContentPin is the policy for one kind of content.
type ContentPin struct {
	MaxAgeHours int      `json:"max_age_hours,omitempty"`
	Version     string   `json:"version,omitempty"`
	Rulesets    []string `json:"rulesets,omitempty"`
}

// Policy limits (the same as the SDK's refresh_content decoder).
const (
	MaxContentPolicyHours  = 24 * 365
	maxContentRulesets     = 32
	maxContentRulesetLen   = 128
	maxPolicyVersionLength = 128
)

var rulesetRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_./:@-]*$`)

// DefaultContentPolicy is the platform default: what applies to a tenant that
// has not set a policy, and fills what a tenant's policy leaves unset.
func DefaultContentPolicy() ContentPolicy {
	return ContentPolicy{
		RefreshIntervalHours: 6,
		Content: map[string]ContentPin{
			ContentTrivyDB:         {MaxAgeHours: 48},
			ContentTrivyJavaDB:     {MaxAgeHours: 168},
			ContentNucleiTemplates: {MaxAgeHours: 336},
			ContentSemgrepRules:    {MaxAgeHours: 168},
		},
	}
}

// Pin returns the policy for one content name (zero value when none).
func (p ContentPolicy) Pin(name string) ContentPin {
	return p.Content[name]
}

// Validate checks a policy a tenant administrator submitted.
func (p ContentPolicy) Validate() error {
	if p.RefreshIntervalHours < 0 || p.RefreshIntervalHours > MaxContentPolicyHours {
		return fmt.Errorf("refresh_interval_hours must be between 0 and %d", MaxContentPolicyHours)
	}
	for name, pin := range p.Content {
		if !IsKnownContentName(name) {
			return fmt.Errorf("unknown content %q (known: %s)", name, strings.Join(KnownContentNames(), ", "))
		}
		if pin.MaxAgeHours < 0 || pin.MaxAgeHours > MaxContentPolicyHours {
			return fmt.Errorf("%s: max_age_hours must be between 0 and %d", name, MaxContentPolicyHours)
		}
		if len(pin.Version) > maxPolicyVersionLength || !versionToken(pin.Version) {
			return fmt.Errorf("%s: version must be a single token of at most %d characters, not starting with '-'", name, maxPolicyVersionLength)
		}
		if len(pin.Rulesets) > 0 && name != ContentSemgrepRules {
			return fmt.Errorf("%s: rulesets apply to %s only", name, ContentSemgrepRules)
		}
		if len(pin.Rulesets) > maxContentRulesets {
			return fmt.Errorf("%s: at most %d rulesets", name, maxContentRulesets)
		}
		for _, rs := range pin.Rulesets {
			if len(rs) > maxContentRulesetLen || !rulesetRE.MatchString(rs) {
				return fmt.Errorf("%s: invalid ruleset %q", name, rs)
			}
		}
	}
	return nil
}

func versionToken(s string) bool {
	if strings.HasPrefix(s, "-") {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f {
			return false
		}
	}
	return true
}

// WithDefaults returns the policy with unset values taken from defaults:
// the refresh interval when 0, and per content the max age when 0. A pinned
// version or rulesets are never invented.
func (p ContentPolicy) WithDefaults(defaults ContentPolicy) ContentPolicy {
	out := ContentPolicy{RefreshIntervalHours: p.RefreshIntervalHours, Content: map[string]ContentPin{}}
	if out.RefreshIntervalHours == 0 {
		out.RefreshIntervalHours = defaults.RefreshIntervalHours
	}
	for _, name := range KnownContentNames() {
		pin, ok := p.Content[name]
		def := defaults.Content[name]
		if !ok {
			pin = ContentPin{MaxAgeHours: def.MaxAgeHours}
		} else if pin.MaxAgeHours == 0 {
			pin.MaxAgeHours = def.MaxAgeHours
		}
		if len(pin.Rulesets) > 0 {
			pin.Rulesets = slices.Clone(pin.Rulesets)
		}
		out.Content[name] = pin
	}
	return out
}
