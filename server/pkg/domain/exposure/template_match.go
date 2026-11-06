package exposure

// Info-severity matches of template scanners as exposures
// (docs/architecture/exposure-taxonomy.md, "Template scanner info matches").
//
// A template scanner (nuclei) reports an info match for what a host shows
// rather than what is wrong with it: the technology it runs, a login panel,
// its TLS and header posture, a WAF in front of it. Filed as findings they
// bury the vulnerabilities; dropped, a scan of a well-kept host reports
// nothing. They are exposures of the asset instead: one event per template,
// matcher and URL, re-seen on every scan that matches again.
//
// Every value comes from a sensor report and is untrusted: values are
// trimmed, single-line and capped, and the URL keeps only scheme, host,
// port and path (a query string can carry a token).

import (
	"net/url"
	"slices"
	"strings"
	"unicode"

	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// SourceTemplateScan is the exposure source of template scanner info
// matches.
const SourceTemplateScan = "template_scan"

// Bounds of the values a template match carries into an event.
const (
	maxTemplateTitle   = 200
	maxTemplateValue   = 128
	maxTemplateURL     = 2048
	maxTemplateTags    = 20
	maxTemplateMatcher = 128
)

// TemplateMatch is one info-severity match of a template scanner, already
// bound to the asset it was reported on.
type TemplateMatch struct {
	AssetID shared.ID
	// Tool is the scanner that reported it (nuclei).
	Tool string
	// RuleID is the template id, Title its name.
	RuleID string
	Title  string
	// Matcher is the template's matcher that fired ("" for a template with
	// one matcher): a header template fires once per missing header.
	Matcher string
	// URL is where it matched.
	URL  string
	Tags []string
	// StepRunID is the scan step run that reported it (nil outside a
	// scan); recorded in the details, not part of the identity.
	StepRunID *shared.ID
}

// TemplateMatchType is the event type of a match, from its template's tags
// and id: panels are exposed web interfaces, ssl/tls templates TLS issues,
// header templates missing headers, spf/dmarc templates weak email
// security, misconfig/exposure templates misconfigurations; anything else
// (technology, WAF detection) is custom.
func TemplateMatchType(ruleID string, tags []string) EventType {
	has := func(names ...string) bool {
		for _, t := range tags {
			if slices.Contains(names, strings.ToLower(strings.TrimSpace(t))) {
				return true
			}
		}
		return false
	}
	id := strings.ToLower(ruleID)
	switch {
	case has("panel", "login"):
		return EventTypeWebInterfaceExposed
	case has("ssl", "tls"):
		return EventTypeSSLIssue
	case has("headers", "header") || strings.Contains(id, "security-headers"):
		return EventTypeHeaderMissing
	case has("spf", "dmarc", "dkim", "mail"):
		return EventTypeEmailSecurityWeak
	case has("misconfig", "exposure", "config"):
		return EventTypeMisconfiguration
	}
	return EventTypeCustom
}

// NewTemplateMatchEvent builds the info exposure event of match m.
func NewTemplateMatchEvent(tenantID shared.ID, m TemplateMatch) (*ExposureEvent, error) {
	title := cleanTemplateValue(m.Title, maxTemplateTitle)
	ruleID := cleanTemplateValue(m.RuleID, maxTemplateValue)
	if title == "" {
		title = ruleID
	}
	matcher := cleanTemplateValue(m.Matcher, maxTemplateMatcher)
	if matcher != "" {
		title += " (" + matcher + ")"
	}
	u := TemplateMatchURL(m.URL)
	var tags []string
	for _, t := range m.Tags {
		if t = cleanTemplateValue(t, maxTemplateValue); t != "" && !slices.Contains(tags, t) && len(tags) < maxTemplateTags {
			tags = append(tags, t)
		}
	}
	details := map[string]any{"rule_id": ruleID, "tool": cleanTemplateValue(m.Tool, maxTemplateValue)}
	if u != "" {
		details["url"] = u
		if pu, err := url.Parse(u); err == nil && pu.Hostname() != "" {
			details["domain"] = pu.Hostname()
		}
	}
	if matcher != "" {
		details["matcher"] = matcher
	}
	if len(tags) > 0 {
		details["tags"] = tags
	}
	t := TemplateMatchType(ruleID, tags)
	switch t {
	case EventTypeSSLIssue:
		details["issue"] = firstNonEmpty(matcher, ruleID)
	case EventTypeHeaderMissing:
		if matcher != "" {
			details["header"] = matcher
		}
	}
	if m.StepRunID != nil {
		details["scan_run_step_id"] = m.StepRunID.String()
	}
	ev, err := NewExposureEvent(tenantID, t, SeverityInfo, title, SourceTemplateScan, details)
	if err != nil {
		return nil, err
	}
	aid := m.AssetID
	ev.SetAssetID(&aid)
	return ev, nil
}

// TemplateMatchURL is u without user info, query or fragment ("" when it
// is not an absolute http(s) URL).
func TemplateMatchURL(u string) string {
	pu, err := url.Parse(strings.TrimSpace(u))
	if err != nil || (pu.Scheme != "http" && pu.Scheme != "https") || pu.Host == "" {
		return ""
	}
	pu.User, pu.RawQuery, pu.ForceQuery, pu.Fragment, pu.RawFragment = nil, "", false, "", ""
	s := pu.String()
	if len(s) > maxTemplateURL {
		return ""
	}
	return s
}

// cleanTemplateValue is v on one line, without control characters, capped
// at limit bytes on a rune boundary.
func cleanTemplateValue(v string, limit int) string {
	v = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, v)
	v = strings.Join(strings.Fields(v), " ")
	if len(v) <= limit {
		return v
	}
	cut := limit
	for cut > 0 && !utf8RuneStart(v[cut]) {
		cut--
	}
	return v[:cut]
}

func utf8RuneStart(b byte) bool { return b&0xC0 != 0x80 }

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
