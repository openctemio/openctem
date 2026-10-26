package assetgroup

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"

	"golang.org/x/net/idna"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A group rule decides which assets belong to a group by themselves. It is
// stored as a versioned JSON document: the filter is the assets list filter
// (the same parameter names, so what a person sees on the Assets page can be
// saved as a group), plus domain conditions with subdomains, the scope
// entries that cover an asset, and the option to bring along the services,
// URLs and certificates of the hosts it matches.

// RuleVersion is the stored rule document version.
const RuleVersion = 1

// Limits of a rule and of the lists a group takes in.
const (
	// DefaultMemberCap is the most members a rule-filled group may hold.
	DefaultMemberCap = 50000
	// MaxPasteLines is the most lines one pasted list may have.
	MaxPasteLines = 10000
	// MaxPasteCreate is the most missing assets one paste creates.
	MaxPasteCreate = 1000
	// MaxRuleDomains is the most domain conditions of a rule.
	MaxRuleDomains = 20
	// MaxRuleCoveredBy is the most scope entries a rule names.
	MaxRuleCoveredBy = 20
	// MaxRuleBytes bounds a stored rule document.
	MaxRuleBytes = 64 * 1024
	// PreviewSampleSize is how many matches a preview lists.
	PreviewSampleSize = 20
)

// Member sources.
const (
	SourceRule   = "rule"
	SourceManual = "manual"
	SourcePaste  = "paste"
)

// ValidSource reports whether s is a member source.
func ValidSource(s string) bool {
	return s == SourceRule || s == SourceManual || s == SourcePaste
}

// Rule evaluation states.
const (
	RuleStatusIdle    = "idle"
	RuleStatusOK      = "ok"
	RuleStatusPaused  = "paused"   // the editor lost access: membership is frozen
	RuleStatusOverCap = "over_cap" // the rule matches more than the cap: membership is frozen
)

// DomainCondition keeps the assets named after a domain: the name itself,
// and with Subdomains every name below it (label boundary: pti.com.vn never
// matches evilpti.com.vn).
type DomainCondition struct {
	Name       string `json:"name"`
	Subdomains bool   `json:"subdomains"`
}

// RuleFilter is the assets list filter a rule applies. Every field is
// optional; the names are the Assets list query parameters.
type RuleFilter struct {
	Name                 string   `json:"name,omitempty"`
	Types                []string `json:"types,omitempty"`
	Lenses               []string `json:"lenses,omitempty"`
	Criticalities        []string `json:"criticalities,omitempty"`
	Statuses             []string `json:"statuses,omitempty"`
	Scopes               []string `json:"scopes,omitempty"`
	Exposures            []string `json:"exposures,omitempty"`
	Tags                 []string `json:"tags,omitempty"`
	TagsMode             string   `json:"tags_mode,omitempty"`
	ExcludeTags          []string `json:"exclude_tags,omitempty"`
	Search               string   `json:"search,omitempty"`
	MinRiskScore         *int     `json:"min_risk_score,omitempty"`
	MaxRiskScore         *int     `json:"max_risk_score,omitempty"`
	HasFindings          *bool    `json:"has_findings,omitempty"`
	IsCrownJewel         *bool    `json:"is_crown_jewel,omitempty"`
	SubType              string   `json:"sub_type,omitempty"`
	BusinessUnitIDs      []string `json:"business_unit_ids,omitempty"`
	OwnerIDs             []string `json:"owner_ids,omitempty"`
	InCIDR               []string `json:"in_cidr,omitempty"`
	HasOwner             *bool    `json:"has_owner,omitempty"`
	DataClassifications  []string `json:"data_classifications,omitempty"`
	IsControlPlane       *bool    `json:"is_control_plane,omitempty"`
	InternetFacing       *bool    `json:"internet_facing,omitempty"`
	Environments         []string `json:"environments,omitempty"`
	Providers            []string `json:"providers,omitempty"`
	Attribution          []string `json:"attribution,omitempty"`
	ScopeStatus          []string `json:"scope_status,omitempty"`
	Technology           []string `json:"technology,omitempty"`
	TechnologyCategories []string `json:"technology_category,omitempty"`
	Freshness            string   `json:"freshness,omitempty"`
	Coverage             string   `json:"coverage,omitempty"`
}

// Rule is the stored rule document of a group.
type Rule struct {
	Version int        `json:"v"`
	Filter  RuleFilter `json:"filter"`
	// Domains keep the assets under any of these domains (OR between them,
	// AND with the rest of the rule).
	Domains []DomainCondition `json:"domains,omitempty"`
	// CoveredBy keeps the assets a scope entry confirmed (any of them).
	CoveredBy []string `json:"covered_by,omitempty"`
	// IncludeRelated brings the services, URLs and certificates of the
	// matched hosts, within the editor's data scope.
	IncludeRelated bool `json:"include_related,omitempty"`
}

// ErrInvalidRule is wrapped by every rule validation error.
var ErrInvalidRule = fmt.Errorf("%w: invalid group rule", shared.ErrValidation)

func ruleErr(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalidRule, fmt.Sprintf(format, a...))
}

// ParseRule reads a rule document, normalises it and checks it. Unknown
// fields, a version other than RuleVersion and a rule with no condition are
// refused.
func ParseRule(raw []byte) (*Rule, error) {
	if len(raw) > MaxRuleBytes {
		return nil, ruleErr("the rule is too large")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r Rule
	if err := dec.Decode(&r); err != nil {
		return nil, ruleErr("the rule is not valid: %s", jsonErrText(err))
	}
	if dec.More() {
		return nil, ruleErr("the rule has trailing data")
	}
	if err := r.Normalize(); err != nil {
		return nil, err
	}
	return &r, nil
}

func jsonErrText(err error) string {
	var ute *json.UnmarshalTypeError
	if errors.As(err, &ute) {
		return "field " + ute.Field + " has the wrong type"
	}
	msg := err.Error()
	if strings.HasPrefix(msg, "json: unknown field") {
		return strings.TrimPrefix(msg, "json: ")
	}
	return "malformed JSON"
}

// JSON is the stored form of the rule.
func (r *Rule) JSON() ([]byte, error) { return json.Marshal(r) }

// Normalize checks the rule and rewrites its domains to their canonical form.
func (r *Rule) Normalize() error {
	if r.Version == 0 {
		r.Version = RuleVersion
	}
	if r.Version != RuleVersion {
		return ruleErr("unsupported rule version %d", r.Version)
	}
	if len(r.Domains) > MaxRuleDomains {
		return ruleErr("at most %d domains", MaxRuleDomains)
	}
	seen := map[string]int{}
	doms := make([]DomainCondition, 0, len(r.Domains))
	for _, d := range r.Domains {
		name, wildcard, err := NormalizeDomain(d.Name)
		if err != nil {
			return err
		}
		sub := d.Subdomains || wildcard
		if i, ok := seen[name]; ok {
			doms[i].Subdomains = doms[i].Subdomains || sub
			continue
		}
		seen[name] = len(doms)
		doms = append(doms, DomainCondition{Name: name, Subdomains: sub})
	}
	r.Domains = doms
	if len(r.CoveredBy) > MaxRuleCoveredBy {
		return ruleErr("at most %d scope entries", MaxRuleCoveredBy)
	}
	for i, id := range r.CoveredBy {
		parsed, err := shared.IDFromString(strings.TrimSpace(id))
		if err != nil || parsed.IsZero() {
			return ruleErr("covered_by must list scope entry ids")
		}
		r.CoveredBy[i] = parsed.String()
	}
	for _, c := range r.Filter.InCIDR {
		if _, err := netip.ParsePrefix(strings.TrimSpace(c)); err != nil {
			return ruleErr("in_cidr %q is not a CIDR range", shortText(c))
		}
	}
	if len(r.Filter.InCIDR) > 10 {
		return ruleErr("at most 10 CIDR ranges")
	}
	if r.Filter.TagsMode != "" && r.Filter.TagsMode != "any" && r.Filter.TagsMode != "all" {
		return ruleErr("tags_mode must be any or all")
	}
	if r.Empty() {
		return ruleErr("a rule needs at least one condition")
	}
	return nil
}

// Empty reports whether the rule has no condition (it would match every
// asset). Every filter field is omitted from its JSON when unset, so an empty
// filter encodes as {}.
func (r *Rule) Empty() bool {
	if len(r.Domains) > 0 || len(r.CoveredBy) > 0 {
		return false
	}
	b, err := json.Marshal(r.Filter)
	return err == nil && string(b) == "{}"
}

func shortText(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 40 {
		s = s[:40]
	}
	return s
}

var domainIDNA = idna.New(idna.MapForLookup(), idna.Transitional(false), idna.StrictDomainName(false))

// NormalizeDomain returns the canonical form of a domain condition: trimmed,
// lowercased, no trailing dot, IDNA ASCII (punycode) form. A leading "*."
// (a wildcard) is accepted and reported: the wildcard means the domain and
// every name below it. A URL, port, path, address or any other wildcard is
// refused, so the value can only be a DNS name.
func NormalizeDomain(s string) (name string, wildcard bool, err error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if strings.HasPrefix(s, "*.") {
		wildcard, s = true, s[2:]
	}
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253*4 {
		return "", false, ruleErr("a domain is empty or too long")
	}
	if strings.ContainsAny(s, "*/?#@:\\[]% \t\r\n\x00,;\"'<>") {
		return "", false, ruleErr("%q is not a domain name", shortText(s))
	}
	if _, perr := netip.ParseAddr(s); perr == nil {
		return "", false, ruleErr("%q is an address, not a domain name", shortText(s))
	}
	ascii, ierr := domainIDNA.ToASCII(s)
	if ierr != nil || ascii == "" {
		return "", false, ruleErr("%q is not a domain name", shortText(s))
	}
	ascii = strings.ToLower(ascii)
	if len(ascii) > 253 {
		return "", false, ruleErr("%q is too long for a domain name", shortText(s))
	}
	labels := strings.Split(ascii, ".")
	if len(labels) < 2 {
		return "", false, ruleErr("%q needs at least two labels", shortText(s))
	}
	for _, l := range labels {
		if !validDomainLabel(l) {
			return "", false, ruleErr("%q is not a domain name", shortText(s))
		}
	}
	return ascii, wildcard, nil
}

func validDomainLabel(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// DomainMatches reports whether name is the domain, or with subdomains a
// name below it, on a label boundary. Both are compared in their normalised
// form; it is the reference the SQL predicate is tested against.
func DomainMatches(c DomainCondition, name string) bool {
	n, _, err := NormalizeDomain(name)
	if err != nil {
		return false
	}
	if n == c.Name {
		return true
	}
	return c.Subdomains && strings.HasSuffix(n, "."+c.Name)
}
