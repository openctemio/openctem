package asset

// The organization's rule for which source decides an attribute
// (docs/rfcs/RFC-069-asset-attribute-reconciliation.md §12).
//
// Attributes are grouped in classes. Each class has a ranked list of source
// rules, or inherits the organization's default list. A rule names a source
// kind ("scan") or one source of a kind ("scan:nmap"); an observation takes
// the position of the rule naming its source, else of the rule naming its
// kind. A rule that is not trusted, or a source with no rule, does not
// decide the class. A person's lock always wins and is not listed.

import (
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// AttributeClass groups attributes that share a source ranking.
type AttributeClass string

const (
	AttrClassIdentity  AttributeClass = "identity"   // hostname, IP addresses
	AttrClassNetwork   AttributeClass = "network"    // services, ports, exposure
	AttrClassSoftware  AttributeClass = "software"   // installed software
	AttrClassOwnership AttributeClass = "ownership"  // owner, criticality, classification
	AttrClassCloudTags AttributeClass = "cloud_tags" // cloud provider tags
	AttrClassLifecycle AttributeClass = "lifecycle"  // exists / decommissioned
)

// AllAttributeClasses lists the classes in display order.
func AllAttributeClasses() []AttributeClass {
	return []AttributeClass{AttrClassIdentity, AttrClassNetwork, AttrClassSoftware, AttrClassOwnership, AttrClassCloudTags, AttrClassLifecycle}
}

// IsValid reports whether c is a known class.
func (c AttributeClass) IsValid() bool {
	for _, k := range AllAttributeClasses() {
		if k == c {
			return true
		}
	}
	return false
}

// AttributeClassOf is the class of a reconciled attribute.
func AttributeClassOf(attr TrackedAttribute) AttributeClass {
	if attr == AttrExposure {
		return AttrClassNetwork
	}
	return AttrClassOwnership
}

// Attributes are the reconciled attributes of class c (none yet for some).
func (c AttributeClass) Attributes() []TrackedAttribute {
	var out []TrackedAttribute
	for _, a := range AllTrackedAttributes() {
		if AttributeClassOf(a) == c {
			out = append(out, a)
		}
	}
	return out
}

// SourceRef names a kind ("scan") or one source of a kind ("scan:nmap").
type SourceRef string

// ParseSourceRef validates r and returns its kind and source name ("" for
// the whole kind). Manual is never listed: a lock always wins.
func ParseSourceRef(r string) (SourceKind, string, error) {
	kind, name, _ := strings.Cut(strings.TrimSpace(r), ":")
	k := SourceKind(kind)
	if !k.IsValid() || k == SourceKindManual {
		return "", "", fmt.Errorf("%w: source %q is not one of integration, import, scan, feed (optionally kind:name)", shared.ErrValidation, r)
	}
	name = strings.TrimSpace(name)
	if len(name) > MaxSourceNameLength {
		return "", "", fmt.Errorf("%w: source name longer than %d characters", shared.ErrValidation, MaxSourceNameLength)
	}
	return k, name, nil
}

// SourceRule is one row of a ranked list.
type SourceRule struct {
	Source SourceRef
	// TTL: how long the source's value counts after it saw it; 0 = never stale.
	TTL time.Duration
	// Trusted: the source may decide the class. An untrusted row keeps its
	// place in the list but is ignored.
	Trusted bool
}

func (r SourceRule) kindName() (SourceKind, string) {
	k, n, _ := strings.Cut(string(r.Source), ":")
	return SourceKind(k), n
}

// ReconciliationPolicy is the organization's rule for picking a value.
type ReconciliationPolicy struct {
	// Default is the list every class without its own uses.
	Default []SourceRule
	// Classes are the classes with their own list.
	Classes map[AttributeClass][]SourceRule
}

const (
	policyDay = 24 * time.Hour
	// MaxSourceTTLDays bounds a configured TTL.
	MaxSourceTTLDays = 3650
	// MaxSourceRules bounds one list.
	MaxSourceRules = 50
)

// DefaultSourceTTL is the TTL of a kind in the defaults.
func DefaultSourceTTL(k SourceKind) time.Duration {
	if k == SourceKindImport {
		return 90 * policyDay
	}
	return 30 * policyDay
}

func rule(k SourceKind, trusted bool) SourceRule {
	return SourceRule{Source: SourceRef(k), TTL: DefaultSourceTTL(k), Trusted: trusted}
}

// DefaultReconciliationPolicy is the policy of an organization that set
// none: connectors, then active scans, then imports, then feeds; for
// ownership and business context only connectors and imports (scanners
// and feeds are not trusted, D1); for network exposure an active scan that
// reached the asset first.
func DefaultReconciliationPolicy() ReconciliationPolicy {
	return ReconciliationPolicy{
		Default: []SourceRule{
			rule(SourceKindIntegration, true), rule(SourceKindScan, true),
			rule(SourceKindImport, true), rule(SourceKindFeed, true),
		},
		Classes: map[AttributeClass][]SourceRule{
			AttrClassOwnership: {
				rule(SourceKindIntegration, true), rule(SourceKindImport, true),
				rule(SourceKindScan, false), rule(SourceKindFeed, false),
			},
			AttrClassNetwork: {
				rule(SourceKindScan, true), rule(SourceKindIntegration, true),
				rule(SourceKindImport, true), rule(SourceKindFeed, true),
			},
		},
	}
}

// RulesFor is the list class c uses.
func (p ReconciliationPolicy) RulesFor(c AttributeClass) []SourceRule {
	if rules, ok := p.Classes[c]; ok {
		return rules
	}
	return p.Default
}

// match is the index of the rule deciding o's source in class c: the rule
// naming its source, else the rule naming its kind; -1 for none.
func (p ReconciliationPolicy) match(c AttributeClass, kind SourceKind, name string) int {
	rules := p.RulesFor(c)
	kindRule := -1
	for i, r := range rules {
		k, n := r.kindName()
		if k != kind {
			continue
		}
		if n != "" && n == name {
			return i
		}
		if n == "" && kindRule < 0 {
			kindRule = i
		}
	}
	return kindRule
}

// rank is the position of o's source for attr (0 for a lock), or -1 when it
// is not trusted for it.
func (p ReconciliationPolicy) rank(attr TrackedAttribute, o AttributeObservation) int {
	if o.Kind == SourceKindManual {
		return 0
	}
	c := AttributeClassOf(attr)
	i := p.match(c, o.Kind, o.Name)
	if i < 0 || !p.RulesFor(c)[i].Trusted {
		return -1
	}
	return i + 1
}

// Trusts reports whether a source of kind named name may decide attr.
func (p ReconciliationPolicy) Trusts(attr TrackedAttribute, kind SourceKind, name string) bool {
	return p.rank(attr, AttributeObservation{Kind: kind, Name: name}) >= 0
}

// Stale reports whether o is past its source's TTL at now (a lock never is).
func (p ReconciliationPolicy) Stale(o AttributeObservation, now time.Time) bool {
	return p.stale(o, now)
}

func (p ReconciliationPolicy) stale(o AttributeObservation, now time.Time) bool {
	if o.IsLock() {
		return false
	}
	c := AttributeClassOf(o.Attribute)
	i := p.match(c, o.Kind, o.Name)
	if i < 0 {
		return false
	}
	ttl := p.RulesFor(c)[i].TTL
	return ttl > 0 && now.Sub(o.ObservedAt) > ttl
}

// SourceRuleSetting is one row as stored in the organization's settings.
type SourceRuleSetting struct {
	Source  string `json:"source"`
	TTLDays int    `json:"ttl_days"`
	Trusted bool   `json:"trusted"`
}

// PolicyFromSettings builds a policy from the stored lists: def is the
// default list (empty: the built-in defaults, classes included); classes
// are the classes with their own list. Unknown classes or sources, a
// source listed twice, a TTL out of range or a list too long is a
// validation error.
func PolicyFromSettings(def []SourceRuleSetting, classes map[string][]SourceRuleSetting) (ReconciliationPolicy, error) {
	if len(def) == 0 && len(classes) == 0 {
		return DefaultReconciliationPolicy(), nil
	}
	p := ReconciliationPolicy{Classes: map[AttributeClass][]SourceRule{}}
	if len(def) == 0 {
		p.Default = DefaultReconciliationPolicy().Default
	} else {
		rules, err := rulesFromSettings("default", def)
		if err != nil {
			return ReconciliationPolicy{}, err
		}
		p.Default = rules
	}
	for name, list := range classes {
		c := AttributeClass(name)
		if !c.IsValid() {
			return ReconciliationPolicy{}, fmt.Errorf("%w: unknown attribute class %q", shared.ErrValidation, name)
		}
		rules, err := rulesFromSettings(name, list)
		if err != nil {
			return ReconciliationPolicy{}, err
		}
		p.Classes[c] = rules
	}
	return p, nil
}

func rulesFromSettings(where string, list []SourceRuleSetting) ([]SourceRule, error) {
	if len(list) > MaxSourceRules {
		return nil, fmt.Errorf("%w: %s: at most %d sources", shared.ErrValidation, where, MaxSourceRules)
	}
	out := make([]SourceRule, 0, len(list))
	seen := map[SourceRef]bool{}
	for _, s := range list {
		k, n, err := ParseSourceRef(s.Source)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		ref := SourceRef(k)
		if n != "" {
			ref = SourceRef(string(k) + ":" + n)
		}
		if seen[ref] {
			return nil, fmt.Errorf("%w: %s: source %q listed twice", shared.ErrValidation, where, ref)
		}
		seen[ref] = true
		if s.TTLDays < 0 || s.TTLDays > MaxSourceTTLDays {
			return nil, fmt.Errorf("%w: %s: %s ttl must be 0-%d days", shared.ErrValidation, where, ref, MaxSourceTTLDays)
		}
		out = append(out, SourceRule{Source: ref, TTL: time.Duration(s.TTLDays) * policyDay, Trusted: s.Trusted})
	}
	return out, nil
}

// SettingsFromRules is the stored form of a list.
func SettingsFromRules(rules []SourceRule) []SourceRuleSetting {
	out := make([]SourceRuleSetting, 0, len(rules))
	for _, r := range rules {
		out = append(out, SourceRuleSetting{Source: string(r.Source), TTLDays: int(r.TTL / policyDay), Trusted: r.Trusted})
	}
	return out
}

// DemotesAuthoritative reports whether next demotes a connector
// (integration) source compared with prev in any class: it loses trust or
// its rule, or a source that ranked below it (or was not trusted) now
// ranks above it. Such a change needs a fresh second factor. A person's
// lock cannot be demoted (it is never listed).
func DemotesAuthoritative(prev, next ReconciliationPolicy) bool {
	for _, c := range AllAttributeClasses() {
		before, after := prev.RulesFor(c), next.RulesFor(c)
		for i, r := range before {
			if k, _ := r.kindName(); k != SourceKindIntegration || !r.Trusted {
				continue
			}
			j := indexOfRule(after, r.Source)
			if j < 0 || !after[j].Trusted {
				return true
			}
			above := map[SourceRef]bool{}
			for _, b := range before[:i] {
				if b.Trusted {
					above[b.Source] = true
				}
			}
			for _, a := range after[:j] {
				if a.Trusted && !above[a.Source] {
					return true
				}
			}
		}
	}
	return false
}

func indexOfRule(rules []SourceRule, ref SourceRef) int {
	for i, r := range rules {
		if r.Source == ref {
			return i
		}
	}
	return -1
}

// MaxSourceSummaries bounds the sources listed on the settings page.
const MaxSourceSummaries = 200

// SourceSummary is a source that reported attributes of the organization's
// assets.
type SourceSummary struct {
	Kind     SourceKind
	Name     string
	LastSeen time.Time
	Assets   int
}

// AttributeSnapshot is one asset's current tracked values and observations.
type AttributeSnapshot struct {
	AssetID      shared.ID
	Name         string
	Current      map[TrackedAttribute]string
	Observations []AttributeObservation
}

// PreviewChange is a value a policy would change.
type PreviewChange struct {
	AssetID   shared.ID
	AssetName string
	Attribute TrackedAttribute
	Current   string
	Next      string
	// NextSource decides the next value.
	NextSource AttributeObservation
	Conflict   bool
}

// PolicyPreview is what a policy would change on the organization's assets.
type PolicyPreview struct {
	ScannedAssets int
	Truncated     bool // more assets have sources than were scanned
	ChangedAssets int
	ChangedValues int
	Conflicts     int
	Samples       []PreviewChange
}

// MaxPreviewSamples bounds the changes a preview lists.
const MaxPreviewSamples = 25

// PreviewSnapshots adds to pv what p would change on snaps at now.
func PreviewSnapshots(pv *PolicyPreview, snaps []AttributeSnapshot, p ReconciliationPolicy, now time.Time) {
	for _, s := range snaps {
		pv.ScannedAssets++
		changed := false
		for _, attr := range AllTrackedAttributes() {
			cur := s.Current[attr]
			res := ResolveFrom(attr, s.Observations, p, now, cur)
			if res.Conflict {
				pv.Conflicts++
			}
			if res.Winner == nil || res.Winner.Value == cur {
				continue
			}
			changed = true
			pv.ChangedValues++
			if len(pv.Samples) < MaxPreviewSamples {
				pv.Samples = append(pv.Samples, PreviewChange{
					AssetID: s.AssetID, AssetName: s.Name, Attribute: attr, Current: cur,
					Next: res.Winner.Value, NextSource: *res.Winner, Conflict: res.Conflict,
				})
			}
		}
		if changed {
			pv.ChangedAssets++
		}
	}
}
