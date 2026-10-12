package asset

// Set-valued asset attributes reconciled per source: IP addresses,
// technologies and open ports.
// Design: docs/rfcs/RFC-069-asset-attribute-reconciliation.md (§13).
//
// Each source keeps its own record of every element it reported, with when
// it last saw it. Not seeing an element is not removing it: an element
// leaves a source's contribution only when the same source observes the
// same coverage again without it (a port scan of the same port range on the
// same host, a DNS resolution of the same name). A partial observation
// never removes what lies outside its coverage. The asset shows the union
// of the current elements of every trusted, fresh source.

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SetAttribute is a set-valued asset attribute reconciled per source.
type SetAttribute string

const (
	// SetAttrIPAddresses: the addresses a host name resolves to
	// (properties.ip_addresses). Class identity.
	SetAttrIPAddresses SetAttribute = "ip_addresses"
	// SetAttrTechnologies: the technologies detected on a host or web
	// application (properties.technologies). Class software.
	SetAttrTechnologies SetAttribute = "technologies"
	// SetAttrOpenPorts: the open ports of an IP address ("443/tcp"); the
	// resolved set is the address's active open_port assets. Class network.
	SetAttrOpenPorts SetAttribute = "open_ports"
)

// AllSetAttributes lists the set attributes.
func AllSetAttributes() []SetAttribute {
	return []SetAttribute{SetAttrIPAddresses, SetAttrTechnologies, SetAttrOpenPorts}
}

// IsValid reports whether a is a set attribute.
func (a SetAttribute) IsValid() bool {
	switch a {
	case SetAttrIPAddresses, SetAttrTechnologies, SetAttrOpenPorts:
		return true
	}
	return false
}

// Class is the attribute class whose source ranking decides which sources
// are trusted for a and their TTL.
func (a SetAttribute) Class() AttributeClass {
	switch a {
	case SetAttrIPAddresses:
		return AttrClassIdentity
	case SetAttrTechnologies:
		return AttrClassSoftware
	}
	return AttrClassNetwork
}

// Bounds on one observation and one element.
const (
	MaxSetElements      = 1000
	MaxSetElementLength = 200
	MaxSetCoverageKey   = 200
)

// NormalizeSetElement validates an element of a and returns it in stored
// form: a canonical IP address, a trimmed technology ("Name:version"), or
// "port/protocol" with protocol tcp or udp (default tcp).
func NormalizeSetElement(a SetAttribute, v string) (string, error) {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > MaxSetElementLength {
		return "", fmt.Errorf("%w: empty or too long %s element", shared.ErrValidation, a)
	}
	switch a {
	case SetAttrIPAddresses:
		ip := net.ParseIP(v)
		if ip == nil {
			return "", fmt.Errorf("%w: invalid IP address", shared.ErrValidation)
		}
		return ip.String(), nil
	case SetAttrTechnologies:
		return v, nil
	case SetAttrOpenPorts:
		port, proto, err := splitPortElement(v)
		if err != nil {
			return "", err
		}
		return strconv.Itoa(port) + "/" + proto, nil
	}
	return "", fmt.Errorf("%w: unknown set attribute %q", shared.ErrValidation, a)
}

func splitPortElement(v string) (int, string, error) {
	p, proto, ok := strings.Cut(strings.ToLower(strings.TrimSpace(v)), "/")
	if !ok || proto == "" {
		proto = string(ProtocolTCP)
	}
	if proto != string(ProtocolTCP) && proto != string(ProtocolUDP) {
		return 0, "", fmt.Errorf("%w: port protocol must be tcp or udp", shared.ErrValidation)
	}
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return 0, "", fmt.Errorf("%w: invalid port", shared.ErrValidation)
	}
	return port, proto, nil
}

// PortRange is an inclusive range of TCP ports a scan covered.
type PortRange struct{ Lo, Hi int }

// SetCoverage is what one observation looked at, and so which of the
// source's elements it may remove by not reporting them.
type SetCoverage struct {
	// Mode says how coverage is decided.
	Mode CoverageMode
	// Key names what was covered (CoverageKeyed and CoverageRanges): the
	// port setting of a scan, for instance. An element remembers the key of
	// the observation that last saw it.
	Key string
	// Ranges are the TCP ports a CoverageRanges observation scanned.
	Ranges []PortRange
}

// CoverageMode is how an observation's coverage is decided.
type CoverageMode string

const (
	// CoverageSightings: the observation removes nothing; its elements
	// leave the source's contribution only through the TTL. Sources that
	// report only part of a set each time (a web probe that reports the one
	// address it connected to) use it.
	CoverageSightings CoverageMode = "sightings"
	// CoverageFull: the observation is the source's whole set for the
	// asset (a DNS resolution of the name, a technology fingerprint of the
	// application).
	CoverageFull CoverageMode = "full"
	// CoverageKeyed: the observation covers the elements the same source
	// last saw under the same key (a "top 100 ports" scan removes only what
	// an earlier "top 100 ports" scan of the same source found).
	CoverageKeyed CoverageMode = "keyed"
	// CoverageRanges: the observation covers the TCP ports in Ranges, and
	// any element last seen under the same key.
	CoverageRanges CoverageMode = "ranges"
)

// Covers reports whether an observation of attribute a with coverage c
// covers element e, which the same source last saw under key.
func (c SetCoverage) Covers(a SetAttribute, e, key string) bool {
	switch c.Mode {
	case CoverageFull:
		return true
	case CoverageKeyed:
		return c.Key != "" && key == c.Key
	case CoverageRanges:
		if c.Key != "" && key == c.Key {
			return true
		}
		return a == SetAttrOpenPorts && c.inRanges(e)
	}
	return false
}

// CoversUnattributed reports whether c covers element e that no source
// has a record of (a value recorded before per-source tracking, or written
// by another path). Only coverage that names the element does: a whole set
// or a port range, never a key.
func (c SetCoverage) CoversUnattributed(a SetAttribute, e string) bool {
	switch c.Mode {
	case CoverageFull:
		return true
	case CoverageRanges:
		return a == SetAttrOpenPorts && c.inRanges(e)
	}
	return false
}

func (c SetCoverage) inRanges(e string) bool {
	port, proto, err := splitPortElement(e)
	if err != nil || proto != string(ProtocolTCP) {
		return false
	}
	for _, r := range c.Ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// PortScanCoverage is the coverage of a port scan from its port settings:
// ports ("80,443,8000-8100", "full", "top-100") and top_ports (100, 1000).
// An explicit list or "full" covers those ports; a top-N or default scan
// covers only what the same source found with the same setting.
func PortScanCoverage(ports, topPorts string) SetCoverage {
	p := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(ports), " ", ""))
	switch {
	case p == "full" || p == "-" || p == "1-65535":
		return SetCoverage{Mode: CoverageRanges, Key: "ports:full", Ranges: []PortRange{{1, 65535}}}
	case strings.HasPrefix(p, "top-"):
		return SetCoverage{Mode: CoverageKeyed, Key: "ports:" + p}
	case p != "":
		if ranges, ok := parsePortList(p); ok {
			key := "ports:" + p
			if len(key) > MaxSetCoverageKey {
				key = key[:MaxSetCoverageKey]
			}
			return SetCoverage{Mode: CoverageRanges, Key: key, Ranges: ranges}
		}
	}
	if t := strings.TrimSpace(topPorts); t != "" {
		return SetCoverage{Mode: CoverageKeyed, Key: "ports:top-" + t}
	}
	return SetCoverage{Mode: CoverageKeyed, Key: "ports:default"}
}

func parsePortList(p string) ([]PortRange, bool) {
	parts := strings.Split(p, ",")
	out := make([]PortRange, 0, len(parts))
	for _, part := range parts {
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(lo)
		if err != nil {
			return nil, false
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(hi); err != nil {
				return nil, false
			}
		}
		if a < 1 || b > 65535 || a > b {
			return nil, false
		}
		out = append(out, PortRange{a, b})
	}
	return out, len(out) > 0
}

// SetObservation is one source's observation of a set attribute of one
// asset.
type SetObservation struct {
	AssetID    shared.ID
	Attribute  SetAttribute
	Kind       SourceKind
	Name       string
	SourceRun  string
	ObservedAt time.Time
	Coverage   SetCoverage
	Elements   []string
	// Created are elements the asset shows only because the report that
	// carries this observation created them (open ports: the report's
	// open_port assets are stored before the set is reconciled). They are
	// not part of what the asset showed before.
	Created []string
}

// SetElement is one source's record of one element.
type SetElement struct {
	AssetID   shared.ID
	Attribute SetAttribute
	Kind      SourceKind
	Name      string
	Element   string
	// CoverageKey is the key of the observation that last saw it.
	CoverageKey string
	FirstSeen   time.Time
	LastSeen    time.Time
	// RemovedAt is when the source observed the element's coverage without
	// it; nil while the source still reports it.
	RemovedAt *time.Time
	SourceRun string
}

// Live reports whether the source still reports the element.
func (e SetElement) Live() bool { return e.RemovedAt == nil }

// SetElementVerdicts are the outcomes of recording one observation, per
// element (ObservationVerdict labels, plus removed).
const ObservationRemoved ObservationVerdict = "removed"

// PlanSetObservation decides what observation in does to the stored records
// of the same source (stored: that source's rows of the asset attribute).
// It returns the rows to write and counts every element's verdict:
//
//   - an element the source never reported, or reports again after it
//     removed it at an earlier time, is (re)added;
//   - an element it still reports is refreshed at most once per
//     ResightingRefreshInterval (no write in between);
//   - a live element in the coverage, not reported, and last seen before
//     this observation is removed;
//   - an observation not strictly newer than an element's record changes
//     nothing for that element (out of order or replayed).
func PlanSetObservation(stored []SetElement, in SetObservation, verdicts map[ObservationVerdict]int) []SetElement {
	byElement := make(map[string]SetElement, len(stored))
	for _, s := range stored {
		byElement[s.Element] = s
	}
	t := in.ObservedAt
	reported := make(map[string]bool, len(in.Elements))
	writes := make([]SetElement, 0, len(in.Elements))
	key := in.Coverage.Key
	for _, e := range in.Elements {
		if reported[e] {
			continue
		}
		reported[e] = true
		s, ok := byElement[e]
		switch {
		case !ok:
			verdicts[ObservationNew]++
			writes = append(writes, SetElement{AssetID: in.AssetID, Attribute: in.Attribute, Kind: in.Kind, Name: in.Name,
				Element: e, CoverageKey: key, FirstSeen: t, LastSeen: t, SourceRun: in.SourceRun})
		case !s.Live():
			if !t.After(*s.RemovedAt) || !t.After(s.LastSeen) {
				verdicts[ObservationOutOfOrder]++
				continue
			}
			verdicts[ObservationChanged]++
			s.RemovedAt, s.LastSeen, s.CoverageKey, s.SourceRun = nil, t, key, in.SourceRun
			writes = append(writes, s)
		case t.Before(s.LastSeen):
			verdicts[ObservationOutOfOrder]++
		case t.Equal(s.LastSeen):
			verdicts[ObservationReplay]++
		case t.Sub(s.LastSeen) >= ResightingRefreshInterval || s.CoverageKey != key:
			verdicts[ObservationRefresh]++
			s.LastSeen, s.CoverageKey, s.SourceRun = t, key, in.SourceRun
			writes = append(writes, s)
		default:
			verdicts[ObservationResighted]++
		}
	}
	for _, s := range stored {
		if reported[s.Element] || !s.Live() || !t.After(s.LastSeen) {
			continue
		}
		if !in.Coverage.Covers(in.Attribute, s.Element, s.CoverageKey) {
			continue
		}
		verdicts[ObservationRemoved]++
		removed := t
		s.RemovedAt, s.SourceRun = &removed, in.SourceRun
		writes = append(writes, s)
	}
	return writes
}

// SetSourceTrusted reports whether the source may contribute to a.
func (p ReconciliationPolicy) SetSourceTrusted(a SetAttribute, kind SourceKind, name string) bool {
	if kind == SourceKindManual {
		return true
	}
	i := p.match(a.Class(), kind, name)
	return i >= 0 && p.RulesFor(a.Class())[i].Trusted
}

// SetElementStale reports whether e is past its source's TTL at now.
func (p ReconciliationPolicy) SetElementStale(e SetElement, now time.Time) bool {
	if e.Kind == SourceKindManual {
		return false
	}
	c := e.Attribute.Class()
	i := p.match(c, e.Kind, e.Name)
	if i < 0 {
		return false
	}
	ttl := p.RulesFor(c)[i].TTL
	return ttl > 0 && now.Sub(e.LastSeen) > ttl
}

// SetResolution is the set an asset shows for a and why.
type SetResolution struct {
	Elements []string // sorted
	// Unattributed are shown elements no source has a record of (kept
	// until a trusted observation that names them leaves them out).
	Unattributed []string
}

// ResolveSet is the set of attribute a: every element a trusted source
// still reports and saw within its TTL, plus the elements of prev no
// source has a record of, except those a trusted observation of this
// reconciliation covered and left out (dropped).
func ResolveSet(a SetAttribute, rows []SetElement, prev []string, dropped map[string]bool, p ReconciliationPolicy, now time.Time) SetResolution {
	in := map[string]bool{}
	attributed := map[string]bool{}
	for _, r := range rows {
		if r.Attribute != a {
			continue
		}
		attributed[r.Element] = true
		if r.Live() && p.SetSourceTrusted(a, r.Kind, r.Name) && !p.SetElementStale(r, now) {
			in[r.Element] = true
		}
	}
	var res SetResolution
	for _, e := range prev {
		if !attributed[e] && !dropped[e] {
			in[e] = true
			res.Unattributed = append(res.Unattributed, e)
		}
	}
	res.Elements = make([]string, 0, len(in))
	for e := range in {
		res.Elements = append(res.Elements, e)
	}
	sort.Strings(res.Elements)
	sort.Strings(res.Unattributed)
	return res
}

// DiffSets returns the elements next has and prev lacks, and the reverse,
// each sorted.
func DiffSets(prev, next []string) (added, removed []string) {
	was := make(map[string]bool, len(prev))
	for _, e := range prev {
		was[e] = true
	}
	is := make(map[string]bool, len(next))
	for _, e := range next {
		is[e] = true
		if !was[e] {
			added = append(added, e)
		}
	}
	for e := range was {
		if !is[e] {
			removed = append(removed, e)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	return added, removed
}

// SetApply is one reconciliation of set attributes.
type SetApply struct {
	Observations []SetObservation
	// Resolve re-resolves these attributes without new observations (a
	// source past its TTL, a policy change).
	Resolve []SetRef
	Policy  ReconciliationPolicy
	Now     time.Time
	// Reason is the timeline reason of a change no observation caused
	// (empty: decided per change, TTL expiry or policy change).
	Reason ChangeReason
}

// SetRef names one set attribute of one asset.
type SetRef struct {
	AssetID   shared.ID
	Attribute SetAttribute
}

// SetChange is what a reconciliation changed in the set an asset shows.
type SetChange struct {
	AssetID        shared.ID
	Attribute      SetAttribute
	Added, Removed []string
	// Source is the observation's source (empty kind for a re-resolution).
	SourceKind SourceKind
	SourceName string
	SourceRun  string
	Reason     ChangeReason
}

// SetApplyResult is what one set reconciliation did.
type SetApplyResult struct {
	Changes  []SetChange
	Events   int
	Verdicts map[ObservationVerdict]int
}

// SetElementRepository stores per-source set elements and applies the
// resolved sets to the assets.
type SetElementRepository interface {
	// ApplySets records the observations and re-resolves every set they
	// touch, in one transaction with the asset rows locked; it writes the
	// resolved set (properties, or the open_port assets' status), and a
	// timeline event per changed set. Observations of assets not in
	// tenantID are dropped.
	ApplySets(ctx context.Context, tenantID shared.ID, in SetApply) (SetApplyResult, error)
	// ListSetElements returns every element record of one asset of the
	// tenant.
	ListSetElements(ctx context.Context, tenantID, assetID shared.ID) ([]SetElement, error)
}
