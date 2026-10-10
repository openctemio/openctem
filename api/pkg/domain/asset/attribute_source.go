package asset

// Attribute reconciliation: which source decides an asset attribute.
// Design: docs/rfcs/RFC-069-asset-attribute-reconciliation.md.
//
// Each source that reports a tracked attribute keeps its own latest value
// (AttributeObservation, one per asset, attribute and source). Resolve picks
// the value the asset shows:
//
//  1. a manual observation is a lock and wins;
//  2. a source kind the policy does not list for the attribute is not trusted;
//  3. an observation older than its kind's TTL is stale and no longer counts;
//  4. the remaining ones rank by the policy's precedence, then by when the
//     source saw the value (observed_at), then confidence, then ingestion time;
//  5. when the most trusted rank holds different values (a conflict), the
//     value the asset already shows keeps winning while a source of that
//     rank still reports it: equal sources disagreeing are shown, not
//     flapped between.
//
// No candidate left means the asset keeps its current value: staleness never
// clears a value, it only stops a source from winning.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// SourceKind is how a value reached the platform. It is decided by the
// platform from the authenticated route a report or edit came through,
// never taken from the report.
type SourceKind string

const (
	// SourceKindManual is a person's edit; it is a lock until released.
	SourceKindManual SourceKind = "manual"
	// SourceKindIntegration is a connector the tenant configured (inventory,
	// CMDB, cloud, ticketing sync).
	SourceKindIntegration SourceKind = "integration"
	// SourceKindImport is a file a person uploaded or an importer read.
	SourceKindImport SourceKind = "import"
	// SourceKindScan is a sensor, CI run or platform scanner.
	SourceKindScan SourceKind = "scan"
)

// AllSourceKinds lists the kinds in their default order of trust.
func AllSourceKinds() []SourceKind {
	return []SourceKind{SourceKindManual, SourceKindIntegration, SourceKindImport, SourceKindScan}
}

// IsValid reports whether k is a known kind.
func (k SourceKind) IsValid() bool {
	switch k {
	case SourceKindManual, SourceKindIntegration, SourceKindImport, SourceKindScan:
		return true
	}
	return false
}

// TrackedAttribute is an asset attribute whose value is reconciled across
// sources.
type TrackedAttribute string

const (
	AttrCriticality        TrackedAttribute = "criticality"
	AttrOwnerRef           TrackedAttribute = "owner_ref"
	AttrExposure           TrackedAttribute = "exposure"
	AttrDataClassification TrackedAttribute = "data_classification"
)

// AllTrackedAttributes lists the reconciled attributes.
func AllTrackedAttributes() []TrackedAttribute {
	return []TrackedAttribute{AttrCriticality, AttrOwnerRef, AttrExposure, AttrDataClassification}
}

// IsValid reports whether a is a reconciled attribute.
func (a TrackedAttribute) IsValid() bool {
	switch a {
	case AttrCriticality, AttrOwnerRef, AttrExposure, AttrDataClassification:
		return true
	}
	return false
}

// MaxOwnerRefLength bounds an owner reference (as the asset edit does).
const MaxOwnerRefLength = 500

// MaxSourceNameLength bounds the informational source name.
const MaxSourceNameLength = 100

// NormalizeAttributeValue validates a value for attribute a and returns it in
// stored form. An empty value is allowed for owner_ref and
// data_classification (a person clearing it).
func NormalizeAttributeValue(a TrackedAttribute, value string) (string, error) {
	v := strings.TrimSpace(value)
	switch a {
	case AttrCriticality:
		c, err := ParseCriticality(v)
		if err != nil {
			return "", fmt.Errorf("%w: invalid criticality", shared.ErrValidation)
		}
		return c.String(), nil
	case AttrExposure:
		e, err := ParseExposure(v)
		if err != nil {
			return "", fmt.Errorf("%w: invalid exposure", shared.ErrValidation)
		}
		return e.String(), nil
	case AttrDataClassification:
		d := DataClassification(strings.ToLower(v))
		if d != "" && !d.IsValid() {
			return "", fmt.Errorf("%w: invalid data classification", shared.ErrValidation)
		}
		return string(d), nil
	case AttrOwnerRef:
		if len(v) > MaxOwnerRefLength {
			return "", fmt.Errorf("%w: owner reference longer than %d characters", shared.ErrValidation, MaxOwnerRefLength)
		}
		return v, nil
	}
	return "", fmt.Errorf("%w: unknown attribute %q", shared.ErrValidation, a)
}

// AttributeValue returns the current value of attribute a on the asset.
func (a *Asset) AttributeValue(attr TrackedAttribute) string {
	switch attr {
	case AttrCriticality:
		return a.criticality.String()
	case AttrOwnerRef:
		return a.ownerRef
	case AttrExposure:
		return a.exposure.String()
	case AttrDataClassification:
		return string(a.dataClassification)
	}
	return ""
}

// SetAttributeValue sets attribute attr to a value NormalizeAttributeValue
// accepted.
func (a *Asset) SetAttributeValue(attr TrackedAttribute, value string) error {
	switch attr {
	case AttrCriticality:
		return a.UpdateCriticality(Criticality(value))
	case AttrOwnerRef:
		a.SetOwnerRef(value)
		return nil
	case AttrExposure:
		return a.UpdateExposure(Exposure(value))
	case AttrDataClassification:
		return a.SetDataClassification(DataClassification(value))
	}
	return fmt.Errorf("%w: unknown attribute %q", shared.ErrValidation, attr)
}

// AttributeObservation is one source's latest value for one attribute of
// one asset.
type AttributeObservation struct {
	AssetID    shared.ID
	Attribute  TrackedAttribute
	Kind       SourceKind
	Name       string // tool, importer, integration or user id; informational
	Value      string
	ObservedAt time.Time // when the source saw the value
	IngestedAt time.Time // when the platform recorded it
	Confidence int       // 0-100, a tie-break only
	// SourceRun is the scan task, CI run, import or feed sequence the value
	// came from (informational).
	SourceRun string
	// Winner: stored flag, this source decided the value the asset shows.
	Winner bool
}

// SameSource reports whether o and other are records of the same source.
func (o AttributeObservation) SameSource(other AttributeObservation) bool {
	return o.AssetID == other.AssetID && o.Attribute == other.Attribute && o.Kind == other.Kind && o.Name == other.Name
}

// ObservationVerdict is what recording an observation does to the stored
// record of the same source.
type ObservationVerdict string

const (
	// ObservationNew: the source had no record; it is stored.
	ObservationNew ObservationVerdict = "new"
	// ObservationChanged: newer and a different value; it replaces the record.
	ObservationChanged ObservationVerdict = "changed"
	// ObservationRefresh: newer, same value, and the record is at least
	// ResightingRefreshInterval old; only observed_at moves.
	ObservationRefresh ObservationVerdict = "refresh"
	// ObservationResighted: newer, same value, recently refreshed: nothing
	// is written.
	ObservationResighted ObservationVerdict = "resighted"
	// ObservationOutOfOrder: the source saw it before its stored record;
	// ignored (a late report never undoes a newer one).
	ObservationOutOfOrder ObservationVerdict = "out_of_order"
	// ObservationReplay: the same observation time as the stored record;
	// ignored (a replayed report, or two values that cannot be ordered).
	ObservationReplay ObservationVerdict = "replay"
)

// Accepted reports whether the verdict writes the record.
func (v ObservationVerdict) Accepted() bool {
	return v == ObservationNew || v == ObservationChanged || v == ObservationRefresh
}

// Rejected reports whether the observation was refused as out of order or
// replayed.
func (v ObservationVerdict) Rejected() bool {
	return v == ObservationOutOfOrder || v == ObservationReplay
}

// ClassifyObservation decides what an incoming observation does to the
// stored record of the same source (nil: none). Only an observation the
// source made strictly after its stored one counts; a re-sighting of the
// same value refreshes observed_at at most once per refresh interval.
func ClassifyObservation(stored *AttributeObservation, in AttributeObservation, refresh time.Duration) ObservationVerdict {
	if stored == nil {
		return ObservationNew
	}
	switch {
	case in.ObservedAt.Before(stored.ObservedAt):
		return ObservationOutOfOrder
	case in.ObservedAt.Equal(stored.ObservedAt):
		return ObservationReplay
	case in.Value != stored.Value:
		return ObservationChanged
	case in.ObservedAt.Sub(stored.ObservedAt) >= refresh:
		return ObservationRefresh
	}
	return ObservationResighted
}

// IsLock reports whether the observation is a person's lock.
func (o AttributeObservation) IsLock() bool { return o.Kind == SourceKindManual }

// ReconciliationPolicy is the tenant's rule for picking a value.
type ReconciliationPolicy struct {
	// Precedence lists, per attribute, the kinds trusted for it, most
	// trusted first. A kind absent from the list is ignored for the
	// attribute. Manual is always trusted (it is a lock).
	Precedence map[TrackedAttribute][]SourceKind
	// TTL is how long a kind's observation counts after the source saw it.
	// Zero or absent: it never goes stale.
	TTL map[SourceKind]time.Duration
}

// DefaultReconciliationPolicy is the policy of a tenant that set none:
// business attributes come from people, then integrations, then imports, and
// scanners are not trusted for them; exposure trusts a scan that reached the
// asset over an inventory's claim.
func DefaultReconciliationPolicy() ReconciliationPolicy {
	business := []SourceKind{SourceKindManual, SourceKindIntegration, SourceKindImport}
	return ReconciliationPolicy{
		Precedence: map[TrackedAttribute][]SourceKind{
			AttrCriticality:        business,
			AttrOwnerRef:           business,
			AttrDataClassification: business,
			AttrExposure:           {SourceKindManual, SourceKindScan, SourceKindIntegration, SourceKindImport},
		},
		TTL: map[SourceKind]time.Duration{
			SourceKindIntegration: 30 * 24 * time.Hour,
			SourceKindImport:      90 * 24 * time.Hour,
			SourceKindScan:        30 * 24 * time.Hour,
		},
	}
}

// rank is the position of kind in the attribute's precedence, or -1 when the
// kind is not trusted for it.
func (p ReconciliationPolicy) rank(attr TrackedAttribute, kind SourceKind) int {
	if kind == SourceKindManual {
		return 0
	}
	for i, k := range p.Precedence[attr] {
		if k == kind {
			return i
		}
	}
	return -1
}

// Trusts reports whether kind may decide attr.
func (p ReconciliationPolicy) Trusts(attr TrackedAttribute, kind SourceKind) bool {
	return p.rank(attr, kind) >= 0
}

// Stale reports whether o is past its kind's TTL at now (a lock never is).
func (p ReconciliationPolicy) Stale(o AttributeObservation, now time.Time) bool {
	return p.stale(o, now)
}

func (p ReconciliationPolicy) stale(o AttributeObservation, now time.Time) bool {
	if o.IsLock() {
		return false
	}
	ttl := p.TTL[o.Kind]
	return ttl > 0 && now.Sub(o.ObservedAt) > ttl
}

// CandidateStatus says why a source's value does or does not decide.
type CandidateStatus string

const (
	CandidateWinner    CandidateStatus = "winner"
	CandidateOutranked CandidateStatus = "outranked" // trusted, fresh, lost on rank or recency
	CandidateStale     CandidateStatus = "stale"     // not re-seen within its kind's TTL
	CandidateUntrusted CandidateStatus = "untrusted" // the kind is not trusted for the attribute
)

// Candidate is one source's value with its standing.
type Candidate struct {
	AttributeObservation
	Status CandidateStatus
}

// Resolution is the outcome for one attribute of one asset.
type Resolution struct {
	Attribute TrackedAttribute
	// Winner is the deciding observation; nil when no source may decide
	// (the asset keeps its current value).
	Winner *AttributeObservation
	// Locked: the winner is a person's lock.
	Locked bool
	// Conflict: the most trusted fresh sources (equal rank) report
	// different values.
	Conflict bool
	// Candidates are every source's value, the winner first.
	Candidates []Candidate
}

// Resolve picks the value of attr from the observations of one asset that
// shows no value yet. Observations of other attributes are ignored.
func Resolve(attr TrackedAttribute, obs []AttributeObservation, p ReconciliationPolicy, now time.Time) Resolution {
	return ResolveFrom(attr, obs, p, now, "")
}

// ResolveFrom is Resolve for an asset that shows current: when the most
// trusted fresh rank disagrees, the source of that rank still reporting
// current keeps winning (the conflict is shown, never flapped between).
func ResolveFrom(attr TrackedAttribute, obs []AttributeObservation, p ReconciliationPolicy, now time.Time, current string) Resolution {
	res := Resolution{Attribute: attr}
	var eligible []AttributeObservation
	for _, o := range obs {
		if o.Attribute != attr {
			continue
		}
		switch {
		case p.rank(attr, o.Kind) < 0:
			res.Candidates = append(res.Candidates, Candidate{o, CandidateUntrusted})
		case p.stale(o, now):
			res.Candidates = append(res.Candidates, Candidate{o, CandidateStale})
		default:
			eligible = append(eligible, o)
		}
	}
	sort.SliceStable(eligible, func(i, j int) bool {
		a, b := eligible[i], eligible[j]
		if ra, rb := p.rank(attr, a.Kind), p.rank(attr, b.Kind); ra != rb {
			return ra < rb
		}
		if !a.ObservedAt.Equal(b.ObservedAt) {
			return a.ObservedAt.After(b.ObservedAt)
		}
		if a.Confidence != b.Confidence {
			return a.Confidence > b.Confidence
		}
		if !a.IngestedAt.Equal(b.IngestedAt) {
			return a.IngestedAt.After(b.IngestedAt)
		}
		return a.Kind+SourceKind(a.Name) < b.Kind+SourceKind(b.Name)
	})
	res.Conflict = keepIncumbent(attr, eligible, p, current)
	ranked := make([]Candidate, 0, len(obs))
	for i, o := range eligible {
		st := CandidateOutranked
		if i == 0 {
			st = CandidateWinner
			w := o
			res.Winner = &w
			res.Locked = o.IsLock()
		}
		ranked = append(ranked, Candidate{o, st})
	}
	res.Candidates = append(ranked, res.Candidates...)
	return res
}

// keepIncumbent reports whether the most trusted rank of the sorted
// eligible observations disagrees, and then moves the newest one of that
// rank reporting current to the front.
func keepIncumbent(attr TrackedAttribute, eligible []AttributeObservation, p ReconciliationPolicy, current string) bool {
	if len(eligible) < 2 {
		return false
	}
	top := p.rank(attr, eligible[0].Kind)
	values := map[string]bool{}
	incumbent := -1
	for i, o := range eligible {
		if p.rank(attr, o.Kind) != top {
			break
		}
		values[o.Value] = true
		if incumbent < 0 && current != "" && o.Value == current {
			incumbent = i
		}
	}
	if len(values) < 2 {
		return false
	}
	if incumbent > 0 {
		w := eligible[incumbent]
		copy(eligible[1:incumbent+1], eligible[:incumbent])
		eligible[0] = w
	}
	return true
}

// AttributeRef names one attribute of one asset.
type AttributeRef struct {
	AssetID   shared.ID
	Attribute TrackedAttribute
}

// AttributeApply is one reconciliation: observations to record, manual locks
// to release, and the policy that resolves the attributes they touch.
type AttributeApply struct {
	// Observations are recorded per (asset, attribute, kind, name); one
	// observed before the stored one of the same source is ignored, so a
	// report delivered late never undoes a newer one.
	Observations []AttributeObservation
	// Release removes the manual lock of these attributes.
	Release []AttributeRef
	// Policy resolves the touched attributes. A manual observation replaces
	// every other manual row of its attribute (one lock per attribute).
	Policy ReconciliationPolicy
	Now    time.Time
	// Resolve re-resolves these attributes without new observations (a
	// policy change, a source going stale).
	Resolve []AttributeRef
	// Actor is the person behind a manual observation or a release.
	Actor *shared.ID
	// Reason is the timeline reason of a change that no observation or
	// release of this apply caused (ChangeReasonTTLExpiry,
	// ChangeReasonPolicyChange). Empty: ChangeReasonNewerObservation.
	Reason ChangeReason
}

// ApplyResult is what one reconciliation did.
type ApplyResult struct {
	// Changes are the values it changed on assets.
	Changes []AttributeChange
	// Events is how many timeline events it wrote or folded into a flap.
	Events int
	// Verdicts counts the observations by what recording them did.
	Verdicts map[ObservationVerdict]int
}

// AttributeChange is a value the reconciliation changed on an asset.
type AttributeChange struct {
	AssetID   shared.ID
	Attribute TrackedAttribute
	Old, New  string
	// Source is the winning observation.
	Source AttributeObservation
	// Reason is why it changed.
	Reason ChangeReason
}

// AttributeSourceRepository stores the per-source observations and applies
// resolutions to the assets.
type AttributeSourceRepository interface {
	// Apply records the observations, releases the locks, re-resolves every
	// attribute it touched and writes the changed values to the assets, in
	// one transaction with the asset rows locked, and records a timeline
	// event for each changed value or deciding source. Observations of
	// assets not in tenantID are dropped.
	Apply(ctx context.Context, tenantID shared.ID, in AttributeApply) (ApplyResult, error)
	// ListForAsset returns every observation of one asset of the tenant.
	ListForAsset(ctx context.Context, tenantID, assetID shared.ID) ([]AttributeObservation, error)
}

// StateChangeFor maps a reconciled change to its state-history type, or ""
// when the attribute has none.
func StateChangeFor(attr TrackedAttribute) StateChangeType {
	switch attr {
	case AttrCriticality:
		return StateChangeCriticalityChanged
	case AttrOwnerRef:
		return StateChangeOwnerChanged
	case AttrExposure:
		return StateChangeExposureChanged
	case AttrDataClassification:
		return StateChangeClassificationChanged
	}
	return ""
}

// ChangeSourceFor maps a source kind to the state-history source.
func ChangeSourceFor(kind SourceKind) ChangeSource {
	switch kind {
	case SourceKindManual:
		return ChangeSourceManual
	case SourceKindIntegration:
		return ChangeSourceIntegration
	case SourceKindImport:
		return ChangeSourceAPI
	}
	return ChangeSourceScan
}

// MaxSourceTTLDays bounds a configured TTL.
const MaxSourceTTLDays = 3650

// PolicyFromSettings builds the policy of a tenant from its settings
// (attribute -> kinds, most trusted first; kind -> TTL days, 0 = never
// stale). Attributes and kinds the settings leave out keep the defaults.
// Manual is implied first and may not be listed; an unknown attribute or
// kind, a repeated kind or a TTL out of range is a validation error.
func PolicyFromSettings(precedence map[string][]string, ttlDays map[string]int) (ReconciliationPolicy, error) {
	p := DefaultReconciliationPolicy()
	for attrName, kinds := range precedence {
		attr := TrackedAttribute(attrName)
		if !attr.IsValid() {
			return p, fmt.Errorf("%w: unknown attribute %q", shared.ErrValidation, attrName)
		}
		list := []SourceKind{SourceKindManual}
		seen := map[SourceKind]bool{}
		for _, k := range kinds {
			kind := SourceKind(k)
			if !kind.IsValid() || kind == SourceKindManual {
				return p, fmt.Errorf("%w: %s: source %q is not one of integration, import, scan", shared.ErrValidation, attrName, k)
			}
			if seen[kind] {
				return p, fmt.Errorf("%w: %s: source %q listed twice", shared.ErrValidation, attrName, k)
			}
			seen[kind] = true
			list = append(list, kind)
		}
		p.Precedence[attr] = list
	}
	for kindName, days := range ttlDays {
		kind := SourceKind(kindName)
		if !kind.IsValid() || kind == SourceKindManual {
			return p, fmt.Errorf("%w: ttl: source %q is not one of integration, import, scan", shared.ErrValidation, kindName)
		}
		if days < 0 || days > MaxSourceTTLDays {
			return p, fmt.Errorf("%w: ttl: %s must be 0-%d days", shared.ErrValidation, kindName, MaxSourceTTLDays)
		}
		p.TTL[kind] = time.Duration(days) * 24 * time.Hour
	}
	return p, nil
}
