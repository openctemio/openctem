// Package assetfreshness is the freshness model of asset data
// (docs/rfcs/RFC-075-asset-freshness.md, docs/architecture/asset-freshness.md):
// which enrichable attribute classes an asset has, which stage observes each,
// how long an observation stays current, and the live / stale / dead / never
// state that follows.
package assetfreshness

import (
	"context"
	"slices"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// Class is an enrichable attribute class: attributes one stage observes
// together.
type Class string

// The classes. The list is closed; the database CHECK holds the same values.
const (
	ClassDNS          Class = "dns"
	ClassRegistration Class = "registration"
	ClassNetworkOwner Class = "network_owner"
	ClassHTTP         Class = "http"
	ClassTLS          Class = "tls"
	ClassPorts        Class = "ports"
)

// State is how current a class (or an asset) is.
type State string

// States, best to worst (see Worse).
const (
	StateLive  State = "live"
	StateStale State = "stale"
	StateDead  State = "dead"
	StateNever State = "never"
)

// TTL bounds and the factor for important assets.
const (
	MinTTL = 6 * time.Hour
	MaxTTL = 30 * 24 * time.Hour
	// DeadAfter is the multiple of the TTL after which an observation is dead.
	DeadAfter = 3
)

// ClassSpec is one class: the stage that observes it, the asset types it
// applies to, its base TTL and whether a passive (T0) stage refreshes it.
type ClassSpec struct {
	Class   Class
	Stage   stage.Key
	Types   []asset.AssetType
	BaseTTL time.Duration
	Passive bool
}

var specs = []ClassSpec{
	{ClassDNS, stage.ResolveDNS, []asset.AssetType{asset.AssetTypeDomain, asset.AssetTypeSubdomain}, 24 * time.Hour, true},
	{ClassRegistration, stage.LookupRDAP, []asset.AssetType{asset.AssetTypeDomain}, 7 * 24 * time.Hour, true},
	{ClassNetworkOwner, stage.LookupASN, []asset.AssetType{asset.AssetTypeIPAddress, asset.AssetTypeNetwork}, 7 * 24 * time.Hour, true},
	{ClassHTTP, stage.ProbeHTTP, []asset.AssetType{
		asset.AssetTypeService, asset.AssetTypeApplication,
		asset.AssetTypeDomain, asset.AssetTypeSubdomain, asset.AssetTypeIPAddress,
	}, 3 * 24 * time.Hour, false},
	{ClassTLS, stage.ProbeHTTP, []asset.AssetType{asset.AssetTypeCertificate}, 3 * 24 * time.Hour, false},
	{ClassPorts, stage.ScanPorts, []asset.AssetType{asset.AssetTypeIPAddress, asset.AssetTypeHost}, 7 * 24 * time.Hour, false},
}

// Specs returns every class, in display order.
func Specs() []ClassSpec { return slices.Clone(specs) }

// Lookup returns the spec of a class.
func Lookup(c Class) (ClassSpec, bool) {
	for _, s := range specs {
		if s.Class == c {
			return s, true
		}
	}
	return ClassSpec{}, false
}

// Applies reports whether the class applies to an asset type.
func (s ClassSpec) Applies(t asset.AssetType) bool { return slices.Contains(s.Types, t) }

// ClassesForTool returns the classes a report of the tool observes on an
// asset of the type: the classes of every stage the tool implements that
// apply to the type. A tool the catalog does not know observes nothing.
func ClassesForTool(tool string, t asset.AssetType) []Class {
	tool = strings.TrimSpace(tool)
	if tool == "" {
		return nil
	}
	var out []Class
	for _, st := range stage.ForTool(tool) {
		for _, s := range specs {
			if s.Stage == st.Key && s.Applies(t) && !slices.Contains(out, s.Class) {
				out = append(out, s.Class)
			}
		}
	}
	return out
}

// PassiveClassesFor returns the passive classes that apply to an asset type:
// the ones that show "never" until observed.
func PassiveClassesFor(t asset.AssetType) []Class {
	var out []Class
	for _, s := range specs {
		if s.Passive && s.Applies(t) {
			out = append(out, s.Class)
		}
	}
	return out
}

// Importance is what shortens a TTL: the asset's criticality and exposure.
type Importance struct {
	Criticality    asset.Criticality
	InternetFacing bool
}

// ImportanceOf reads the importance of an asset.
func ImportanceOf(a *asset.Asset) Importance {
	return Importance{
		Criticality:    a.Criticality(),
		InternetFacing: a.IsInternetFacing(),
	}
}

// Important reports whether the TTL is halved: critical or high, or
// internet-facing.
func (i Importance) Important() bool {
	return i.InternetFacing || i.Criticality == asset.CriticalityCritical || i.Criticality == asset.CriticalityHigh
}

// TTL is how long an observation of the class stays live for an asset of
// this importance, within [MinTTL, MaxTTL].
func (s ClassSpec) TTL(imp Importance) time.Duration {
	ttl := s.BaseTTL
	if imp.Important() {
		ttl /= 2
	}
	return min(max(ttl, MinTTL), MaxTTL)
}

func stateOf(age, ttl time.Duration) State {
	switch {
	case age <= ttl:
		return StateLive
	case age <= DeadAfter*ttl:
		return StateStale
	default:
		return StateDead
	}
}

// StateOf is the state of an observation made at observedAt, at now.
func StateOf(observedAt time.Time, ttl time.Duration, now time.Time) State {
	return stateOf(now.Sub(observedAt), ttl)
}

// rank orders states best to worst.
var rank = map[State]int{StateLive: 0, StateStale: 1, StateNever: 2, StateDead: 3}

// Worse returns the worse of two states.
func Worse(a, b State) State {
	if rank[b] > rank[a] {
		return b
	}
	return a
}

// Observation is one class of one asset as last observed.
type Observation struct {
	AssetID    shared.ID
	Class      Class
	ObservedAt time.Time
	Source     string
}

// ClassView is one class of an asset with its state.
type ClassView struct {
	Class      Class      `json:"class"`
	State      State      `json:"state"`
	ObservedAt *time.Time `json:"observed_at,omitempty"`
	Source     string     `json:"source,omitempty"`
	TTLSeconds int64      `json:"ttl_seconds"`
	Passive    bool       `json:"passive"`
	// DueAt is when the class turns stale (observed + TTL); nil when never observed.
	DueAt *time.Time `json:"due_at,omitempty"`
}

// AssetView is an asset's freshness: its classes and overall state.
type AssetView struct {
	State   State       `json:"state"`
	Classes []ClassView `json:"classes"`
	// NextDueAt is the earliest DueAt among the classes; nil when none was observed.
	NextDueAt *time.Time `json:"next_due_at,omitempty"`
	// Enrichment is the asset's pending or last automatic enrichment; nil
	// when it never had one.
	Enrichment *Request `json:"enrichment,omitempty"`
}

// View computes an asset's freshness from its observations: every observed
// class, plus each passive class that applies to the type and was never
// observed (state never). The asset's state is its worst class; an asset
// with no class at all is live (there is nothing to keep fresh).
func View(t asset.AssetType, imp Importance, obs []Observation, now time.Time) AssetView {
	byClass := make(map[Class]Observation, len(obs))
	for _, o := range obs {
		byClass[o.Class] = o
	}
	out := AssetView{State: StateLive, Classes: []ClassView{}}
	for _, s := range specs {
		o, seen := byClass[s.Class]
		if !seen && !(s.Passive && s.Applies(t)) {
			continue
		}
		ttl := s.TTL(imp)
		cv := ClassView{Class: s.Class, TTLSeconds: int64(ttl / time.Second), Passive: s.Passive, State: StateNever}
		if seen {
			at := o.ObservedAt.UTC()
			due := at.Add(ttl)
			cv.ObservedAt, cv.Source, cv.DueAt = &at, o.Source, &due
			cv.State = StateOf(at, ttl, now)
			if out.NextDueAt == nil || due.Before(*out.NextDueAt) {
				d := due
				out.NextDueAt = &d
			}
		}
		out.State = Worse(out.State, cv.State)
		out.Classes = append(out.Classes, cv)
	}
	return out
}

// Repository stores observations. Every method is scoped to one tenant.
type Repository interface {
	// Record upserts the observations; a stored observation newer than the
	// incoming one is kept.
	Record(ctx context.Context, tenantID shared.ID, obs []Observation) error
	// ListForAsset returns the asset's observations.
	ListForAsset(ctx context.Context, tenantID, assetID shared.ID) ([]Observation, error)
}

// Filter values of the inventory's freshness filter.
const (
	FilterStale = "stale"
	FilterNever = "never"
)
