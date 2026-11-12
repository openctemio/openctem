package exploration

// The lead type catalog (configs/lead-types.yaml, generated into
// lead_types_generated.go by cmd/gen-lead-types).

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/domain/stage"
)

// LeadTypeAction is one typed next action of a lead type.
type LeadTypeAction struct {
	Capability string
	// Tier is the stage catalog's tier of the capability.
	Tier stage.Tier
	// AssetTypes are the subject types the action applies to (registry
	// names); empty: any type the capability takes.
	AssetTypes []string
	// Params are the param keys the action accepts; anything else is refused.
	Params []string
}

// LeadType is one kind of question.
type LeadType struct {
	ID          string
	Version     int
	Subject     string
	Likelihood  Likelihood
	ValueWeight float64
	MaxAttempts int
	Reasons     []string
	// Settle is how a finished step answers the question (SettleFinding,
	// SettleLiveness, SettleMatch).
	Settle  string
	Actions []LeadTypeAction
}

// Settle modes of a lead type.
const (
	SettleFinding  = "finding"
	SettleLiveness = "liveness"
	SettleMatch    = "match"
)

// RuleRef is the origin reference a rule of this type records: "<id>@<version>".
func (t LeadType) RuleRef() string { return t.ID + "@" + strconv.Itoa(t.Version) }

// LeadTypes returns the catalog in its file order.
func LeadTypes() []LeadType { return slices.Clone(leadTypes) }

// LookupLeadType returns the catalog entry of id.
func LookupLeadType(id string) (LeadType, bool) {
	for _, t := range leadTypes {
		if t.ID == id {
			return t, true
		}
	}
	return LeadType{}, false
}

// ActionFor returns the type's first action that applies to a subject of
// the stored (type, sub_type) pair; ok is false when none does.
func (t LeadType) ActionFor(assetType asset.AssetType, subType string) (LeadTypeAction, bool) {
	got := asset.CanonicalPair(assetType, subType)
	for _, a := range t.Actions {
		st, ok := stage.Lookup(stage.Key(a.Capability))
		if !ok || !st.Accepts(got) {
			continue
		}
		if len(a.AssetTypes) == 0 {
			return a, true
		}
		for _, name := range a.AssetTypes {
			want := asset.CanonicalPair(asset.AssetType(name), "")
			if want.Type == got.Type && (want.SubType == "" || want.SubType == got.SubType) {
				return a, true
			}
		}
	}
	return LeadTypeAction{}, false
}

// ErrNotInCatalog: the lead's type, reason or action is not one the
// catalog declares.
var ErrNotInCatalog = fmt.Errorf("%w: not allowed by the lead type catalog", shared.ErrValidation)

// CheckCatalog validates a lead against its catalog entry: a known type,
// one of its reasons, one of its actions (by capability) with only the
// declared params, and the catalog's tier.
func CheckCatalog(l *Lead) (LeadType, error) {
	t, ok := LookupLeadType(l.Type)
	if !ok {
		return LeadType{}, fmt.Errorf("%w: unknown lead type", ErrNotInCatalog)
	}
	if !slices.Contains(t.Reasons, l.ReasonCode) {
		return t, fmt.Errorf("%w: reason", ErrNotInCatalog)
	}
	for _, a := range t.Actions {
		if a.Capability != l.Action.Capability {
			continue
		}
		for k := range l.Action.Params {
			if !slices.Contains(a.Params, k) {
				return t, fmt.Errorf("%w: param %q", ErrNotInCatalog, k)
			}
		}
		if a.Tier != l.Tier {
			return t, fmt.Errorf("%w: tier", ErrNotInCatalog)
		}
		return t, nil
	}
	return t, fmt.Errorf("%w: action", ErrNotInCatalog)
}
