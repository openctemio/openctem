package threatmodel

import (
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ScopeType identifies what a threat model is keyed to.
type ScopeType string

// Recognized scope types (mirror the threat_models.scope_type CHECK).
const (
	ScopeCrownJewel   ScopeType = "crown_jewel"
	ScopeBusinessUnit ScopeType = "business_unit"
	ScopeAssetGroup   ScopeType = "asset_group"
	ScopeTenant       ScopeType = "tenant"
)

// Valid reports whether s is a recognized scope type.
func (s ScopeType) Valid() bool {
	switch s {
	case ScopeCrownJewel, ScopeBusinessUnit, ScopeAssetGroup, ScopeTenant:
		return true
	default:
		return false
	}
}

// String returns the scope type as a string.
func (s ScopeType) String() string { return string(s) }

// ThreatStatus is the derived status of an enumerated threat. It is computed at
// generation time from live findings/validation and cached on the row — never a
// manually edited field.
type ThreatStatus string

// Recognized threat statuses (mirror the threat_model_threats.status CHECK).
const (
	// StatusOpen — a matching open finding exists on the hop asset.
	StatusOpen ThreatStatus = "open"
	// StatusMitigated — the matching finding is fixed/resolved, or a compensating control covers the hop.
	StatusMitigated ThreatStatus = "mitigated"
	// StatusCovered — a validation/BAS record for the technique returned blocked/detected.
	StatusCovered ThreatStatus = "covered"
	// StatusAccepted — a finding exception / risk acceptance applies.
	StatusAccepted ThreatStatus = "accepted"
	// StatusTheoretical — technique is applicable but no finding/validation exists yet.
	StatusTheoretical ThreatStatus = "theoretical"
)

// Valid reports whether s is a recognized threat status.
func (s ThreatStatus) Valid() bool {
	switch s {
	case StatusOpen, StatusMitigated, StatusCovered, StatusAccepted, StatusTheoretical:
		return true
	default:
		return false
	}
}

// String returns the status as a string.
func (s ThreatStatus) String() string { return string(s) }

// ThreatModel is one generated threat model keyed to a scope. It is fully
// regenerated each CTEM cycle (never edited), so it is modeled as a projection
// with exported fields plus a validating constructor rather than a rich mutable
// aggregate. Rollup counters are cached for query/filter and recomputed from the
// threats via RecomputeRollups.
type ThreatModel struct {
	ID                      shared.ID
	TenantID                shared.ID
	ScopeType               ScopeType
	ScopeRefID              *shared.ID // nil for tenant-wide models
	Name                    string
	GeneratedAt             time.Time
	InputHash               string
	TechniqueDatasetVersion string

	// Cached rollups (recomputed from threats each generation).
	ThreatsTotal     int
	ThreatsOpen      int
	ThreatsMitigated int
	ThreatsCovered   int
	CoveragePct      float64

	CreatedAt time.Time
	UpdatedAt time.Time
}

// NewThreatModel builds a threat model for a scope, validating scope_type and
// name and assigning a fresh id + timestamps. scopeRefID may be nil for a
// tenant-wide model.
func NewThreatModel(tenantID shared.ID, scopeType ScopeType, scopeRefID *shared.ID, name string) (*ThreatModel, error) {
	if !scopeType.Valid() {
		return nil, ErrInvalidScope
	}
	if name == "" {
		return nil, ErrEmptyName
	}
	now := time.Now().UTC()
	return &ThreatModel{
		ID:          shared.NewID(),
		TenantID:    tenantID,
		ScopeType:   scopeType,
		ScopeRefID:  scopeRefID,
		Name:        name,
		GeneratedAt: now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}, nil
}

// RecomputeRollups recalculates the cached counters and coverage percentage from
// the supplied threats. "Covered" for the purposes of the coverage percentage is
// the union of mitigated + covered + accepted threats (i.e. not open and not
// merely theoretical); theoretical threats count toward the total but are neither
// open nor covered. This keeps coverage_pct honest: it is
// (mitigated+covered+accepted) / (open+mitigated+covered+accepted).
func (m *ThreatModel) RecomputeRollups(threats []*ThreatModelThreat) {
	var total, open, mitigated, covered, accepted int
	for _, t := range threats {
		if t == nil {
			continue
		}
		total++
		switch t.Status {
		case StatusOpen:
			open++
		case StatusMitigated:
			mitigated++
		case StatusCovered:
			covered++
		case StatusAccepted:
			accepted++
		case StatusTheoretical:
			// counts toward total only
		}
	}
	m.ThreatsTotal = total
	m.ThreatsOpen = open
	m.ThreatsMitigated = mitigated
	m.ThreatsCovered = covered

	addressed := mitigated + covered + accepted
	denom := open + addressed
	if denom > 0 {
		m.CoveragePct = float64(addressed) / float64(denom) * 100
	} else {
		m.CoveragePct = 0
	}
}

// ThreatModelThreat is one enumerated threat: (attacker × chain-hop × technique).
// Regenerated wholesale (delete-and-insert) per model — never reconciled.
type ThreatModelThreat struct {
	ID                shared.ID
	TenantID          shared.ID
	ThreatModelID     shared.ID
	AttackerProfileID *shared.ID
	EntryPointAssetID *shared.ID
	TargetAssetID     *shared.ID
	HopAssetID        *shared.ID
	HopIndex          int
	ChainFingerprint  string
	TechniqueID       string
	Tactic            string
	MitigationID      string
	Status            ThreatStatus
	StatusReason      string
	EvidenceFindingID *shared.ID
	Score             float64
	CreatedAt         time.Time
}

// NewThreatModelThreat builds an enumerated threat under a model, validating the
// status enum and assigning a fresh id + timestamp. threatModelID and tenantID
// tie the threat to its parent model and tenant.
func NewThreatModelThreat(tenantID, threatModelID shared.ID, status ThreatStatus) (*ThreatModelThreat, error) {
	if !status.Valid() {
		return nil, ErrInvalidStatus
	}
	return &ThreatModelThreat{
		ID:            shared.NewID(),
		TenantID:      tenantID,
		ThreatModelID: threatModelID,
		Status:        status,
		CreatedAt:     time.Now().UTC(),
	}, nil
}
