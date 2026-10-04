// Package scoping holds the read model behind the Scoping overview: one
// tenant-wide answer to "is our scope ready for this cycle?". It does not own
// any table; every number is an aggregate over the registers that make up
// CTEM scoping (cycles, crown jewels, business services and units, scope
// targets and exclusions, attacker profiles, threat models).
//
// Proposal: ui docs/ui/scoping-ia-2026-10.md, section 5.2 (decision D9).
package scoping

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Summary is the Scoping overview read model. JSON field names are the API
// contract (GET /api/v1/scoping/summary); add fields, never rename them.
type Summary struct {
	// ActiveCycle is the cycle the scope is being written for: the tenant's
	// active cycle, else the most recent one in review, else the most recent
	// one in planning. Nil when there is none of those.
	ActiveCycle      *CycleSummary      `json:"active_cycle"`
	CrownJewels      CrownJewelSummary  `json:"crown_jewels"`
	BusinessServices ServiceSummary     `json:"business_services"`
	BusinessUnits    CountSummary       `json:"business_units"`
	Assets           AssetSummary       `json:"assets"`
	Boundary         BoundarySummary    `json:"boundary"`
	AttackerProfiles CountSummary       `json:"attacker_profiles"`
	ThreatModels     ThreatModelSummary `json:"threat_models"`
	Cycles           CountSummary       `json:"cycles"`
}

// CycleSummary describes the cycle in focus and how complete its charter is.
type CycleSummary struct {
	ID        string     `json:"id"`
	Name      string     `json:"name"`
	Status    string     `json:"status"`
	StartDate *time.Time `json:"start_date"`
	EndDate   *time.Time `json:"end_date"`
	// Charter array lengths.
	Objectives      int `json:"objectives"`
	SuccessCriteria int `json:"success_criteria"`
	InScopeServices int `json:"in_scope_services"`
	Exclusions      int `json:"exclusions"`
	ThreatScenarios int `json:"threat_scenarios"`
	// ScopeAssets is the number of rows in the cycle's scope snapshot (zero
	// until the cycle is activated).
	ScopeAssets int `json:"scope_assets"`
	// AttackerProfiles is the number of profiles linked to the cycle.
	AttackerProfiles int `json:"attacker_profiles"`
}

// CountSummary is a bare total.
type CountSummary struct {
	Total int `json:"total"`
}

// CrownJewelSummary counts crown jewels and those with an owner (an
// asset_owners row naming a user or group of the tenant).
type CrownJewelSummary struct {
	Total     int `json:"total"`
	WithOwner int `json:"with_owner"`
}

// ServiceSummary counts business services and those linked to an asset.
type ServiceSummary struct {
	Total      int `json:"total"`
	WithAssets int `json:"with_assets"`
}

// AssetSummary counts non-archived assets and those mapped to a business unit.
type AssetSummary struct {
	Total          int `json:"total"`
	InBusinessUnit int `json:"in_business_unit"`
}

// BoundarySummary counts scope targets and exclusions (the totals GET
// /scope/stats reports).
type BoundarySummary struct {
	Targets    int `json:"targets"`
	Exclusions int `json:"exclusions"`
}

// ThreatModelSummary counts threat models and the crown jewels one is scoped to.
type ThreatModelSummary struct {
	Total              int `json:"total"`
	CrownJewelsCovered int `json:"crown_jewels_covered"`
}

// SummaryReader computes the Scoping overview for one tenant.
type SummaryReader interface {
	GetSummary(ctx context.Context, tenantID shared.ID) (*Summary, error)
}
