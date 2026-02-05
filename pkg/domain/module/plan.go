// Package licensing provides domain models for subscription plans and module.
package module

import (
	"time"

	"github.com/google/uuid"
)

// ID represents a unique identifier for licensing entities.
type ID = uuid.UUID

// ParseID parses a string into a licensing ID.
func ParseID(s string) (ID, error) {
	return uuid.Parse(s)
}

// NewID generates a new licensing ID.
func NewID() ID {
	return uuid.New()
}

// Plan represents a subscription plan/tier.
type Plan struct {
	id          ID
	slug        string
	name        string
	description string

	// Pricing
	priceMonthly *float64
	priceYearly  *float64
	currency     string

	// Stripe integration
	stripeProductID      string
	stripePriceIDMonthly string
	stripePriceIDYearly  string

	// Display
	isPublic     bool
	isPopular    bool
	isActive     bool
	displayOrder int

	// Marketing
	features []string
	badge    string

	// Plan limits (for quick reference)
	trialDays    int
	maxUsers     int
	maxAssets    int
	supportLevel string

	// Modules included in this plan
	modules []PlanModule

	// Timestamps
	createdAt time.Time
	updatedAt time.Time
}

// PlanModule represents a module included in a plan with optional limits.
type PlanModule struct {
	moduleID string
	module   *Module
	limits   map[string]any
}

// Getters for Plan

func (p *Plan) ID() ID                       { return p.id }
func (p *Plan) Slug() string                 { return p.slug }
func (p *Plan) Name() string                 { return p.name }
func (p *Plan) Description() string          { return p.description }
func (p *Plan) PriceMonthly() *float64       { return p.priceMonthly }
func (p *Plan) PriceYearly() *float64        { return p.priceYearly }
func (p *Plan) Currency() string             { return p.currency }
func (p *Plan) StripeProductID() string      { return p.stripeProductID }
func (p *Plan) StripePriceIDMonthly() string { return p.stripePriceIDMonthly }
func (p *Plan) StripePriceIDYearly() string  { return p.stripePriceIDYearly }
func (p *Plan) IsPublic() bool               { return p.isPublic }
func (p *Plan) IsPopular() bool              { return p.isPopular }
func (p *Plan) IsActive() bool               { return p.isActive }
func (p *Plan) DisplayOrder() int            { return p.displayOrder }
func (p *Plan) Features() []string           { return p.features }
func (p *Plan) Badge() string                { return p.badge }
func (p *Plan) TrialDays() int               { return p.trialDays }
func (p *Plan) MaxUsers() int                { return p.maxUsers }
func (p *Plan) MaxAssets() int               { return p.maxAssets }
func (p *Plan) SupportLevel() string         { return p.supportLevel }
func (p *Plan) Modules() []PlanModule        { return p.modules }
func (p *Plan) CreatedAt() time.Time         { return p.createdAt }
func (p *Plan) UpdatedAt() time.Time         { return p.updatedAt }

// Getters for PlanModule

func (pm *PlanModule) ModuleID() string       { return pm.moduleID }
func (pm *PlanModule) Module() *Module        { return pm.module }
func (pm *PlanModule) Limits() map[string]any { return pm.limits }

// HasModule checks if the plan includes a specific module.
func (p *Plan) HasModule(moduleID string) bool {
	for _, pm := range p.modules {
		if pm.moduleID == moduleID {
			return true
		}
	}
	return false
}

// GetModuleLimit returns the limit for a specific metric in a module.
// Returns -1 if no limit is set (unlimited).
func (p *Plan) GetModuleLimit(moduleID, metric string) int64 {
	for _, pm := range p.modules {
		if pm.moduleID == moduleID {
			if limit, ok := pm.limits[metric]; ok {
				if f, ok := limit.(float64); ok {
					return int64(f)
				}
			}
			return -1 // No limit
		}
	}
	return 0 // Module not in plan
}

// GetModuleIDs returns all module IDs included in this plan.
func (p *Plan) GetModuleIDs() []string {
	ids := make([]string, 0, len(p.modules))
	for _, pm := range p.modules {
		ids = append(ids, pm.moduleID)
	}
	return ids
}

// ReconstructPlan creates a Plan from stored data.
func ReconstructPlan(
	id ID,
	slug, name, description string,
	priceMonthly, priceYearly *float64,
	currency string,
	stripeProductID, stripePriceIDMonthly, stripePriceIDYearly string,
	isPublic, isPopular, isActive bool,
	displayOrder int,
	features []string,
	badge string,
	trialDays, maxUsers, maxAssets int,
	supportLevel string,
	modules []PlanModule,
	createdAt, updatedAt time.Time,
) *Plan {
	return &Plan{
		id:                   id,
		slug:                 slug,
		name:                 name,
		description:          description,
		priceMonthly:         priceMonthly,
		priceYearly:          priceYearly,
		currency:             currency,
		stripeProductID:      stripeProductID,
		stripePriceIDMonthly: stripePriceIDMonthly,
		stripePriceIDYearly:  stripePriceIDYearly,
		isPublic:             isPublic,
		isPopular:            isPopular,
		isActive:             isActive,
		displayOrder:         displayOrder,
		features:             features,
		badge:                badge,
		trialDays:            trialDays,
		maxUsers:             maxUsers,
		maxAssets:            maxAssets,
		supportLevel:         supportLevel,
		modules:              modules,
		createdAt:            createdAt,
		updatedAt:            updatedAt,
	}
}

// ReconstructPlanModule creates a PlanModule from stored data.
func ReconstructPlanModule(moduleID string, module *Module, limits map[string]any) PlanModule {
	return PlanModule{
		moduleID: moduleID,
		module:   module,
		limits:   limits,
	}
}
