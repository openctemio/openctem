package threatmodel

import (
	"context"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/pagination"
)

// ThreatFilter narrows the threats returned for a model. Zero-value fields are
// ignored (no filter).
type ThreatFilter struct {
	Status            ThreatStatus // "" = any status
	AttackerProfileID *shared.ID   // nil = any attacker
	Tactic            string       // "" = any tactic
	TechniqueID       string       // "" = any technique
}

// ModelFilter narrows the models returned by List. Zero-value fields are ignored.
type ModelFilter struct {
	ScopeType  ScopeType  // "" = any scope type
	ScopeRefID *shared.ID // nil = any scope ref
}

// Repository persists and reads threat models (tenant-scoped runtime tables) and
// reads the global ATT&CK catalog (tenant-agnostic seed).
type Repository interface {
	// Save creates or replaces a threat model AND its threats in a single
	// transaction: the model is upserted on its (tenant, scope) unique key and
	// its threats are delete-and-inserted (full regeneration — no drift, no
	// stale-row reconciliation). The passed model's rollup counters are persisted
	// as-is; call ThreatModel.RecomputeRollups before Save.
	Save(ctx context.Context, model *ThreatModel, threats []*ThreatModelThreat) error

	// GetByID returns a model by id, tenant-scoped. Returns ErrNotFound if absent.
	GetByID(ctx context.Context, tenantID, id shared.ID) (*ThreatModel, error)

	// GetByScope returns the model for a (scopeType, scopeRefID) pair, tenant-
	// scoped. scopeRefID is nil for a tenant-wide model. Returns ErrNotFound if
	// no model has been generated for the scope yet.
	GetByScope(ctx context.Context, tenantID shared.ID, scopeType ScopeType, scopeRefID *shared.ID) (*ThreatModel, error)

	// ListModels returns models for a tenant, filtered and paginated, plus the
	// total count matching the filter (ignoring pagination).
	ListModels(ctx context.Context, tenantID shared.ID, filter ModelFilter, page pagination.Pagination) ([]*ThreatModel, int, error)

	// ListThreats returns the threats for a model, tenant-scoped and filterable
	// by status / attacker / tactic / technique. Ordered by hop_index, score.
	ListThreats(ctx context.Context, tenantID, modelID shared.ID, filter ThreatFilter) ([]*ThreatModelThreat, error)

	// Delete removes a model and (via ON DELETE CASCADE) its threats. Tenant-scoped.
	Delete(ctx context.Context, tenantID, id shared.ID) error

	// ListTechniqueMitigations returns the global technique→mitigation catalog for
	// a dataset version. Not tenant-scoped (global seed).
	ListTechniqueMitigations(ctx context.Context, datasetVersion string) ([]TechniqueMitigation, error)

	// ListApplicability returns the global technique-applicability catalog for a
	// dataset version. Not tenant-scoped (global seed).
	ListApplicability(ctx context.Context, datasetVersion string) ([]TechniqueApplicability, error)
}
