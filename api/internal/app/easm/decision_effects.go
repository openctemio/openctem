package easm

// What follows a person's attribution decision (research/22 P0-9):
//
//   - the findings on the decided assets are reclassified now (bug 22c B4:
//     the P2 cap on unconfirmed assets lifted only on the 12-hour sweep);
//   - on "rejected" ("Not ours"), the EASM exposures of that name and every
//     name under it (CT and DNS checks) are resolved (bug 22c B2).
//
// Both are best effort: the decision is already stored and audited, and a
// failure here is logged, never returned. Architecture: docs/architecture/easm.md.

import (
	"context"

	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RejectedExposureResolver resolves the EASM exposures of rejected names
// (*postgres.ExposureRepository).
type RejectedExposureResolver interface {
	ResolveRejectedNames(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID) (int, error)
}

// AssetReclassifier queues an asset-scoped priority reclassification.
type AssetReclassifier func(ctx context.Context, tenantID shared.ID, assetIDs []shared.ID)

// DecisionEffects runs the follow-ups of an attribution decision.
type DecisionEffects struct {
	resolver   RejectedExposureResolver
	reclassify AssetReclassifier
	logger     *logger.Logger
}

// NewDecisionEffects wires the follow-ups; either may be nil.
func NewDecisionEffects(resolver RejectedExposureResolver, reclassify AssetReclassifier, log *logger.Logger) *DecisionEffects {
	if log == nil {
		log = logger.NewNop()
	}
	return &DecisionEffects{resolver: resolver, reclassify: reclassify, logger: log.With("service", "easm_decision_effects")}
}

// AfterDecision runs the follow-ups for assets of the tenant that a person
// just set to state. Ids must be ones the decision stored (tenant and data
// scope already checked by the caller).
func (e *DecisionEffects) AfterDecision(ctx context.Context, tenantID shared.ID, assetIDs []string, state attribution.State) {
	if e == nil || len(assetIDs) == 0 {
		return
	}
	ids := make([]shared.ID, 0, len(assetIDs))
	for _, raw := range assetIDs {
		if id, err := shared.IDFromString(raw); err == nil {
			ids = append(ids, id)
		}
	}
	if len(ids) == 0 {
		return
	}
	if state == attribution.StateRejected && e.resolver != nil {
		n, err := e.resolver.ResolveRejectedNames(ctx, tenantID, ids)
		if err != nil {
			e.logger.Warn("exposures of rejected names not resolved", "tenant_id", tenantID.String(), "error", err)
		} else if n > 0 {
			e.logger.Info("exposures of rejected names resolved", "tenant_id", tenantID.String(), "count", n)
		}
	}
	if e.reclassify != nil {
		e.reclassify(ctx, tenantID, ids)
	}
}
