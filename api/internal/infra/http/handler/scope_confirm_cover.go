package handler

// Confirming an asset also puts it in scope (RFC-054 §14, R3). Both decision
// routes (the review queue and an asset's attribution) call the scope
// service after a confirmation and answer what it did.

import (
	"context"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeConfirmCoverer adds the exact scope entry of confirmed assets
// (*scope.Service).
type ScopeConfirmCoverer interface {
	CoverConfirmedAssets(ctx context.Context, tenantID string, actor scope.Actor, assetIDs []string) (*scope.ConfirmCoverage, error)
}

// coverConfirmed runs the rule for the assets just set to confirmed. A
// failure is logged and answered as nothing added: the decision is saved
// and audited already, and the caller can still add the entries.
func coverConfirmed(r *http.Request, c ScopeConfirmCoverer, log *logger.Logger, tenantID string, state attribution.State, assetIDs []string) *scope.ConfirmCoverage {
	if c == nil || state != attribution.StateConfirmed || len(assetIDs) == 0 {
		return nil
	}
	out, err := c.CoverConfirmedAssets(r.Context(), tenantID, scopeActor(r), assetIDs)
	if err != nil {
		log.Warn("adding confirmed assets to scope failed", "error", logger.SanitizeError(err))
		return nil
	}
	return out
}
