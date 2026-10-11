package handler

// GET /api/v1/scope/suggestions/addresses: the public addresses in-scope
// names resolve to, for one click into scope. Design:
// docs/rfcs/RFC-054-scope-model.md §14.7.

import (
	"context"
	"encoding/json"
	"net/http"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScopeAddressSuggester lists address suggestions (*easm.AddressSuggester).
type ScopeAddressSuggester interface {
	Suggest(ctx context.Context, tenantID shared.ID) (*easmapp.AddressSuggestions, error)
}

// SetAddressSuggester wires the address suggestions.
func (h *ScopeHandler) SetAddressSuggester(s ScopeAddressSuggester) { h.addresses = s }

// SuggestAddresses handles GET /api/v1/scope/suggestions/addresses
// @Summary      Addresses behind in-scope names
// @Description  The public addresses the organization's in-scope names resolve to that no scope entry covers, each with the names it came from (RFC-054 §14.7). Addresses that look shared (an edge or CDN provider, or names of three or more registrable domains resolve to them) are left out and counted. Narrowed to the caller's data scope. Nothing is added: add them with POST /scope/targets/bulk.
// @Tags         Scope
// @Produce      json
// @Success      200  {object}  easmapp.AddressSuggestions
// @Failure      401  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/suggestions/addresses [get]
func (h *ScopeHandler) SuggestAddresses(w http.ResponseWriter, r *http.Request) {
	if h.addresses == nil {
		apierror.NotFound("Address suggestions").WriteJSON(w)
		return
	}
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	out, err := h.addresses.Suggest(r.Context(), tenantID)
	if err != nil {
		h.logger.Error("scope address suggestions", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to list address suggestions").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}
