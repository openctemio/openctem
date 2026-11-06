package handler

import (
	"context"
	"encoding/json"
	"net/http"

	easmapp "github.com/openctemio/openctem/api/internal/app/easm"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// EASMSuggester builds the attack surface suggestion cards (research/117).
type EASMSuggester interface {
	Cards(ctx context.Context, tenantID shared.ID, canAdd bool) (*easmapp.SuggestionCards, error)
}

// SetSuggestions wires the suggestion cards.
func (h *EASMHandler) SetSuggestions(s EASMSuggester) *EASMHandler {
	h.suggestions = s
	return h
}

// HasSuggestions reports whether the suggestion cards are wired.
func (h *EASMHandler) HasSuggestions() bool { return h.suggestions != nil }

// SuggestionCards handles GET /api/v1/easm/suggestions
// @Summary      Attack surface suggestions
// @Description  The scope decisions that still need a person, one card each. addresses_behind_names: the addresses the organization's in-scope names resolve to and no entry covers (a name never lends its address authority); shared or CDN addresses are listed apart with the reason and never offered, and an address whose network is unknown is counted as such, never presented as safe. Addresses the organization's unclassified-scans mode already checks are listed in checked_addresses and wait for nothing. confirmed_out_of_scope: assets a person confirmed that no entry covers. total (the Review badge) counts the cards that offer something plus name_rules, the review-by-rule cards over the names that need review. Nothing is added here: accepting a card is POST /scope/targets/bulk with its items (can_add says whether the caller may). Narrowed to the caller's data scope.
// @Tags         Attack Surface
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  easmapp.SuggestionCards
// @Failure      401  {object}  apierror.Error
// @Failure      500  {object}  apierror.Error
// @Router       /easm/suggestions [get]
func (h *EASMHandler) SuggestionCards(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(ctx))
	if err != nil {
		apierror.Unauthorized("Invalid tenant ID").WriteJSON(w)
		return
	}
	out, err := h.suggestionCards(ctx, tenantID, middleware.HasPermission(ctx, permission.ScopeWrite.String()))
	if err != nil {
		h.logger.Error("attack surface suggestions", "error", logger.SanitizeError(err))
		apierror.InternalServerError("failed to build suggestions").WriteJSON(w)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// suggestionCards is the cards with Total: the cards that offer something
// plus the review-by-rule cards of names (one per suggested rule, and one for
// the names no rule groups), over the same states the Review tab lists
// (easmapp.DecisionStates). Address rule suggestions are left out: the
// addresses card holds them.
func (h *EASMHandler) suggestionCards(ctx context.Context, tenantID shared.ID, canAdd bool) (*easmapp.SuggestionCards, error) {
	out, err := h.suggestions.Cards(ctx, tenantID, canAdd)
	if err != nil {
		return nil, err
	}
	if h.rules == nil {
		out.Finish(0)
		return out, nil
	}
	rs, err := h.rules.Suggest(ctx, tenantID, easmapp.DecisionStates, easmapp.MaxRuleSuggestions)
	if err != nil {
		return nil, err
	}
	out.Finish(easmapp.NameRuleCards(rs))
	return out, nil
}
