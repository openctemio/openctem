package handler

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
)

// SetExclusionTesting handles PUT /api/v1/scope/exclusions/{id}/testing
// @Summary      Set how a path exclusion may be tested
// @Description  blocked (default: nothing is sent), read_only (GET and HEAD only) or allowed (treated as in scope),
// @Description  optionally until testing_until (at most 90 days), after which it is blocked again. Only a path
// @Description  exclusion has a testing mode. Needs attack_surface:scope:exclusions:approve and a recent sign-in
// @Description  (step-up); audited, and the administrators are notified. It never widens scope: a target must still
// @Description  be the organization's in-scope asset, and tier ceilings, guardrails and the deny list still apply (RFC-056).
// @Tags         Scope
// @Accept       json
// @Produce      json
// @Param        id    path  string                      true  "Exclusion ID"
// @Param        body  body  SetExclusionTestingRequest  true  "Testing mode"
// @Success      200  {object}  ScopeExclusionResponse
// @Failure      400  {object}  apierror.Error
// @Failure      401  {object}  apierror.Error "Step-up required"
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Security     BearerAuth
// @Router       /scope/exclusions/{id}/testing [put]
func (h *ScopeHandler) SetExclusionTesting(w http.ResponseWriter, r *http.Request) {
	exclusionID := chi.URLParam(r, "id")
	tenantID := middleware.MustGetTenantID(r.Context())
	userID := middleware.GetUserID(r.Context())

	var req SetExclusionTestingRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		apierror.BadRequest("Invalid JSON").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	before, after, err := h.service.ChangeExclusionTesting(r.Context(), scope.SetTestingInput{
		TenantID: tenantID, ExclusionID: exclusionID, Testing: req.Testing,
		TestingUntil: req.TestingUntil, ChangedBy: userID,
	})
	if err != nil {
		h.handleServiceError(w, "Scope exclusion", err)
		return
	}
	h.auditExclusion(r, audit.ActionScopeExclusionUpdated, exclusionID, before, after)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toScopeExclusionResponse(after))
}
