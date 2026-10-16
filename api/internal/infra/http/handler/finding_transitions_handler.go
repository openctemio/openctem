package handler

import (
	"encoding/json"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingTransitionsResponse lists the moves the lifecycle has from the
// finding's status, each with the caller's decision.
type FindingTransitionsResponse struct {
	Status      string                             `json:"status"`
	Transitions []vulnerability.TransitionDecision `json:"transitions"`
}

// EvaluateTransitionsRequest is the bulk dry run's body.
type EvaluateTransitionsRequest struct {
	FindingIDs []string `json:"finding_ids" validate:"required,min=1,max=100,dive,uuid"`
	To         string   `json:"to" validate:"required,max=32"`
}

// EvaluateTransitionsResponse is the per-finding answer of a dry run.
type EvaluateTransitionsResponse struct {
	To      string                        `json:"to"`
	Results []finding.EvaluatedTransition `json:"results"`
}

// callerTransitionPermissions are the finding permissions of the request's
// caller (an owner or admin holds them all).
func callerTransitionPermissions(r *http.Request) finding.TransitionPermissions {
	has := func(p permission.Permission) bool { return middleware.HasPermission(r.Context(), string(p)) }
	return finding.TransitionPermissions{
		Status:   has(permission.FindingsStatus),
		Verify:   has(permission.FindingsVerify),
		FixApply: has(permission.FindingsFixApply),
		Triage:   has(permission.FindingsTriage),
		Write:    has(permission.FindingsWrite),
	}
}

// GetFindingTransitions handles GET /api/v1/findings/{id}/transitions.
// @Summary      Allowed status moves of a finding
// @Description  Every move the lifecycle has from the finding's status, with the caller's decision: allowed, how (direct, an approval request, the duplicate picker), the inputs it needs, or the reason codes why not. The same engine decides every status change.
// @Tags         Findings
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Finding ID"
// @Success      200  {object}  FindingTransitionsResponse
// @Failure      404  {object}  map[string]string
// @Router       /findings/{id}/transitions [get]
func (h *VulnerabilityHandler) GetFindingTransitions(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	tenantID := middleware.GetTenantID(r.Context())
	actorID := middleware.GetUserID(r.Context())
	transitions, status, err := h.service.ListFindingTransitions(r.Context(), tenantID, id, actorID, callerTransitionPermissions(r))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	writeJSON(w, http.StatusOK, FindingTransitionsResponse{Status: status.String(), Transitions: transitions})
}

// EvaluateFindingTransitions handles POST /api/v1/findings/transitions/preview.
// @Summary      Dry run of a status change for many findings
// @Description  For each finding (at most 100), whether the caller may move it to the target status and the reason codes why not. Changes nothing. An id that is not a finding the caller can see is answered not_found.
// @Tags         Findings
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        request  body      EvaluateTransitionsRequest  true  "Findings and target status"
// @Success      200  {object}  EvaluateTransitionsResponse
// @Failure      400  {object}  map[string]string
// @Router       /findings/transitions/preview [post]
func (h *VulnerabilityHandler) EvaluateFindingTransitions(w http.ResponseWriter, r *http.Request) {
	var req EvaluateTransitionsRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	tenantID := middleware.GetTenantID(r.Context())
	actorID := middleware.GetUserID(r.Context())
	results, err := h.service.EvaluateFindingTransitions(r.Context(), tenantID, req.FindingIDs, req.To, actorID, callerTransitionPermissions(r))
	if err != nil {
		h.handleServiceError(w, err, "Finding")
		return
	}
	writeJSON(w, http.StatusOK, EvaluateTransitionsResponse{To: req.To, Results: results})
}
