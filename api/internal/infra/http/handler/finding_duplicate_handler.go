package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/finding"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AddFindingDuplicateRequest names the finding that duplicates the one in
// the path.
type AddFindingDuplicateRequest struct {
	FindingID string `json:"finding_id" validate:"required,uuid"`
}

// AddFindingDuplicate handles POST /api/v1/findings/{id}/duplicates: the
// finding in the body is marked a duplicate of the one in the path.
//
//	@Summary		Mark a finding as a duplicate of this one
//	@Description	Folds the finding named in the body into the finding in the path, the original (RFC-043 §9). Both must be in the caller's organization and data scope and on the same asset, and neither may already be a duplicate. The canonical finding keeps the stronger status and inherits the duplicate's comments, activities, retests, evidence, tickets and fingerprints; the duplicate stays as a tombstone (status duplicate, duplicate_of). Merging with a false positive or risk acceptance also requires findings:approve. Pentest findings are managed in the pentest module. Returns the canonical finding.
//	@Tags			Findings
//	@Accept			json
//	@Produce		json
//	@Security		BearerAuth
//	@Param			id		path		string						true	"ID of the original finding"
//	@Param			request	body		AddFindingDuplicateRequest	true	"The finding that duplicates it"
//	@Success		200		{object}	FindingResponse
//	@Failure		400		{object}	apierror.Error
//	@Failure		403		{object}	apierror.Error
//	@Failure		404		{object}	apierror.Error
//	@Failure		409		{object}	apierror.Error
//	@Router			/findings/{id}/duplicates [post]
func (h *VulnerabilityHandler) AddFindingDuplicate(w http.ResponseWriter, r *http.Request) {
	var req AddFindingDuplicateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req); err != nil {
		apierror.BadRequest("Invalid request body").WriteJSON(w)
		return
	}
	if err := h.validator.Validate(req); err != nil {
		h.handleValidationError(w, err)
		return
	}
	ctx := r.Context()
	f, err := h.service.MarkDuplicateOf(ctx, finding.MarkDuplicateInput{
		TenantID:      middleware.MustGetTenantID(ctx),
		FindingID:     req.FindingID,
		DuplicateOfID: r.PathValue("id"),
		ActorID:       middleware.GetUserID(ctx),
		CanApprove:    middleware.HasPermission(ctx, string(permission.FindingsApprove)),
		Audit:         h.buildAuditContext(r),
	})
	switch {
	case errors.Is(err, vulnerability.ErrDuplicateNeedsApproval):
		apierror.Forbidden("Merging with a false positive or risk acceptance requires findings:approve").WriteJSON(w)
		return
	case errors.Is(err, vulnerability.ErrDuplicateAlreadyMerged):
		apierror.Conflict("One of the findings is already a duplicate").WriteJSON(w)
		return
	case err != nil:
		h.handleServiceError(w, err, "Finding")
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(toFindingResponse(f))
}
