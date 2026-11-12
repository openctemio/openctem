package handler

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/finding"
	appremediation "github.com/openctemio/openctem/api/internal/app/remediation"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
	remediationdom "github.com/openctemio/openctem/api/pkg/domain/remediation"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// RemediationGroupHandler exposes remediation groups — the "fix a whole solution
// family in one action" surface (RFC-015).
type RemediationGroupHandler struct {
	service *appremediation.GroupService
}

// NewRemediationGroupHandler constructs the handler.
func NewRemediationGroupHandler(service *appremediation.GroupService) *RemediationGroupHandler {
	return &RemediationGroupHandler{service: service}
}

type remediationGroupsResponse struct {
	Groups []remediationdom.Group `json:"groups"`
}

// ListGroups handles GET /api/v1/findings/remediation-groups
// @Summary      List remediation groups
// @Description  Groups the tenant's open findings by the fix that resolves them (one patch → many findings).
// @Tags         Findings
// @Security     BearerAuth
// @Success      200  {object}  remediationGroupsResponse
// @Router       /findings/remediation-groups [get]
func (h *RemediationGroupHandler) ListGroups(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}

	groups, err := h.service.ListGroups(r.Context(), tenantID)
	if err != nil {
		apierror.InternalError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(remediationGroupsResponse{Groups: groups})
}

// ResolveGroupRequest is the body for resolving a remediation group.
type ResolveGroupRequest struct {
	// Status: "fix_applied" (the default and the only target). A group
	// resolve marks its findings fixed; each one is verified on its own.
	Status string `json:"status" validate:"omitempty,oneof=fix_applied"`
	// Resolution is the note of the fix claim (required).
	Resolution string `json:"resolution" validate:"max=1000"`
	// Approved lets an over-ceiling bulk through the abuse guard.
	Approved bool `json:"approved"`
}

// ResolveGroup handles POST /api/v1/findings/remediation-groups/{key}/resolve
// @Summary      Mark a remediation group fixed
// @Description  Marks every open, in-scope finding sharing the fix fixed (fix_applied through the legal steps), with a note, for the caller's own findings, and queues a proof-of-fix re-check per finding. Never closes a finding. Every finding not updated is listed with the reason.
// @Tags         Findings
// @Security     BearerAuth
// @Param        key  path  string  true  "Remediation group key"
// @Param        body body ResolveGroupRequest true "Fix claim"
// @Success      200  {object}  MarkFixedResponse
// @Router       /findings/remediation-groups/{key}/resolve [post]
func (h *RemediationGroupHandler) ResolveGroup(w http.ResponseWriter, r *http.Request) {
	tenantID, err := shared.IDFromString(middleware.MustGetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant").WriteJSON(w)
		return
	}
	key := r.PathValue("key")
	if key == "" {
		apierror.BadRequest("group key is required").WriteJSON(w)
		return
	}

	var req ResolveGroupRequest
	if r.ContentLength > 0 {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			apierror.BadRequest("invalid request body").WriteJSON(w)
			return
		}
	}

	result, err := h.service.ResolveGroup(r.Context(), tenantID, appremediation.ResolveGroupInput{
		Key:                   key,
		Status:                req.Status,
		Resolution:            req.Resolution,
		ActorID:               middleware.GetUserID(r.Context()),
		HasVerifyPermission:   middleware.HasPermission(r.Context(), string(permission.FindingsVerify)),
		HasFixApplyPermission: middleware.HasPermission(r.Context(), string(permission.FindingsFixApply)),
		OperatorApproved:      req.Approved,
	})
	if err != nil {
		writeGroupResolveError(w, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(newMarkFixedResponse(result.Updated, result.Skipped, result.Failed, result.ValidationsQueued, result.Rows))
}

// MarkFixedRow is one finding a "mark fixed" did not update, and why.
type MarkFixedRow struct {
	FindingID string `json:"finding_id"`
	Outcome   string `json:"outcome"` // skipped | failed
	Reason    string `json:"reason"`
}

// MarkFixedResponse is the outcome of marking a remediation group or a
// campaign fixed: no failure is silent.
type MarkFixedResponse struct {
	Updated           int            `json:"updated"`
	Skipped           int            `json:"skipped"`
	Failed            int            `json:"failed"`
	ValidationsQueued int            `json:"validations_queued"`
	Rows              []MarkFixedRow `json:"rows"`
}

func newMarkFixedResponse(updated, skipped, failed, queued int, rows []finding.BulkRowResult) MarkFixedResponse {
	out := MarkFixedResponse{Updated: updated, Skipped: skipped, Failed: failed, ValidationsQueued: queued,
		Rows: make([]MarkFixedRow, 0, len(rows))}
	for _, r := range rows {
		out.Rows = append(out.Rows, MarkFixedRow(r))
	}
	return out
}

// writeGroupResolveError maps a group-resolve failure to its HTTP status:
// a refused resolve (no findings:verify) is 403 and a bad request 400, not the
// 500 a raw domain error would become.
func writeGroupResolveError(w http.ResponseWriter, err error) {
	if apiErr, ok := errors.AsType[*apierror.Error](err); ok {
		apiErr.WriteJSON(w)
		return
	}
	switch {
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("remediation group").WriteJSON(w)
	default:
		apierror.FromError(err).WriteJSON(w)
	}
}
