package handler

import (
	"encoding/json"
	"net/http"

	appremediation "github.com/openctemio/api/internal/app/remediation"
	"github.com/openctemio/api/internal/infra/http/middleware"
	"github.com/openctemio/api/pkg/apierror"
	"github.com/openctemio/api/pkg/domain/permission"
	remediationdom "github.com/openctemio/api/pkg/domain/remediation"
	"github.com/openctemio/api/pkg/domain/shared"
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
	// Status to move the group's findings to: "fix_applied" (default, pending
	// rescan verification) or "resolved" (immediate close).
	Status string `json:"status" validate:"omitempty,oneof=fix_applied resolved"`
	// Resolution note.
	Resolution string `json:"resolution" validate:"max=1000"`
	// Approved lets an over-ceiling bulk through the abuse guard.
	Approved bool `json:"approved"`
}

// ResolveGroup handles POST /api/v1/findings/remediation-groups/{key}/resolve
// @Summary      Resolve a remediation group
// @Description  Transitions every open finding sharing the fix to the requested status in one action.
// @Tags         Findings
// @Security     BearerAuth
// @Param        key  path  string  true  "Remediation group key"
// @Success      200  {object}  map[string]int
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
		Key:                 key,
		Status:              req.Status,
		Resolution:          req.Resolution,
		ActorID:             middleware.GetUserID(r.Context()),
		HasVerifyPermission: middleware.HasPermission(r.Context(), string(permission.FindingsVerify)),
		OperatorApproved:    req.Approved,
	})
	if err != nil {
		apierror.FromError(err).WriteJSON(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]int{
		"updated": result.Updated,
		"failed":  result.Failed,
	})
}
