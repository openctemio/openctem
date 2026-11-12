package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/internal/app/lifecycle"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// IdleWorkspaceHandler serves an organization's idle lifecycle in the
// console (docs/architecture/idle-workspaces.md).
type IdleWorkspaceHandler struct {
	svc    *lifecycle.Service
	logger *logger.Logger
}

// NewIdleWorkspaceHandler creates the handler.
func NewIdleWorkspaceHandler(svc *lifecycle.Service, log *logger.Logger) *IdleWorkspaceHandler {
	return &IdleWorkspaceHandler{svc: svc, logger: log.With("handler", "idle-workspace")}
}

// IdleWorkspaceResponse is an organization's idle lifecycle.
type IdleWorkspaceResponse struct {
	Stage          string     `json:"stage"`
	StageChangedAt *time.Time `json:"stage_changed_at,omitempty"`
	LastSignIn     *time.Time `json:"last_sign_in,omitempty"`
	ReadOnly       bool       `json:"read_only"`
	PolicyEnabled  bool       `json:"policy_enabled"`
	PolicyReason   string     `json:"policy_reason,omitempty"`
	PolicySetAt    *time.Time `json:"policy_set_at,omitempty"`
}

// SetIdlePolicyRequest turns the idle policy on or off for an organization.
type SetIdlePolicyRequest struct {
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason"`
}

func (h *IdleWorkspaceHandler) write(w http.ResponseWriter, r *http.Request, id shared.ID) {
	st, err := h.svc.Status(r.Context(), id)
	if err != nil {
		if errors.Is(err, shared.ErrNotFound) {
			apierror.NotFound("Organization").WriteJSON(w)
			return
		}
		h.logger.Error("read idle lifecycle", "error", err)
		apierror.InternalServerError("could not read the idle lifecycle").WriteJSON(w)
		return
	}
	writeJSON(w, http.StatusOK, IdleWorkspaceResponse{
		Stage: string(st.Stage), StageChangedAt: st.StageChangedAt, LastSignIn: st.LastSignIn,
		ReadOnly: h.svc.ReadOnly(r.Context(), id), PolicyEnabled: st.PolicyEnabled, PolicyReason: st.PolicyReason, PolicySetAt: st.PolicySetAt,
	})
}

// Get returns an organization's idle lifecycle (any admin).
// @Summary      Get an organization's idle lifecycle (platform admin)
// @Description  Only for organizations the idle policy is on for (off by default): nobody signs in, reminded at 60 days, read-only at 90, warned at 113 and due for deletion at 120.
// @Tags         Admin Organizations
// @Produce      json
// @Param        tenantId  path  string  true  "Organization ID"
// @Success      200  {object}  IdleWorkspaceResponse
// @Router       /admin/tenants/{tenantId}/idle [get]
func (h *IdleWorkspaceHandler) Get(w http.ResponseWriter, r *http.Request) {
	if id, ok := adminTenantID(w, r); ok {
		h.write(w, r, id)
	}
}

// SetPolicy turns the idle policy on or off for an organization (ops_admin+,
// audited; a reason is required both ways).
// @Summary      Turn the idle policy on or off for an organization (platform admin)
// @Description  Off by default. When on, an organization nobody signs in to is reminded, then made read-only, then marked for deletion; a sign-in resets it.
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                true  "Organization ID"
// @Param        request   body  SetIdlePolicyRequest  true  "Policy"
// @Success      200  {object}  IdleWorkspaceResponse
// @Router       /admin/tenants/{tenantId}/idle/policy [put]
func (h *IdleWorkspaceHandler) SetPolicy(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok {
		return
	}
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req SetIdlePolicyRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.svc.ChangePolicy(r.Context(), actor, id, req.Enabled, req.Reason, middleware.ClientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, lifecycle.ErrInvalidPolicyReason) {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		h.logger.Error("set idle policy", "error", err)
		apierror.InternalServerError("could not change the idle policy").WriteJSON(w)
		return
	}
	h.write(w, r, id)
}
