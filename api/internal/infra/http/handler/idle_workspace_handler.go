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
	Exempt         bool       `json:"exempt"`
	ExemptReason   string     `json:"exempt_reason,omitempty"`
	ExemptAt       *time.Time `json:"exempt_at,omitempty"`
}

// SetIdleExemptionRequest exempts an organization (or lifts it).
type SetIdleExemptionRequest struct {
	Exempt bool   `json:"exempt"`
	Reason string `json:"reason"`
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
		ReadOnly: h.svc.ReadOnly(r.Context(), id), Exempt: st.Exempt, ExemptReason: st.ExemptReason, ExemptAt: st.ExemptAt,
	})
}

// Get returns an organization's idle lifecycle (any admin).
// @Summary      Get an organization's idle lifecycle (platform admin)
// @Description  Free organizations nobody signs in to are reminded at 60 days, read-only at 90, warned at 113 and due for deletion at 120.
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

// SetExemption exempts an organization from the idle lifecycle or lifts the
// exemption (ops_admin+, audited; a reason is required to exempt).
// @Summary      Exempt an organization from the idle lifecycle (platform admin)
// @Tags         Admin Organizations
// @Accept       json
// @Produce      json
// @Param        tenantId  path  string                   true  "Organization ID"
// @Param        request   body  SetIdleExemptionRequest  true  "Exemption"
// @Success      200  {object}  IdleWorkspaceResponse
// @Router       /admin/tenants/{tenantId}/idle/exemption [put]
func (h *IdleWorkspaceHandler) SetExemption(w http.ResponseWriter, r *http.Request) {
	actor := middleware.GetAdminUser(r.Context())
	id, ok := adminTenantID(w, r)
	if !ok {
		return
	}
	if actor == nil {
		apierror.Unauthorized("administrator session required").WriteJSON(w)
		return
	}
	var req SetIdleExemptionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&req); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return
	}
	if err := h.svc.ChangeExemption(r.Context(), actor, id, req.Exempt, req.Reason, middleware.ClientIP(r), r.UserAgent()); err != nil {
		if errors.Is(err, lifecycle.ErrInvalidExemption) {
			apierror.BadRequest(err.Error()).WriteJSON(w)
			return
		}
		h.logger.Error("set idle exemption", "error", err)
		apierror.InternalServerError("could not change the exemption").WriteJSON(w)
		return
	}
	h.write(w, r, id)
}
