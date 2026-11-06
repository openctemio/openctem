package handler

import (
	"net/http"

	"github.com/openctemio/openctem/api/internal/app/securityoverview"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// SecurityOverviewHandler serves the organization's security overview
// (docs/architecture/security-overview.md): owners and administrators with
// settings:read.
type SecurityOverviewHandler struct {
	svc    *securityoverview.Service
	logger *logger.Logger
}

// NewSecurityOverviewHandler creates the handler.
func NewSecurityOverviewHandler(svc *securityoverview.Service, log *logger.Logger) *SecurityOverviewHandler {
	return &SecurityOverviewHandler{svc: svc, logger: log.With("handler", "security_overview")}
}

// Get returns the security overview of the organization of the credential.
// @Summary      Get the organization's security overview
// @Description  Posture checks (sign-in, people, credentials, scanning, organization) with a status and a score. Ids, statuses, counts and links only; the console renders the wording.
// @Tags         Tenants
// @Produce      json
// @Success      200  {object}  securityoverview.Overview
// @Failure      403  {object}  map[string]string
// @Router       /organization/security-overview [get]
func (h *SecurityOverviewHandler) Get(w http.ResponseWriter, r *http.Request) {
	id, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil {
		apierror.BadRequest("invalid tenant context").WriteJSON(w)
		return
	}
	o, err := h.svc.Get(r.Context(), id)
	if err != nil {
		h.logger.Error("security overview", "error", err)
		apierror.InternalServerError("could not compute the security overview").WriteJSON(w)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, o)
}
