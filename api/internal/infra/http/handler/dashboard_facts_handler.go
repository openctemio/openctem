package handler

// "Rebuild dashboard data" (docs/architecture/dashboards.md, "Facts
// maintainer"): the organization's owners and administrators, and platform
// administrators in the console, read the fact status and ask for a full
// rebuild, at most once per hour per organization. The tenant comes from the
// authenticated context (the session's organization, or the console's path
// organization set by AdminTenantScope), never from the body.

import (
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	factsapp "github.com/openctemio/openctem/api/internal/app/dashboard/facts"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	"github.com/openctemio/openctem/api/pkg/domain/dashboardfact"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// DashboardFactsHandler serves the dashboard fact status and rebuild routes.
type DashboardFactsHandler struct {
	svc    *factsapp.Service
	logger *logger.Logger
}

// NewDashboardFactsHandler creates the handler.
func NewDashboardFactsHandler(svc *factsapp.Service, log *logger.Logger) *DashboardFactsHandler {
	return &DashboardFactsHandler{svc: svc, logger: log}
}

func (h *DashboardFactsHandler) tenant(w http.ResponseWriter, r *http.Request) (shared.ID, bool) {
	tid, err := shared.IDFromString(middleware.GetTenantID(r.Context()))
	if err != nil || tid.IsZero() {
		apierror.BadRequest("organization context required").WriteJSON(w)
		return shared.ID{}, false
	}
	return tid, true
}

// Status returns the fact status of the caller's organization.
func (h *DashboardFactsHandler) Status(w http.ResponseWriter, r *http.Request) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	st, err := h.svc.Status(r.Context(), tid)
	if err != nil {
		h.logger.Error("dashboard fact status failed", "error", err)
		apierror.InternalServerError("could not read dashboard data status").WriteJSON(w)
		return
	}
	writeFactStatus(w, http.StatusOK, st)
}

// RequestRebuild asks for a rebuild of the caller's organization's
// dashboard data (owner or administrator).
func (h *DashboardFactsHandler) RequestRebuild(w http.ResponseWriter, r *http.Request) {
	h.requestRebuild(w, r, factsapp.OriginOrganization)
}

// ConsoleRequestRebuild is RequestRebuild for a platform administrator, on
// the organization named in the console path.
func (h *DashboardFactsHandler) ConsoleRequestRebuild(w http.ResponseWriter, r *http.Request) {
	h.requestRebuild(w, r, factsapp.OriginConsole)
}

func (h *DashboardFactsHandler) requestRebuild(w http.ResponseWriter, r *http.Request, origin factsapp.Origin) {
	tid, ok := h.tenant(w, r)
	if !ok {
		return
	}
	st, err := h.svc.RequestRebuild(r.Context(), tid, origin, configAuditContext(r))
	if err != nil {
		if tooSoon, isTooSoon := dashboardfact.AsTooSoon(err); isTooSoon {
			secs := int(math.Ceil(time.Until(tooSoon.RetryAt).Seconds()))
			w.Header().Set("Retry-After", strconv.Itoa(max(secs, 1)))
			apierror.TooManyRequests("Dashboard data can be rebuilt once per hour").WriteJSON(w)
			return
		}
		if errors.Is(err, shared.ErrValidation) {
			apierror.BadRequest("organization context required").WriteJSON(w)
			return
		}
		h.logger.Error("dashboard rebuild request failed", "error", err)
		apierror.InternalServerError("could not request a dashboard data rebuild").WriteJSON(w)
		return
	}
	writeFactStatus(w, http.StatusAccepted, st)
}

func writeFactStatus(w http.ResponseWriter, code int, st dashboardfact.Status) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(st)
}
