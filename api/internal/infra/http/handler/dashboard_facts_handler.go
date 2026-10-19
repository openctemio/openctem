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
// @Summary     Dashboard data status
// @Description Freshness and queue state of the organization's pre-computed dashboard data (owner or administrator).
// @Tags        Dashboards
// @Produce     json
// @Security    BearerAuth
// @Success     200 {object} dashboardfact.Status
// @Failure     400 {object} map[string]string
// @Failure     401 {object} map[string]string
// @Failure     403 {object} map[string]string
// @Failure     500 {object} map[string]string
// @Router      /dashboard-data [get]
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
// @Summary     Request a dashboard data rebuild
// @Description Asks for a rebuild of derived dashboard data; accepted once per hour per organization.
// @Tags        Dashboards
// @Produce     json
// @Security    BearerAuth
// @Success     202 {object} dashboardfact.Status
// @Failure     400 {object} map[string]string
// @Failure     401 {object} map[string]string
// @Failure     403 {object} map[string]string
// @Failure     429 {object} map[string]string
// @Failure     500 {object} map[string]string
// @Router      /dashboard-data/rebuild [post]
func (h *DashboardFactsHandler) RequestRebuild(w http.ResponseWriter, r *http.Request) {
	h.requestRebuild(w, r, factsapp.OriginOrganization)
}

// ConsoleStatus is Status for a platform administrator, on the organization
// named in the console path.
// @Summary     Dashboard data status of an organization
// @Description Platform admin console: freshness and queue state of the organization's pre-computed dashboard data.
// @Tags        Admin Organization Dashboard Data
// @Produce     json
// @Param       tenantId path string true "Organization ID"
// @Security    BearerAuth
// @Success     200 {object} dashboardfact.Status
// @Failure     400 {object} map[string]string
// @Failure     401 {object} map[string]string
// @Failure     403 {object} map[string]string
// @Failure     500 {object} map[string]string
// @Router      /admin/tenants/{tenantId}/dashboard-data [get]
func (h *DashboardFactsHandler) ConsoleStatus(w http.ResponseWriter, r *http.Request) {
	h.Status(w, r)
}

// ConsoleRequestRebuild is RequestRebuild for a platform administrator, on
// the organization named in the console path.
// @Summary     Request a dashboard data rebuild for an organization
// @Description Platform admin console: asks for a rebuild of the organization's derived dashboard data; shares the once-per-hour limit with the organization's own request. Audited.
// @Tags        Admin Organization Dashboard Data
// @Produce     json
// @Param       tenantId path string true "Organization ID"
// @Security    BearerAuth
// @Success     202 {object} dashboardfact.Status
// @Failure     400 {object} map[string]string
// @Failure     401 {object} map[string]string
// @Failure     403 {object} map[string]string
// @Failure     429 {object} map[string]string
// @Failure     500 {object} map[string]string
// @Router      /admin/tenants/{tenantId}/dashboard-data/rebuild [post]
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
