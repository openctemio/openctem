package handler

import (
	"net/http"
	"time"

	"github.com/openctemio/openctem/api/pkg/logger"
)

const (
	// overviewCacheTTL is how long one caller's computed overview is served
	// again. The dashboard reloads it on every visit; its aggregates scan a
	// tenant's findings and assets, seconds of database time at scale.
	overviewCacheTTL = 15 * time.Second
	// overviewTenantParts caps the parts one tenant's overviews run at the
	// same time, across all its callers, so a burst of dashboard loads in one
	// tenant cannot take every database connection.
	overviewTenantParts = 4
	// overviewReadCost is what one overview takes from the caller's read
	// budget (twelve parts, several of them heavy aggregates).
	overviewReadCost = 6
)

// DashboardOverviewParts are the reads the CTEM dashboard shows, by the exact
// URL the web asks for each one. The overview answers them in one response
// (research/81: the dashboard sent twelve requests on every load).
var DashboardOverviewParts = []string{ //nolint:gochecknoglobals // fixed allowlist
	"/api/v1/me/dashboards",
	"/api/v1/dashboard/risk-trend?days=90",
	"/api/v1/dashboard/executive-summary",
	"/api/v1/dashboard/stats",
	"/api/v1/threat-intel/stats",
	"/api/v1/attack-surface/exposure-chains",
	"/api/v1/attack-surface/attack-paths",
	"/api/v1/scans/coverage",
	"/api/v1/validation/coverage",
	"/api/v1/scoping/summary",
	"/api/v1/ctem-cycles/metrics/trend",
	"/api/v1/assets/stats",
}

// DashboardOverviewResponse maps each part's URL to its answer.
type DashboardOverviewResponse = ViewResponse

// DashboardOverviewHandler serves GET /dashboard/overview: the dashboard's
// reads in one response.
//
// Each part is answered by sending its GET through the API's own router with
// the caller's credentials (the Cookie and Authorization headers of this
// request), so every part goes through exactly the gates of its endpoint:
// authentication, tenant, permission, module and data scope. A part the
// caller may not read comes back with its 401/403/404 and no body, as the
// endpoint would answer. Only the fixed DashboardOverviewParts are ever
// dispatched; nothing in the request chooses a path.
type DashboardOverviewHandler struct {
	view *viewParts
}

// NewDashboardOverviewHandler creates the handler. router returns the API's
// root router (read at request time, when every route is registered).
func NewDashboardOverviewHandler(router func() http.Handler, log *logger.Logger) *DashboardOverviewHandler {
	return &DashboardOverviewHandler{view: newViewParts(router, log, viewOptions{
		name: "dashboard overview", cacheTTL: overviewCacheTTL, tenantParts: overviewTenantParts, readCost: overviewReadCost,
	})}
}

// Overview handles GET /api/v1/dashboard/overview
// @Summary      Dashboard overview
// @Description  The CTEM dashboard's reads in one response: each part keyed by the URL of its endpoint, with that
// @Description  endpoint's status and JSON body. Every part goes through its own endpoint's permission, module and
// @Description  data-scope gates; a part the caller may not read has its error status and no body.
// @Description  A caller's overview is reused for a few seconds, and one tenant runs only a few parts at a time.
// @Tags         Dashboard
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  ViewResponse
// @Router       /dashboard/overview [get]
func (h *DashboardOverviewHandler) Overview(w http.ResponseWriter, r *http.Request) {
	h.view.serve(w, r, "", DashboardOverviewParts)
}
