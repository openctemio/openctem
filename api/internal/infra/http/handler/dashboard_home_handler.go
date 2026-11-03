package handler

import (
	"net/http"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

// DashboardHomeResponse is everything the dashboard home needs to paint.
type DashboardHomeResponse struct {
	// Personal is the caller's own dashboards (the same list as
	// GET /me/dashboards).
	Personal []UserDashboardResponse `json:"personal"`
	// Organization is the organization dashboards the caller may read (the
	// same list as GET /organization/dashboards). Absent without
	// dashboards:org:view or dashboards:org:manage.
	Organization *[]UserDashboardResponse `json:"organization,omitempty"`
	// Landing is the dashboard to open; null when the caller has none.
	Landing *dashboardapp.Ref `json:"landing"`
	// Data is the landing dashboard's widget results, the payload of its
	// /data route. Absent when there is no landing dashboard, the caller
	// cannot read dashboard figures, or the figures could not be read now
	// (the client then asks the /data route, which says why).
	Data *widgets.DashboardData `json:"data,omitempty"`
}

// Home handles GET /api/v1/me/dashboards/home
// @Summary      Open the dashboard home
// @Description  The dashboard home in one read: the caller's dashboards, the organization dashboards the caller may read (omitted without dashboards:org:view or dashboards:org:manage), the dashboard to open, and that dashboard's widget results. The landing rule: the dashboard named by choice while it is one the caller can read, else the caller's own default, else the organization default (or its first dashboard), else the caller's first own dashboard. A choice that is malformed, deleted, someone else's or outside the audience is ignored. Every list and figure is what the per-dashboard routes return for the same caller.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        choice  query     string  false  "The viewer's remembered dashboard: personal:<id> or organization:<id>"
// @Success      200     {object}  DashboardHomeResponse
// @Router       /me/dashboards/home [get]
func (h *UserDashboardHandler) Home(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	home, err := h.service.Home(r.Context(), c, dashboardapp.ParseRef(r.URL.Query().Get("choice")))
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := DashboardHomeResponse{
		Personal: make([]UserDashboardResponse, 0, len(home.Personal)),
		Landing:  home.Landing,
	}
	for _, d := range home.Personal {
		out.Personal = append(out.Personal, toUserDashboardResponse(d))
	}
	if home.Organization != nil {
		org := make([]UserDashboardResponse, 0, len(home.Organization))
		for i := range home.Organization {
			org = append(org, toOrgDashboardResponse(&home.Organization[i]))
		}
		out.Organization = &org
	}
	out.Data = h.homeData(r, c, home.Landing)
	writeJSON(w, http.StatusOK, out)
}

// homeData reads the landing dashboard's figures through the same service
// calls as the /data routes (the personal route also needs dashboard:read).
// A failure leaves the figures out: the lists are still right, and the
// client's own read of the /data route reports the reason (busy, forbidden).
func (h *UserDashboardHandler) homeData(r *http.Request, c dashboardapp.Caller, landing *dashboardapp.Ref) *widgets.DashboardData {
	if landing == nil || h.widgets == nil {
		return nil
	}
	var (
		out *widgets.DashboardData
		err error
	)
	if landing.Kind == "organization" {
		out, err = h.widgets.OrgData(r.Context(), c, landing.ID)
	} else {
		if !c.Has(permission.DashboardRead.String()) {
			return nil
		}
		out, err = h.widgets.PersonalData(r.Context(), c, landing.ID)
	}
	if err != nil {
		h.logger.Warn("dashboard home: figures not read", "error", sanitizeLogField(err.Error()))
		return nil
	}
	return out
}
