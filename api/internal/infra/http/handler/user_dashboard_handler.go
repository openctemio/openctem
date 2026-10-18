package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/internal/infra/http/middleware"
	"github.com/openctemio/openctem/api/pkg/apierror"
	dashboard "github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// UserDashboardHandler serves the dashboards API (docs/architecture/dashboards.md):
// personal dashboards under /api/v1/me/dashboards (the caller's own) and
// organization dashboards under /api/v1/organization/dashboards (gated by
// dashboards:org:view / dashboards:org:manage). Tenant and user are read from
// the authenticated context, never from the request.
type UserDashboardHandler struct {
	service *dashboardapp.Service
	logger  *logger.Logger
}

// NewUserDashboardHandler creates a new UserDashboardHandler.
func NewUserDashboardHandler(svc *dashboardapp.Service, log *logger.Logger) *UserDashboardHandler {
	return &UserDashboardHandler{service: svc, logger: log}
}

// UserDashboardResponse is a dashboard as the API returns it.
type UserDashboardResponse struct {
	ID          string             `json:"id"`
	Kind        string             `json:"kind" enums:"personal,organization"`
	Name        string             `json:"name"`
	Description string             `json:"description"`
	Columns     int                `json:"columns"`
	IsDefault   bool               `json:"is_default"`
	Layout      []dashboard.Widget `json:"layout"`
	Origin      string             `json:"origin" enums:"user,builtin,duplicated,shared"`
	// RefreshSchedule is empty when the dashboard follows the organization
	// default.
	RefreshSchedule    string     `json:"refresh_schedule" enums:",manual,5m,15m,1h,6h,daily"`
	RefreshDailyMinute *int       `json:"refresh_daily_minute,omitempty"`
	NextRefreshAt      *time.Time `json:"next_refresh_at,omitempty"`
	PausedAt           *time.Time `json:"paused_at,omitempty"`
	// Organization dashboards only.
	Position     *int `json:"position,omitempty"`
	IsOrgDefault bool `json:"is_org_default,omitempty"`
	// Audience is returned to managers only; empty means every holder of
	// dashboards:org:view.
	Audience  []DashboardAudienceEntry `json:"audience,omitempty"`
	CreatedAt time.Time                `json:"created_at"`
	UpdatedAt time.Time                `json:"updated_at"`
}

// DashboardAudienceEntry is one role or team of an audience.
type DashboardAudienceEntry struct {
	Type string `json:"type" enums:"role,group"`
	ID   string `json:"id"`
	Name string `json:"name,omitempty"`
}

// UserDashboardRequest creates or replaces a dashboard's layout.
type UserDashboardRequest struct {
	// FromOrganizationDashboardID (create of a personal dashboard only)
	// copies the layout of that organization dashboard instead ("duplicate to
	// mine"); the other fields are then ignored.
	FromOrganizationDashboardID string             `json:"from_organization_dashboard_id,omitempty"`
	Name                        string             `json:"name"`
	Description                 string             `json:"description"`
	Columns                     int                `json:"columns"`
	Layout                      []dashboard.Widget `json:"layout"`
}

// DashboardScheduleRequest sets a refresh schedule.
type DashboardScheduleRequest struct {
	// RefreshSchedule: manual, 5m, 15m, 1h, 6h, daily, or empty for the
	// organization default (dashboards only).
	RefreshSchedule    string `json:"refresh_schedule"`
	RefreshDailyMinute *int   `json:"refresh_daily_minute"`
}

// DashboardAudienceRequest replaces an organization dashboard's audience.
type DashboardAudienceRequest struct {
	Audience []DashboardAudienceEntry `json:"audience"`
}

// DashboardOrderRequest sets the order of the organization dashboards.
type DashboardOrderRequest struct {
	IDs []string `json:"ids"`
}

// DashboardShareRequest shares a personal dashboard's layout.
type DashboardShareRequest struct {
	UserIDs []string `json:"user_ids"`
}

// DashboardShareResponse says who got a copy.
type DashboardShareResponse struct {
	Shared  []string                  `json:"shared"`
	Skipped []DashboardShareSkippedID `json:"skipped"`
}

// DashboardShareSkippedID is a recipient who got no copy.
type DashboardShareSkippedID struct {
	UserID string `json:"user_id"`
	Reason string `json:"reason" enums:"not_a_member,limit_reached,self"`
}

// DashboardSettingsResponse is the organization's dashboard defaults.
type DashboardSettingsResponse struct {
	DefaultRefreshSchedule    string `json:"default_refresh_schedule"`
	DefaultRefreshDailyMinute *int   `json:"default_refresh_daily_minute,omitempty"`
	// RefreshFloorMinutes is the shortest cadence this organization may use.
	RefreshFloorMinutes int `json:"refresh_floor_minutes"`
}

func toUserDashboardResponse(d *dashboard.Dashboard) UserDashboardResponse {
	layout := d.Widgets()
	if layout == nil {
		layout = make([]dashboard.Widget, 0)
	}
	s := d.Schedule()
	resp := UserDashboardResponse{
		ID:                 d.ID().String(),
		Kind:               string(d.Kind()),
		Name:               d.Name(),
		Description:        d.Description(),
		Columns:            d.Columns(),
		IsDefault:          d.IsDefault(),
		Layout:             layout,
		Origin:             string(d.Origin()),
		RefreshSchedule:    string(s.Interval),
		RefreshDailyMinute: s.DailyMinute,
		NextRefreshAt:      s.NextRefreshAt,
		PausedAt:           s.PausedAt,
		CreatedAt:          d.CreatedAt(),
		UpdatedAt:          d.UpdatedAt(),
	}
	if d.Kind() == dashboard.KindOrganization {
		pos := d.Position()
		resp.Position = &pos
		resp.IsOrgDefault = d.IsOrgDefault()
	}
	return resp
}

func toOrgDashboardResponse(d *dashboardapp.OrgDashboard) UserDashboardResponse {
	resp := toUserDashboardResponse(d.Dashboard)
	if d.Audience != nil {
		resp.Audience = make([]DashboardAudienceEntry, 0, len(d.Audience))
		for _, e := range d.Audience {
			resp.Audience = append(resp.Audience, DashboardAudienceEntry{Type: string(e.Type), ID: e.ID.String(), Name: e.Name})
		}
	}
	return resp
}

func (h *UserDashboardHandler) caller(w http.ResponseWriter, r *http.Request) (dashboardapp.Caller, bool) {
	ctx := r.Context()
	tid, _ := shared.IDFromString(middleware.GetTenantID(ctx))
	uid, _ := shared.IDFromString(middleware.GetUserID(ctx))
	if tid.IsZero() || uid.IsZero() {
		apierror.Unauthorized("user context required").WriteJSON(w)
		return dashboardapp.Caller{}, false
	}
	return dashboardapp.Caller{
		TenantID: tid,
		UserID:   uid,
		Has:      func(p string) bool { return middleware.HasPermission(ctx, p) },
		Audit: auditapp.AuditContext{
			TenantID: tid.String(), ActorID: uid.String(), ActorEmail: auditActorEmail(ctx),
			ActorIP: getClientIP(r), UserAgent: r.UserAgent(), RequestID: r.Header.Get("X-Request-ID"),
		},
	}, true
}

func decodeDashboardBody(w http.ResponseWriter, r *http.Request, v any) bool {
	// Unknown fields are ignored (layouts saved by older clients carry extra
	// widget keys); the domain validates what is stored.
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := dec.Decode(v); err != nil {
		apierror.BadRequest("invalid request body").WriteJSON(w)
		return false
	}
	return true
}

// ---------------------------------------------------------------------------
// Personal dashboards
// ---------------------------------------------------------------------------

// List handles GET /api/v1/me/dashboards
// @Summary      List my dashboards
// @Description  The caller's personal dashboards (at most 30).
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string][]UserDashboardResponse
// @Router       /me/dashboards [get]
func (h *UserDashboardHandler) List(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	items, err := h.service.List(r.Context(), c.TenantID.String(), c.UserID.String())
	if err != nil {
		h.handleError(w, err)
		return
	}
	data := make([]UserDashboardResponse, 0, len(items))
	for _, d := range items {
		data = append(data, toUserDashboardResponse(d))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// Create handles POST /api/v1/me/dashboards
// @Summary      Create a personal dashboard
// @Description  A new personal dashboard of the caller (at most 30, 40 widgets, 4 KB of config per widget). With from_organization_dashboard_id it copies the layout of that organization dashboard ("duplicate to mine": needs dashboards:org:view and the dashboard's audience); the copy is computed for the caller's own data scope.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      UserDashboardRequest  true  "Dashboard"
// @Success      201   {object}  UserDashboardResponse
// @Failure      400   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Router       /me/dashboards [post]
func (h *UserDashboardHandler) Create(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req UserDashboardRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	if req.FromOrganizationDashboardID != "" {
		d, err := h.service.DuplicateOrg(r.Context(), c, req.FromOrganizationDashboardID)
		if err != nil {
			h.handleError(w, err)
			return
		}
		writeJSON(w, http.StatusCreated, toUserDashboardResponse(d))
		return
	}
	d, err := h.service.Create(r.Context(), c.TenantID.String(), c.UserID.String(), toCreateInput(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toUserDashboardResponse(d))
}

// Get handles GET /api/v1/me/dashboards/{id}
// @Summary      Get one of my dashboards
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  UserDashboardResponse
// @Failure      404  {object}  apierror.Error
// @Router       /me/dashboards/{id} [get]
func (h *UserDashboardHandler) Get(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	d, err := h.service.Get(r.Context(), c.TenantID.String(), c.UserID.String(), r.PathValue("id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserDashboardResponse(d))
}

// Update handles PUT /api/v1/me/dashboards/{id}
// @Summary      Replace one of my dashboards
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                true  "Dashboard ID"
// @Param        body  body      UserDashboardRequest  true  "Dashboard"
// @Success      200   {object}  UserDashboardResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Router       /me/dashboards/{id} [put]
func (h *UserDashboardHandler) Update(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req UserDashboardRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	d, err := h.service.Update(r.Context(), c.TenantID.String(), c.UserID.String(), r.PathValue("id"), toCreateInput(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserDashboardResponse(d))
}

// Delete handles DELETE /api/v1/me/dashboards/{id}
// @Summary      Delete one of my dashboards
// @Tags         Dashboards
// @Security     BearerAuth
// @Param        id   path  string  true  "Dashboard ID"
// @Success      204
// @Failure      404  {object}  apierror.Error
// @Router       /me/dashboards/{id} [delete]
func (h *UserDashboardHandler) Delete(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	if err := h.service.Delete(r.Context(), c.TenantID.String(), c.UserID.String(), r.PathValue("id")); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetDefault handles POST /api/v1/me/dashboards/{id}/default
// @Summary      Make one of my dashboards my default
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  map[string]string
// @Failure      404  {object}  apierror.Error
// @Router       /me/dashboards/{id}/default [post]
func (h *UserDashboardHandler) SetDefault(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	if err := h.service.SetDefault(r.Context(), c.TenantID.String(), c.UserID.String(), r.PathValue("id")); err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// SetSchedule handles PUT /api/v1/me/dashboards/{id}/schedule
// @Summary      Set the refresh schedule of one of my dashboards
// @Description  manual, 5m, 15m, 1h, 6h, daily (with refresh_daily_minute, UTC) or empty for the organization default; never below the organization's refresh floor.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                    true  "Dashboard ID"
// @Param        body  body      DashboardScheduleRequest  true  "Schedule"
// @Success      200   {object}  UserDashboardResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Router       /me/dashboards/{id}/schedule [put]
func (h *UserDashboardHandler) SetSchedule(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req DashboardScheduleRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	d, err := h.service.SetPersonalSchedule(r.Context(), c, r.PathValue("id"), toScheduleInput(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toUserDashboardResponse(d))
}

// Share handles POST /api/v1/me/dashboards/{id}/share
// @Summary      Share the layout of one of my dashboards
// @Description  Each recipient (an active member of this organization, at most 10 per call) gets a personal copy of the layout, computed for their own data scope. No data, schedule or access is shared. Audited.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                 true  "Dashboard ID"
// @Param        body  body      DashboardShareRequest  true  "Recipients"
// @Success      200   {object}  DashboardShareResponse
// @Failure      400   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Router       /me/dashboards/{id}/share [post]
func (h *UserDashboardHandler) Share(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req DashboardShareRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	ids := make([]shared.ID, 0, len(req.UserIDs))
	for _, raw := range req.UserIDs {
		id, err := shared.IDFromString(raw)
		if err != nil {
			apierror.BadRequest("user_ids must be user ids").WriteJSON(w)
			return
		}
		ids = append(ids, id)
	}
	res, err := h.service.SharePersonal(r.Context(), c, r.PathValue("id"), ids)
	if err != nil {
		h.handleError(w, err)
		return
	}
	out := DashboardShareResponse{Shared: make([]string, 0, len(res.Shared)), Skipped: make([]DashboardShareSkippedID, 0, len(res.Skipped))}
	for _, u := range res.Shared {
		out.Shared = append(out.Shared, u.String())
	}
	for _, sk := range res.Skipped {
		out.Skipped = append(out.Skipped, DashboardShareSkippedID{UserID: sk.UserID.String(), Reason: sk.Reason})
	}
	writeJSON(w, http.StatusOK, out)
}

// ---------------------------------------------------------------------------
// Organization dashboards
// ---------------------------------------------------------------------------

// ListOrg handles GET /api/v1/organization/dashboards
// @Summary      List organization dashboards
// @Description  Needs dashboards:org:view. Viewers get the dashboards whose audience admits them; managers (dashboards:org:manage) get every one with its audience. In order; is_org_default marks the default.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  map[string][]UserDashboardResponse
// @Failure      403  {object}  apierror.Error
// @Router       /organization/dashboards [get]
func (h *UserDashboardHandler) ListOrg(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	items, err := h.service.ListOrg(r.Context(), c)
	if err != nil {
		h.handleError(w, err)
		return
	}
	data := make([]UserDashboardResponse, 0, len(items))
	for i := range items {
		data = append(data, toOrgDashboardResponse(&items[i]))
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": data})
}

// GetOrg handles GET /api/v1/organization/dashboards/{id}
// @Summary      Get an organization dashboard
// @Description  Needs dashboards:org:view; outside the dashboard's audience it is not found.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  UserDashboardResponse
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /organization/dashboards/{id} [get]
func (h *UserDashboardHandler) GetOrg(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	d, err := h.service.GetOrg(r.Context(), c, r.PathValue("id"))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOrgDashboardResponse(d))
}

// CreateOrg handles POST /api/v1/organization/dashboards
// @Summary      Create an organization dashboard
// @Description  Needs dashboards:org:manage (at most 50 per organization). Audited.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      UserDashboardRequest  true  "Dashboard"
// @Success      201   {object}  UserDashboardResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Router       /organization/dashboards [post]
func (h *UserDashboardHandler) CreateOrg(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req UserDashboardRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	d, err := h.service.CreateOrg(r.Context(), c, toCreateInput(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, toOrgDashboardResponse(d))
}

// UpdateOrg handles PUT /api/v1/organization/dashboards/{id}
// @Summary      Replace an organization dashboard's layout
// @Description  Needs dashboards:org:manage. Audited.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                true  "Dashboard ID"
// @Param        body  body      UserDashboardRequest  true  "Dashboard"
// @Success      200   {object}  UserDashboardResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Router       /organization/dashboards/{id} [put]
func (h *UserDashboardHandler) UpdateOrg(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req UserDashboardRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	d, err := h.service.UpdateOrg(r.Context(), c, r.PathValue("id"), toCreateInput(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOrgDashboardResponse(d))
}

// DeleteOrg handles DELETE /api/v1/organization/dashboards/{id}
// @Summary      Delete an organization dashboard
// @Description  Needs dashboards:org:manage. Audited.
// @Tags         Dashboards
// @Security     BearerAuth
// @Param        id   path  string  true  "Dashboard ID"
// @Success      204
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /organization/dashboards/{id} [delete]
func (h *UserDashboardHandler) DeleteOrg(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	if err := h.service.DeleteOrg(r.Context(), c, r.PathValue("id")); err != nil {
		h.handleError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// SetOrgDefault handles POST /api/v1/organization/dashboards/{id}/default
// @Summary      Make an organization dashboard the organization default
// @Description  Needs dashboards:org:manage. Audited.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  map[string]string
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Router       /organization/dashboards/{id}/default [post]
func (h *UserDashboardHandler) SetOrgDefault(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	if err := h.service.SetOrgDefault(r.Context(), c, r.PathValue("id")); err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// ReorderOrg handles PUT /api/v1/organization/dashboards/order
// @Summary      Order the organization dashboards
// @Description  Needs dashboards:org:manage. ids must list every organization dashboard exactly once (409 when the list is stale). Audited.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      DashboardOrderRequest  true  "Order"
// @Success      200   {object}  map[string]string
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      409   {object}  apierror.Error
// @Router       /organization/dashboards/order [put]
func (h *UserDashboardHandler) ReorderOrg(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req DashboardOrderRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	if err := h.service.ReorderOrg(r.Context(), c, req.IDs); err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "updated"})
}

// SetOrgAudience handles PUT /api/v1/organization/dashboards/{id}/audience
// @Summary      Set an organization dashboard's audience
// @Description  Needs dashboards:org:manage. Roles and teams of this organization (at most 20); empty means every dashboards:org:view holder. An audience only narrows: its members still need dashboards:org:view. Audited.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                    true  "Dashboard ID"
// @Param        body  body      DashboardAudienceRequest  true  "Audience"
// @Success      200   {object}  UserDashboardResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Router       /organization/dashboards/{id}/audience [put]
func (h *UserDashboardHandler) SetOrgAudience(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req DashboardAudienceRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	entries := make([]dashboard.AudienceEntry, 0, len(req.Audience))
	for _, e := range req.Audience {
		id, err := shared.IDFromString(e.ID)
		if err != nil {
			apierror.BadRequest("audience ids must be role or team ids").WriteJSON(w)
			return
		}
		entries = append(entries, dashboard.AudienceEntry{Type: dashboard.PrincipalType(e.Type), ID: id})
	}
	d, err := h.service.SetOrgAudience(r.Context(), c, r.PathValue("id"), entries)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOrgDashboardResponse(d))
}

// SetOrgSchedule handles PUT /api/v1/organization/dashboards/{id}/schedule
// @Summary      Set an organization dashboard's refresh schedule
// @Description  Needs dashboards:org:manage. Never below the organization's refresh floor. Audited.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        id    path      string                    true  "Dashboard ID"
// @Param        body  body      DashboardScheduleRequest  true  "Schedule"
// @Success      200   {object}  UserDashboardResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Failure      404   {object}  apierror.Error
// @Router       /organization/dashboards/{id}/schedule [put]
func (h *UserDashboardHandler) SetOrgSchedule(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req DashboardScheduleRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	d, err := h.service.SetOrgSchedule(r.Context(), c, r.PathValue("id"), toScheduleInput(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toOrgDashboardResponse(d))
}

// GetSettings handles GET /api/v1/organization/settings/dashboards
// @Summary      Get the organization's dashboard defaults
// @Description  The default refresh schedule and the refresh floor (the shortest cadence this organization may use).
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  DashboardSettingsResponse
// @Router       /organization/settings/dashboards [get]
func (h *UserDashboardHandler) GetSettings(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	st, err := h.service.GetSettings(r.Context(), c)
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDashboardSettingsResponse(st))
}

// UpdateSettings handles PUT /api/v1/organization/settings/dashboards
// @Summary      Set the organization's default refresh schedule
// @Description  Owners and administrators. A cadence (manual, 5m, 15m, 1h, 6h, daily) not below the refresh floor. Audited.
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      DashboardScheduleRequest  true  "Default schedule"
// @Success      200   {object}  DashboardSettingsResponse
// @Failure      400   {object}  apierror.Error
// @Failure      403   {object}  apierror.Error
// @Router       /organization/settings/dashboards [put]
func (h *UserDashboardHandler) UpdateSettings(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok {
		return
	}
	var req DashboardScheduleRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	st, err := h.service.UpdateSettings(r.Context(), c, toScheduleInput(req))
	if err != nil {
		h.handleError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, toDashboardSettingsResponse(st))
}

func toDashboardSettingsResponse(st *dashboardapp.Settings) DashboardSettingsResponse {
	return DashboardSettingsResponse{
		DefaultRefreshSchedule:    string(st.DefaultInterval),
		DefaultRefreshDailyMinute: st.DefaultDailyMinute,
		RefreshFloorMinutes:       st.FloorMinutes,
	}
}

func toCreateInput(req UserDashboardRequest) dashboardapp.CreateInput {
	return dashboardapp.CreateInput{Name: req.Name, Description: req.Description, Columns: req.Columns, Widgets: req.Layout}
}

func toScheduleInput(req DashboardScheduleRequest) dashboardapp.ScheduleInput {
	return dashboardapp.ScheduleInput{Interval: dashboard.Interval(req.RefreshSchedule), DailyMinute: req.RefreshDailyMinute}
}

func (h *UserDashboardHandler) handleError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, shared.ErrNotFound):
		apierror.NotFound("Dashboard").WriteJSON(w)
	case errors.Is(err, shared.ErrForbidden):
		apierror.Forbidden(strings.TrimPrefix(err.Error(), shared.ErrForbidden.Error()+": ")).WriteJSON(w)
	case errors.Is(err, shared.ErrValidation):
		apierror.BadRequest(err.Error()).WriteJSON(w)
	case errors.Is(err, shared.ErrConflict):
		apierror.Conflict(strings.TrimPrefix(err.Error(), shared.ErrConflict.Error()+": ")).WriteJSON(w)
	default:
		h.logger.Error("dashboard error", "error", sanitizeLogField(err.Error()))
		apierror.InternalServerError("internal error").WriteJSON(w)
	}
}
