package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/openctemio/openctem/api/internal/app/dashboard/widgets"
	"github.com/openctemio/openctem/api/pkg/apierror"
	dashboard "github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// WidgetCatalogMetric is one metric of the typed widget catalog. Shapes maps
// a group-by count ("0", "1", "2") to the result shape and the valid
// visualizations (default first), so the web never re-derives the rules.
type WidgetCatalogMetric struct {
	ID             string                         `json:"id"`
	Group          string                         `json:"group"`
	Filters        []dashboard.Dimension          `json:"filters"`
	GroupBys       []dashboard.Dimension          `json:"group_bys"`
	MaxGroupBy     int                            `json:"max_group_by"`
	DefaultGroupBy []dashboard.Dimension          `json:"default_group_by"`
	DefaultFilter  dashboard.WidgetFilter         `json:"default_filter"`
	Polarity       dashboard.Polarity             `json:"polarity" enums:"lower_better,higher_better,neutral"`
	Timed          bool                           `json:"timed"`
	Flow           bool                           `json:"flow"`
	Shapes         map[string]WidgetCatalogShapes `json:"shapes"`
}

// WidgetCatalogShapes is the result shape for one group-by count.
type WidgetCatalogShapes struct {
	Shape  dashboard.Shape     `json:"shape" enums:"scalar,ratio,duration,category,time_series,matrix,items"`
	Vizzes []dashboard.VizType `json:"vizzes"`
}

// WidgetCatalogResponse is the typed widget catalog.
type WidgetCatalogResponse struct {
	SpecVersion int                              `json:"spec_version"`
	Metrics     []WidgetCatalogMetric            `json:"metrics"`
	Dimensions  map[dashboard.Dimension][]string `json:"dimensions"`
	TimeRanges  []string                         `json:"time_ranges"`
	TimeBuckets []string                         `json:"time_buckets"`
	Comparisons []string                         `json:"comparisons"`
	TargetOps   []string                         `json:"target_ops"`
}

var widgetCatalog = buildWidgetCatalog()

func buildWidgetCatalog() WidgetCatalogResponse {
	metrics := dashboard.Catalog()
	out := WidgetCatalogResponse{
		SpecVersion: dashboard.WidgetSpecVersion,
		Metrics:     make([]WidgetCatalogMetric, 0, len(metrics)),
		Dimensions:  dashboard.FilterValues(),
		TimeRanges:  dashboard.TimeRanges,
		TimeBuckets: dashboard.TimeBuckets,
		Comparisons: dashboard.Comparisons,
		TargetOps:   dashboard.TargetOps,
	}
	for _, m := range metrics {
		shapes := map[string]WidgetCatalogShapes{}
		for n := 0; n <= m.MaxGroupBy; n++ {
			gb := m.DefaultGroupBy
			if n > 0 && len(m.GroupBys) >= n {
				gb = m.GroupBys[:n]
			}
			key := string(rune('0' + n))
			shapes[key] = WidgetCatalogShapes{Shape: m.ShapeFor(m.EffectiveGroupBy(gb)), Vizzes: m.Vizzes(m.EffectiveGroupBy(gb))}
		}
		out.Metrics = append(out.Metrics, WidgetCatalogMetric{
			ID: m.ID, Group: m.Group, Filters: nonNilDims(m.Filters), GroupBys: nonNilDims(m.GroupBys),
			MaxGroupBy: m.MaxGroupBy, DefaultGroupBy: nonNilDims(m.DefaultGroupBy), DefaultFilter: m.DefaultFilter,
			Polarity: m.Polarity, Timed: m.Timed, Flow: m.Flow, Shapes: shapes,
		})
	}
	return out
}

func nonNilDims(d []dashboard.Dimension) []dashboard.Dimension {
	if d == nil {
		return []dashboard.Dimension{}
	}
	return d
}

// WidgetCatalog handles GET /api/v1/me/dashboards/widget-catalog
// @Summary      Typed widget catalog
// @Description  The metrics a typed dashboard widget can show (config.data.metric), with the dimensions each may be filtered and grouped by, its result shape per group-by count and the visualizations that fit, plus the allowed enum values. Static: the same for every caller and holds no organization data.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Success      200  {object}  WidgetCatalogResponse
// @Router       /me/dashboards/widget-catalog [get]
func (h *UserDashboardHandler) WidgetCatalog(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.caller(w, r); !ok {
		return
	}
	writeJSON(w, http.StatusOK, widgetCatalog)
}

// SetWidgetData wires the widget data service (the data and preview routes
// answer 503 without it).
func (h *UserDashboardHandler) SetWidgetData(svc *widgets.Service) *UserDashboardHandler {
	h.widgets = svc
	return h
}

func (h *UserDashboardHandler) widgetsReady(w http.ResponseWriter) bool {
	if h.widgets == nil {
		apierror.ServiceUnavailable("dashboard data is not available").WriteJSON(w)
		return false
	}
	return true
}

func (h *UserDashboardHandler) widgetError(w http.ResponseWriter, err error) {
	var budget *widgets.ErrRefreshBudget
	if errors.As(err, &budget) {
		w.Header().Set("Retry-After", strconv.Itoa(max(int(budget.RetryAfter.Seconds()+0.999), 1)))
		apierror.TooManyRequests(budget.Error()).WriteJSON(w)
		return
	}
	var preview *widgets.ErrPreviewRate
	if errors.As(err, &preview) {
		w.Header().Set("Retry-After", strconv.Itoa(max(int(preview.RetryAfter.Seconds()+0.999), 1)))
		apierror.TooManyRequests(preview.Error()).WriteJSON(w)
		return
	}
	for _, busy := range []error{widgets.ErrBusy, widgets.ErrRefreshRunning} {
		if errors.Is(err, busy) {
			w.Header().Set("Retry-After", "2")
			apierror.TooManyRequests(busy.Error()).WriteJSON(w)
			return
		}
	}
	h.handleError(w, err)
}

// PersonalData handles GET /api/v1/me/dashboards/{id}/data
// @Summary      Widget results of my dashboard
// @Description  Every widget of the caller's personal dashboard, computed from the dashboard fact tables for the caller's own data scope and the pentest campaign rule. Typed widgets and the legacy tiles the facts can answer return a result; other legacy tiles return state "unsupported". Another person's dashboard is 404. 429 when too many dashboard reads run.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  widgets.DashboardData
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /me/dashboards/{id}/data [get]
func (h *UserDashboardHandler) PersonalData(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok || !h.widgetsReady(w) {
		return
	}
	out, err := h.widgets.PersonalData(r.Context(), c, r.PathValue("id"))
	if err != nil {
		h.widgetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// OrgData handles GET /api/v1/organization/dashboards/{id}/data
// @Summary      Widget results of an organization dashboard
// @Description  Every widget of an organization dashboard, computed for the whole organization (needs dashboards:org:view; outside the dashboard's audience it is 404). Finding titles in lists still follow the viewer's pentest campaign membership. 429 when too many dashboard reads run.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  widgets.DashboardData
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /organization/dashboards/{id}/data [get]
func (h *UserDashboardHandler) OrgData(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok || !h.widgetsReady(w) {
		return
	}
	out, err := h.widgets.OrgData(r.Context(), c, r.PathValue("id"))
	if err != nil {
		h.widgetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// WidgetPreviewRequest is one typed widget to preview.
type WidgetPreviewRequest struct {
	WidgetType string         `json:"widget_type" enums:"metric,note"`
	Config     map[string]any `json:"config"`
}

// PreviewWidget handles POST /api/v1/me/dashboards/widget-preview
// @Summary      Preview a typed widget
// @Description  Computes one typed widget spec for the caller's own data scope (the widget gallery and the config panel). The spec is validated like a saved widget (400 when refused). 429 with Retry-After when too many dashboard reads run or the caller previews faster than the per-person limit (a burst of 24, then one every 2 s).
// @Tags         Dashboards
// @Accept       json
// @Produce      json
// @Security     BearerAuth
// @Param        body  body      WidgetPreviewRequest  true  "Widget"
// @Success      200   {object}  widgets.WidgetValue
// @Failure      400   {object}  apierror.Error
// @Failure      429   {object}  apierror.Error
// @Router       /me/dashboards/widget-preview [post]
func (h *UserDashboardHandler) PreviewWidget(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok || !h.widgetsReady(w) {
		return
	}
	var req WidgetPreviewRequest
	if !decodeDashboardBody(w, r, &req) {
		return
	}
	out, err := h.widgets.Preview(r.Context(), c, req.WidgetType, req.Config)
	if err != nil {
		h.widgetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// RefreshPersonal handles POST /api/v1/me/dashboards/{id}/refresh
// @Summary      Refresh my dashboard now
// @Description  Recomputes the caller's personal dashboard from the fact tables and stores the snapshot ("Refresh now"). Budget: once a minute per person and dashboard, 30 an hour per organization (429 with Retry-After); 429 also while another refresh of the dashboard runs (the budget is not used). A refresh that cannot compute gives its budget back.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  widgets.DashboardData
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /me/dashboards/{id}/refresh [post]
func (h *UserDashboardHandler) RefreshPersonal(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok || !h.widgetsReady(w) {
		return
	}
	out, err := h.widgets.RefreshPersonal(r.Context(), c, r.PathValue("id"))
	if err != nil {
		h.widgetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

// RefreshOrg handles POST /api/v1/organization/dashboards/{id}/refresh
// @Summary      Refresh an organization dashboard now
// @Description  Recomputes an organization dashboard the caller may read (dashboards:org:view and the audience) and stores the snapshot. Budget: once a minute per person and dashboard, 30 an hour per organization (429 with Retry-After); 429 also while another refresh of the dashboard runs (the budget is not used). A refresh that cannot compute gives its budget back.
// @Tags         Dashboards
// @Produce      json
// @Security     BearerAuth
// @Param        id   path      string  true  "Dashboard ID"
// @Success      200  {object}  widgets.DashboardData
// @Failure      403  {object}  apierror.Error
// @Failure      404  {object}  apierror.Error
// @Failure      429  {object}  apierror.Error
// @Router       /organization/dashboards/{id}/refresh [post]
func (h *UserDashboardHandler) RefreshOrg(w http.ResponseWriter, r *http.Request) {
	c, ok := h.caller(w, r)
	if !ok || !h.widgetsReady(w) {
		return
	}
	out, err := h.widgets.RefreshOrg(r.Context(), c, r.PathValue("id"))
	if err != nil {
		h.widgetError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}
