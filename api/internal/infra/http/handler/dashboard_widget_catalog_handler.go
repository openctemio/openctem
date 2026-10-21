package handler

import (
	"net/http"

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
