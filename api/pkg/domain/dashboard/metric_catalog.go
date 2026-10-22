package dashboard

// The widget metric catalog: every metric a typed widget can show, what shape
// its result has, which dimensions it may be filtered and grouped by, and
// which visualizations fit. The catalog is code, not data: the data endpoint
// can only compute what is listed here, and the web renders the gallery and
// the config panel from GET /api/v1/me/dashboards/widget-catalog.
//
// Every metric here is answered from the per-asset fact tables
// (docs/architecture/dashboards.md, "Fact layer"), so any viewer scope applies
// as a join at read time.

// Shape is the form of a widget result.
type Shape string

// Result shapes.
const (
	ShapeScalar     Shape = "scalar"
	ShapeRatio      Shape = "ratio"
	ShapeDuration   Shape = "duration"
	ShapeCategory   Shape = "category"
	ShapeTimeSeries Shape = "time_series"
	ShapeMatrix     Shape = "matrix"
	ShapeItems      Shape = "items"
	// ShapeStages is the CTEM loop: one figure per stage with its status
	// and the list it counts.
	ShapeStages Shape = "stages"
	// ShapePaths is the attack paths that reach crown jewels: a reachable
	// count and the top paths.
	ShapePaths Shape = "paths"
)

// VizType is how a widget result is drawn.
type VizType string

// Visualizations.
const (
	VizStat      VizType = "stat"
	VizProgress  VizType = "progress"
	VizBar       VizType = "bar"
	VizColumn    VizType = "column"
	VizArea      VizType = "area"
	VizLine      VizType = "line"
	VizDiverging VizType = "diverging"
	VizTable     VizType = "table"
	VizHeatmap   VizType = "heatmap"
	VizList      VizType = "list"
	VizDonut     VizType = "donut"
	VizNote      VizType = "note"
	VizLoop      VizType = "loop"
	VizPaths     VizType = "paths"
)

// vizByShape lists the visualizations valid for each result shape; the first
// is the default when a metric declares none for that shape.
var vizByShape = map[Shape][]VizType{
	ShapeScalar:     {VizStat, VizProgress},
	ShapeRatio:      {VizProgress, VizStat},
	ShapeDuration:   {VizStat},
	ShapeCategory:   {VizBar, VizColumn, VizTable, VizDonut, VizStat},
	ShapeTimeSeries: {VizArea, VizLine, VizColumn, VizTable},
	ShapeMatrix:     {VizHeatmap, VizTable, VizColumn},
	ShapeItems:      {VizList, VizTable},
	ShapeStages:     {VizLoop, VizTable},
	ShapePaths:      {VizPaths, VizTable},
}

// Dimension is a fact column a widget may filter or group by.
type Dimension string

// Dimensions carried by the fact tables.
const (
	DimSeverity      Dimension = "severity"
	DimPriorityClass Dimension = "priority_class"
	DimSource        Dimension = "source"
	DimSLAState      Dimension = "sla_state"
	DimAgeBand       Dimension = "age_band"
	DimKEV           Dimension = "kev"
	DimReachable     Dimension = "reachable"
	DimAssetGroup    Dimension = "asset_group"
)

// Polarity says which direction of a change is good, so a delta is colored
// by meaning ("down is good" for open counts), never by sign.
type Polarity string

// Polarities.
const (
	PolarityLowerBetter  Polarity = "lower_better"
	PolarityHigherBetter Polarity = "higher_better"
	PolarityNeutral      Polarity = "neutral"
)

// MetricKind says how a metric's result is computed, so the shape follows
// from the group-by.
type MetricKind string

// Metric kinds.
const (
	// MetricKindCount is a count of open findings (F1): no group-by gives a
	// scalar, one a category, two a matrix.
	MetricKindCount MetricKind = "count"
	// MetricKindRatio is a share (F1): always a ratio.
	MetricKindRatio MetricKind = "ratio"
	// MetricKindDuration is a time-to-fix distribution (F2): a duration, or a
	// category of durations with one group-by.
	MetricKindDuration MetricKind = "duration"
	// MetricKindSeries is a value per time bucket (F1 + F2), split by at most
	// one dimension.
	MetricKindSeries MetricKind = "series"
	// MetricKindItems is a ranked list of findings (F3).
	MetricKindItems MetricKind = "items"
	// MetricKindAssetCount counts assets (crown jewels) with open findings
	// matching the filter (F1 joined to assets): always a scalar.
	MetricKindAssetCount MetricKind = "asset_count"
	// MetricKindStages is the CTEM loop: five stage figures, each read from
	// the source named in docs/architecture/dashboards.md ("CTEM metrics").
	MetricKindStages MetricKind = "stages"
	// MetricKindPaths is the attack paths that reach a crown jewel in scope.
	MetricKindPaths MetricKind = "paths"
)

// Metric is one catalog entry.
type Metric struct {
	ID    string `json:"id"`
	Group string `json:"group"`
	Kind  MetricKind
	// Filters are the dimensions a widget may filter this metric on;
	// GroupBys the ones it may group by (at most MaxGroupBy of them).
	Filters    []Dimension `json:"filters"`
	GroupBys   []Dimension `json:"group_bys"`
	MaxGroupBy int         `json:"max_group_by"`
	// DefaultGroupBy applies when a widget names none (series and fixed
	// matrices).
	DefaultGroupBy []Dimension `json:"default_group_by,omitempty"`
	// DefaultFilter is the preset the metric stands for (for example P0+P1);
	// a widget filter on the same dimension replaces it.
	DefaultFilter WidgetFilter `json:"default_filter"`
	Polarity      Polarity     `json:"polarity"`
	// Timed metrics read a time range (flows, durations, series); counts and
	// ratios are current values whose previous period comes from F2.
	Timed bool `json:"timed"`
	// DefaultViz overrides the first valid visualization of the shape for a
	// widget without group-by.
	DefaultViz VizType `json:"default_viz,omitempty"`
	// Flow marks a series of flows (opened, fixed): columns or diverging
	// bars, never a stacked area that reads as a stock.
	Flow bool `json:"flow,omitempty"`
}

var f1Dims = []Dimension{DimSeverity, DimPriorityClass, DimSource, DimSLAState, DimAgeBand, DimKEV, DimReachable, DimAssetGroup}
var f2Dims = []Dimension{DimSeverity, DimPriorityClass, DimAssetGroup}

// The rank fact keeps the top 10 per asset by its own order, so a merged
// list is exact for up to 10 rows only without filters that cut into that
// order: rank lists take the asset group filter alone.
var f3Dims = []Dimension{DimAssetGroup}
var groupableF1 = []Dimension{DimSeverity, DimPriorityClass, DimSource, DimSLAState, DimAgeBand, DimKEV, DimReachable}

var catalog = []Metric{
	{ID: "findings.open", Group: "exposure", Kind: MetricKindCount, Filters: f1Dims, GroupBys: groupableF1, MaxGroupBy: 2, Polarity: PolarityLowerBetter},
	{ID: "exposure.priority_open", Group: "exposure", Kind: MetricKindCount, Filters: f1Dims, GroupBys: groupableF1, MaxGroupBy: 2,
		DefaultFilter: WidgetFilter{PriorityClass: []string{"P0", "P1"}}, Polarity: PolarityLowerBetter},
	{ID: "exposure.open_by_priority", Group: "exposure", Kind: MetricKindSeries, Filters: f2Dims, GroupBys: []Dimension{DimPriorityClass, DimSeverity}, MaxGroupBy: 1,
		DefaultGroupBy: []Dimension{DimPriorityClass}, DefaultFilter: WidgetFilter{PriorityClass: []string{"P0", "P1", "P2"}}, Polarity: PolarityLowerBetter, Timed: true},
	{ID: "intel.kev_open", Group: "threat_intel", Kind: MetricKindCount, Filters: f1Dims, GroupBys: groupableF1, MaxGroupBy: 2,
		DefaultFilter: WidgetFilter{KEV: boolPtr(true)}, Polarity: PolarityLowerBetter},
	{ID: "findings.age_bands", Group: "remediation", Kind: MetricKindCount, Filters: f1Dims, GroupBys: groupableF1, MaxGroupBy: 2,
		DefaultGroupBy: []Dimension{DimSeverity, DimAgeBand}, Polarity: PolarityLowerBetter},
	{ID: "sla.within", Group: "remediation", Kind: MetricKindRatio, Filters: f1Dims, Polarity: PolarityHigherBetter},
	{ID: "fix.time_to_fix", Group: "remediation", Kind: MetricKindDuration, Filters: f2Dims, GroupBys: []Dimension{DimPriorityClass, DimSeverity}, MaxGroupBy: 1,
		Polarity: PolarityLowerBetter, Timed: true},
	{ID: "flow.new_vs_fixed", Group: "remediation", Kind: MetricKindSeries, Filters: f2Dims, Polarity: PolarityNeutral, Timed: true,
		DefaultViz: VizDiverging, Flow: true},
	// Open P0-P2 findings in rank order (priority, severity, newest); P3 and
	// unclassified come after all of them in the rank, so leaving them out
	// keeps the merged list exact.
	{ID: "fix.next", Group: "exposure", Kind: MetricKindItems, Filters: f3Dims, Polarity: PolarityNeutral},
	{ID: "sla.at_risk", Group: "remediation", Kind: MetricKindItems, Filters: f3Dims, Polarity: PolarityNeutral},
	// Crown jewels in scope with at least one open finding of the filter's
	// priority classes (P0 and P1 by default).
	{ID: "crown_jewels.exposed", Group: "ctem", Kind: MetricKindAssetCount, Filters: []Dimension{DimPriorityClass},
		DefaultFilter: WidgetFilter{PriorityClass: []string{"P0", "P1"}}, Polarity: PolarityLowerBetter},
	// The five CTEM stages for the reader's scope.
	{ID: "ctem.loop", Group: "ctem", Kind: MetricKindStages, Polarity: PolarityNeutral},
	// Attack paths ending at a crown jewel in scope, entry point in scope.
	{ID: "attack_paths.to_crown_jewels", Group: "ctem", Kind: MetricKindPaths, Polarity: PolarityLowerBetter},
}

var catalogByID = func() map[string]Metric {
	m := make(map[string]Metric, len(catalog))
	for _, x := range catalog {
		m[x.ID] = x
	}
	return m
}()

func boolPtr(b bool) *bool { return &b }

// Catalog returns the metric catalog in gallery order (a copy).
func Catalog() []Metric {
	out := make([]Metric, len(catalog))
	copy(out, catalog)
	return out
}

// LookupMetric returns the catalog entry for id.
func LookupMetric(id string) (Metric, bool) {
	m, ok := catalogByID[id]
	return m, ok
}

// ShapeFor is the result shape of the metric for the given group-by.
func (m Metric) ShapeFor(groupBy []Dimension) Shape {
	switch m.Kind {
	case MetricKindRatio:
		return ShapeRatio
	case MetricKindDuration:
		if len(groupBy) > 0 {
			return ShapeCategory
		}
		return ShapeDuration
	case MetricKindSeries:
		return ShapeTimeSeries
	case MetricKindItems:
		return ShapeItems
	case MetricKindAssetCount:
		return ShapeScalar
	case MetricKindStages:
		return ShapeStages
	case MetricKindPaths:
		return ShapePaths
	default: // count
		switch len(groupBy) {
		case 0:
			return ShapeScalar
		case 1:
			return ShapeCategory
		default:
			return ShapeMatrix
		}
	}
}

// Vizzes lists the visualizations valid for the metric with the given
// (effective) group-by, the default first.
func (m Metric) Vizzes(groupBy []Dimension) []VizType {
	if m.Flow {
		// A flow series: diverging bars or columns; an area would read as a stock.
		return []VizType{VizDiverging, VizColumn, VizTable}
	}
	shape := m.ShapeFor(groupBy)
	base := vizByShape[shape]
	out := make([]VizType, 0, len(base)+1)
	if m.DefaultViz != "" && shape == m.ShapeFor(m.DefaultGroupBy) {
		out = append(out, m.DefaultViz)
	}
	for _, v := range base {
		if !containsViz(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// Current reports a metric with no time window or comparison: a ranked
// list, the CTEM loop, attack paths and asset counts are read as they are
// now (no fact history traces them).
func (m Metric) Current() bool {
	switch m.Kind {
	case MetricKindItems, MetricKindAssetCount, MetricKindStages, MetricKindPaths:
		return true
	}
	return false
}

// EffectiveGroupBy is the widget's group-by, or the metric default.
func (m Metric) EffectiveGroupBy(groupBy []Dimension) []Dimension {
	if len(groupBy) > 0 {
		return groupBy
	}
	return m.DefaultGroupBy
}

func containsDim(list []Dimension, d Dimension) bool {
	for _, x := range list {
		if x == d {
			return true
		}
	}
	return false
}

func containsViz(list []VizType, v VizType) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
