package dashboard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// Typed widgets (docs/architecture/dashboards.md, "Widget spec").
//
// A typed widget is a query over the metric catalog plus how to draw it:
// Widget.WidgetType is the data kind ("metric" or "note") and Widget.Config is
// a WidgetSpec. The spec is decoded strictly (unknown fields refused), every
// enum is checked against the catalog, and the stored config is the
// normalized spec, so nothing the server did not validate is ever kept.
//
// A widget of any other type is a legacy tile, drawn by its id; its config is
// never read, so a legacy tile cannot smuggle a query either. LegacySpec maps
// the legacy ids that the facts can answer to an equivalent spec.

// Widget kinds of a typed widget (Widget.WidgetType and WidgetSpec.Data.Kind).
const (
	WidgetKindMetric = "metric"
	WidgetKindNote   = "note"
)

// WidgetSpecVersion is the version of the typed widget config.
const WidgetSpecVersion = 2

const (
	maxWidgetTitleLen  = 120
	maxNoteTextLen     = 2000
	maxFilterValues    = 20
	maxAssetGroups     = 10
	maxItemsLimit      = 10
	defaultItemsLimit  = 10
	maxCategoryLimit   = 50
	defaultTimeRange   = TimeRangeInherit
	defaultTimeBucket  = TimeBucketAuto
	defaultTimeCompare = CompareNone
)

// Time ranges, buckets and comparisons a widget may ask for. "inherit" uses
// the dashboard's range (30 days until the dashboard filter bar exists).
const (
	TimeRangeInherit = "inherit"
	TimeRange7d      = "7d"
	TimeRange30d     = "30d"
	TimeRange90d     = "90d"
	TimeRange365d    = "365d"

	TimeBucketAuto  = "auto"
	TimeBucketDay   = "day"
	TimeBucketWeek  = "week"
	TimeBucketMonth = "month"

	CompareNone           = "none"
	ComparePreviousPeriod = "previous_period"
)

// Allowed values, in display order.
var (
	TimeRanges   = []string{TimeRangeInherit, TimeRange7d, TimeRange30d, TimeRange90d, TimeRange365d}
	TimeBuckets  = []string{TimeBucketAuto, TimeBucketDay, TimeBucketWeek, TimeBucketMonth}
	Comparisons  = []string{CompareNone, ComparePreviousPeriod}
	TargetOps    = []string{"<=", ">="}
	DrillModes   = []string{"auto", "none"}
	Orientations = []string{"horizontal", "vertical"}
	// Fact-side enum values of the dimensions that are not finding enums.
	SLAStates      = []string{"ok", "warning", "breached", "none"}
	AgeBands       = []string{"0-30", "31-60", "61-90", "90+"}
	PriorityValues = []string{"P0", "P1", "P2", "P3", "none"}
)

var widgetIDPattern = regexp.MustCompile(`^w_[a-z0-9]{1,16}$`)

// WidgetSpec is the typed widget config.
type WidgetSpec struct {
	V          int           `json:"v"`
	ID         string        `json:"id"`
	Title      string        `json:"title,omitempty"`
	Data       WidgetData    `json:"data"`
	Viz        WidgetViz     `json:"viz"`
	Target     *WidgetTarget `json:"target,omitempty"`
	Drill      string        `json:"drill,omitempty"`
	PinFilters bool          `json:"pin_filters,omitempty"`
}

// WidgetData is what the widget computes.
type WidgetData struct {
	Kind    string       `json:"kind"`
	Metric  string       `json:"metric,omitempty"`
	Filter  WidgetFilter `json:"filter"`
	GroupBy []Dimension  `json:"group_by,omitempty"`
	Time    WidgetTime   `json:"time"`
	Limit   int          `json:"limit,omitempty"`
	Text    string       `json:"text,omitempty"`
}

// WidgetFilter narrows a metric on the dimensions the fact tables carry.
// Values are enum members; asset groups are ids resolved inside the reader's
// tenant at read time (an id of another tenant matches nothing).
type WidgetFilter struct {
	Severity      []string `json:"severity,omitempty"`
	PriorityClass []string `json:"priority_class,omitempty"`
	Source        []string `json:"source,omitempty"`
	SLAState      []string `json:"sla_state,omitempty"`
	AgeBand       []string `json:"age_band,omitempty"`
	KEV           *bool    `json:"kev,omitempty"`
	Reachable     *bool    `json:"reachable,omitempty"`
	AssetGroupIDs []string `json:"asset_group_id,omitempty"`
}

// WidgetTime is the window of a timed metric and the comparison period.
type WidgetTime struct {
	Range   string `json:"range,omitempty"`
	Bucket  string `json:"bucket,omitempty"`
	Compare string `json:"compare,omitempty"`
}

// WidgetViz is how the result is drawn.
type WidgetViz struct {
	Type    VizType    `json:"type"`
	Options VizOptions `json:"options"`
}

// VizOptions are the drawing options a visualization may take.
type VizOptions struct {
	Orientation string `json:"orientation,omitempty"`
	Stacked     bool   `json:"stacked,omitempty"`
	ShowTable   bool   `json:"show_table,omitempty"`
	Sparkline   bool   `json:"sparkline,omitempty"`
}

// WidgetTarget is the widget's own target; a widget without one uses none
// (program targets in settings come later).
type WidgetTarget struct {
	Op    string  `json:"op"`
	Value float64 `json:"value"`
}

// IsTypedWidget reports whether a widget type is a typed (spec) widget.
func IsTypedWidget(widgetType string) bool {
	return widgetType == WidgetKindMetric || widgetType == WidgetKindNote
}

// ParseWidgetSpec decodes and validates a typed widget config. Unknown fields,
// unknown metrics, dimensions the metric does not allow, values outside an
// enum and visualizations that do not fit the result shape are refused.
func ParseWidgetSpec(widgetType string, config map[string]any) (WidgetSpec, error) {
	raw, err := json.Marshal(config)
	if err != nil {
		return WidgetSpec{}, fmt.Errorf("%w: config is not valid JSON", shared.ErrValidation)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var s WidgetSpec
	if err := dec.Decode(&s); err != nil {
		return WidgetSpec{}, fmt.Errorf("%w: config: %s", shared.ErrValidation, sanitizeDecodeError(err))
	}
	if err := s.normalize(widgetType); err != nil {
		return WidgetSpec{}, err
	}
	return s, nil
}

// sanitizeDecodeError keeps the decoder's reason short and free of the input.
func sanitizeDecodeError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, "unknown field "); i >= 0 {
		return msg[i:]
	}
	if strings.Contains(msg, "cannot unmarshal") {
		return "a field has the wrong type"
	}
	return "malformed"
}

func (s *WidgetSpec) normalize(widgetType string) error {
	if s.V != WidgetSpecVersion {
		return fmt.Errorf("%w: config.v must be %d", shared.ErrValidation, WidgetSpecVersion)
	}
	if !widgetIDPattern.MatchString(s.ID) {
		return fmt.Errorf("%w: config.id must match w_[a-z0-9]{1,16}", shared.ErrValidation)
	}
	s.Title = strings.TrimSpace(s.Title)
	if len([]rune(s.Title)) > maxWidgetTitleLen {
		return fmt.Errorf("%w: config.title must be at most %d characters", shared.ErrValidation, maxWidgetTitleLen)
	}
	if s.Data.Kind != widgetType {
		return fmt.Errorf("%w: config.data.kind must equal widget_type", shared.ErrValidation)
	}
	if s.Drill == "" {
		s.Drill = "auto"
	}
	if !containsStr(DrillModes, s.Drill) {
		return fmt.Errorf("%w: config.drill must be one of %v", shared.ErrValidation, DrillModes)
	}
	if s.Viz.Options.Orientation != "" && !containsStr(Orientations, s.Viz.Options.Orientation) {
		return fmt.Errorf("%w: config.viz.options.orientation must be one of %v", shared.ErrValidation, Orientations)
	}
	switch widgetType {
	case WidgetKindNote:
		return s.normalizeNote()
	case WidgetKindMetric:
		return s.normalizeMetric()
	default:
		return fmt.Errorf("%w: unknown widget kind", shared.ErrValidation)
	}
}

func (s *WidgetSpec) normalizeNote() error {
	s.Data.Text = strings.TrimSpace(s.Data.Text)
	if s.Data.Text == "" || len([]rune(s.Data.Text)) > maxNoteTextLen {
		return fmt.Errorf("%w: a note needs text of at most %d characters", shared.ErrValidation, maxNoteTextLen)
	}
	if s.Data.Metric != "" || len(s.Data.GroupBy) > 0 || s.Data.Limit != 0 || !s.Data.Filter.isEmpty() ||
		s.Data.Time != (WidgetTime{}) || s.Target != nil {
		return fmt.Errorf("%w: a note takes only text", shared.ErrValidation)
	}
	if s.Viz.Type == "" {
		s.Viz.Type = VizNote
	}
	if s.Viz.Type != VizNote {
		return fmt.Errorf("%w: a note is drawn as a note", shared.ErrValidation)
	}
	s.Drill = "none"
	return nil
}

//nolint:cyclop // one check per field of the spec, in order
func (s *WidgetSpec) normalizeMetric() error {
	m, ok := LookupMetric(s.Data.Metric)
	if !ok {
		return fmt.Errorf("%w: unknown metric", shared.ErrValidation)
	}
	if s.Data.Text != "" {
		return fmt.Errorf("%w: only a note takes text", shared.ErrValidation)
	}
	if err := s.Data.Filter.validate(m); err != nil {
		return err
	}
	if len(s.Data.GroupBy) > m.MaxGroupBy {
		return fmt.Errorf("%w: metric %s takes at most %d group-by dimensions", shared.ErrValidation, m.ID, m.MaxGroupBy)
	}
	seen := map[Dimension]bool{}
	for _, d := range s.Data.GroupBy {
		if !containsDim(m.GroupBys, d) || seen[d] {
			return fmt.Errorf("%w: metric %s cannot be grouped by %q", shared.ErrValidation, m.ID, d)
		}
		seen[d] = true
	}
	if err := s.Data.Time.normalize(m); err != nil {
		return err
	}
	shape := m.ShapeFor(m.EffectiveGroupBy(s.Data.GroupBy))
	switch shape {
	case ShapeItems, ShapePaths:
		if s.Data.Limit == 0 {
			s.Data.Limit = defaultItemsLimit
		}
		if s.Data.Limit < 1 || s.Data.Limit > maxItemsLimit {
			return fmt.Errorf("%w: limit must be within 1..%d", shared.ErrValidation, maxItemsLimit)
		}
	case ShapeCategory, ShapeMatrix:
		if s.Data.Limit < 0 || s.Data.Limit > maxCategoryLimit {
			return fmt.Errorf("%w: limit must be within 0..%d", shared.ErrValidation, maxCategoryLimit)
		}
	default:
		if s.Data.Limit != 0 {
			return fmt.Errorf("%w: limit applies only to lists and groups", shared.ErrValidation)
		}
	}
	valid := m.Vizzes(m.EffectiveGroupBy(s.Data.GroupBy))
	if s.Viz.Type == "" {
		s.Viz.Type = valid[0]
	}
	if !containsViz(valid, s.Viz.Type) {
		return fmt.Errorf("%w: visualization %q does not fit a %s result (allowed: %v)", shared.ErrValidation, s.Viz.Type, shape, valid)
	}
	if s.Target != nil {
		if !containsStr(TargetOps, s.Target.Op) {
			return fmt.Errorf("%w: config.target.op must be one of %v", shared.ErrValidation, TargetOps)
		}
		if s.Target.Value < 0 || s.Target.Value > 1e9 {
			return fmt.Errorf("%w: config.target.value is out of range", shared.ErrValidation)
		}
		if shape != ShapeScalar && shape != ShapeRatio && shape != ShapeDuration {
			return fmt.Errorf("%w: a target applies to a single figure", shared.ErrValidation)
		}
	}
	return nil
}

func (t *WidgetTime) normalize(m Metric) error {
	if t.Range == "" {
		t.Range = defaultTimeRange
	}
	if t.Bucket == "" {
		t.Bucket = defaultTimeBucket
	}
	if t.Compare == "" {
		t.Compare = defaultTimeCompare
	}
	if !containsStr(TimeRanges, t.Range) || !containsStr(TimeBuckets, t.Bucket) || !containsStr(Comparisons, t.Compare) {
		return fmt.Errorf("%w: config.data.time has a value outside %v / %v / %v", shared.ErrValidation, TimeRanges, TimeBuckets, Comparisons)
	}
	if m.Current() && (t.Range != defaultTimeRange || t.Compare != CompareNone) {
		return fmt.Errorf("%w: metric %s has no time range or comparison", shared.ErrValidation, m.ID)
	}
	if !m.Comparable() && t.Compare != CompareNone {
		return fmt.Errorf("%w: this metric has no previous-period comparison", shared.ErrValidation)
	}
	return nil
}

func (f WidgetFilter) isEmpty() bool {
	return len(f.Severity) == 0 && len(f.PriorityClass) == 0 && len(f.Source) == 0 && len(f.SLAState) == 0 &&
		len(f.AgeBand) == 0 && f.KEV == nil && f.Reachable == nil && len(f.AssetGroupIDs) == 0
}

//nolint:cyclop // one check per dimension
func (f WidgetFilter) validate(m Metric) error {
	check := func(d Dimension, vals []string, allowed []string) error {
		if len(vals) == 0 {
			return nil
		}
		if !containsDim(m.Filters, d) {
			return fmt.Errorf("%w: metric %s cannot be filtered by %q", shared.ErrValidation, m.ID, d)
		}
		if len(vals) > maxFilterValues {
			return fmt.Errorf("%w: at most %d values per filter", shared.ErrValidation, maxFilterValues)
		}
		for _, v := range vals {
			if !containsStr(allowed, v) {
				return fmt.Errorf("%w: %q is not a %s value", shared.ErrValidation, v, d)
			}
		}
		return nil
	}
	for _, c := range []struct {
		d       Dimension
		vals    []string
		allowed []string
	}{
		{DimSeverity, f.Severity, severityValues()},
		{DimPriorityClass, f.PriorityClass, PriorityValues},
		{DimSource, f.Source, sourceValues()},
		{DimSLAState, f.SLAState, SLAStates},
		{DimAgeBand, f.AgeBand, AgeBands},
	} {
		if err := check(c.d, c.vals, c.allowed); err != nil {
			return err
		}
	}
	if f.KEV != nil && !containsDim(m.Filters, DimKEV) {
		return fmt.Errorf("%w: metric %s cannot be filtered by kev", shared.ErrValidation, m.ID)
	}
	if f.Reachable != nil && !containsDim(m.Filters, DimReachable) {
		return fmt.Errorf("%w: metric %s cannot be filtered by reachable", shared.ErrValidation, m.ID)
	}
	if len(f.AssetGroupIDs) > 0 {
		if !containsDim(m.Filters, DimAssetGroup) {
			return fmt.Errorf("%w: metric %s cannot be filtered by asset group", shared.ErrValidation, m.ID)
		}
		if len(f.AssetGroupIDs) > maxAssetGroups {
			return fmt.Errorf("%w: at most %d asset groups", shared.ErrValidation, maxAssetGroups)
		}
		for _, id := range f.AssetGroupIDs {
			if _, err := shared.IDFromString(id); err != nil {
				return fmt.Errorf("%w: asset_group_id must be ids", shared.ErrValidation)
			}
		}
	}
	return nil
}

// ToConfig renders the normalized spec as the stored widget config.
func (s WidgetSpec) ToConfig() (map[string]any, error) {
	raw, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return out, nil
}

// Merged returns the metric's default filter with this filter on top: a
// widget filter on a dimension replaces the default on that dimension.
func (f WidgetFilter) Merged(def WidgetFilter) WidgetFilter {
	out := def
	if len(f.Severity) > 0 {
		out.Severity = f.Severity
	}
	if len(f.PriorityClass) > 0 {
		out.PriorityClass = f.PriorityClass
	}
	if len(f.Source) > 0 {
		out.Source = f.Source
	}
	if len(f.SLAState) > 0 {
		out.SLAState = f.SLAState
	}
	if len(f.AgeBand) > 0 {
		out.AgeBand = f.AgeBand
	}
	if f.KEV != nil {
		out.KEV = f.KEV
	}
	if f.Reachable != nil {
		out.Reachable = f.Reachable
	}
	if len(f.AssetGroupIDs) > 0 {
		out.AssetGroupIDs = f.AssetGroupIDs
	}
	return out
}

func severityValues() []string {
	out := make([]string, 0, 6)
	for _, s := range vulnerability.AllSeverities() {
		out = append(out, s.String())
	}
	return out
}

func sourceValues() []string {
	out := make([]string, 0, 24)
	for _, s := range vulnerability.AllFindingSources() {
		out = append(out, s.String())
	}
	return out
}

// FilterValues lists the allowed values of every enum dimension, for the
// catalog endpoint.
func FilterValues() map[Dimension][]string {
	return map[Dimension][]string{
		DimSeverity:      severityValues(),
		DimPriorityClass: PriorityValues,
		DimSource:        sourceValues(),
		DimSLAState:      SLAStates,
		DimAgeBand:       AgeBands,
	}
}

func containsStr(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// legacySpecs maps legacy tile ids to the typed widget computing the same
// figure from the facts. Ids missing here (assets total, the "mine" tiles,
// risk score, scan coverage, reachable assets) need data the facts do not
// hold yet and keep their legacy rendering.
var legacySpecs = map[string]WidgetSpec{
	"findings_by_severity": {Data: WidgetData{Kind: WidgetKindMetric, Metric: "findings.open", GroupBy: []Dimension{DimSeverity}}, Viz: WidgetViz{Type: VizBar}},
	"open_findings":        {Data: WidgetData{Kind: WidgetKindMetric, Metric: "findings.open"}, Viz: WidgetViz{Type: VizStat}},
	"overdue_sla":          {Data: WidgetData{Kind: WidgetKindMetric, Metric: "findings.open", Filter: WidgetFilter{SLAState: []string{"breached"}}}, Viz: WidgetViz{Type: VizStat}},
	"sla_compliance":       {Data: WidgetData{Kind: WidgetKindMetric, Metric: "sla.within"}, Viz: WidgetViz{Type: VizProgress}},
	"mttr_critical":        {Data: WidgetData{Kind: WidgetKindMetric, Metric: "fix.time_to_fix", Filter: WidgetFilter{Severity: []string{"critical"}}}, Viz: WidgetViz{Type: VizStat}},
	"p0_open":              {Data: WidgetData{Kind: WidgetKindMetric, Metric: "exposure.priority_open", Filter: WidgetFilter{PriorityClass: []string{"P0"}}}, Viz: WidgetViz{Type: VizStat}},
	"threat_intel":         {Data: WidgetData{Kind: WidgetKindMetric, Metric: "intel.kev_open"}, Viz: WidgetViz{Type: VizStat}},
}

// LegacySpec returns the typed spec equivalent to a legacy tile id, with the
// given widget id, or false when the facts cannot answer that tile.
func LegacySpec(widgetType, id string) (WidgetSpec, bool) {
	base, ok := legacySpecs[widgetType]
	if !ok {
		return WidgetSpec{}, false
	}
	s := base
	s.V = WidgetSpecVersion
	s.ID = id
	s.Data.GroupBy = append([]Dimension(nil), base.Data.GroupBy...)
	if err := s.normalize(WidgetKindMetric); err != nil {
		return WidgetSpec{}, false
	}
	return s, true
}
