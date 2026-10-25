// Package widgets computes typed dashboard widgets from the dashboard fact
// tables (docs/architecture/dashboards.md, "Widget data").
//
// Whose numbers a read computes is decided here, from the authenticated
// caller, never from the widget spec or the request:
//   - a personal dashboard (and a preview) reads the caller's own data scope
//     and the pentest campaign rule for the caller;
//   - an organization dashboard reads the whole organization, after the
//     dashboard service checked dashboards:org:view and the audience; list
//     rows (finding titles) still follow the viewer's campaign membership.
//
// Results are stored per dashboard (snapshot.go): a personal snapshot is
// served only to its owner and only while their scope is the one it was
// computed for; an organization snapshot holds organization-wide figures and
// is served to every permitted viewer, its list rows filtered per viewer.
package widgets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"sync"
	"time"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/internal/app/datascope"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Concurrency caps for widget reads (one dashboard read or one preview
// holds one slot while its widgets run in sequence).
const (
	MaxPerUser    = 2
	MaxPerTenant  = 6
	MaxPerProcess = 12
	// dashboardReadTimeout bounds one dashboard read; widgets not reached
	// in time report an error state, the others keep their result.
	dashboardReadTimeout = 20 * time.Second
)

// ErrBusy is returned when the caller, the tenant or the process already
// runs the maximum number of widget reads (429).
var ErrBusy = errors.New("too many dashboard reads running; try again in a moment")

// Widget states.
const (
	StateReady       = "ready"
	StateNotMeasured = "not_measured"
	StateBuilding    = "building"
	StateUnsupported = "unsupported"
	StateError       = "error"
)

// Reasons (machine codes the web translates).
const (
	ReasonNoDenominator  = "no_denominator"
	ReasonTooFewFixed    = "too_few_fixed"
	ReasonLegacyTile     = "legacy_tile"
	ReasonFactsBuilding  = "facts_building"
	ReasonFailed         = "failed"
	ReasonTimeout        = "timeout"
	ReasonNoHistoryForBy = "previous_not_in_history"
	ReasonForbidden      = "forbidden"
)

// Service computes widget results.
type Service struct {
	dash      *dashboardapp.Service
	dataScope *datascope.Enforcer
	facts     dashboard.FactReader
	limiter   *limiter
	paths     AttackPathReader
	previews  *previewLimiter
	logger    *logger.Logger
	now       func() time.Time

	// Snapshot storage and the refresher's readers (SetSnapshots).
	snapshots dashboard.SnapshotStore
	repo      dashboard.Repository
	members   MembershipReader
	settings  dashboardapp.SettingsStore
}

// NewService returns a widget data service.
func NewService(dash *dashboardapp.Service, dataScope *datascope.Enforcer, facts dashboard.FactReader, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{dash: dash, dataScope: dataScope, facts: facts, limiter: newLimiter(MaxPerUser, MaxPerTenant, MaxPerProcess), previews: newPreviewLimiter(PreviewBurst, PreviewEvery), logger: log, now: time.Now}
}

// DashboardData is the result of every widget of one dashboard.
type DashboardData struct {
	DashboardID string `json:"dashboard_id"`
	// Scope is "organization" (whole-organization numbers) or "personal"
	// (the viewer's own data scope).
	Scope string `json:"scope" enums:"organization,personal"`
	// Restricted: a personal read whose data scope is narrower than the
	// organization (the web shows "Your scope").
	Restricted bool `json:"restricted"`
	// FactsBuiltAt is the last full build of the organization's facts; nil
	// while the first build runs (widgets then report "building").
	FactsBuiltAt *time.Time `json:"facts_built_at"`
	// ComputedAt is when these figures were computed (the snapshot time).
	ComputedAt time.Time `json:"computed_at"`
	// RefreshSchedule is the effective schedule (the organization default
	// resolved); NextRefreshAt is nil for a manual or paused schedule.
	RefreshSchedule string     `json:"refresh_schedule,omitempty" enums:"manual,5m,15m,1h,6h,daily"`
	NextRefreshAt   *time.Time `json:"next_refresh_at,omitempty"`
	// Stale: older than twice the schedule, or the last refresh failed
	// (LastRefreshError says why); the figures shown are the last good ones.
	Stale            bool          `json:"stale"`
	LastRefreshError string        `json:"last_refresh_error,omitempty"`
	Widgets          []WidgetValue `json:"widgets"`
}

// WidgetValue is one widget's result. Exactly one of the shape payloads is
// set when State is "ready".
type WidgetValue struct {
	ID         string                  `json:"id"`
	Index      int                     `json:"index"`
	WidgetType string                  `json:"widget_type"`
	State      string                  `json:"state" enums:"ready,not_measured,building,unsupported,error"`
	Reason     string                  `json:"reason,omitempty"`
	Metric     string                  `json:"metric,omitempty"`
	Shape      dashboard.Shape         `json:"shape,omitempty"`
	Viz        dashboard.VizType       `json:"viz,omitempty"`
	Polarity   dashboard.Polarity      `json:"polarity,omitempty"`
	Target     *dashboard.WidgetTarget `json:"target,omitempty"`
	// TargetMet is set for a single figure with a target.
	TargetMet *bool `json:"target_met,omitempty"`
	// Drill is the findings list counted with the same filter; empty when
	// the list cannot express the filter exactly.
	Drill  string  `json:"drill,omitempty"`
	Window *Window `json:"window,omitempty"`
	// PreviousReason says why a previous-period figure is missing.
	PreviousReason string `json:"previous_reason,omitempty"`

	Scalar   *ScalarValue   `json:"scalar,omitempty"`
	Ratio    *RatioValue    `json:"ratio,omitempty"`
	Duration *DurationValue `json:"duration,omitempty"`
	Category *CategoryValue `json:"category,omitempty"`
	Series   *SeriesValue   `json:"series,omitempty"`
	Matrix   *MatrixValue   `json:"matrix,omitempty"`
	Items    *ItemsValue    `json:"items,omitempty"`
	Stages   *StagesValue   `json:"stages,omitempty"`
	Paths    *PathsValue    `json:"paths,omitempty"`
	Flow     *FlowValue     `json:"flow,omitempty"`
	Intake   *IntakeValue   `json:"intake,omitempty"`
}

// ScalarValue is one count, with the previous period and a sparkline when
// the history can trace it.
type ScalarValue struct {
	Value    int64   `json:"value"`
	Previous *int64  `json:"previous,omitempty"`
	Delta    *int64  `json:"delta,omitempty"`
	Series   []Point `json:"series,omitempty"`
}

// RatioValue is a share; ValuePct is nil when Den is 0 (not measured).
type RatioValue struct {
	Num      int64    `json:"num"`
	Den      int64    `json:"den"`
	ValuePct *float64 `json:"value_pct"`
}

// DurationValue is a time-to-fix estimate from hour buckets.
type DurationValue struct {
	MedianHours         *float64 `json:"median_hours"`
	P90Hours            *float64 `json:"p90_hours"`
	N                   int64    `json:"n"`
	PreviousMedianHours *float64 `json:"previous_median_hours,omitempty"`
	PreviousN           *int64   `json:"previous_n,omitempty"`
	// Bucketed: the figures are estimated from doubling hour buckets.
	Bucketed bool `json:"bucketed"`
}

// CategoryRow is one key of a category result. For a duration grouped by a
// key, Value is the median hours and P90/N are set.
type CategoryRow struct {
	Key      string   `json:"key"`
	Value    float64  `json:"value"`
	Previous *float64 `json:"previous,omitempty"`
	P90      *float64 `json:"p90,omitempty"`
	N        *int64   `json:"n,omitempty"`
	Drill    string   `json:"drill,omitempty"`
}

// CategoryValue is a value per key.
type CategoryValue struct {
	Rows  []CategoryRow `json:"rows"`
	Total float64       `json:"total"`
}

// SeriesLine is one key of a time series.
type SeriesLine struct {
	Key    string  `json:"key"`
	Points []Point `json:"points"`
}

// SeriesValue is a value per bucket and key.
type SeriesValue struct {
	Bucket string       `json:"bucket"`
	Series []SeriesLine `json:"series"`
	// Totals per key over the window (flows), and the previous window when
	// asked.
	Totals         map[string]int64 `json:"totals,omitempty"`
	PreviousTotals map[string]int64 `json:"previous_totals,omitempty"`
}

// MatrixValue is a count per row and column key.
type MatrixValue struct {
	Rows  []string  `json:"rows"`
	Cols  []string  `json:"cols"`
	Cells [][]int64 `json:"cells"`
}

// ItemRow is one finding of a list.
type ItemRow struct {
	ID            string     `json:"id"`
	Title         string     `json:"title"`
	Severity      string     `json:"severity"`
	PriorityClass string     `json:"priority_class"`
	AssetID       string     `json:"asset_id,omitempty"`
	AssetName     string     `json:"asset_name,omitempty"`
	SLADeadline   *time.Time `json:"sla_deadline,omitempty"`
	KEV           bool       `json:"kev"`
	// Pentest and CampaignID are kept in stored snapshots so the viewer's
	// campaign membership can be applied on read; forViewer clears them
	// from every response.
	Pentest    bool   `json:"pentest,omitempty"`
	CampaignID string `json:"campaign_id,omitempty"`
}

// ItemsValue is a ranked list.
type ItemsValue struct {
	Rows []ItemRow `json:"rows"`
}

// PersonalData returns every widget of the caller's own dashboard, for the
// caller's data scope: the stored snapshot when it was computed for this
// layout and this scope, otherwise a fresh computation (stored for the next
// open). Another person's dashboard is not found.
func (s *Service) PersonalData(ctx context.Context, c dashboardapp.Caller, id string) (*DashboardData, error) {
	d, err := s.dash.Get(ctx, c.TenantID.String(), c.UserID.String(), id)
	if err != nil {
		return nil, err
	}
	scope, err := s.personalScope(ctx, c)
	if err != nil {
		return nil, err
	}
	out, err := s.read(ctx, c, d, scope, false)
	if err != nil {
		return nil, err
	}
	return s.personalForViewer(ctx, out, c, scope)
}

// OrgData returns every widget of an organization dashboard the caller may
// read (dashboards:org:view and the audience, checked by the dashboard
// service; outside the audience the dashboard is not found). The figures
// are organization-wide; list rows follow the caller's campaign membership.
func (s *Service) OrgData(ctx context.Context, c dashboardapp.Caller, id string) (*DashboardData, error) {
	d, err := s.dash.GetOrg(ctx, c, id)
	if err != nil {
		return nil, err
	}
	out, err := s.read(ctx, c, d.Dashboard, orgScope(c.TenantID), false)
	if err != nil {
		return nil, err
	}
	return s.forViewer(ctx, out, c, s.campaignViewer(ctx, c))
}

// Preview computes one widget spec for the caller's own scope (the gallery
// and the config panel). The spec is validated like a saved widget; a
// preview is never stored.
func (s *Service) Preview(ctx context.Context, c dashboardapp.Caller, widgetType string, config map[string]any) (*WidgetValue, error) {
	if !dashboard.IsTypedWidget(widgetType) {
		return nil, fmt.Errorf("%w: preview takes a typed widget", shared.ErrValidation)
	}
	if _, err := dashboard.ParseWidgetSpec(widgetType, config); err != nil {
		return nil, err
	}
	if wait := s.previews.take(c.TenantID.String()+"/"+c.UserID.String(), s.now()); wait > 0 {
		return nil, &ErrPreviewRate{RetryAfter: wait}
	}
	scope, err := s.personalScope(ctx, c)
	if err != nil {
		return nil, err
	}
	out, err := s.compute(ctx, c.TenantID, c.UserID, "", []dashboard.Widget{{WidgetType: widgetType, Config: config}}, "personal", scope, true)
	if err != nil {
		return nil, err
	}
	out, err = s.personalForViewer(ctx, out, c, scope)
	if err != nil {
		return nil, err
	}
	return &out.Widgets[0], nil
}

func orgScope(tenantID shared.ID) dashboard.ReadScope {
	// Organization figures: every asset, every published pentest finding.
	return dashboard.ReadScope{TenantID: tenantID}
}

func (s *Service) personalScope(ctx context.Context, c dashboardapp.Caller) (dashboard.ReadScope, error) {
	assets, err := s.dataScope.ResolveStrict(ctx, c.TenantID)
	if err != nil {
		return dashboard.ReadScope{}, fmt.Errorf("resolve data scope: %w", err)
	}
	return dashboard.ReadScope{TenantID: c.TenantID, Assets: assets, CampaignViewer: s.campaignViewer(ctx, c)}, nil
}

// campaignViewer is the caller for the pentest campaign rule, nil for an
// administrator (who sees every campaign). An API key never counts as an
// administrator here, as in every metrics read.
func (s *Service) campaignViewer(ctx context.Context, c dashboardapp.Caller) *shared.ID {
	dc := s.dataScope.CallerOf(ctx)
	if dc.IsAdmin && !dc.APIKey {
		return nil
	}
	uid := c.UserID
	return &uid
}

// compute runs every widget of a layout for one scope. limited: an
// interactive read that takes a concurrency slot (the refresher does not).
func (s *Service) compute(ctx context.Context, tenantID, userID shared.ID, dashID string, ws []dashboard.Widget, kind string, scope dashboard.ReadScope, limited bool) (*DashboardData, error) {
	if limited {
		release, err := s.limiter.acquire(tenantID.String(), userID.String())
		if err != nil {
			return nil, err
		}
		defer release()
	}
	ctx, cancel := context.WithTimeout(ctx, dashboardReadTimeout)
	defer cancel()

	builtAt, err := s.facts.FactsBuiltAt(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := &DashboardData{
		DashboardID: dashID, Scope: kind, Restricted: scope.Assets.Restricted(),
		FactsBuiltAt: builtAt, ComputedAt: s.now().UTC(), Widgets: make([]WidgetValue, 0, len(ws)),
	}
	for i, w := range ws {
		out.Widgets = append(out.Widgets, s.widget(ctx, i, w, builtAt != nil, scope))
	}
	return out, nil
}

// personalForViewer is the one exit of every personal read (data, refresh,
// preview): widgets whose metric the caller may not read are masked first,
// then forViewer applies the campaign rules. A new personal path returns
// through here so it cannot skip the mask.
func (s *Service) personalForViewer(ctx context.Context, d *DashboardData, c dashboardapp.Caller, scope dashboard.ReadScope) (*DashboardData, error) {
	maskForbidden(d, c)
	return s.forViewer(ctx, d, c, scope.CampaignViewer)
}

// forViewer prepares stored or computed figures for one viewer: list rows of
// pentest findings stay only for an administrator or a member of their
// campaign, and the campaign fields never leave the server.
func (s *Service) forViewer(ctx context.Context, d *DashboardData, c dashboardapp.Caller, viewer *shared.ID) (*DashboardData, error) {
	var member map[string]bool
	for i := range d.Widgets {
		it := d.Widgets[i].Items
		if it == nil {
			continue
		}
		kept := it.Rows[:0]
		for _, r := range it.Rows {
			if r.Pentest && viewer != nil {
				if member == nil {
					ids, err := s.facts.CampaignsOf(ctx, c.TenantID, *viewer)
					if err != nil {
						return nil, err
					}
					member = make(map[string]bool, len(ids))
					for _, id := range ids {
						member[id.String()] = true
					}
				}
				if r.CampaignID == "" || !member[r.CampaignID] {
					continue
				}
			}
			r.Pentest, r.CampaignID = false, ""
			kept = append(kept, r)
		}
		it.Rows = kept
	}
	return d, nil
}

func (s *Service) widget(ctx context.Context, i int, w dashboard.Widget, factsReady bool, scope dashboard.ReadScope) WidgetValue {
	v := WidgetValue{Index: i, WidgetType: w.WidgetType, ID: "w_legacy" + strconv.Itoa(i)}
	var spec dashboard.WidgetSpec
	if dashboard.IsTypedWidget(w.WidgetType) {
		parsed, err := dashboard.ParseWidgetSpec(w.WidgetType, w.Config)
		if err != nil {
			// Stored layouts are validated on write; a spec that no longer
			// parses (the catalog changed) is reported, never guessed.
			v.State, v.Reason = StateUnsupported, ReasonFailed
			return v
		}
		spec = parsed
	} else {
		mapped, ok := dashboard.LegacySpec(w.WidgetType, v.ID)
		if !ok {
			v.State, v.Reason = StateUnsupported, ReasonLegacyTile
			return v
		}
		spec = mapped
	}
	v.ID = spec.ID
	if spec.Data.Kind == dashboard.WidgetKindNote {
		// A note has no data; the web renders the stored text.
		v.State, v.Viz = StateReady, dashboard.VizNote
		return v
	}
	m, _ := dashboard.LookupMetric(spec.Data.Metric)
	v.Metric, v.Viz, v.Polarity, v.Target = m.ID, spec.Viz.Type, m.Polarity, spec.Target
	if !factsReady {
		v.State, v.Reason = StateBuilding, ReasonFactsBuilding
		return v
	}
	if ctx.Err() != nil {
		v.State, v.Reason = StateError, ReasonTimeout
		return v
	}
	if err := s.metric(ctx, &v, m, spec, scope); err != nil {
		reason := ReasonFailed
		if errors.Is(err, context.DeadlineExceeded) || ctx.Err() != nil {
			reason = ReasonTimeout
		}
		s.logger.Warn("dashboard widget read failed", "metric", m.ID, "error", err.Error())
		v.State, v.Reason = StateError, reason
		v.Scalar, v.Ratio, v.Duration, v.Category, v.Series, v.Matrix, v.Items = nil, nil, nil, nil, nil, nil, nil
		v.Stages, v.Paths, v.Flow, v.Intake = nil, nil, nil, nil
	}
	return v
}

//nolint:cyclop // one branch per metric kind and shape
func (s *Service) metric(ctx context.Context, v *WidgetValue, m dashboard.Metric, spec dashboard.WidgetSpec, agg dashboard.ReadScope) error {
	f := spec.Data.Filter.Merged(m.DefaultFilter)
	gb := m.EffectiveGroupBy(spec.Data.GroupBy)
	v.Shape = m.ShapeFor(gb)
	v.State = StateReady
	win := newWindow(s.now(), spec.Data.Time)
	compare := spec.Data.Time.Compare == dashboard.ComparePreviousPeriod

	switch m.Kind {
	case dashboard.MetricKindCount:
		v.Drill = drillHref(f)
		return s.count(ctx, v, f, gb, win, compare, spec.Data.Limit, agg)
	case dashboard.MetricKindRatio:
		if m.ID == "coverage.discovery" {
			return s.discoveryCoverage(ctx, v, spec.Target, compare, agg)
		}
		num, den, err := s.facts.SLAWithin(ctx, agg, f)
		if err != nil {
			return err
		}
		v.Ratio = &RatioValue{Num: num, Den: den}
		// The breached ones are what to look at.
		bf := f
		bf.SLAState = []string{"breached"}
		v.Drill = drillHref(bf)
		if den == 0 {
			v.State, v.Reason = StateNotMeasured, ReasonNoDenominator
			return nil
		}
		pct := round1(float64(num) * 100 / float64(den))
		v.Ratio.ValuePct = &pct
		v.TargetMet = targetMet(spec.Target, pct)
		if compare {
			v.PreviousReason = ReasonNoHistoryForBy
		}
		return nil
	case dashboard.MetricKindDuration:
		v.Window = &win
		return s.duration(ctx, v, f, gb, win, compare, spec.Target, agg)
	case dashboard.MetricKindSeries:
		v.Window = &win
		if m.Flow {
			return s.flow(ctx, v, f, win, compare, agg)
		}
		return s.openSeries(ctx, v, f, gb, win, agg)
	case dashboard.MetricKindItems:
		kind := dashboard.RankFixNext
		if m.ID == "sla.at_risk" {
			kind = dashboard.RankSLADue
		}
		// An organization read lists every published pentest finding with
		// its campaign; forViewer applies the viewer's membership on read.
		items, err := s.facts.Rank(ctx, agg, kind, f, spec.Data.Limit)
		if err != nil {
			return err
		}
		out := &ItemsValue{Rows: make([]ItemRow, 0, len(items))}
		for _, it := range items {
			r := ItemRow{ID: it.FindingID.String(), Title: it.Title, Severity: it.Severity, PriorityClass: it.PriorityClass,
				AssetName: it.AssetName, SLADeadline: it.SLADeadline, KEV: it.KEV, Pentest: it.Pentest}
			if it.Pentest {
				r.CampaignID = it.CampaignID.String()
			}
			if it.AssetID != nil {
				r.AssetID = it.AssetID.String()
			}
			out.Rows = append(out.Rows, r)
		}
		v.Items = out
		lf := f
		lf.PriorityClass = []string{"P0", "P1", "P2"}
		v.Drill = drillHref(lf)
		return nil
	case dashboard.MetricKindAssetCount:
		return s.crownJewelsExposed(ctx, v, f, agg)
	case dashboard.MetricKindStages:
		return s.ctemLoop(ctx, v, agg)
	case dashboard.MetricKindPaths:
		return s.attackPaths(ctx, v, spec.Data.Limit, agg)
	case dashboard.MetricKindExposureFlow:
		v.Window = &win
		return s.exposureFlow(ctx, v, win, agg)
	case dashboard.MetricKindIntake:
		v.Window = &win
		return s.intakeMetric(ctx, v, win, agg)
	}
	return fmt.Errorf("unknown metric kind %q", m.Kind)
}

func (s *Service) count(ctx context.Context, v *WidgetValue, f dashboard.WidgetFilter, gb []dashboard.Dimension, win Window, compare bool, limit int, scope dashboard.ReadScope) error {
	rowsNow, err := s.facts.CountOpen(ctx, scope, f, gb)
	if err != nil {
		return err
	}
	traceable := historyCompatible(f, gb)
	var days []dashboard.DayRow
	// The history traces a scalar (sparkline, previous) or one group-by
	// (previous); a matrix shows the current counts only.
	if traceable && (len(gb) == 0 || (compare && len(gb) == 1)) {
		var by dashboard.Dimension
		if len(gb) == 1 {
			by = gb[0]
		}
		days, err = s.facts.Days(ctx, scope, f, by, win.from, win.to)
		if err != nil {
			return err
		}
		v.Window = &win
	}
	if compare && (!traceable || len(gb) > 1) {
		v.PreviousReason = ReasonNoHistoryForBy
	}
	switch len(gb) {
	case 0:
		var n int64
		for _, r := range rowsNow {
			n += r.Count
		}
		sv := &ScalarValue{Value: n}
		if traceable {
			ends := bucketEnds(win.from, win.to, win.Bucket)
			sv.Series = backcast(n, days, ends)
			if compare {
				var net int64
				for _, d := range days {
					net += d.NetDelta
				}
				prev := n - net
				delta := n - prev
				sv.Previous, sv.Delta = &prev, &delta
			}
		}
		v.Scalar = sv
		v.TargetMet = targetMet(v.Target, float64(n))
	case 1:
		net := map[string]int64{}
		for _, d := range days {
			net[d.Key] += d.NetDelta
		}
		cv := &CategoryValue{Rows: make([]CategoryRow, 0, len(rowsNow))}
		for _, r := range rowsNow {
			row := CategoryRow{Key: r.Keys[0], Value: float64(r.Count), Drill: drillHref(withKey(f, gb[0], r.Keys[0]))}
			if compare && traceable {
				p := float64(r.Count - net[r.Keys[0]])
				row.Previous = &p
			}
			cv.Total += float64(r.Count)
			cv.Rows = append(cv.Rows, row)
		}
		sortCategory(cv.Rows, gb[0])
		if limit > 0 && len(cv.Rows) > limit {
			cv.Rows = cv.Rows[:limit]
		}
		v.Category = cv
	default:
		v.Matrix = matrix(rowsNow, gb)
	}
	return nil
}

func (s *Service) duration(ctx context.Context, v *WidgetValue, f dashboard.WidgetFilter, gb []dashboard.Dimension, win Window, compare bool, target *dashboard.WidgetTarget, scope dashboard.ReadScope) error {
	var by dashboard.Dimension
	if len(gb) == 1 {
		by = gb[0]
	}
	cur, err := s.facts.FixHist(ctx, scope, f, by, win.from, win.to)
	if err != nil {
		return err
	}
	var prev []dashboard.FixHistRow
	if compare {
		if prev, err = s.facts.FixHist(ctx, scope, f, by, win.prevFrom, win.prevTo); err != nil {
			return err
		}
	}
	if by == "" {
		var h, ph [12]int64
		for _, r := range cur {
			addHist(&h, r.Hist)
		}
		for _, r := range prev {
			addHist(&ph, r.Hist)
		}
		dv := &DurationValue{Bucketed: true}
		med, n := histQuantile(h, 0.5)
		p90, _ := histQuantile(h, 0.9)
		dv.N = n
		if compare {
			pm, pn := histQuantile(ph, 0.5)
			dv.PreviousN = &pn
			if pn >= minFixedForDuration {
				pm = round1(pm)
				dv.PreviousMedianHours = &pm
			}
		}
		v.Duration = dv
		if n < minFixedForDuration {
			v.State, v.Reason = StateNotMeasured, ReasonTooFewFixed
			return nil
		}
		med, p90 = round1(med), round1(p90)
		dv.MedianHours, dv.P90Hours = &med, &p90
		v.TargetMet = targetMet(target, med)
		return nil
	}
	prevByKey := map[string][12]int64{}
	for _, r := range prev {
		prevByKey[r.Key] = r.Hist
	}
	cv := &CategoryValue{Rows: []CategoryRow{}}
	for _, r := range cur {
		med, n := histQuantile(r.Hist, 0.5)
		if n < minFixedForDuration {
			continue // a key with too few fixes has no median
		}
		p90, _ := histQuantile(r.Hist, 0.9)
		med, p90 = round1(med), round1(p90)
		nn := n
		row := CategoryRow{Key: r.Key, Value: med, P90: &p90, N: &nn}
		if ph, ok := prevByKey[r.Key]; ok && compare {
			if pm, pn := histQuantile(ph, 0.5); pn >= minFixedForDuration {
				pm = round1(pm)
				row.Previous = &pm
			}
		}
		cv.Rows = append(cv.Rows, row)
	}
	sortCategory(cv.Rows, by)
	if len(cv.Rows) == 0 {
		v.State, v.Reason = StateNotMeasured, ReasonTooFewFixed
	}
	v.Category = cv
	return nil
}

func (s *Service) flow(ctx context.Context, v *WidgetValue, f dashboard.WidgetFilter, win Window, compare bool, scope dashboard.ReadScope) error {
	from := win.from
	if compare {
		from = win.prevFrom
	}
	days, err := s.facts.Days(ctx, scope, f, "", from, win.to)
	if err != nil {
		return err
	}
	ends := bucketEnds(win.from, win.to, win.Bucket)
	opened, fixed := flows(days, win.from, ends)
	sv := &SeriesValue{Bucket: win.Bucket, Series: []SeriesLine{{Key: "opened", Points: opened}, {Key: "fixed", Points: fixed}},
		Totals: map[string]int64{"opened": 0, "fixed": 0}}
	if compare {
		sv.PreviousTotals = map[string]int64{"opened": 0, "fixed": 0}
	}
	for _, d := range days {
		day := dayOf(d.Day)
		if !day.Before(win.from) {
			sv.Totals["opened"] += d.Opened
			sv.Totals["fixed"] += d.Fixed
		} else if compare {
			sv.PreviousTotals["opened"] += d.Opened
			sv.PreviousTotals["fixed"] += d.Fixed
		}
	}
	v.Series = sv
	return nil
}

func (s *Service) openSeries(ctx context.Context, v *WidgetValue, f dashboard.WidgetFilter, gb []dashboard.Dimension, win Window, scope dashboard.ReadScope) error {
	by := gb[0]
	now, err := s.facts.CountOpen(ctx, scope, f, []dashboard.Dimension{by})
	if err != nil {
		return err
	}
	days, err := s.facts.Days(ctx, scope, f, by, win.from, win.to)
	if err != nil {
		return err
	}
	open := map[string]int64{}
	for _, r := range now {
		open[r.Keys[0]] = r.Count
	}
	perKey := map[string][]dashboard.DayRow{}
	for _, d := range days {
		perKey[d.Key] = append(perKey[d.Key], d)
		if _, ok := open[d.Key]; !ok {
			open[d.Key] = 0 // a key with history but nothing open now
		}
	}
	keys := make([]string, 0, len(open))
	for k := range open {
		keys = append(keys, k)
	}
	sortKeys(keys, by)
	ends := bucketEnds(win.from, win.to, win.Bucket)
	sv := &SeriesValue{Bucket: win.Bucket, Series: make([]SeriesLine, 0, len(keys))}
	for _, k := range keys {
		sv.Series = append(sv.Series, SeriesLine{Key: k, Points: backcast(open[k], perKey[k], ends)})
	}
	v.Series = sv
	return nil
}

func addHist(dst *[12]int64, src [12]int64) {
	for i := range dst {
		dst[i] += src[i]
	}
}

func targetMet(t *dashboard.WidgetTarget, v float64) *bool {
	if t == nil {
		return nil
	}
	met := v <= t.Value
	if t.Op == ">=" {
		met = v >= t.Value
	}
	return &met
}

// withKey narrows a filter to one key of a group-by dimension (for the
// drill of one bar or row).
func withKey(f dashboard.WidgetFilter, d dashboard.Dimension, key string) dashboard.WidgetFilter {
	switch d {
	case dashboard.DimSeverity:
		f.Severity = []string{key}
	case dashboard.DimPriorityClass:
		f.PriorityClass = []string{key}
	case dashboard.DimSource:
		f.Source = []string{key}
	case dashboard.DimSLAState:
		f.SLAState = []string{key}
	case dashboard.DimAgeBand:
		f.AgeBand = []string{key}
	case dashboard.DimKEV:
		b := key == "true"
		f.KEV = &b
	case dashboard.DimReachable:
		b := key == "true"
		f.Reachable = &b
	}
	return f
}

// ordinal orders keys of ordinal dimensions (severity critical first,
// priority P0 first, SLA breached first, age young first); other keys sort
// by name.
var ordinal = map[dashboard.Dimension][]string{
	dashboard.DimSeverity:      {"critical", "high", "medium", "low", "info", "none"},
	dashboard.DimPriorityClass: {"P0", "P1", "P2", "P3", "none"},
	dashboard.DimSLAState:      {"breached", "warning", "ok", "none"},
	dashboard.DimAgeBand:       {"0-30", "31-60", "61-90", "90+"},
	dashboard.DimKEV:           {"true", "false"},
	dashboard.DimReachable:     {"true", "false"},
}

func rank(d dashboard.Dimension, k string) int {
	for i, x := range ordinal[d] {
		if x == k {
			return i
		}
	}
	return len(ordinal[d])
}

func sortKeys(keys []string, d dashboard.Dimension) {
	sort.SliceStable(keys, func(i, j int) bool {
		ri, rj := rank(d, keys[i]), rank(d, keys[j])
		if ri != rj {
			return ri < rj
		}
		return keys[i] < keys[j]
	})
}

func sortCategory(rows []CategoryRow, d dashboard.Dimension) {
	if _, ok := ordinal[d]; ok {
		sort.SliceStable(rows, func(i, j int) bool {
			ri, rj := rank(d, rows[i].Key), rank(d, rows[j].Key)
			if ri != rj {
				return ri < rj
			}
			return rows[i].Key < rows[j].Key
		})
		return
	}
	// A nominal dimension (source): largest first.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Value != rows[j].Value {
			return rows[i].Value > rows[j].Value
		}
		return rows[i].Key < rows[j].Key
	})
}

func matrix(rows []dashboard.CountRow, gb []dashboard.Dimension) *MatrixValue {
	rset, cset := map[string]bool{}, map[string]bool{}
	for _, r := range rows {
		rset[r.Keys[0]], cset[r.Keys[1]] = true, true
	}
	rk, ck := keysOf(rset), keysOf(cset)
	sortKeys(rk, gb[0])
	sortKeys(ck, gb[1])
	ri, ci := index(rk), index(ck)
	cells := make([][]int64, len(rk))
	for i := range cells {
		cells[i] = make([]int64, len(ck))
	}
	for _, r := range rows {
		cells[ri[r.Keys[0]]][ci[r.Keys[1]]] += r.Count
	}
	return &MatrixValue{Rows: rk, Cols: ck, Cells: cells}
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

func index(keys []string) map[string]int {
	m := make(map[string]int, len(keys))
	for i, k := range keys {
		m[k] = i
	}
	return m
}

// limiter bounds concurrent widget reads per user, per tenant and in total
// (one API process; each replica has its own).
type limiter struct {
	mu                      sync.Mutex
	perUser, perTenant, max int
	running                 int
	users, tenants          map[string]int
}

func newLimiter(perUser, perTenant, total int) *limiter {
	return &limiter{perUser: perUser, perTenant: perTenant, max: total, users: map[string]int{}, tenants: map[string]int{}}
}

func (l *limiter) acquire(tenantID, userID string) (func(), error) {
	uk := tenantID + "/" + userID
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.users[uk] >= l.perUser || l.tenants[tenantID] >= l.perTenant || l.running >= l.max {
		return nil, ErrBusy
	}
	l.running++
	l.users[uk]++
	l.tenants[tenantID]++
	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.running--
			if l.users[uk]--; l.users[uk] <= 0 {
				delete(l.users, uk)
			}
			if l.tenants[tenantID]--; l.tenants[tenantID] <= 0 {
				delete(l.tenants, tenantID)
			}
		})
	}, nil
}
