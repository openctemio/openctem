package widgets

// The exposure flow and the intake (docs/architecture/dashboards.md,
// "Exposure flow and intake"). Every figure carries the list it counts:
// findings figures open the findings list in the same scope, intake
// figures open the receipt list with the same source, tool and window, and
// the receipt list's totals are the same sums. Receipts are organization
// figures (tool volumes are not asset-scoped), so a personal read gets the
// flow without its intake, with a reason, never an estimate.

import (
	"context"
	"net/url"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// Intake reasons and health states.
const (
	// ReasonOrganizationOnly: the figure is an organization figure and the
	// read is personal.
	ReasonOrganizationOnly = "organization_only"
	// ReasonNoReceipts: no source sent anything in the window.
	ReasonNoReceipts = "no_receipts"

	HealthOK     = "ok"
	HealthStale  = "stale"
	HealthFailed = "failed"
)

// staleFactor and minStaleAfter decide when a source is stale: nothing new
// for more than twice its usual interval (the median time between its
// receipts in the window), and never sooner than a day. A source with fewer
// than three receipts has no usual interval and is never called stale.
const (
	staleFactor   = 2
	minStaleAfter = 24 * time.Hour
)

// drillReceipts is the receipt list (web /findings/imports) of a filter.
const drillReceipts = "/findings/imports"

// priorityClasses are the classes of the actionable ring, in fixed order.
var priorityClasses = []string{"P0", "P1", "P2", "P3"}

// FlowFigure is one figure and the list it counts. Key names the part
// (a priority class, a severity) where the figure is one of several.
type FlowFigure struct {
	Key   string `json:"key,omitempty"`
	Value int64  `json:"value"`
	Drill string `json:"drill,omitempty"`
}

// IntakeSource is what one source (a source group and a tool) sent in the
// window, from its receipts, and its health.
type IntakeSource struct {
	Origin        string `json:"origin" enums:"sensor,import,connector,ci"`
	Tool          string `json:"tool"`
	Receipts      int64  `json:"receipts"`
	Received      int64  `json:"received"`
	Created       int64  `json:"created"`
	StillDetected int64  `json:"still_detected"`
	Reopened      int64  `json:"reopened"`
	Closed        int64  `json:"closed"`
	Suppressed    int64  `json:"suppressed"`
	// NotStored: skipped (out of scope, excluded, invalid) or failed.
	NotStored int64     `json:"not_stored"`
	LastAt    time.Time `json:"last_at"`
	// LastStatus is the latest receipt's status.
	LastStatus    string `json:"last_status"`
	LastReceiptID string `json:"last_receipt_id"`
	Health        string `json:"health" enums:"ok,stale,failed"`
	// ExpectedEverySeconds is the source's usual interval (the median time
	// between its receipts); absent with fewer than three receipts.
	ExpectedEverySeconds *int64 `json:"expected_every_seconds,omitempty"`
	// Drill is the receipt list of this source in the window.
	Drill string `json:"drill"`
}

// IntakeNoise splits what was received in the window into new or reopened
// findings (the receipt list's New plus Reopened), merged into findings
// that exist (seen again, or repeated in a report) and not stored; these
// three sum to Received. Suppressed is the part of New that an approved
// rule closed on arrival (the receipt list's Suppressed); it is stored, so
// it is already inside New and is not a fourth part.
type IntakeNoise struct {
	Received   int64 `json:"received"`
	New        int64 `json:"new"`
	Merged     int64 `json:"merged"`
	Suppressed int64 `json:"suppressed"`
	NotStored  int64 `json:"not_stored"`
}

// IntakeValue is the organization's intake in the window.
type IntakeValue struct {
	Since   time.Time      `json:"since"`
	Sources []IntakeSource `json:"sources"`
	// Totals sums every source; Drill is the receipt list of the window,
	// whose totals are these sums.
	Totals IntakeSource `json:"totals"`
	Noise  IntakeNoise  `json:"noise"`
	// Failing and Stale count the sources in those states.
	Failing int    `json:"failing"`
	Stale   int    `json:"stale"`
	Drill   string `json:"drill"`
	// FalsePositive is the findings marked false positive in the window.
	FalsePositive FlowFigure `json:"false_positive"`
}

// FlowValue is the exposure flow of the read's scope in the window.
type FlowValue struct {
	Since time.Time `json:"since"`
	// Intake is nil for a personal read (IntakeReason organization_only).
	Intake       *IntakeValue `json:"intake,omitempty"`
	IntakeReason string       `json:"intake_reason,omitempty" enums:"organization_only,no_receipts"`
	// Actionable is the open findings of classes P0 to P3, by class.
	Actionable FlowFigure   `json:"actionable"`
	Classes    []FlowFigure `json:"classes"`
	// Open is every open finding, by severity; PastSLA and InProgress are
	// open findings now.
	Open       FlowFigure   `json:"open"`
	Severity   []FlowFigure `json:"severity"`
	PastSLA    FlowFigure   `json:"past_sla"`
	InProgress FlowFigure   `json:"in_progress"`
	// Fixed, Accepted and FalsePositive closed in the window.
	Fixed         FlowFigure   `json:"fixed"`
	Accepted      FlowFigure   `json:"accepted"`
	FalsePositive FlowFigure   `json:"false_positive"`
	Stages        *StagesValue `json:"stages"`
}

// orgRead reports a read of whole-organization figures.
func orgRead(scope dashboard.ReadScope) bool { return scope.Assets == nil }

// exposureFlow computes the flow for the read's scope.
func (s *Service) exposureFlow(ctx context.Context, v *WidgetValue, win Window, scope dashboard.ReadScope) error {
	since := win.from
	out := &FlowValue{Since: since, Classes: make([]FlowFigure, 0, len(priorityClasses))}

	byClass, err := s.facts.CountOpen(ctx, scope, dashboard.WidgetFilter{}, []dashboard.Dimension{dashboard.DimPriorityClass})
	if err != nil {
		return err
	}
	counts := map[string]int64{}
	var open int64
	for _, r := range byClass {
		if len(r.Keys) == 1 {
			counts[r.Keys[0]] += r.Count
		}
		open += r.Count
	}
	for _, p := range priorityClasses {
		out.Classes = append(out.Classes, FlowFigure{Key: p, Value: counts[p],
			Drill: drillHref(dashboard.WidgetFilter{PriorityClass: []string{p}})})
		out.Actionable.Value += counts[p]
	}
	out.Actionable.Drill = drillHref(dashboard.WidgetFilter{PriorityClass: priorityClasses})
	out.Open = FlowFigure{Value: open, Drill: drillHref(dashboard.WidgetFilter{})}

	bySev, err := s.facts.CountOpen(ctx, scope, dashboard.WidgetFilter{}, []dashboard.Dimension{dashboard.DimSeverity})
	if err != nil {
		return err
	}
	rows := make([]CategoryRow, 0, len(bySev))
	for _, r := range bySev {
		if len(r.Keys) == 1 && r.Count > 0 {
			rows = append(rows, CategoryRow{Key: r.Keys[0], Value: float64(r.Count)})
		}
	}
	sortCategory(rows, dashboard.DimSeverity)
	out.Severity = make([]FlowFigure, 0, len(rows))
	for _, r := range rows {
		out.Severity = append(out.Severity, FlowFigure{Key: r.Key, Value: int64(r.Value),
			Drill: drillHref(dashboard.WidgetFilter{Severity: []string{r.Key}})})
	}

	breachedF := dashboard.WidgetFilter{SLAState: []string{"breached"}}
	breached, err := s.openCount(ctx, scope, breachedF)
	if err != nil {
		return err
	}
	out.PastSLA = FlowFigure{Value: breached, Drill: drillHref(breachedF)}

	oc, err := s.facts.Outcomes(ctx, scope, since)
	if err != nil {
		return err
	}
	out.InProgress = FlowFigure{Value: oc.InProgress, Drill: drillStatus("in_progress", nil)}
	out.Fixed = FlowFigure{Value: oc.Fixed, Drill: drillStatus("resolved", &since)}
	out.Accepted = FlowFigure{Value: oc.Accepted, Drill: drillStatus("accepted", &since)}
	out.FalsePositive = FlowFigure{Value: oc.FalsePositive, Drill: drillStatus("false_positive", &since)}

	loop := &WidgetValue{}
	if err := s.ctemLoop(ctx, loop, scope); err != nil {
		return err
	}
	out.Stages = loop.Stages

	if !orgRead(scope) {
		out.IntakeReason = ReasonOrganizationOnly
	} else {
		in, err := s.intake(ctx, scope, since, out.FalsePositive)
		if err != nil {
			return err
		}
		out.Intake = in
		if len(in.Sources) == 0 {
			out.IntakeReason = ReasonNoReceipts
		}
	}
	v.Flow = out
	v.Drill = out.Actionable.Drill
	return nil
}

// intakeMetric computes the intake widget: organization reads only.
func (s *Service) intakeMetric(ctx context.Context, v *WidgetValue, win Window, scope dashboard.ReadScope) error {
	if !orgRead(scope) {
		v.State, v.Reason = StateNotMeasured, ReasonOrganizationOnly
		return nil
	}
	since := win.from
	oc, err := s.facts.Outcomes(ctx, scope, since)
	if err != nil {
		return err
	}
	in, err := s.intake(ctx, scope, since, FlowFigure{Value: oc.FalsePositive, Drill: drillStatus("false_positive", &since)})
	if err != nil {
		return err
	}
	v.Intake = in
	v.Drill = in.Drill
	if len(in.Sources) == 0 {
		v.State, v.Reason = StateNotMeasured, ReasonNoReceipts
	}
	return nil
}

// intake reads the organization's receipts in the window.
func (s *Service) intake(ctx context.Context, scope dashboard.ReadScope, since time.Time, fp FlowFigure) (*IntakeValue, error) {
	rows, err := s.facts.OrgIntake(ctx, scope.TenantID, since)
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := &IntakeValue{Since: since, Sources: make([]IntakeSource, 0, len(rows)), Drill: drillReceiptList("", "", since),
		FalsePositive: fp}
	t := &out.Totals
	for _, r := range rows {
		src := IntakeSource{Origin: r.Origin, Tool: r.Tool, Receipts: r.Receipts, Received: r.Received, Created: r.Created,
			StillDetected: r.StillDetected, Reopened: r.Reopened, Closed: r.Closed, Suppressed: r.Suppressed,
			NotStored: r.Skipped + r.Failed, LastAt: r.LastAt.UTC(), LastStatus: r.LastStatus, Health: HealthOK,
			Drill: drillReceiptList(r.Origin, r.Tool, since)}
		if !r.LastReceiptID.IsZero() {
			src.LastReceiptID = r.LastReceiptID.String()
		}
		if r.MedianGap != nil {
			secs := int64(r.MedianGap.Seconds())
			src.ExpectedEverySeconds = &secs
		}
		src.Health = sourceHealth(r, now)
		switch src.Health {
		case HealthFailed:
			out.Failing++
		case HealthStale:
			out.Stale++
		}
		out.Sources = append(out.Sources, src)

		t.Receipts += src.Receipts
		t.Received += src.Received
		t.Created += src.Created
		t.StillDetected += src.StillDetected
		t.Reopened += src.Reopened
		t.Closed += src.Closed
		t.Suppressed += src.Suppressed
		t.NotStored += src.NotStored
		if src.LastAt.After(t.LastAt) {
			t.LastAt, t.LastStatus, t.LastReceiptID = src.LastAt, src.LastStatus, src.LastReceiptID
		}
	}
	t.Health, t.Drill = HealthOK, out.Drill
	out.Noise = noiseOf(*t)
	return out, nil
}

// sourceHealth is failed when the latest receipt failed, stale when
// nothing came for more than twice the usual interval (at least a day).
func sourceHealth(r dashboard.IntakeRow, now time.Time) string {
	if r.LastStatus == "failed" {
		return HealthFailed
	}
	if r.MedianGap != nil {
		after := max(time.Duration(staleFactor)*(*r.MedianGap), minStaleAfter)
		if now.Sub(r.LastAt) > after {
			return HealthStale
		}
	}
	return HealthOK
}

// noiseOf splits the received findings. Every figure is a sum the receipt
// list shows for the same filter: New is Created plus Reopened, so a figure
// equals the list it opens. Suppressed findings are stored (as closed), so
// they stay inside New; Merged is the rest after new, reopened and not
// stored, so New, Merged and NotStored sum to Received.
func noiseOf(t IntakeSource) IntakeNoise {
	n := IntakeNoise{Received: t.Received, Suppressed: t.Suppressed, NotStored: t.NotStored,
		New: t.Created + t.Reopened}
	n.Merged = max(t.Received-t.Created-t.Reopened-t.NotStored, 0)
	return n
}

// drillStatus is the findings list of one status, closed at or after
// since when set.
func drillStatus(status string, since *time.Time) string {
	q := url.Values{}
	q.Set("status", status)
	if since != nil {
		q.Set("resolved_at_gte", since.UTC().Format(time.RFC3339))
	}
	return "/findings?" + q.Encode()
}

// drillReceiptList is the receipt list of a source (origin and tool, both
// optional) with activity since the given time.
func drillReceiptList(origin, tool string, since time.Time) string {
	q := url.Values{}
	if origin != "" {
		q.Set("origin", origin)
	}
	if tool != "" {
		q.Set("tool", tool)
	}
	q.Set("since", since.UTC().Format(time.RFC3339))
	return drillReceipts + "?" + strings.ReplaceAll(q.Encode(), "%3A", ":")
}
