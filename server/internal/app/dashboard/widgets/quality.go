package widgets

// Closure quality, remediation campaign progress and false positives by tool
// (docs/architecture/dashboards.md, "Closure quality, campaigns and detection
// quality"). Each is a category read through FactReader with the scope the
// server built for the read and stored in the snapshot like every widget.
// Every row with a figure opens the list it counts.

import (
	"context"
	"math"
	"net/url"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// Reasons of the quality breakdowns.
const (
	// ReasonNoClosures: nothing was fixed or reopened in the window and no
	// proposal waits, so the rows would all read 0.
	ReasonNoClosures = "no_closures"
	// ReasonNoActiveCampaigns: the reader sees no active campaign with a task.
	ReasonNoActiveCampaigns = "no_active_campaigns"
	// ReasonTooFewClosed: no tool closed MinToolClosed findings in the
	// window, so no rate would be meaningful.
	ReasonTooFewClosed = "too_few_closed"
)

// Keys of the closure quality rows (the web translates them).
const (
	ClosureByPerson     = "closed_by_person"
	ClosureAutomatic    = "closed_automatically"
	ClosureReopened     = "reopened"
	ClosureReadyToClose = "ready_to_close"
)

const (
	// MinToolClosed is the closes in the window a tool needs before its
	// false-positive rate is shown: 1 of 2 is not "50 %".
	MinToolClosed = 20
	// maxToolRows and maxCampaignRows bound the rows of a widget.
	maxToolRows      = 8
	maxCampaignRows  = 5
	readyToCloseHref = "/findings/ready-to-close"
	campaignsHref    = "/remediation/campaigns"
)

// closureQuality counts the window's fixes by a person and by the platform,
// the fixed findings that came back, and the Ready to close backlog. The
// three window rows open the findings list with the same comparisons; Ready
// to close opens its own page, counted with its own statement.
func (s *Service) closureQuality(ctx context.Context, v *WidgetValue, win Window, compare bool, scope dashboard.ReadScope) error {
	c, err := s.facts.ClosureQuality(ctx, scope, win.from, win.prevFrom)
	if err != nil {
		return err
	}
	cur, prev := c.Current, c.Previous
	if cur.ByPerson+cur.Automatic+cur.Reopened+c.ReadyToClose == 0 && (!compare || prev.ByPerson+prev.Automatic+prev.Reopened == 0) {
		v.State, v.Reason = StateNotMeasured, ReasonNoClosures
		return nil
	}
	since := win.from.UTC().Format(time.RFC3339)
	rows := []CategoryRow{
		{Key: ClosureByPerson, Value: float64(cur.ByPerson), Drill: fixedHref(since, "false")},
		{Key: ClosureAutomatic, Value: float64(cur.Automatic), Drill: fixedHref(since, "true")},
		{Key: ClosureReopened, Value: float64(cur.Reopened), Drill: reopenedHref(since)},
		{Key: ClosureReadyToClose, Value: float64(c.ReadyToClose), Drill: readyToCloseHref},
	}
	if compare {
		for i, p := range []int64{prev.ByPerson, prev.Automatic, prev.Reopened} {
			f := float64(p)
			rows[i].Previous = &f
		}
	}
	out := &CategoryValue{Rows: rows}
	for i := range rows {
		out.Total += rows[i].Value
		if rows[i].Value == 0 {
			out.Rows[i].Drill = ""
		}
	}
	v.Category = out
	if cur.ByPerson+cur.Automatic > 0 {
		v.Drill = drillStatus("resolved", &win.from)
	}
	return nil
}

// fixedHref is the fixed findings since the window's first day, closed by a
// person (resolved_by set: byPlatform "false") or with no person recorded
// ("true"), informational included as the counts include them.
func fixedHref(since, byPlatform string) string {
	q := url.Values{}
	q.Set("status", "resolved")
	q.Set("resolved_at_gte", since)
	q.Set("resolved_by_null", byPlatform)
	q.Set("informational", "true")
	return "/findings?" + q.Encode()
}

// reopenedHref is every finding (any status now) that came back after a fix
// since the window's first day.
func reopenedHref(since string) string {
	q := url.Values{}
	q.Set("state", "all")
	q.Set("last_reopened_at_gte", since)
	q.Set("informational", "true")
	return "/findings?" + q.Encode()
}

// campaignProgress shows the active campaigns the reader sees, the latest
// first (most overdue tasks, then the earliest due date passed, then the
// least done), each as the share of its visible tasks that are done. Total is
// the share over every active campaign the reader sees. A row opens the
// campaign.
func (s *Service) campaignProgress(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	all, err := s.facts.ActiveCampaigns(ctx, scope)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	rows := make([]dashboard.CampaignProgressRow, 0, len(all))
	var tasks, done int64
	for _, c := range all {
		if c.Tasks == 0 {
			continue
		}
		rows = append(rows, c)
		tasks += c.Tasks
		done += c.Done
	}
	if len(rows) == 0 {
		v.State, v.Reason = StateNotMeasured, ReasonNoActiveCampaigns
		return nil
	}
	pastDue := func(c dashboard.CampaignProgressRow) bool { return c.DueDate != nil && c.DueDate.Before(now) }
	sort.SliceStable(rows, func(i, j int) bool {
		a, b := rows[i], rows[j]
		if a.Overdue != b.Overdue {
			return a.Overdue > b.Overdue
		}
		if pastDue(a) != pastDue(b) {
			return pastDue(a)
		}
		if pastDue(a) && !a.DueDate.Equal(*b.DueDate) {
			return a.DueDate.Before(*b.DueDate)
		}
		pa, pb := share(a.Done, a.Tasks), share(b.Done, b.Tasks)
		if pa != pb {
			return pa < pb
		}
		return a.Name < b.Name
	})
	if len(rows) > maxCampaignRows {
		rows = rows[:maxCampaignRows]
	}
	out := &CategoryValue{Rows: make([]CategoryRow, 0, len(rows)), Total: share(done, tasks)}
	for _, c := range rows {
		n := c.Tasks
		out.Rows = append(out.Rows, CategoryRow{
			Key: c.ID.String(), Label: c.Name, Value: share(c.Done, c.Tasks), N: &n,
			Drill: campaignsHref + "/" + url.PathEscape(c.ID.String()),
		})
	}
	v.Category = out
	v.Drill = campaignsHref
	return nil
}

// fpRateByTool is, per tool, the findings closed as false positive in the
// window over the findings closed in the window. An organization figure:
// tool names are not asset-scoped, so a personal read is not measured. A
// tool with fewer than MinToolClosed closes is left out. A row opens the
// tool's false positives closed in the window; Total is the rate over the
// tools shown.
func (s *Service) fpRateByTool(ctx context.Context, v *WidgetValue, win Window, scope dashboard.ReadScope) error {
	if !orgRead(scope) {
		v.State, v.Reason = StateNotMeasured, ReasonOrganizationOnly
		return nil
	}
	all, err := s.facts.ClosedByTool(ctx, scope, win.from)
	if err != nil {
		return err
	}
	rows := make([]dashboard.ToolClosedRow, 0, len(all))
	for _, r := range all {
		if r.Tool != "" && r.Closed >= MinToolClosed {
			rows = append(rows, r)
		}
	}
	if len(rows) == 0 {
		v.State, v.Reason = StateNotMeasured, ReasonTooFewClosed
		return nil
	}
	sort.SliceStable(rows, func(i, j int) bool {
		pi, pj := share(rows[i].FalsePositive, rows[i].Closed), share(rows[j].FalsePositive, rows[j].Closed)
		if pi != pj {
			return pi > pj
		}
		if rows[i].Closed != rows[j].Closed {
			return rows[i].Closed > rows[j].Closed
		}
		return rows[i].Tool < rows[j].Tool
	})
	if len(rows) > maxToolRows {
		rows = rows[:maxToolRows]
	}
	since := win.from.UTC().Format(time.RFC3339)
	out := &CategoryValue{Rows: make([]CategoryRow, 0, len(rows))}
	var fp, closed int64
	for _, r := range rows {
		n := r.Closed
		row := CategoryRow{Key: r.Tool, Label: r.Tool, Value: share(r.FalsePositive, r.Closed), N: &n}
		if r.FalsePositive > 0 {
			row.Drill = falsePositiveHref(r.Tool, since)
		}
		out.Rows = append(out.Rows, row)
		fp += r.FalsePositive
		closed += r.Closed
	}
	out.Total = share(fp, closed)
	v.Category = out
	if fp > 0 {
		v.Drill = falsePositiveHref("", since)
	}
	return nil
}

// falsePositiveHref is the findings closed as false positive since the
// window's first day, of one tool when given.
func falsePositiveHref(tool, since string) string {
	q := url.Values{}
	q.Set("status", "false_positive")
	if tool != "" {
		q.Set("tool_name", tool)
	}
	q.Set("resolved_at_gte", since)
	q.Set("informational", "true")
	return "/findings?" + q.Encode()
}

// share is num/den in percent, one decimal; 0 when den is 0.
func share(num, den int64) float64 {
	if den == 0 {
		return 0
	}
	return math.Round(float64(num)*1000/float64(den)) / 10
}
