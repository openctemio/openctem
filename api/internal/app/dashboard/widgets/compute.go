package widgets

import (
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// Window is the time window of a widget read, in UTC days.
type Window struct {
	From         string `json:"from"`
	To           string `json:"to"`
	PreviousFrom string `json:"previous_from,omitempty"`
	PreviousTo   string `json:"previous_to,omitempty"`
	Bucket       string `json:"bucket"`
	Days         int    `json:"days"`

	from, to, prevFrom, prevTo time.Time
}

// rangeDays maps a spec range to days; "inherit" is the dashboard range,
// 30 days until the dashboard filter bar exists.
func rangeDays(r string) int {
	switch r {
	case dashboard.TimeRange7d:
		return 7
	case dashboard.TimeRange90d:
		return 90
	case dashboard.TimeRange365d:
		return 365
	default:
		return 30
	}
}

func dayOf(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

// newWindow is the window ending today (UTC) and the same length before it.
func newWindow(now time.Time, t dashboard.WidgetTime) Window {
	days := rangeDays(t.Range)
	to := dayOf(now)
	from := to.AddDate(0, 0, -(days - 1))
	prevTo := from.AddDate(0, 0, -1)
	prevFrom := prevTo.AddDate(0, 0, -(days - 1))
	bucket := t.Bucket
	if bucket == "" || bucket == dashboard.TimeBucketAuto {
		switch {
		case days <= 31:
			bucket = dashboard.TimeBucketDay
		case days <= 90:
			bucket = dashboard.TimeBucketWeek
		default:
			bucket = dashboard.TimeBucketMonth
		}
	}
	w := Window{
		From: from.Format(time.DateOnly), To: to.Format(time.DateOnly), Bucket: bucket, Days: days,
		from: from, to: to, prevFrom: prevFrom, prevTo: prevTo,
	}
	if t.Compare == dashboard.ComparePreviousPeriod {
		w.PreviousFrom, w.PreviousTo = prevFrom.Format(time.DateOnly), prevTo.Format(time.DateOnly)
	}
	return w
}

// bucketEnds lists the last day of every bucket in [from, to], ascending;
// the last bucket ends on to.
func bucketEnds(from, to time.Time, bucket string) []time.Time {
	var ends []time.Time
	switch bucket {
	case dashboard.TimeBucketWeek:
		for e := to; !e.Before(from); e = e.AddDate(0, 0, -7) {
			ends = append(ends, e)
		}
		sort.Slice(ends, func(i, j int) bool { return ends[i].Before(ends[j]) })
	case dashboard.TimeBucketMonth:
		for m := time.Date(from.Year(), from.Month(), 1, 0, 0, 0, 0, time.UTC); !m.After(to); m = m.AddDate(0, 1, 0) {
			e := m.AddDate(0, 1, -1)
			if e.After(to) {
				e = to
			}
			if !e.Before(from) {
				ends = append(ends, e)
			}
		}
	default:
		for d := from; !d.After(to); d = d.AddDate(0, 0, 1) {
			ends = append(ends, d)
		}
	}
	return ends
}

// Point is one value at a bucket end.
type Point struct {
	T string  `json:"t"`
	V float64 `json:"v"`
}

// backcast turns the open count now and the daily net changes into the open
// count at the end of each bucket: open at the end of day E is open now
// minus every net change after E (the F2 identity).
func backcast(openNow int64, days []dashboard.DayRow, ends []time.Time) []Point {
	out := make([]Point, len(ends))
	for i, e := range ends {
		var after int64
		for _, d := range days {
			if dayOf(d.Day).After(e) {
				after += d.NetDelta
			}
		}
		out[i] = Point{T: e.Format(time.DateOnly), V: float64(openNow - after)}
	}
	return out
}

// flows sums the opened and fixed findings of each bucket (prevEnd, end].
func flows(days []dashboard.DayRow, from time.Time, ends []time.Time) (opened, fixed []Point) {
	opened, fixed = make([]Point, len(ends)), make([]Point, len(ends))
	start := from.AddDate(0, 0, -1)
	for i, e := range ends {
		var o, f int64
		for _, d := range days {
			day := dayOf(d.Day)
			if day.After(start) && !day.After(e) {
				o += d.Opened
				f += d.Fixed
			}
		}
		opened[i] = Point{T: e.Format(time.DateOnly), V: float64(o)}
		fixed[i] = Point{T: e.Format(time.DateOnly), V: float64(f)}
		start = e
	}
	return opened, fixed
}

// histBounds are the hour bounds of the 12 fix-hours buckets: under 1 h,
// then [2^(k-1), 2^k) for k = 1..10, then 1024 h and more.
func histBound(k int) (lo, hi float64) {
	switch {
	case k <= 0:
		return 0, 1
	case k >= 11:
		return 1024, math.Inf(1)
	default:
		return math.Pow(2, float64(k-1)), math.Pow(2, float64(k))
	}
}

// histQuantile estimates the q-quantile in hours from the bucket counts:
// linear inside the first bucket, geometric inside the doubling buckets, and
// the lower bound of the last, open-ended bucket. n is the total count.
func histQuantile(h [12]int64, q float64) (hours float64, n int64) {
	for _, c := range h {
		n += c
	}
	if n == 0 {
		return 0, 0
	}
	target := q * float64(n)
	var cum float64
	for k, c := range h {
		if c == 0 {
			continue
		}
		if cum+float64(c) >= target {
			frac := (target - cum) / float64(c)
			lo, hi := histBound(k)
			switch {
			case k == 0:
				return lo + frac*(hi-lo), n
			case math.IsInf(hi, 1):
				return lo, n
			default:
				return lo * math.Pow(hi/lo, frac), n
			}
		}
		cum += float64(c)
	}
	lo, _ := histBound(11)
	return lo, n
}

// minFixedForDuration is the sample below which a time to fix is not
// measured: a median of three fixes says nothing.
const minFixedForDuration = 5

// slaListValues maps a fact SLA state to the findings list's sla_status
// values; "none" (no SLA) has no exact list filter.
var slaListValues = map[string][]string{
	"ok":       {"on_track"},
	"warning":  {"warning"},
	"breached": {"overdue", "exceeded"},
}

// drillHref is the findings list built from the same filter the figure is
// counted with, so the list total equals the figure. A filter the list
// cannot express exactly (age band, "no SLA", KEV or reachable false, more
// than one asset group) gives no link rather than a link to a wider list.
func drillHref(f dashboard.WidgetFilter) string {
	q := url.Values{}
	q.Set("state", "open")
	if len(f.Severity) > 0 {
		q.Set("severity", strings.Join(f.Severity, ","))
	}
	if len(f.Severity) == 0 && len(f.PriorityClass) == 0 && len(f.SLAState) == 0 {
		// The facts count informational findings; the findings page hides them
		// unless asked (an explicit severity always shows them), so a plain
		// open link asks for them and the list total equals the figure. A
		// priority or SLA link is left as it is.
		q.Set("informational", "true")
	}
	if len(f.PriorityClass) > 0 {
		for _, p := range f.PriorityClass {
			if p == "none" {
				return ""
			}
		}
		q.Set("priority_class", strings.Join(f.PriorityClass, ","))
	}
	if len(f.Source) > 0 {
		q.Set("source", strings.Join(f.Source, ","))
	}
	if len(f.SLAState) > 0 {
		var vals []string
		for _, s := range f.SLAState {
			v, ok := slaListValues[s]
			if !ok {
				return ""
			}
			vals = append(vals, v...)
		}
		q.Set("sla_status", strings.Join(vals, ","))
	}
	if len(f.AgeBand) > 0 {
		return ""
	}
	if f.KEV != nil {
		if !*f.KEV {
			return ""
		}
		q.Set("is_in_kev", "true")
	}
	if f.Reachable != nil {
		if !*f.Reachable {
			return ""
		}
		q.Set("is_reachable", "true")
	}
	switch len(f.AssetGroupIDs) {
	case 0:
	case 1:
		q.Set("asset_group_id", f.AssetGroupIDs[0])
	default:
		return ""
	}
	// Commas stay readable; the list splits on them.
	return "/findings?" + strings.ReplaceAll(q.Encode(), "%2C", ",")
}

// historyCompatible reports whether a count can be traced back with the
// daily history (F2), which carries severity, priority and asset only.
func historyCompatible(f dashboard.WidgetFilter, groupBy []dashboard.Dimension) bool {
	if len(f.Source) > 0 || len(f.SLAState) > 0 || len(f.AgeBand) > 0 || f.KEV != nil || f.Reachable != nil {
		return false
	}
	for _, d := range groupBy {
		if d != dashboard.DimSeverity && d != dashboard.DimPriorityClass {
			return false
		}
	}
	return true
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
