package widgets

// The emerging-threats breakdown (docs/architecture/dashboards.md, "Emerging
// threats"): the open emerging-threat alerts affecting the reader's scope by
// level, counted with the alert list's own summary statement, so each level
// equals the list it opens for the same viewer.

import (
	"context"
	"net/url"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

const metricEmergingThreats = "intel.emerging_threats"

// ReasonNoThreatAlerts: no emerging-threat alert ever affected an asset in
// the scope, so "no open alert" would read as an all-clear the feed has not
// earned yet.
const ReasonNoThreatAlerts = "no_threat_alerts"

// Alert levels, in the order the list ranks them (the web keeps the order).
var alertLevels = []string{"immediate", "digest", "listed"}

// emergingThreats counts the open alerts in scope by level. A level opens the
// alert list filtered to that level and the open states; an empty level has
// no link. Not measured while no alert in any state is in the scope.
func (s *Service) emergingThreats(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	c, err := s.facts.EmergingThreats(ctx, scope)
	if err != nil {
		return err
	}
	if c.Seen == 0 {
		v.State, v.Reason = StateNotMeasured, ReasonNoThreatAlerts
		return nil
	}
	counts := map[string]int64{"immediate": c.Immediate, "digest": c.Digest, "listed": c.Listed}
	out := &CategoryValue{Rows: make([]CategoryRow, 0, len(alertLevels))}
	for _, level := range alertLevels {
		row := CategoryRow{Key: level, Value: float64(counts[level])}
		if counts[level] > 0 {
			row.Drill = emergingThreatsHref(level)
		}
		out.Rows = append(out.Rows, row)
		out.Total += row.Value
	}
	v.Category = out
	if c.Open > 0 {
		v.Drill = emergingThreatsHref("")
	}
	return nil
}

// emergingThreatsHref is the alert list of the open states, of one level when
// given (the list's own level and state parameters).
func emergingThreatsHref(level string) string {
	q := url.Values{}
	if level != "" {
		q.Set("level", level)
	}
	q.Set("state", "open")
	return "/emerging-threats?" + q.Encode()
}
