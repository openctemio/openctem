package widgets

// The attack surface and accepted-risk breakdowns
// (docs/architecture/dashboards.md, "Attack surface and accepted risk"):
// assets added in the window by type, certificates by expiry band and
// accepted risks by when the acceptance ends. Each is a category whose rows
// carry the list they count, read through FactReader with the scope the
// server built for the read, and stored in the snapshot like every widget.

import (
	"context"
	"net/url"
	"sort"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
)

// Reasons of the breakdowns.
const (
	// ReasonNoCertificates: no certificate is in the scope, so "none
	// expiring" would read as an all-clear.
	ReasonNoCertificates = "no_certificates"
)

// Keys of the expiry bands (the web translates them).
const (
	BandExpired   = "expired"
	BandWithin7d  = "within_7d"
	BandWithin30d = "within_30d"
	BandWithin90d = "within_90d"
	BandLater     = "later"
)

const oneDay = 24 * time.Hour

// breakdown dispatches a MetricKindBreakdown metric by id.
func (s *Service) breakdown(ctx context.Context, v *WidgetValue, m dashboard.Metric, win Window, compare bool, scope dashboard.ReadScope) error {
	switch m.ID {
	case "surface.new_assets":
		v.Window = &win
		return s.newAssets(ctx, v, win, compare, scope)
	case "certificates.expiry":
		return s.certificateExpiry(ctx, v, scope)
	case "exceptions.expiring":
		return s.acceptanceExpiry(ctx, v, scope)
	case metricEmergingThreats:
		return s.emergingThreats(ctx, v, scope)
	}
	return errUnknownBreakdown
}

type breakdownError string

func (e breakdownError) Error() string { return string(e) }

const errUnknownBreakdown = breakdownError("unknown breakdown metric")

// newAssets counts the assets added in the window by type. Each row opens
// the asset list of that type added since the window's first day (the
// list's first_seen_after is created_at at or after that day), program-only
// assets left out like every dashboard read, so the row equals its list.
func (s *Service) newAssets(ctx context.Context, v *WidgetValue, win Window, compare bool, scope dashboard.ReadScope) error {
	rows, err := s.facts.NewAssets(ctx, scope, win.from, win.prevFrom)
	if err != nil {
		return err
	}
	out := &CategoryValue{Rows: make([]CategoryRow, 0, len(rows))}
	since := win.from.Format(time.DateOnly)
	for _, r := range rows {
		if r.Current == 0 && (!compare || r.Previous == 0) {
			continue
		}
		row := CategoryRow{Key: r.AssetType, Value: float64(r.Current)}
		if r.Current > 0 {
			row.Drill = newAssetsHref(r.AssetType, since)
		}
		if compare {
			p := float64(r.Previous)
			row.Previous = &p
		}
		out.Rows = append(out.Rows, row)
		out.Total += float64(r.Current)
	}
	sort.SliceStable(out.Rows, func(i, j int) bool {
		if out.Rows[i].Value != out.Rows[j].Value {
			return out.Rows[i].Value > out.Rows[j].Value
		}
		return out.Rows[i].Key < out.Rows[j].Key
	})
	v.Category = out
	if out.Total > 0 {
		v.Drill = "/assets?first_seen_after=" + since + "&program_assets=exclude"
	}
	return nil
}

func newAssetsHref(assetType, since string) string {
	q := url.Values{}
	q.Set("types", assetType)
	q.Set("first_seen_after", since)
	q.Set("program_assets", "exclude")
	return "/assets?" + q.Encode()
}

// certificateExpiry counts the certificates in scope by expiry band. A band
// opens the certificate assets whose expiry is strictly inside it, the same
// comparisons the asset list's expires_after / expires_before filters use.
// No certificate in scope is not measured, never "0 expiring".
func (s *Service) certificateExpiry(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	now := s.now().UTC().Truncate(time.Minute)
	c, err := s.facts.CertificateExpiry(ctx, scope, now)
	if err != nil {
		return err
	}
	if c.Total == 0 {
		v.State, v.Reason = StateNotMeasured, ReasonNoCertificates
		return nil
	}
	t7, t30, t90 := now.Add(7*oneDay), now.Add(30*oneDay), now.Add(90*oneDay)
	rows := []CategoryRow{
		{Key: BandExpired, Value: float64(c.Expired), Drill: certificatesHref(time.Time{}, now)},
		{Key: BandWithin7d, Value: float64(c.Within7d), Drill: certificatesHref(now, t7)},
		{Key: BandWithin30d, Value: float64(c.Within30d), Drill: certificatesHref(t7, t30)},
		{Key: BandWithin90d, Value: float64(c.Within90d), Drill: certificatesHref(t30, t90)},
	}
	out := &CategoryValue{Rows: rows}
	for i := range rows {
		out.Total += rows[i].Value
		if rows[i].Value == 0 {
			out.Rows[i].Drill = ""
		}
	}
	v.Category = out
	v.Drill = "/attack-surface/certificates"
	return nil
}

func certificatesHref(after, before time.Time) string {
	q := url.Values{}
	q.Set("types", "certificate")
	if !after.IsZero() {
		q.Set("expires_after", after.Format(time.RFC3339))
	}
	q.Set("expires_before", before.Format(time.RFC3339))
	q.Set("program_assets", "exclude")
	return "/assets?" + q.Encode()
}

// acceptanceExpiry counts the accepted findings in scope by when their
// acceptance ends. A band opens the accepted findings with the findings
// list's relative filters (P7D is seven days from when the list is opened),
// so a band equals its list at the snapshot's time. Every acceptance ends
// (at most 90 days after it is granted), so the three bands cover them all.
func (s *Service) acceptanceExpiry(ctx context.Context, v *WidgetValue, scope dashboard.ReadScope) error {
	c, err := s.facts.AcceptanceExpiry(ctx, scope, s.now().UTC())
	if err != nil {
		return err
	}
	rows := []CategoryRow{
		{Key: BandWithin7d, Value: float64(c.Within7d), Drill: acceptedHref("acceptance_expires_at_lte", "P7D")},
		{Key: BandWithin30d, Value: float64(c.Within30d), Drill: acceptedHref("acceptance_expires_at_gt", "P7D", "acceptance_expires_at_lte", "P30D")},
		{Key: BandLater, Value: float64(c.Later), Drill: acceptedHref("acceptance_expires_at_gt", "P30D")},
	}
	out := &CategoryValue{Rows: rows}
	for i := range rows {
		out.Total += rows[i].Value
		if rows[i].Value == 0 {
			out.Rows[i].Drill = ""
		}
	}
	v.Category = out
	if c.Accepted > 0 {
		v.Drill = acceptedHref()
	}
	return nil
}

// acceptedHref is the accepted findings list (informational included, as
// the counts include them) with the given parameter pairs.
func acceptedHref(kv ...string) string {
	q := url.Values{}
	q.Set("status", "accepted")
	q.Set("informational", "true")
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	return "/findings?" + q.Encode()
}
