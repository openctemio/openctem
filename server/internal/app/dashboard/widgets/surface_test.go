package widgets

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	dashboardapp "github.com/openctemio/openctem/api/internal/app/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/dashboard"
	"github.com/openctemio/openctem/api/pkg/domain/permission"
)

func surfaceWidget(metric string, rng, compare string) dashboard.Widget {
	tm := map[string]any{}
	if rng != "" {
		tm["range"] = rng
	}
	if compare != "" {
		tm["compare"] = compare
	}
	return dashboard.Widget{WidgetType: "metric", Config: map[string]any{
		"v": 2, "id": "w_s1",
		"data": map[string]any{"kind": "metric", "metric": metric, "filter": map[string]any{}, "time": tm},
		"viz":  map[string]any{"type": "bar", "options": map[string]any{}},
	}}
}

func sameScope(t *testing.T, facts *ctemFacts, want dashboard.ReadScope) {
	t.Helper()
	if len(facts.scopes) == 0 {
		t.Fatal("no read")
	}
	for _, got := range facts.scopes {
		if got.TenantID != want.TenantID || got.Assets != want.Assets || got.CampaignViewer != want.CampaignViewer {
			t.Fatalf("a read used another scope: %+v", got)
		}
	}
}

func query(t *testing.T, href string) url.Values {
	t.Helper()
	u, err := url.Parse(href)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query()
}

func TestNewAssets_ByTypeWithPreviousAndLists(t *testing.T) {
	facts := &ctemFacts{newAssets: []dashboard.NewAssetRow{
		{AssetType: "domain", Current: 3, Previous: 1},
		{AssetType: "certificate", Current: 9, Previous: 9},
		{AssetType: "ip_address", Current: 0, Previous: 4},
		{AssetType: "host", Current: 0, Previous: 0},
	}}
	s := NewService(nil, nil, facts, nil)
	now := fixedNow(s)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, surfaceWidget("surface.new_assets", "7d", "previous_period"), true, scope)
	if v.State != StateReady || v.Shape != dashboard.ShapeCategory || v.Category == nil {
		t.Fatalf("state %s shape %s", v.State, v.Shape)
	}
	sameScope(t, facts, scope)
	from := time.Date(now.Year(), now.Month(), now.Day()-6, 0, 0, 0, 0, time.UTC)
	if !facts.newFrom[0].Equal(from) || !facts.newFrom[1].Equal(from.AddDate(0, 0, -7)) {
		t.Fatalf("window %v", facts.newFrom)
	}
	rows := v.Category.Rows
	// Largest first; a type that only had additions before stays (with no
	// list); a type with none in either window is left out.
	if len(rows) != 3 || rows[0].Key != "certificate" || rows[1].Key != "domain" || rows[2].Key != "ip_address" {
		t.Fatalf("rows %+v", rows)
	}
	if v.Category.Total != 12 {
		t.Errorf("total %v", v.Category.Total)
	}
	if rows[2].Drill != "" || rows[2].Previous == nil || *rows[2].Previous != 4 {
		t.Errorf("dropped type %+v", rows[2])
	}
	q := query(t, rows[1].Drill)
	if !strings.HasPrefix(rows[1].Drill, "/assets?") || q.Get("types") != "domain" ||
		q.Get("first_seen_after") != from.Format(time.DateOnly) || q.Get("program_assets") != "exclude" {
		t.Errorf("domain list %s", rows[1].Drill)
	}

	// Without a comparison, types with no addition in the window are left out.
	facts.scopes = nil
	v = s.widget(context.Background(), 0, surfaceWidget("surface.new_assets", "", ""), true, scope)
	if len(v.Category.Rows) != 2 || v.Category.Rows[0].Previous != nil {
		t.Errorf("rows without compare %+v", v.Category.Rows)
	}
}

func TestCertificateExpiry_BandsAndNotMeasured(t *testing.T) {
	facts := &ctemFacts{certs: dashboard.CertificateExpiryCounts{Total: 40, Expired: 2, Within7d: 0, Within30d: 5, Within90d: 11}}
	s := NewService(nil, nil, facts, nil)
	now := fixedNow(s)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, surfaceWidget("certificates.expiry", "", ""), true, scope)
	if v.State != StateReady || v.Category == nil {
		t.Fatalf("state %s reason %s", v.State, v.Reason)
	}
	sameScope(t, facts, scope)
	if !facts.breakdownNow.Equal(now) {
		t.Errorf("now %v", facts.breakdownNow)
	}
	r := v.Category.Rows
	keys := []string{BandExpired, BandWithin7d, BandWithin30d, BandWithin90d}
	for i, k := range keys {
		if r[i].Key != k {
			t.Fatalf("band %d is %s", i, r[i].Key)
		}
	}
	if v.Category.Total != 18 {
		t.Errorf("total %v", v.Category.Total)
	}
	// An empty band opens nothing; the others open the certificates
	// strictly inside the band.
	if r[1].Drill != "" {
		t.Errorf("empty band links %s", r[1].Drill)
	}
	exp := query(t, r[0].Drill)
	if exp.Get("types") != "certificate" || exp.Get("expires_after") != "" || exp.Get("expires_before") != now.Format(time.RFC3339) {
		t.Errorf("expired list %s", r[0].Drill)
	}
	b30 := query(t, r[2].Drill)
	if b30.Get("expires_after") != now.Add(7*oneDay).Format(time.RFC3339) || b30.Get("expires_before") != now.Add(30*oneDay).Format(time.RFC3339) ||
		b30.Get("program_assets") != "exclude" {
		t.Errorf("30 day list %s", r[2].Drill)
	}

	// No certificate in scope: not measured, never "0 expiring".
	facts.certs = dashboard.CertificateExpiryCounts{}
	v = s.widget(context.Background(), 0, surfaceWidget("certificates.expiry", "", ""), true, scope)
	if v.State != StateNotMeasured || v.Reason != ReasonNoCertificates || v.Category != nil {
		t.Errorf("no certificates: %s %s %+v", v.State, v.Reason, v.Category)
	}
}

func TestAcceptanceExpiry_Bands(t *testing.T) {
	facts := &ctemFacts{accepted: dashboard.AcceptanceExpiryCounts{Accepted: 6, Within7d: 1, Within30d: 2, Later: 3}}
	s := NewService(nil, nil, facts, nil)
	fixedNow(s)
	scope := restrictedScope()
	v := s.widget(context.Background(), 0, surfaceWidget("exceptions.expiring", "", ""), true, scope)
	if v.State != StateReady || v.Category == nil || v.Category.Total != 6 {
		t.Fatalf("state %s %+v", v.State, v.Category)
	}
	sameScope(t, facts, scope)
	want := map[string]map[string]string{
		BandWithin7d:  {"acceptance_expires_at_lte": "P7D"},
		BandWithin30d: {"acceptance_expires_at_gt": "P7D", "acceptance_expires_at_lte": "P30D"},
		BandLater:     {"acceptance_expires_at_gt": "P30D"},
	}
	for _, r := range v.Category.Rows {
		q := query(t, r.Drill)
		if q.Get("status") != "accepted" || q.Get("informational") != "true" {
			t.Errorf("%s list %s", r.Key, r.Drill)
		}
		for k, val := range want[r.Key] {
			if q.Get(k) != val {
				t.Errorf("%s list %s: %s", r.Key, r.Drill, k)
			}
		}
	}

	// The spec refuses a time range: the bands are counted from now.
	if _, err := dashboard.ParseWidgetSpec("metric", surfaceWidget("exceptions.expiring", "90d", "").Config); err == nil {
		t.Error("a range on a current breakdown was accepted")
	}
}

func TestBreakdowns_Permissions(t *testing.T) {
	facts := &ctemFacts{
		newAssets: []dashboard.NewAssetRow{{AssetType: "domain", Current: 1}},
		certs:     dashboard.CertificateExpiryCounts{Total: 1, Expired: 1},
		accepted:  dashboard.AcceptanceExpiryCounts{Accepted: 1, Later: 1},
	}
	s := NewService(nil, nil, facts, nil)
	scope := restrictedScope()
	d := &DashboardData{Widgets: []WidgetValue{
		s.widget(context.Background(), 0, surfaceWidget("surface.new_assets", "", ""), true, scope),
		s.widget(context.Background(), 1, surfaceWidget("certificates.expiry", "", ""), true, scope),
		s.widget(context.Background(), 2, surfaceWidget("exceptions.expiring", "", ""), true, scope),
	}}
	// findings:read alone: the asset breakdowns are masked, accepted risk is not.
	maskForbidden(d, dashboardapp.Caller{Has: func(p string) bool { return p == permission.FindingsRead.String() }})
	for i := 0; i < 2; i++ {
		if w := d.Widgets[i]; w.State != StateUnsupported || w.Reason != ReasonForbidden || w.Category != nil {
			t.Errorf("widget %d not masked: %+v", i, w)
		}
	}
	if d.Widgets[2].Category == nil {
		t.Error("accepted risk masked with findings:read")
	}
}
