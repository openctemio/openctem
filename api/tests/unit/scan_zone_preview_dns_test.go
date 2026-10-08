package unit

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/actscope"
	scanservice "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanzone"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// countingResolver records every name it was asked to resolve.
type countingResolver struct {
	tableResolver
	asked []string
}

func (r *countingResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	r.asked = append(r.asked, host)
	return r.tableResolver.LookupNetIP(ctx, network, host)
}

// refuseFreeText is an act scope that refuses the listed free-text targets.
type refuseFreeText map[string]bool

func (r refuseFreeText) Check(_ context.Context, in actscope.Input) (*actscope.Decision, error) {
	d := &actscope.Decision{RefusedTargets: map[string]string{}, RefusedAssets: map[shared.ID]bool{}}
	for _, t := range in.Targets {
		if r[t] {
			d.RefusedTargets[t] = actscope.ReasonNoScopeTarget
		}
	}
	return d, nil
}

// The scan-zone preview must not be a way to resolve arbitrary names through
// the platform's resolver (sensor → platform review, M1): a target the
// caller may not scan is refused before any lookup, and an answer that is
// private outside the tenant's zones is never shown.
func TestScanZonePreview_NoInternalDNSRecon(t *testing.T) {
	tenant := shared.NewID()
	z := zone(t, tenant, "dc-a", false, []shared.ID{shared.NewID()}, "10.1.0.0/16")
	res := &countingResolver{tableResolver: tableResolver{
		"db.internal.example": {"10.99.0.5"},
		"app.example.com":     {"10.88.0.7"},
		"in-zone.example.com": {"10.1.0.9"},
		"public.example.com":  {"93.184.216.34"},
	}}
	svc, _ := newZonedScanService(&fakeZoneDir{zones: []*scanzone.Zone{z}}, nil, nil,
		scanservice.WithScanZones(&fakeZoneDir{zones: []*scanzone.Zone{z}}, res),
		scanservice.WithActScope(refuseFreeText{"db.internal.example": true}))

	p := preview(t, svc, scanservice.ZoneRoutingPreviewInput{
		TenantID:    tenant.String(),
		ScannerName: "nuclei",
		Targets:     []string{"db.internal.example", "app.example.com", "in-zone.example.com", "public.example.com"},
	})
	for _, h := range res.asked {
		if h == "db.internal.example" {
			t.Fatal("a target outside the caller's scope was resolved")
		}
	}
	by := previewByTarget(p)
	if got := by["db.internal.example"]; got.Status != scanservice.PreviewStatusUncovered || len(got.Addresses) != 0 {
		t.Errorf("out-of-scope target = %+v, want uncovered with no address", got)
	}
	got := by["app.example.com"]
	if len(got.Addresses) != 0 || strings.Contains(got.Reason, "10.88") {
		t.Errorf("a private answer outside every zone was shown: %+v", got)
	}
	if got := by["in-zone.example.com"]; len(got.Addresses) != 1 || got.Addresses[0] != "10.1.0.9" {
		t.Errorf("an answer inside the tenant's zone = %+v, want it shown", got)
	}
	if got := by["public.example.com"]; len(got.Addresses) != 1 {
		t.Errorf("a public answer = %+v, want it shown", got)
	}
}
