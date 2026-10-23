package sla

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// memSLARepo answers GetByAsset / GetTenantDefault with the same rules as the
// SQL in the postgres repository, so the per-finding path and the batch path
// can be compared on one data set.
type memSLARepo struct {
	sladom.Repository
	policies []*sladom.Policy
	lists    int
	lookups  int
}

func (r *memSLARepo) ListByTenant(_ context.Context, tenantID shared.ID) ([]*sladom.Policy, error) {
	r.lists++
	var out []*sladom.Policy
	for _, p := range r.policies {
		if p.TenantID() == tenantID {
			out = append(out, p)
		}
	}
	return out, nil
}

func (r *memSLARepo) GetByAsset(_ context.Context, tenantID, assetID shared.ID) (*sladom.Policy, error) {
	r.lookups++
	var def *sladom.Policy
	for _, p := range r.policies {
		if p.TenantID() != tenantID || !p.IsActive() {
			continue
		}
		if a := p.AssetID(); a != nil && *a == assetID {
			return p, nil
		}
		if p.AssetID() == nil && p.IsDefault() && def == nil {
			def = p
		}
	}
	if def == nil {
		return nil, sladom.ErrNotFound
	}
	return def, nil
}

func (r *memSLARepo) GetTenantDefault(_ context.Context, tenantID shared.ID) (*sladom.Policy, error) {
	r.lookups++
	for _, p := range r.policies {
		if p.TenantID() == tenantID && p.AssetID() == nil && p.IsDefault() && p.IsActive() {
			return p, nil
		}
	}
	return nil, sladom.ErrNotFound
}

func mkPolicy(tenant shared.ID, asset *shared.ID, isDefault, active bool, highDays int, created time.Time) *sladom.Policy {
	return sladom.Reconstitute(shared.NewID(), tenant, asset, "p", "", isDefault,
		2, highDays, 30, 90, 0, 80, false, nil, active, created, created)
}

// SLADeadlineFunc must pick the same policy as the per-finding lookups for
// every case, while loading the policies once.
func TestSLADeadlineFunc_MatchesPerFindingLookup(t *testing.T) {
	tenant, other := shared.NewID(), shared.NewID()
	own, inactiveOwn, plain := shared.NewID(), shared.NewID(), shared.NewID()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := &memSLARepo{policies: []*sladom.Policy{
		mkPolicy(tenant, nil, true, true, 7, t0),
		mkPolicy(tenant, &own, false, true, 3, t0.Add(time.Hour)),
		mkPolicy(tenant, &inactiveOwn, false, false, 1, t0.Add(time.Hour)),
		// Another tenant's policy for the same asset id must never apply.
		mkPolicy(other, &plain, false, true, 99, t0),
	}}
	svc := NewService(repo, logger.NewNop())
	ctx := context.Background()
	fn, err := svc.SLADeadlineFunc(ctx, tenant.String())
	if err != nil {
		t.Fatalf("SLADeadlineFunc: %v", err)
	}
	detected := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name, asset string
		sev         vulnerability.Severity
		class       string
	}{
		{"own policy", own.String(), vulnerability.SeverityHigh, ""},
		{"inactive own policy falls back to default", inactiveOwn.String(), vulnerability.SeverityHigh, ""},
		{"no own policy", plain.String(), vulnerability.SeverityHigh, ""},
		{"no asset", "", vulnerability.SeverityHigh, ""},
		{"priority class", own.String(), vulnerability.SeverityMedium, "P1"},
		{"informational", plain.String(), vulnerability.SeverityInfo, ""},
	} {
		want, werr := svc.CalculateSLADeadlineForPriority(ctx, tenant.String(), tc.asset, tc.class, tc.sev, detected)
		got, gerr := fn(tc.asset, tc.class, tc.sev, detected)
		if (werr != nil) != (gerr != nil) || !got.Equal(want) {
			t.Errorf("%s: batch = %v (%v), per-finding = %v (%v)", tc.name, got, gerr, want, werr)
		}
	}
	if repo.lists != 1 {
		t.Errorf("ListByTenant calls = %d, want 1", repo.lists)
	}
}

// An inactive default never governs, with or without an asset: asset-less
// findings fall back to the platform windows, not the inactive policy's.
func TestSLADeadlineFunc_InactiveDefaultIgnored(t *testing.T) {
	tenant := shared.NewID()
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	repo := &memSLARepo{policies: []*sladom.Policy{mkPolicy(tenant, nil, true, false, 1, t0)}}
	svc := NewService(repo, logger.NewNop())
	ctx := context.Background()
	fn, err := svc.SLADeadlineFunc(ctx, tenant.String())
	if err != nil {
		t.Fatal(err)
	}
	detected := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for _, asset := range []string{"", shared.NewID().String()} {
		got, _ := fn(asset, "", vulnerability.SeverityHigh, detected)
		want, _ := deadlineForPriority(nil, "", vulnerability.SeverityHigh, detected)
		if !got.Equal(want) {
			t.Errorf("asset %q: deadline %v follows the inactive default, want platform %v", asset, got, want)
		}
	}
}

// With no policy at all, both paths fall back to the built-in defaults.
func TestSLADeadlineFunc_NoPolicies(t *testing.T) {
	tenant := shared.NewID()
	svc := NewService(&memSLARepo{}, logger.NewNop())
	ctx := context.Background()
	fn, err := svc.SLADeadlineFunc(ctx, tenant.String())
	if err != nil {
		t.Fatalf("SLADeadlineFunc: %v", err)
	}
	detected := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	want, _ := svc.CalculateSLADeadlineForPriority(ctx, tenant.String(), shared.NewID().String(), "", vulnerability.SeverityCritical, detected)
	got, _ := fn(shared.NewID().String(), "", vulnerability.SeverityCritical, detected)
	if !got.Equal(want) || got.IsZero() {
		t.Fatalf("batch = %v, per-finding = %v", got, want)
	}
}

type batchCalc struct {
	fakeCalc
	fnCalls int
}

func (b *batchCalc) SLADeadlineFunc(_ context.Context, _ string) (DeadlineFunc, error) {
	b.fnCalls++
	return func(_, _ string, _ vulnerability.Severity, at time.Time) (time.Time, error) {
		return at.Add(24 * time.Hour), nil
	}, nil
}

// The applier loads policies once per batch when the calculator can.
func TestSLAApplier_UsesBatchDeadlineFunc(t *testing.T) {
	calc := &batchCalc{}
	a := NewApplier(calc)
	fs := []*vulnerability.Finding{
		newAppliedFinding(t, "P1", vulnerability.SeverityHigh),
		newAppliedFinding(t, "", vulnerability.SeverityLow),
	}
	if err := a.ApplyBatch(context.Background(), shared.NewID(), fs); err != nil {
		t.Fatalf("ApplyBatch: %v", err)
	}
	if calc.fnCalls != 1 || calc.calls != 0 {
		t.Fatalf("batch loads = %d, per-finding calls = %d; want 1 and 0", calc.fnCalls, calc.calls)
	}
	for _, f := range fs {
		if f.SLADeadline() == nil {
			t.Fatal("deadline not set")
		}
	}
}
