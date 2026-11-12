package easm

import (
	"context"
	"testing"
	"time"

	"github.com/openctemio/openctem/server/pkg/domain/asset"
	"github.com/openctemio/openctem/server/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/server/pkg/domain/scope"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// Dispatch honors an exception to the government and military rule
// (docs/rfcs/RFC-154-blocked-target-names.md) for its organization and name
// only, and refuses it again once it expires or is revoked.
func TestActiveGate_GovernmentNameException(t *testing.T) {
	f := newGateFixture(t)
	gov, err := scopedom.NewTarget(f.tenant, scopedom.TargetTypeDomain, "*.agency.gov.vn", "", "")
	if err != nil {
		t.Fatal(err)
	}
	f.targets = append(f.targets, gov)
	now := time.Now()
	policy := scopedom.NewNamePolicy()
	policy.SetClock(func() time.Time { return now })
	policy.Set(scopedom.NameSnapshot{Exceptions: []scopedom.NameException{
		{TenantID: f.tenant, Name: "agency.gov.vn", Subdomains: true, ExpiresAt: now.Add(time.Hour)},
	}})
	scopedom.SetPlatformNamePolicy(policy)
	t.Cleanup(func() { scopedom.SetPlatformNamePolicy(nil) })
	gr, _ := scopedom.NewGuardrails(0, 0, nil)
	g := NewActiveGate(f, f, f, f).WithPlatformPolicy(gr)

	targets := []string{"x.agency.gov.vn", "https://x.agency.gov.vn/", "other.gov.vn"}
	typed, err := g.BlockedTargets(context.Background(), f.tenant, targets)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range targets[:2] {
		if typed[d] == attribution.StatePlatformDenied {
			t.Errorf("%s refused although the organization holds an exception", d)
		}
	}
	if typed["other.gov.vn"] != attribution.StatePlatformDenied {
		t.Errorf("a name outside the exception passed: %v", typed)
	}

	// Another organization gets nothing from it.
	other, err := g.BlockedTargets(context.Background(), shared.NewID(), targets[:1])
	if err != nil {
		t.Fatal(err)
	}
	if other[targets[0]] != attribution.StatePlatformDenied {
		t.Errorf("another organization used the exception: %v", other)
	}

	// A confirmed asset under the name is dispatched while the exception lasts.
	portal := f.add(t, "portal.agency.gov.vn", asset.AssetTypeSubdomain)
	f.record(portal, attribution.StateConfirmed, true)
	got, err := g.ActiveCheckBlocked(context.Background(), f.tenant, []string{portal.ID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if got[portal.ID().String()] == attribution.StatePlatformDenied {
		t.Fatalf("excepted asset refused: %v", got)
	}

	// Expired: refused at dispatch without any refresh.
	now = now.Add(2 * time.Hour)
	got, err = g.ActiveCheckBlocked(context.Background(), f.tenant, []string{portal.ID().String()})
	if err != nil {
		t.Fatal(err)
	}
	if got[portal.ID().String()] != attribution.StatePlatformDenied {
		t.Fatalf("expired exception still dispatched: %v", got)
	}
}
