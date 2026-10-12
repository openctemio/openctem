package scan

import (
	"context"
	"slices"
	"testing"
	"time"

	scopeapp "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/pkg/domain/attribution"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

type activeExclusions struct {
	scopedom.ExclusionRepository
	active []*scopedom.Exclusion
}

func (a activeExclusions) ListActive(context.Context, shared.ID) ([]*scopedom.Exclusion, error) {
	return a.active, nil
}

func approvedPathRule(t *testing.T, tenant shared.ID, host, prefix string, mode scopedom.Testing) *scopedom.Exclusion {
	t.Helper()
	e, err := scopedom.NewExclusion(tenant, scopedom.ExclusionTypePath, host, "admin console", nil, "r")
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Approve("a"); err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	e.SetWeb(&scopedom.WebRule{PathPrefix: prefix, Testing: mode, TestingUntil: &until})
	return e
}

// RFC-056, owner 2026-10-07: setting an exclusion to "allowed" re-enables its
// paths only on the organization's own in-scope assets. A host the exclusion
// pattern ("*") covers but the tenant does not own is still refused by the
// authority check; the exclusion never widens scope.
func TestDispatch_AllowedPathExclusionNeverWidensScope(t *testing.T) {
	tenant := shared.NewID()
	excl := scopeapp.NewService(nil, activeExclusions{active: []*scopedom.Exclusion{
		approvedPathRule(t, tenant, "*", "/admin", scopedom.TestingAllowed),
	}}, nil, logger.NewNop())
	gate := &stubGate{blockedTyped: map[string]attribution.State{"https://not-ours.example.net/admin": attribution.StateUnattributed}}
	svc := &Service{scopeExclusions: excl, attributionGate: gate, logger: logger.NewNop()}

	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{TenantID: tenant,
		Targets: []string{"https://app.example.com/admin", "https://not-ours.example.net/admin"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Allowed, []string{"https://app.example.com/admin"}) {
		t.Fatalf("allowed = %v, want only the tenant's own target", got.Allowed)
	}
	if r := refusedTargets(got); !slices.Equal(r, []string{"https://not-ours.example.net/admin"}) {
		t.Fatalf("refused = %v, want the host outside the organization's assets", r)
	}
}

// A blocked path exclusion keeps URL targets under it out of the dispatch;
// the host itself still dispatches.
func TestDispatch_BlockedPathExclusionDropsURLTargets(t *testing.T) {
	tenant := shared.NewID()
	excl := scopeapp.NewService(nil, activeExclusions{active: []*scopedom.Exclusion{
		approvedPathRule(t, tenant, "*", "/admin/debug", scopedom.TestingBlocked),
	}}, nil, logger.NewNop())
	svc := &Service{scopeExclusions: excl, attributionGate: &stubGate{}, logger: logger.NewNop()}
	got, err := svc.ResolveDispatchTargets(context.Background(), DispatchTargetsInput{TenantID: tenant,
		Targets: []string{"https://app.example.com/admin/debug/x", "https://app.example.com", "app.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Excluded, []string{"https://app.example.com/admin/debug/x"}) ||
		!slices.Equal(got.Allowed, []string{"https://app.example.com", "app.example.com"}) {
		t.Fatalf("excluded = %v, allowed = %v", got.Excluded, got.Allowed)
	}
}
