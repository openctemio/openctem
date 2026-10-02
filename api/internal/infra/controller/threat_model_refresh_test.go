package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	tmdom "github.com/openctemio/api/pkg/domain/threatmodel"
)

// --- fakes -----------------------------------------------------------

// fakeThreatModelGenerator implements the controller's threatModelGenerator
// interface without pulling in a real threatmodel.Service. One call per
// tenant; errs[tenantID] forces an error for that tenant only.
type fakeThreatModelGenerator struct {
	errs  map[string]error
	calls []fakeThreatModelCall
}

type fakeThreatModelCall struct {
	tenantID   shared.ID
	scopeType  tmdom.ScopeType
	scopeRefID *shared.ID
}

func (f *fakeThreatModelGenerator) GenerateForScope(_ context.Context, tenantID shared.ID, scopeType tmdom.ScopeType, scopeRefID *shared.ID) (*tmdom.ThreatModel, error) {
	f.calls = append(f.calls, fakeThreatModelCall{tenantID: tenantID, scopeType: scopeType, scopeRefID: scopeRefID})
	if err, ok := f.errs[tenantID.String()]; ok && err != nil {
		return nil, err
	}
	return &tmdom.ThreatModel{}, nil
}

// fakeTenantLister only implements the slice of tenant.Repository the
// controller actually calls (ListActiveTenantIDs). The rest panics if
// touched.
type fakeTenantLister struct {
	tenant.Repository
	ids []shared.ID
	err error
}

func (f *fakeTenantLister) ListActiveTenantIDs(_ context.Context) ([]shared.ID, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.ids, nil
}

// --- tests -------------------------------------------------------------

func TestThreatModelRefresh_GeneratesForEveryActiveTenant(t *testing.T) {
	t1, t2, t3 := shared.NewID(), shared.NewID(), shared.NewID()
	gen := &fakeThreatModelGenerator{}
	repo := &fakeTenantLister{ids: []shared.ID{t1, t2, t3}}
	c := NewThreatModelRefreshController(gen, repo, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 3 {
		t.Fatalf("expected 3 tenants regenerated, got %d", n)
	}
	if len(gen.calls) != 3 {
		t.Fatalf("expected 3 calls, got %d", len(gen.calls))
	}
	for _, call := range gen.calls {
		if call.scopeType != tmdom.ScopeTenant {
			t.Fatalf("expected ScopeTenant, got %v", call.scopeType)
		}
		if call.scopeRefID != nil {
			t.Fatalf("expected nil scopeRefID, got %v", call.scopeRefID)
		}
	}
}

func TestThreatModelRefresh_PerTenantErrorDoesNotStopOthers(t *testing.T) {
	t1, t2, t3 := shared.NewID(), shared.NewID(), shared.NewID()
	gen := &fakeThreatModelGenerator{errs: map[string]error{t2.String(): errors.New("generation failed")}}
	repo := &fakeTenantLister{ids: []shared.ID{t1, t2, t3}}
	c := NewThreatModelRefreshController(gen, repo, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	// All three tenants must still be attempted...
	if len(gen.calls) != 3 {
		t.Fatalf("expected all 3 tenants attempted, got %d calls", len(gen.calls))
	}
	// ...but only the two that succeeded count toward the result.
	if n != 2 {
		t.Fatalf("expected 2 successful regenerations, got %d", n)
	}
}

func TestThreatModelRefresh_TenantListErrorPropagates(t *testing.T) {
	gen := &fakeThreatModelGenerator{}
	repo := &fakeTenantLister{err: errors.New("db down")}
	c := NewThreatModelRefreshController(gen, repo, nil)

	if _, err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("tenant list error must propagate")
	}
	if len(gen.calls) != 0 {
		t.Fatalf("generator must not be called when tenant list fails, got %d calls", len(gen.calls))
	}
}

func TestThreatModelRefresh_Meta(t *testing.T) {
	c := NewThreatModelRefreshController(&fakeThreatModelGenerator{}, &fakeTenantLister{}, nil)
	if c.Name() != "threat-model-refresh" {
		t.Fatalf("name: %q", c.Name())
	}
	if c.Interval() <= 0 {
		t.Fatal("interval should default to a positive duration")
	}
}
