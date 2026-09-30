package controller

import (
	"context"
	"testing"

	"github.com/openctemio/api/internal/app/asset"
	moduledom "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
)

// This file proves the compute-level plugin guard: a connector/enrichment
// controller that loops tenants must skip a tenant that has turned the
// governing module OFF, and must run for everyone when no guard is wired
// (backward compatible) or when a tenant left the module ON.
//
// It complements control_test_scheduler_test.go (which proves the same for the
// control-testing sweep) by covering the threat-model and graph-enrichment
// controllers wired in this change. Fakes fakeTenantLister / fakeModuleGuard /
// fakeThreatModelGenerator are defined in sibling *_test.go files in this
// package.

// fakeGraphEnricher records which tenants it was asked to enrich.
type fakeGraphEnricher struct {
	calls []string
}

func (f *fakeGraphEnricher) EnrichGraph(_ context.Context, tenantID string) (asset.EnrichGraphResult, error) {
	f.calls = append(f.calls, tenantID)
	return asset.EnrichGraphResult{EdgesCreated: 1}, nil
}

func TestThreatModelRefresh_SkipsTenantWithModuleDisabled(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	gen := &fakeThreatModelGenerator{}
	repo := &fakeTenantLister{ids: []shared.ID{on, off}}
	guard := &fakeModuleGuard{disabledByTenant: map[string]map[string]bool{
		off.String(): {moduledom.ModuleThreatModel: true},
	}}
	c := NewThreatModelRefreshController(gen, repo, &ThreatModelRefreshControllerConfig{ModuleGuard: guard})

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 tenant regenerated (the enabled one), got %d", n)
	}
	if len(gen.calls) != 1 || gen.calls[0].tenantID != on {
		t.Fatalf("expected generation only for the enabled tenant, got calls=%v", gen.calls)
	}
}

func TestThreatModelRefresh_NoGuardRunsForAll(t *testing.T) {
	t1, t2 := shared.NewID(), shared.NewID()
	gen := &fakeThreatModelGenerator{}
	repo := &fakeTenantLister{ids: []shared.ID{t1, t2}}
	// ModuleGuard nil — backward-compatible "always run".
	c := NewThreatModelRefreshController(gen, repo, &ThreatModelRefreshControllerConfig{})

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 2 || len(gen.calls) != 2 {
		t.Fatalf("expected both tenants regenerated with no guard, got n=%d calls=%d", n, len(gen.calls))
	}
}

func TestGraphEnrichment_SkipsTenantWithModuleDisabled(t *testing.T) {
	on, off := shared.NewID(), shared.NewID()
	enricher := &fakeGraphEnricher{}
	repo := &fakeTenantLister{ids: []shared.ID{on, off}}
	guard := &fakeModuleGuard{disabledByTenant: map[string]map[string]bool{
		off.String(): {moduledom.ModuleAttackSurface: true},
	}}
	c := NewGraphEnrichmentController(enricher, repo, &GraphEnrichmentControllerConfig{ModuleGuard: guard})

	total, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(enricher.calls) != 1 || enricher.calls[0] != on.String() {
		t.Fatalf("expected enrichment only for the enabled tenant, got calls=%v", enricher.calls)
	}
	if total != 1 {
		t.Fatalf("expected 1 edge (only the enabled tenant), got %d", total)
	}
}

func TestGraphEnrichment_NoGuardRunsForAll(t *testing.T) {
	t1, t2 := shared.NewID(), shared.NewID()
	enricher := &fakeGraphEnricher{}
	repo := &fakeTenantLister{ids: []shared.ID{t1, t2}}
	c := NewGraphEnrichmentController(enricher, repo, &GraphEnrichmentControllerConfig{})

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(enricher.calls) != 2 {
		t.Fatalf("expected both tenants enriched with no guard, got %d", len(enricher.calls))
	}
}
