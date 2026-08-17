package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	moduledom "github.com/openctemio/api/pkg/domain/module"
)

type fakeDisabledProvider struct {
	disabled map[string]bool
	calls    int
}

func (f *fakeDisabledProvider) TenantDisabledModules(_ context.Context, _ string) map[string]bool {
	f.calls++
	return f.disabled
}

func TestModuleGate_IsEnabled(t *testing.T) {
	prov := &fakeDisabledProvider{disabled: map[string]bool{"pentest": true}}
	g := NewModuleGate(prov, time.Minute)
	ctx := context.Background()

	if g.IsEnabled(ctx, "t1", "pentest") {
		t.Error("explicitly-disabled non-core module should be blocked")
	}
	if !g.IsEnabled(ctx, "t1", "compliance") {
		t.Error("a module not in the disabled set should be enabled (fail-open)")
	}

	// Core modules can never be gated, even if (wrongly) in the disabled set.
	var coreID string
	for id := range moduledom.CoreModuleIDs {
		coreID = id
		break
	}
	prov.disabled[coreID] = true
	if !g.IsEnabled(ctx, "t1", coreID) {
		t.Errorf("core module %q must always be enabled", coreID)
	}
}

func TestModuleGate_FailOpen(t *testing.T) {
	ctx := context.Background()
	// Nil gate → enabled.
	var nilGate *ModuleGate
	if !nilGate.IsEnabled(ctx, "t1", "pentest") {
		t.Error("nil gate must fail open")
	}
	// Empty tenant → enabled.
	g := NewModuleGate(&fakeDisabledProvider{disabled: map[string]bool{"pentest": true}}, time.Minute)
	if !g.IsEnabled(ctx, "", "pentest") {
		t.Error("empty tenant must fail open")
	}
}

func TestModuleGate_Caches(t *testing.T) {
	prov := &fakeDisabledProvider{disabled: map[string]bool{"pentest": true}}
	g := NewModuleGate(prov, time.Minute)
	ctx := context.Background()
	for range 5 {
		g.IsEnabled(ctx, "t1", "pentest")
	}
	if prov.calls != 1 {
		t.Errorf("expected the disabled set to be fetched once (cached), got %d calls", prov.calls)
	}
	g.Invalidate("t1")
	g.IsEnabled(ctx, "t1", "pentest")
	if prov.calls != 2 {
		t.Errorf("expected a refetch after Invalidate, got %d calls", prov.calls)
	}
}

// TestRequireModule_NewlyGatedGroups asserts the Phase-3 enforcement contract
// for the route groups that gained a RequireModule gate: with no bundle
// subscription (empty disabled set) every gate ALLOWS, and when a tenant has
// subsetted its modules so the group's module is not subscribed the gate BLOCKS.
func TestRequireModule_NewlyGatedGroups(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	req := httptest.NewRequest(http.MethodGet, "/x", nil).
		WithContext(context.WithValue(context.Background(), TenantIDKey, "t1"))

	gated := []string{
		moduledom.ModuleComponents,
		moduledom.ModuleBranches,
		moduledom.ModuleCredentials,
		moduledom.ModuleExposures,
		moduledom.ModuleSuppressions,
		moduledom.ModuleReports,
		moduledom.ModuleIntegrations,
		moduledom.ModuleIOCs,
		moduledom.ModuleCompensatingControls,
		moduledom.ModuleAttackerProfiles,
		moduledom.ModuleCTEMCycles,
		moduledom.ModulePriorityRules,
		moduledom.ModuleBusinessServices,
		moduledom.ModuleAttackSurface,
	}

	// No subscription → empty disabled set → every gate ALLOWS (backward compatible).
	allow := NewModuleGate(&fakeDisabledProvider{disabled: map[string]bool{}}, time.Minute)
	for _, id := range gated {
		rec := httptest.NewRecorder()
		allow.RequireModule(id)(next).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("module %q with no subscription should ALLOW, got %d", id, rec.Code)
		}
	}

	// Module not in the subscribed subset → gate BLOCKS with 403.
	for _, id := range gated {
		block := NewModuleGate(&fakeDisabledProvider{disabled: map[string]bool{id: true}}, time.Minute)
		rec := httptest.NewRecorder()
		block.RequireModule(id)(next).ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("module %q outside the subscription should BLOCK (403), got %d", id, rec.Code)
		}
	}
}

func TestRequireModule_BlocksDisabled(t *testing.T) {
	g := NewModuleGate(&fakeDisabledProvider{disabled: map[string]bool{"pentest": true}}, time.Minute)
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })

	// Disabled → 403 (tenant in context).
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/x", nil).
		WithContext(context.WithValue(context.Background(), TenantIDKey, "t1"))
	g.RequireModule("pentest")(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("disabled module should 403, got %d", rec.Code)
	}

	// Enabled module → passes through.
	rec2 := httptest.NewRecorder()
	g.RequireModule("compliance")(next).ServeHTTP(rec2, req)
	if rec2.Code != http.StatusOK {
		t.Errorf("enabled module should pass, got %d", rec2.Code)
	}
}
