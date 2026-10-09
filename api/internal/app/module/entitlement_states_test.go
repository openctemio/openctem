package module

import (
	"context"
	"errors"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// --- fakes ------------------------------------------------------------------

type fakeModuleRepo struct{ modules []*moduledom.Module }

func (f *fakeModuleRepo) ListAllModules(context.Context) ([]*moduledom.Module, error) {
	return f.modules, nil
}
func (f *fakeModuleRepo) ListActiveModules(context.Context) ([]*moduledom.Module, error) {
	return f.modules, nil
}
func (f *fakeModuleRepo) GetModuleByID(context.Context, string) (*moduledom.Module, error) {
	return nil, nil
}
func (f *fakeModuleRepo) GetSubModules(context.Context, string) ([]*moduledom.Module, error) {
	return nil, nil
}
func (f *fakeModuleRepo) ListAllSubModules(context.Context) (map[string][]*moduledom.Module, error) {
	return nil, nil
}

type fakeTenantModuleRepo struct {
	overrides []*moduledom.TenantModuleOverride
}

func (f *fakeTenantModuleRepo) ListByTenant(context.Context, shared.ID) ([]*moduledom.TenantModuleOverride, error) {
	return f.overrides, nil
}
func (f *fakeTenantModuleRepo) UpsertBatch(context.Context, shared.ID, []moduledom.TenantModuleUpdate, *shared.ID) error {
	return nil
}
func (f *fakeTenantModuleRepo) DeleteByTenant(context.Context, shared.ID) error { return nil }

func mod(id string, core bool) *moduledom.Module {
	return moduledom.ReconstructModule(id, id, id, "", "", "security", 0, true, core, "released", nil, nil)
}

const tid = "00000000-0000-0000-0000-0000000000aa"

type fakeEntitlements struct {
	off map[string]bool
	err error
}

func (f fakeEntitlements) NotEntitled(context.Context, string) (map[string]bool, error) {
	return f.off, f.err
}

func newStatesService(ent EntitlementReader, overrides ...*moduledom.TenantModuleOverride) *ModuleService {
	s := NewModuleService(&fakeModuleRepo{modules: []*moduledom.Module{
		mod(moduledom.ModuleAssets, true), mod(moduledom.ModuleFindings, true),
		mod(moduledom.ModulePentest, false), mod(moduledom.ModuleCompliance, false),
		mod(moduledom.ModuleAttackSurface, false),
	}}, logger.NewNop())
	s.SetTenantModuleRepo(&fakeTenantModuleRepo{overrides: overrides})
	if ent != nil {
		s.SetEntitlements(ent)
	}
	return s
}

func TestModuleStates_Reasons(t *testing.T) {
	s := newStatesService(fakeEntitlements{off: map[string]bool{moduledom.ModulePentest: true}},
		&moduledom.TenantModuleOverride{ModuleID: moduledom.ModuleCompliance, IsEnabled: false},
		// An organization that switched pentest off while not entitled: the
		// entitlement reason wins.
		&moduledom.TenantModuleOverride{ModuleID: moduledom.ModulePentest, IsEnabled: false},
	)
	got := s.TenantModuleStates(context.Background(), tid)
	want := map[string]string{
		moduledom.ModulePentest:    ReasonNotEntitled,
		moduledom.ModuleCompliance: ReasonDisabledByAdmin,
	}
	if len(got) != len(want) {
		t.Fatalf("states %v, want %v", got, want)
	}
	for id, r := range want {
		if got[id] != r {
			t.Errorf("%s: %q, want %q", id, got[id], r)
		}
	}
	if !s.TenantDisabledModules(context.Background(), tid)[moduledom.ModulePentest] {
		t.Error("a module that is not entitled must be in the disabled set (jobs, MCP, gate)")
	}
}

// Fail-closed: an entitlement read error turns every non-core module off,
// never on.
func TestModuleStates_EntitlementErrorFailsClosed(t *testing.T) {
	s := newStatesService(fakeEntitlements{err: errors.New("db down")})
	got := s.TenantModuleStates(context.Background(), tid)
	for _, d := range moduledom.Registry {
		switch {
		case d.Core && got[d.ID] != "":
			t.Errorf("core %s: %q, want on", d.ID, got[d.ID])
		case !d.Core && got[d.ID] != ReasonUnavailable:
			t.Errorf("%s: %q, want %q", d.ID, got[d.ID], ReasonUnavailable)
		}
	}
}

func TestModuleStates_NoEntitlementsWiredIsPreferenceOnly(t *testing.T) {
	s := newStatesService(nil)
	if got := s.TenantModuleStates(context.Background(), tid); len(got) != 0 {
		t.Fatalf("states %v, want none", got)
	}
}

// The organization cannot switch on what its plan does not include; it can
// still switch it off (a preference) and switch other modules on.
func TestUpdateTenantModules_RefusesEnablingNotEntitled(t *testing.T) {
	s := newStatesService(fakeEntitlements{off: map[string]bool{moduledom.ModulePentest: true}})
	ctx := context.Background()
	_, err := s.UpdateTenantModules(ctx, tid,
		[]moduledom.TenantModuleUpdate{{ModuleID: moduledom.ModulePentest, IsEnabled: true}}, auditapp.AuditContext{})
	if !errors.Is(err, moduledom.ErrModuleNotEntitled) {
		t.Fatalf("enable not-entitled: err = %v, want ErrModuleNotEntitled", err)
	}
	out, err := s.UpdateTenantModules(ctx, tid,
		[]moduledom.TenantModuleUpdate{{ModuleID: moduledom.ModuleCompliance, IsEnabled: true}}, auditapp.AuditContext{})
	if err != nil {
		t.Fatalf("enable entitled: %v", err)
	}
	_ = out
}

func TestTenantModuleConfig_ReportsEntitlement(t *testing.T) {
	s := newStatesService(fakeEntitlements{off: map[string]bool{moduledom.ModulePentest: true}})
	cfg, err := s.GetTenantModuleConfig(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, m := range cfg.Modules {
		switch m.Module.ID() {
		case moduledom.ModulePentest:
			seen++
			if m.Entitled || m.IsEnabled {
				t.Errorf("pentest: entitled=%v enabled=%v, want false/false", m.Entitled, m.IsEnabled)
			}
		case moduledom.ModuleCompliance:
			seen++
			if !m.Entitled || !m.IsEnabled {
				t.Errorf("compliance: entitled=%v enabled=%v, want true/true", m.Entitled, m.IsEnabled)
			}
		}
	}
	if seen != 2 {
		t.Fatalf("modules missing from the config: %d", seen)
	}
}
