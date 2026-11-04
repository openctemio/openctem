package module

import (
	"context"
	"errors"
	"testing"

	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
)

type fakePlatform struct {
	off map[string]bool
	err error
}

func (f fakePlatform) PlatformModuleOff(_ context.Context, id string) (bool, error) {
	return f.off[id], f.err
}

// withPlatformModule declares a platform-scoped module for one test.
func withPlatformModule(t *testing.T, id string) {
	t.Helper()
	saved := moduledom.Registry
	moduledom.Registry = append(append([]moduledom.Definition{}, saved...), moduledom.Definition{
		ID: id, Slug: id, Name: id, Scope: moduledom.ScopePlatform,
	})
	t.Cleanup(func() { moduledom.Registry = saved })
}

func TestPlatformModule_OffForEveryOrganization(t *testing.T) {
	const id = "vuln_catalog_test"
	withPlatformModule(t, id)
	ctx := context.Background()

	// Not wired: nothing says the platform enabled it, so it is off.
	s := newSnapshotService(fakeEntitlements{})
	if got := s.TenantModuleStates(ctx, tid)[id]; got != ReasonDisabledByPlatform {
		t.Fatalf("unwired platform module: %q, want disabled_by_platform", got)
	}

	// The platform has it on: on.
	s.SetPlatformModules(fakePlatform{})
	if got := s.TenantModuleStates(ctx, tid)[id]; got != "" {
		t.Fatalf("enabled platform module reads %q", got)
	}

	// The platform has it off: off, whatever the plan and the organization say.
	s.SetPlatformModules(fakePlatform{off: map[string]bool{id: true}})
	if got := s.TenantModuleStates(ctx, tid)[id]; got != ReasonDisabledByPlatform {
		t.Fatalf("platform-off module reads %q", got)
	}
	if s.TenantDisabledModules(ctx, tid)[id] != true {
		t.Fatal("a job guard must see the platform-off module as disabled")
	}

	// The switch cannot be read: off (fail closed) and the answer is not cacheable.
	s.SetPlatformModules(fakePlatform{err: errors.New("settings unreadable")})
	states, _, cacheable := s.TenantModuleStateSnapshot(ctx, tid)
	if states[id] != ReasonDisabledByPlatform || cacheable {
		t.Fatalf("unreadable switch: state %q cacheable %v", states[id], cacheable)
	}
}

// The platform reason wins over the plan's deny and the organization's own
// switch, and the organization cannot switch the module on.
func TestPlatformModule_WinsOverPlanAndPreference(t *testing.T) {
	const id = "vuln_catalog_test"
	withPlatformModule(t, id)
	s := newSnapshotService(fakeEntitlements{off: map[string]bool{id: true}})
	s.SetPlatformModules(fakePlatform{off: map[string]bool{id: true}})
	if got := s.TenantModuleStates(context.Background(), tid)[id]; got != ReasonDisabledByPlatform {
		t.Fatalf("got %q", got)
	}
	if entitledState(ReasonDisabledByPlatform) {
		t.Fatal("an organization must not be able to switch on a module the platform disabled")
	}
}

// An organization's own switch counts only for a module Settings > Modules
// lists: core modules are always on and unlisted modules have no switch (an
// old row is ignored).
func TestModuleStates_IgnoresSwitchesThatAreNotSwitches(t *testing.T) {
	s := newStatesService(nil,
		&moduledom.TenantModuleOverride{ModuleID: moduledom.ModuleSuppressions, IsEnabled: false},
		&moduledom.TenantModuleOverride{ModuleID: moduledom.ModuleRiskScoring, IsEnabled: false},
		&moduledom.TenantModuleOverride{ModuleID: moduledom.ModuleAITriage, IsEnabled: false},
		&moduledom.TenantModuleOverride{ModuleID: moduledom.ModuleBranches, IsEnabled: false},
		&moduledom.TenantModuleOverride{ModuleID: moduledom.ModulePentest, IsEnabled: false},
	)
	got := s.TenantModuleStates(context.Background(), tid)
	if len(got) != 1 || got[moduledom.ModulePentest] != ReasonDisabledByAdmin {
		t.Fatalf("only the listed switch counts, got %v", got)
	}
}

// Suppressions and risk scoring are always on.
func TestAlwaysOnModules(t *testing.T) {
	for _, id := range []string{moduledom.ModuleSuppressions, moduledom.ModuleRiskScoring} {
		if !moduledom.IsCoreModule(id) {
			t.Errorf("%s must be core (always on)", id)
		}
	}
	for _, id := range []string{"risk_analysis", "sbom_export", "tools", "scan_profiles", "business_impact",
		"crown_jewels", "ctem_maturity", "executive_summary", "mitre_coverage", "integrations.scm"} {
		if _, ok := moduledom.Lookup(id); ok {
			t.Errorf("%s is retired and must not be in the registry", id)
		}
	}
}
