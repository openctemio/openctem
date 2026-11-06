package module

import (
	"context"
	"errors"
	"testing"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/logger"
)

func newClosureService(ent EntitlementReader, overrides ...*moduledom.TenantModuleOverride) *ModuleService {
	s := NewModuleService(&fakeModuleRepo{modules: fullCatalogue()}, logger.NewNop())
	s.SetTenantModuleRepo(&fakeTenantModuleRepo{overrides: overrides})
	if ent != nil {
		s.SetEntitlements(ent)
	}
	return s
}

// A deny of a module reaches the modules that hard-require it: control
// testing (its scheduler, routes and pages) is off when compensating controls
// are not available, though the organization never switched it off.
func TestModuleStates_DenyReachesHardDependents(t *testing.T) {
	s := newClosureService(fakeEntitlements{off: map[string]bool{moduledom.ModuleCompensatingControls: true}})
	ctx := context.Background()
	got := s.TenantModuleStates(ctx, tid)
	if got[moduledom.ModuleControlTesting] != ReasonNotEntitled {
		t.Fatalf("control_testing: %q, want %q", got[moduledom.ModuleControlTesting], ReasonNotEntitled)
	}
	if !s.TenantDisabledModules(ctx, tid)[moduledom.ModuleControlTesting] {
		t.Error("jobs and MCP read TenantDisabledModules: control_testing must be in it")
	}
	// The organization cannot switch the dependent on either.
	_, err := s.UpdateTenantModules(ctx, tid,
		[]moduledom.TenantModuleUpdate{{ModuleID: moduledom.ModuleControlTesting, IsEnabled: true}}, auditapp.AuditContext{})
	if !errors.Is(err, moduledom.ErrModuleNotEntitled) {
		t.Fatalf("enabling control_testing: %v, want ErrModuleNotEntitled", err)
	}
}

// A dependent of a module in its read-only grace is read-only until the same date.
func TestModuleStates_GraceReachesHardDependents(t *testing.T) {
	until := time.Now().Add(72 * time.Hour).UTC().Truncate(time.Second)
	s := newClosureService(fakeEntitlements{grace: map[string]time.Time{moduledom.ModuleScannerTemplates: until}})
	out, err := s.GetTenantEnabledModules(context.Background(), tid)
	if err != nil {
		t.Fatal(err)
	}
	if got := out.ReadOnlyModules[moduledom.ModuleTemplateSources]; !got.Equal(until) {
		t.Fatalf("template_sources read-only until %v, want %v", got, until)
	}
}

// An inconsistent stored state (a dependency added after the organization
// switched its target off) is closed too: the preference reason is inherited.
func TestModuleStates_PreferenceOffReachesHardDependents(t *testing.T) {
	s := newClosureService(nil, &moduledom.TenantModuleOverride{ModuleID: moduledom.ModuleAttackerProfiles, IsEnabled: false})
	if got := s.TenantModuleStates(context.Background(), tid)[moduledom.ModuleAttackSimulation]; got != ReasonDisabledByAdmin {
		t.Fatalf("attack_simulation: %q, want %q", got, ReasonDisabledByAdmin)
	}
}

// A preset names a module the organization is not entitled to: it applies
// the rest and reports that module as unavailable instead of failing.
func TestApplyPreset_SkipsModulesNotEntitled(t *testing.T) {
	s, repo := newPresetService()
	s.SetEntitlements(fakeEntitlements{off: map[string]bool{moduledom.ModuleThreatIntel: true}})
	ctx := context.Background()
	diff, err := s.PreviewPreset(ctx, tid, "ctem_full")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range diff.Unavailable {
		if r.ModuleID == moduledom.ModuleThreatIntel {
			found = true
		}
	}
	if !found {
		t.Fatalf("threat_intel not reported unavailable: %+v", diff.Unavailable)
	}
	if _, err := s.ApplyPreset(ctx, tid, "ctem_full", auditapp.AuditContext{}); err != nil {
		t.Fatalf("ctem_full with threat_intel denied: %v", err)
	}
	if on, ok := repo.state[moduledom.ModuleThreatIntel]; ok && on {
		t.Error("the preset stored threat_intel on although it is not entitled")
	}
}

// A preset leaves modules Settings > Modules does not list as they are.
func TestPreviewPreset_LeavesUnlistedModules(t *testing.T) {
	s, _ := newPresetService()
	diff, err := s.PreviewPreset(context.Background(), tid, "minimal")
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range diff.ToDisable {
		if !moduledom.IsUserFacing(r.ModuleID) {
			t.Errorf("minimal switches off %s, which Settings > Modules does not list", r.ModuleID)
		}
	}
}
