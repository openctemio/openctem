package unit

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/app/module"
	moduledom "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
)

// TestUpdateTenantModules_BlockerReturnsToggleError — disabling a
// module with a still-enabled hard-dependent must return a structured
// *module.ToggleError (not a plain string) so the handler renders JSON.
func TestUpdateTenantModules_BlockerReturnsToggleError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("findings", "Findings", true, false))
	repo.addModule(makeModule("ai_triage", "AI Triage", true, false))
	// Both default-enabled (mock has no overrides).

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(),
		[]moduledom.TenantModuleUpdate{
			{ModuleID: "findings", IsEnabled: false},
		},
		app.AuditContext{ActorID: validActorID()},
	)
	if err == nil {
		t.Fatal("expected error; got nil")
	}
	var toggle *module.ToggleError
	if !errors.As(err, &toggle) {
		t.Fatalf("expected *module.ToggleError; got %T (%v)", err, err)
	}
	if toggle.Action != "disable" {
		t.Errorf("action want disable, got %q", toggle.Action)
	}
	if toggle.ModuleID != "findings" {
		t.Errorf("module_id want findings, got %q", toggle.ModuleID)
	}
	found := false
	for _, b := range toggle.Blockers {
		if b.ModuleID == "ai_triage" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ai_triage should be in blockers, got %+v", toggle.Blockers)
	}
}

// TestUpdateTenantModules_MissingHardDepReturnsToggleError — enabling
// a module whose hard dep isn't enabled must also return a structured
// error. "Required" field populated instead of "Blockers".
func TestUpdateTenantModules_MissingHardDepReturnsToggleError(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("findings", "Findings", true, false))
	repo.addModule(makeModule("ai_triage", "AI Triage", true, false))

	tenantRepo := newModuleTenantMockRepo()
	// Pre-disable findings using the existing mock helper.
	tid := validTenantID()
	tidParsed, _ := shared.IDFromString(tid)
	tenantRepo.addOverride(tidParsed, "findings", false)

	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	_, err := svc.UpdateTenantModules(context.Background(), tid,
		[]moduledom.TenantModuleUpdate{
			{ModuleID: "ai_triage", IsEnabled: true},
		},
		app.AuditContext{ActorID: validActorID()},
	)
	if err == nil {
		t.Fatal("expected error when enabling ai_triage with findings disabled")
	}
	var toggle *module.ToggleError
	if !errors.As(err, &toggle) {
		t.Fatalf("expected *module.ToggleError; got %T (%v)", err, err)
	}
	if toggle.Action != "enable" {
		t.Errorf("action want enable, got %q", toggle.Action)
	}
	found := false
	for _, r := range toggle.Required {
		if r.ModuleID == "findings" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("findings should appear as required, got %+v", toggle.Required)
	}
}

// TestUpdateTenantModules_SoftWarningSurfaced — disabling threat_intel
// with priority_rules still on is allowed (soft dep) but the config
// output's Warnings array must mention priority_rules so the UI can
// toast about degradation.
func TestUpdateTenantModules_SoftWarningSurfaced(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("findings", "Findings", true, true)) // core, always on
	repo.addModule(makeModule("threat_intel", "Threat Intel", true, false))
	repo.addModule(makeModule("priority_rules", "Priority Rules", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	out, err := svc.UpdateTenantModules(context.Background(), validTenantID(),
		[]moduledom.TenantModuleUpdate{
			{ModuleID: "threat_intel", IsEnabled: false},
		},
		app.AuditContext{ActorID: validActorID()},
	)
	if err != nil {
		t.Fatalf("expected success (soft dep is a warning, not blocker); got %v", err)
	}
	if len(out.Warnings) == 0 {
		t.Fatal("expected at least one warning (priority_rules degrades)")
	}
	ids := make([]string, 0, len(out.Warnings))
	for _, w := range out.Warnings {
		ids = append(ids, w.ModuleID)
	}
	if !contains(ids, "priority_rules") {
		t.Fatalf("priority_rules should be warned about; got %v", ids)
	}
}

// TestValidateToggle_DryRunDoesNotMutate — the preview endpoint must
// return the same issues without writing. Calling UpsertBatch via the
// mock counter must NOT happen.
func TestValidateToggle_DryRunDoesNotMutate(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("findings", "Findings", true, false))
	repo.addModule(makeModule("ai_triage", "AI Triage", true, false))

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	issues, err := svc.ValidateToggle(context.Background(), validTenantID(),
		[]moduledom.TenantModuleUpdate{
			{ModuleID: "findings", IsEnabled: false},
		})
	if err != nil {
		t.Fatalf("validate returned error: %v", err)
	}
	if len(issues.Blockers) == 0 {
		t.Fatal("expected blockers for disabling findings")
	}
	// Crucial: no DB write happened.
	if tenantRepo.upsertBatchCalls != 0 {
		t.Fatalf("validate must not persist; UpsertBatch called %d times", tenantRepo.upsertBatchCalls)
	}
}

// TestUpdateTenantModules_CoreCannotBeDisabled — core modules are
// rejected BEFORE dependency check. Error message must mention core,
// not dependency.
func TestUpdateTenantModules_CoreCannotBeDisabled(t *testing.T) {
	repo := newModuleMockRepo()
	repo.addModule(makeModule("findings", "Findings", true, true)) // core

	tenantRepo := newModuleTenantMockRepo()
	svc := newTestModuleServiceWithTenant(repo, tenantRepo)

	_, err := svc.UpdateTenantModules(context.Background(), validTenantID(),
		[]moduledom.TenantModuleUpdate{
			{ModuleID: "findings", IsEnabled: false},
		},
		app.AuditContext{ActorID: validActorID()},
	)
	if err == nil {
		t.Fatal("core module disable should be rejected")
	}
	if !strings.Contains(err.Error(), "core module") {
		t.Fatalf("error should mention 'core module'; got %v", err)
	}
}

// local helpers --------------------------------------------------------------

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
