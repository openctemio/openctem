package module

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"testing"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	moduledom "github.com/openctemio/openctem/api/pkg/domain/module"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// statefulTenantModuleRepo stores upserts so a later read sees them, which the
// preset tests need to chain one preset after another.
type statefulTenantModuleRepo struct {
	state map[string]bool
}

func (r *statefulTenantModuleRepo) ListByTenant(context.Context, shared.ID) ([]*moduledom.TenantModuleOverride, error) {
	out := make([]*moduledom.TenantModuleOverride, 0, len(r.state))
	for id, on := range r.state {
		out = append(out, &moduledom.TenantModuleOverride{ModuleID: id, IsEnabled: on})
	}
	return out, nil
}

func (r *statefulTenantModuleRepo) UpsertBatch(_ context.Context, _ shared.ID, updates []moduledom.TenantModuleUpdate, _ *shared.ID) error {
	for _, u := range updates {
		r.state[u.ModuleID] = u.IsEnabled
	}
	return nil
}

func (r *statefulTenantModuleRepo) DeleteByTenant(context.Context, shared.ID) error {
	r.state = map[string]bool{}
	return nil
}

// fullCatalogue is every module the presets and the permission mapping know
// about: the real catalog is far larger than the per-request toggle cap.
func fullCatalogue() []*moduledom.Module {
	ids := map[string]bool{}
	for id := range moduledom.ModulePermissionMapping {
		ids[id] = true
	}
	for id := range moduledom.CoreModuleIDs {
		ids[id] = true
	}
	for i := range moduledom.ModulePresets {
		for _, id := range moduledom.ModulePresets[i].EnabledModules {
			ids[id] = true
		}
	}
	sorted := make([]string, 0, len(ids))
	for id := range ids {
		sorted = append(sorted, id)
	}
	sort.Strings(sorted)
	out := make([]*moduledom.Module, 0, len(sorted))
	for _, id := range sorted {
		out = append(out, mod(id, moduledom.CoreModuleIDs[id]))
	}
	return out
}

func newPresetService() (*ModuleService, *statefulTenantModuleRepo) {
	s := NewModuleService(&fakeModuleRepo{modules: fullCatalogue()}, logger.NewNop())
	repo := &statefulTenantModuleRepo{state: map[string]bool{}}
	s.SetTenantModuleRepo(repo)
	return s, repo
}

// enabledSet is the tenant's effective state as every module gate reads it.
func enabledSet(s *ModuleService) map[string]bool {
	disabled := s.getTenantDisabledModules(context.Background(), tid)
	out := map[string]bool{}
	for _, m := range fullCatalogue() {
		out[m.ID()] = m.IsCore() || !disabled[m.ID()]
	}
	return out
}

func assertPresetState(t *testing.T, s *ModuleService, p *moduledom.ModulePreset) {
	t.Helper()
	cat := fullCatalogue()
	want := moduledom.ResolvePresetModules(p)
	applySubModuleInheritance(want, cat)
	got := enabledSet(s)
	for _, m := range cat {
		id := m.ID()
		if want[id] != got[id] && !m.IsCore() {
			t.Errorf("preset %s: module %s enabled=%v, want %v", p.ID, id, got[id], want[id])
		}
	}
}

// Every preset applies on a fresh (all modules on) tenant, including the
// presets whose diff is larger than the per-request toggle cap.
func TestApplyPreset_EveryPresetAppliesFromAllOn(t *testing.T) {
	if n := len(fullCatalogue()); n <= maxModuleUpdatesPerRequest {
		t.Fatalf("catalog has %d modules; the test needs more than the cap (%d) to be meaningful", n, maxModuleUpdatesPerRequest)
	}
	for i := range moduledom.ModulePresets {
		p := &moduledom.ModulePresets[i]
		t.Run(p.ID, func(t *testing.T) {
			s, _ := newPresetService()
			if _, err := s.ApplyPreset(context.Background(), tid, p.ID, auditapp.AuditContext{}); err != nil {
				t.Fatalf("ApplyPreset(%s): %v", p.ID, err)
			}
			assertPresetState(t, s, p)
		})
	}
}

// Switching from any preset to any other preset applies too.
func TestApplyPreset_EveryPresetToEveryPreset(t *testing.T) {
	for i := range moduledom.ModulePresets {
		from := &moduledom.ModulePresets[i]
		for j := range moduledom.ModulePresets {
			to := &moduledom.ModulePresets[j]
			t.Run(fmt.Sprintf("%s_to_%s", from.ID, to.ID), func(t *testing.T) {
				s, _ := newPresetService()
				ctx := context.Background()
				if _, err := s.ApplyPreset(ctx, tid, from.ID, auditapp.AuditContext{}); err != nil {
					t.Fatalf("ApplyPreset(%s): %v", from.ID, err)
				}
				if _, err := s.ApplyPreset(ctx, tid, to.ID, auditapp.AuditContext{}); err != nil {
					t.Fatalf("ApplyPreset(%s) after %s: %v", to.ID, from.ID, err)
				}
				assertPresetState(t, s, to)
			})
		}
	}
}

// Applying a preset is not subject to the per-request toggle cap. The cap is
// lowered below the minimal preset's diff so the test does not depend on the
// size of the catalog.
func TestApplyPreset_NotSubjectToRequestCap(t *testing.T) {
	saved := maxModuleUpdatesPerRequest
	maxModuleUpdatesPerRequest = 10
	t.Cleanup(func() { maxModuleUpdatesPerRequest = saved })
	s, _ := newPresetService()
	diff, err := s.PreviewPreset(context.Background(), tid, "minimal")
	if err != nil {
		t.Fatalf("PreviewPreset: %v", err)
	}
	if n := len(diff.ToEnable) + len(diff.ToDisable); n <= maxModuleUpdatesPerRequest {
		t.Fatalf("minimal diff has %d updates; expected more than the cap %d", n, maxModuleUpdatesPerRequest)
	}
	if _, err := s.ApplyPreset(context.Background(), tid, "minimal", auditapp.AuditContext{}); err != nil {
		t.Fatalf("ApplyPreset(minimal): %v", err)
	}
}

// A caller-supplied toggle batch is still capped.
func TestUpdateTenantModules_CallerBatchStillCapped(t *testing.T) {
	s, repo := newPresetService()
	updates := make([]moduledom.TenantModuleUpdate, 0, maxModuleUpdatesPerRequest+1)
	for _, m := range fullCatalogue() {
		if len(updates) > maxModuleUpdatesPerRequest {
			break
		}
		updates = append(updates, moduledom.TenantModuleUpdate{ModuleID: m.ID(), IsEnabled: true})
	}
	_, err := s.UpdateTenantModules(context.Background(), tid, updates, auditapp.AuditContext{})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("expected a validation error for %d updates, got %v", len(updates), err)
	}
	if len(repo.state) != 0 {
		t.Fatalf("a refused batch must not write anything, wrote %d rows", len(repo.state))
	}
}
