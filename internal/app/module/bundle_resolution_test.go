package module

import (
	"context"
	"testing"

	auditapp "github.com/openctemio/api/internal/app/audit"
	moduledom "github.com/openctemio/api/pkg/domain/module"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
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

type fakeBundleStore struct{ bundles []string }

func (f *fakeBundleStore) GetSubscribedBundles(context.Context, string) ([]string, error) {
	return f.bundles, nil
}
func (f *fakeBundleStore) SetSubscribedBundles(_ context.Context, _ string, ids []string) error {
	f.bundles = ids
	return nil
}

func mod(id string, core bool) *moduledom.Module {
	return moduledom.ReconstructModule(id, id, id, "", "", "security", 0, true, core, "released", nil, nil)
}

// A representative catalog: 2 core + one module in ASM, one only in ASPM, one
// in neither. This is enough to prove every resolution rule.
func testCatalogue() []*moduledom.Module {
	return []*moduledom.Module{
		mod("assets", true),          // core
		mod("findings", true),        // core
		mod("attack_surface", false), // in ASM (and ASPM)
		mod("sbom_export", false),    // in ASPM only
		mod("pentest", false),        // in neither
	}
}

func newResolutionService(bundles []string, overrides []*moduledom.TenantModuleOverride) *ModuleService {
	s := NewModuleService(&fakeModuleRepo{modules: testCatalogue()}, logger.NewNop())
	s.SetTenantModuleRepo(&fakeTenantModuleRepo{overrides: overrides})
	if bundles != nil {
		s.SetBundleStore(&fakeBundleStore{bundles: bundles})
	}
	return s
}

const tid = "00000000-0000-0000-0000-0000000000aa"

// --- tests ------------------------------------------------------------------

// No subscription = every module on (nothing disabled). This is the
// backward-compatible default for every existing tenant.
func TestResolution_NoSubscription_AllOn(t *testing.T) {
	s := newResolutionService(nil, nil)
	disabled := s.getTenantDisabledModules(context.Background(), tid)
	if len(disabled) != 0 {
		t.Fatalf("no subscription must disable nothing, got %v", disabled)
	}
}

// Subscribing to ASM enables ASM's modules and disables everything else
// (except always-on core).
func TestResolution_ASM_SubsetsToBundle(t *testing.T) {
	s := newResolutionService([]string{"asm"}, nil)
	d := s.getTenantDisabledModules(context.Background(), tid)

	if d["assets"] || d["findings"] {
		t.Error("core must never be disabled")
	}
	if d["attack_surface"] {
		t.Error("attack_surface is in ASM — must stay enabled")
	}
	if !d["sbom_export"] {
		t.Error("sbom_export is not in ASM — must be disabled")
	}
	if !d["pentest"] {
		t.Error("pentest is not in ASM — must be disabled")
	}
}

// The flexibility guarantee: an ASM tenant later adds ASPM → the union turns on,
// with no re-provisioning. sbom_export (ASPM-only) flips from off to on while
// ASM's modules stay on and pentest (in neither) stays off.
func TestResolution_AddBundleLater_ExpandsLive(t *testing.T) {
	ctx := context.Background()

	asmOnly := newResolutionService([]string{"asm"}, nil).getTenantDisabledModules(ctx, tid)
	if !asmOnly["sbom_export"] {
		t.Fatal("precondition: sbom_export off under ASM alone")
	}

	asmPlusAspm := newResolutionService([]string{"asm", "aspm"}, nil).getTenantDisabledModules(ctx, tid)
	if asmPlusAspm["sbom_export"] {
		t.Error("adding ASPM must enable sbom_export (add-later flexibility)")
	}
	if asmPlusAspm["attack_surface"] {
		t.Error("ASM modules must stay on when ASPM is added")
	}
	if !asmPlusAspm["pentest"] {
		t.Error("pentest is in neither bundle — must stay off")
	}
}

// An admin override to ENABLE a module outside the subscription wins over the
// bundle baseline (fine-grained opt-in on top of a bundle).
func TestResolution_OverrideOn_BeatsBaselineOff(t *testing.T) {
	overrides := []*moduledom.TenantModuleOverride{{ModuleID: "pentest", IsEnabled: true}}
	d := newResolutionService([]string{"asm"}, overrides).getTenantDisabledModules(context.Background(), tid)
	if d["pentest"] {
		t.Error("admin explicit-on must re-enable a module outside the bundle")
	}
}

// An admin override to DISABLE a bundle module wins over the baseline.
func TestResolution_OverrideOff_BeatsBaselineOn(t *testing.T) {
	overrides := []*moduledom.TenantModuleOverride{{ModuleID: "attack_surface", IsEnabled: false}}
	d := newResolutionService([]string{"asm"}, overrides).getTenantDisabledModules(context.Background(), tid)
	if !d["attack_surface"] {
		t.Error("admin explicit-off must disable even a bundle module")
	}
}

// Regression (empty-baseline lockout): a subscription of ONLY unknown bundle IDs
// — e.g. a bundle was renamed/removed from the catalog after the tenant
// subscribed — must NOT disable every module. It fails safe to all-on.
func TestResolution_UnknownBundlesFailSafeToAllOn(t *testing.T) {
	s := newResolutionService([]string{"removed-bundle", "typo"}, nil)
	d := s.getTenantDisabledModules(context.Background(), tid)
	if len(d) != 0 {
		t.Fatalf("a subscription of only-unknown bundles must disable nothing (fail safe), got %v", d)
	}
}

// A mix of valid + invalid bundle IDs still subsets to the valid one.
func TestResolution_MixedValidInvalidBundles_UsesValid(t *testing.T) {
	s := newResolutionService([]string{"asm", "removed-bundle"}, nil)
	d := s.getTenantDisabledModules(context.Background(), tid)
	if d["attack_surface"] {
		t.Error("the valid bundle (asm) must keep attack_surface enabled")
	}
	if !d["sbom_export"] {
		t.Error("sbom_export (not in asm) must be disabled")
	}
}

// SubscribeBundles rejects an unknown bundle and accepts + dedupes known ones.
func TestSubscribeBundles_ValidatesAndDedupes(t *testing.T) {
	store := &fakeBundleStore{}
	s := NewModuleService(&fakeModuleRepo{modules: testCatalogue()}, logger.NewNop())
	s.SetBundleStore(store)

	if err := s.SubscribeBundles(context.Background(), tid, []string{"asm", "nope"}, auditapp.AuditContext{}); err == nil {
		t.Error("expected rejection of an unknown bundle id")
	}
	if err := s.SubscribeBundles(context.Background(), tid, []string{"asm", "asm", "aspm"}, auditapp.AuditContext{}); err != nil {
		t.Fatalf("valid subscribe failed: %v", err)
	}
	if len(store.bundles) != 2 || store.bundles[0] != "asm" || store.bundles[1] != "aspm" {
		t.Errorf("expected deduped [asm aspm], got %v", store.bundles)
	}
}
