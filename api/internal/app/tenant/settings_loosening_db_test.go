package tenant_test

import (
	"context"
	"errors"
	"testing"

	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

type fakeGate struct{ err error }

func (g fakeGate) RequireRecentAuth(context.Context, string) error { return g.err }

var errNeedsStepUp = errors.New("step up required")

// Loosening the asset lifecycle, cycle and attack-surface settings needs a
// recent re-authentication; tightening does not, and a refused loosening
// saves nothing.
func TestSettingsLoosening_NeedsStepUp(t *testing.T) {
	f := newSettingsFixture(t)
	ctx := context.Background()
	f.svc.SetStepUpGate(fakeGate{})
	actx := noAudit()

	// A fresh login: loosening works and is stored.
	if _, err := f.svc.UpdateCycleSettings(ctx, f.tenantID, tenantdom.CycleSettings{EnforceCoverageSLO: true}, actx); err != nil {
		t.Fatalf("tighten cycle: %v", err)
	}
	if _, err := f.svc.UpdateEASMSettings(ctx, f.tenantID, tenantdom.EASMSettings{}, actx); err != nil {
		t.Fatalf("easm no-op: %v", err)
	}
	f.svc.SetStepUpGate(fakeGate{})
	if _, err := f.raw.Exec(`UPDATE tenants SET settings = jsonb_set(settings, '{asset_lifecycle}', $2::jsonb) WHERE id=$1`,
		f.tenantID, `{"enabled":true,"stale_threshold_days":14,"grace_period_days":3,"pause_on_integration_failure":true,"dry_run_completed_at":1}`); err != nil {
		t.Fatalf("seed lifecycle: %v", err)
	}

	// An old login: tightening passes, loosening is refused and not saved.
	f.svc.SetStepUpGate(fakeGate{err: errNeedsStepUp})

	loose := tenantdom.CycleSettings{EnforceCoverageSLO: false}
	if _, err := f.svc.UpdateCycleSettings(ctx, f.tenantID, loose, actx); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("cycle loosening: err = %v, want step-up refusal", err)
	}
	if got := f.section(t, "cycles")["enforce_coverage_slo"]; got != true {
		t.Fatalf("refused loosening was saved: %v", got)
	}

	if _, err := f.svc.UpdateEASMSettings(ctx, f.tenantID, tenantdom.EASMSettings{CTDisabled: true}, actx); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("easm loosening: err = %v, want step-up refusal", err)
	}
	if got := f.section(t, "easm")["ct_disabled"]; got == true {
		t.Fatal("refused EASM loosening was saved")
	}

	shorter := tenantdom.AssetLifecycleSettings{Enabled: true, StaleThresholdDays: 7, GracePeriodDays: 3, PauseOnIntegrationFailure: true}
	if _, err := f.svc.UpdateAssetLifecycleSettings(ctx, f.tenantID, shorter, actx); !errors.Is(err, errNeedsStepUp) {
		t.Fatalf("lifecycle loosening: err = %v, want step-up refusal", err)
	}
	if got := f.section(t, "asset_lifecycle")["stale_threshold_days"]; got != float64(14) {
		t.Fatalf("refused lifecycle loosening was saved: %v", got)
	}

	// Tightening works without a recent login.
	longer := tenantdom.AssetLifecycleSettings{Enabled: true, StaleThresholdDays: 30, GracePeriodDays: 3, PauseOnIntegrationFailure: true}
	if _, err := f.svc.UpdateAssetLifecycleSettings(ctx, f.tenantID, longer, actx); err != nil {
		t.Fatalf("lifecycle tighten: %v", err)
	}
	if _, err := f.svc.UpdateEASMSettings(ctx, f.tenantID, tenantdom.EASMSettings{WeeklyDigestDisabled: false}, actx); err != nil {
		t.Fatalf("easm tighten: %v", err)
	}
	if _, err := f.svc.UpdateCycleSettings(ctx, f.tenantID, tenantdom.CycleSettings{EnforceCoverageSLO: true}, actx); err != nil {
		t.Fatalf("cycle same: %v", err)
	}
}
