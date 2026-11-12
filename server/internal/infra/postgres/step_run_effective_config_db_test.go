package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// A step run's effective config and the sensor's settings are stored on the
// step run and read back with it; a write for another tenant's step run
// changes nothing and reports not found.
func TestStepRunConfigRecorder_RoundTripAndTenantScope(t *testing.T) {
	ctx := context.Background()
	db := openTimeoutDB(t)
	repo := NewStepRunRepository(&DB{DB: db})
	tenantA := seedTestTenant(ctx, t, db)
	tenantB := seedTestTenant(ctx, t, db)
	templateID := seedTimeoutTemplate(ctx, t, db, tenantA)
	runID := seedRun(ctx, t, db, tenantA, templateID, nil, "running", 0)
	stepRunID := shared.NewID()
	mustExec(t, db, `INSERT INTO scan_run_steps (id, scan_run_id, step_key, step_order, status)
		VALUES ($1, $2, 'vuln', 1, 'queued')`, stepRunID.String(), runID.String())

	cfg := scanrun.EffectiveConfig{Tool: "nuclei", Depth: "standard", Params: map[string]scanrun.ParamValue{
		"severity": {Value: []string{"low", "high"}, Source: scanrun.ParamSourceDepthOverlay}}}
	if err := repo.SetEffectiveConfig(ctx, tenantA, stepRunID, cfg); err != nil {
		t.Fatal(err)
	}
	ss := scanrun.SensorSettings{IgnoredConfigKeys: []string{"targets"},
		Effective: map[string]scanrun.SensorSetting{"rate": {Value: 50.0, Source: "policy"}},
		SentWith: []scanrun.AppliedIdentity{{Tool: "nuclei", UserAgent: "ua/2", UserAgentPool: 3, Required: true,
			Carrier: scanrun.CarrierForwarder, Query: &scanrun.AppliedQuery{Name: "scan", Value: "corp", Applied: true}}}}
	if err := repo.SetSensorSettings(ctx, tenantA, stepRunID, ss); err != nil {
		t.Fatal(err)
	}
	got, err := repo.GetByID(ctx, stepRunID)
	if err != nil {
		t.Fatal(err)
	}
	if got.EffectiveConfig == nil || got.EffectiveConfig.Params["severity"].Source != scanrun.ParamSourceDepthOverlay ||
		got.EffectiveConfig.Tool != "nuclei" {
		t.Fatalf("effective config: %+v", got.EffectiveConfig)
	}
	if got.SensorSettings == nil || got.SensorSettings.IgnoredConfigKeys[0] != "targets" ||
		got.SensorSettings.Effective["rate"].Source != "policy" || len(got.SensorSettings.SentWith) != 1 ||
		got.SensorSettings.SentWith[0].UserAgentPool != 3 || got.SensorSettings.SentWith[0].Query.Value != "corp" {
		t.Fatalf("sensor settings: %+v", got.SensorSettings)
	}

	// Another tenant cannot write this step run.
	other := scanrun.EffectiveConfig{Tool: "evil", Params: map[string]scanrun.ParamValue{}}
	if err := repo.SetEffectiveConfig(ctx, tenantB, stepRunID, other); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant effective config: %v", err)
	}
	if err := repo.SetSensorSettings(ctx, tenantB, stepRunID, scanrun.SensorSettings{IgnoredConfigKeys: []string{"x"}}); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant sensor settings: %v", err)
	}
	again, _ := repo.GetByID(ctx, stepRunID)
	if again.EffectiveConfig.Tool != "nuclei" || again.SensorSettings.IgnoredConfigKeys[0] != "targets" {
		t.Fatalf("another tenant's write landed: %+v %+v", again.EffectiveConfig, again.SensorSettings)
	}
}
