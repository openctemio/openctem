package integration

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"
	"github.com/openctemio/openctem/api/internal/infra/controller"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// coverageDispatcher is cmd/server's connectorCoverageDispatcher.
type coverageDispatcher struct{ svc *tenablesc.Service }

func (d coverageDispatcher) DispatchTenableScan(ctx context.Context, in scancoverage.DispatchTenableInput) (shared.ID, string, error) {
	if in.IntegrationID == nil {
		return shared.ID{}, "", errors.New("no integration")
	}
	s := in.SessionID
	if s == "" {
		s = shared.NewID().String()
	}
	id, err := d.svc.DispatchCoverageBatch(ctx, in.TenantID, *in.IntegrationID, in.Targets, s, in.NewAddresses)
	return id, s, err
}

// Rolling coverage on the connector (RFC-047 §9) on a migrated database: an
// estate of 30 hosts behind a Tenable.sc licensed for 20 addresses (2 kept
// as a safety margin) is scanned in batches that never exceed the headroom;
// the next batch waits for the previous one to finish; once Tenable.sc
// reports the license full, nothing more is dispatched.
func TestTenableSCCoverage_RollingBatchesStayInsideTheLicense(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenant := seedLifecycleTenant(ctx, t, db)
	sensorID := seedReportingSensor(t, db, tenant, tenablesc.ToolName)
	for i := range 30 {
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, criticality)
			VALUES ($1, $2, $3, 'host', 'active', 'medium')`, shared.NewID().String(), tenant.String(),
			fmt.Sprintf("10.20.0.%d", i+1)); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}

	intRepo := postgres.NewIntegrationRepository(pg)
	intg := integration.NewIntegration(shared.NewID(), tenant, "sc", integration.CategorySecurity,
		integration.ProviderTenable, integration.AuthTypeAPIKey)
	intg.SetConfig(map[string]any{"engine": "tenable_sc", "execution_mode": "sensor", "sensor_id": sensorID.String(),
		"coverage_enabled": true, "coverage_policy_id": float64(1000003), "coverage_repository_id": float64(5),
		"safety_margin": float64(2), "batch_size": float64(256)})
	intg.SetConnected()
	intg.SetMetadata(map[string]any{"tenable_sync": map[string]any{"licensed_ips": 20, "active_ips": 0}})
	if err := intRepo.Create(ctx, intg); err != nil {
		t.Fatal(err)
	}

	cmdRepo := postgres.NewCommandRepository(pg)
	connector := tenablesc.NewService(intRepo, postgres.NewSensorRepository(pg), cmdRepo, postgres.NewFindingRepository(pg), nil, logger.NewNop())
	sched := controller.NewCoverageScheduler(intRepo, postgres.NewScanCoverageRepository(pg), coverageDispatcher{connector},
		&controller.CoverageSchedulerConfig{Gate: newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
			scansvc.WithAttributionGate(ownershipGate(db))), Connector: connector})

	batchTargets := func() (shared.ID, []string) {
		t.Helper()
		var (
			id      string
			payload []byte
		)
		if err := db.QueryRowContext(ctx, `SELECT id, payload FROM commands WHERE tenant_id = $1 AND type = 'connector_scan'
			ORDER BY created_at DESC LIMIT 1`, tenant.String()).Scan(&id, &payload); err != nil {
			t.Fatalf("read batch: %v", err)
		}
		var p tenablesc.ScanPayload
		_ = json.Unmarshal(payload, &p)
		cid, _ := shared.IDFromString(id)
		return cid, p.Targets
	}
	finish := func(id shared.ID, active int) {
		t.Helper()
		res, _ := json.Marshal(map[string]any{"metadata": map[string]any{"licensed_ips": 20, "active_ips": active}})
		if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed', result = $3 WHERE tenant_id = $1 AND id = $2`,
			tenant.String(), id.String(), res); err != nil {
			t.Fatal(err)
		}
	}

	// Batch 1: headroom 20 - 0 - 2 = 18.
	if n, err := sched.Reconcile(ctx); err != nil || n != 1 {
		t.Fatalf("first pass: n=%d err=%v", n, err)
	}
	first, targets := batchTargets()
	if len(targets) != 18 {
		t.Fatalf("first batch %d targets, want 18", len(targets))
	}
	// While it runs nothing else is dispatched.
	if n, _ := sched.Reconcile(ctx); n != 0 {
		t.Fatal("a second batch while the first is open")
	}
	// Tenable.sc now counts 18 active addresses: headroom 0. Nothing more.
	finish(first, 18)
	if n, _ := sched.Reconcile(ctx); n != 0 {
		t.Fatal("a batch past the license")
	}
	stored, _ := intRepo.GetByTenantAndID(ctx, tenant, intg.ID())
	if st := tenablesc.State(stored); st.ActiveIPs != 18 || st.CoverageCommandID != "" {
		t.Fatalf("state after batch 1: %+v", st)
	}

	// Tenable.sc aged data out (its own setting): 8 active, headroom 10;
	// the rotation picks the 12 never-scanned hosts first, 10 of them.
	if _, err := db.ExecContext(ctx, `UPDATE integrations SET metadata = jsonb_set(metadata, '{tenable_sync,active_ips}', '8')
		WHERE tenant_id = $1 AND id = $2`, tenant.String(), intg.ID().String()); err != nil {
		t.Fatal(err)
	}
	if n, err := sched.Reconcile(ctx); err != nil || n != 1 {
		t.Fatalf("after aging: n=%d err=%v", n, err)
	}
	_, second := batchTargets()
	if len(second) != 10 {
		t.Fatalf("second batch %d targets, want 10", len(second))
	}
	seen := map[string]bool{}
	for _, tg := range targets {
		seen[tg] = true
	}
	for _, tg := range second {
		if seen[tg] {
			t.Fatalf("second batch re-scanned %s before every host had a turn", tg)
		}
	}
}

// License rotation by recycling (research/143 §4) on a migrated database:
// 40 hosts behind a license of 10. A simulated connector applies the
// license guard, recycles the rotation repository when the batch asks (which
// frees the previous batch's addresses at once) and reports per-target
// outcomes. The license is never exceeded, recycling only follows an
// ingested batch, every host is assessed once per cycle, and the cycle
// rolls over once all were. A batch that fails after launching stalls the
// rotation until an administrator resumes it.
func TestTenableSCCoverage_RecycleRotationCoversTheEstate(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	tenant := seedLifecycleTenant(ctx, t, db)
	sensorID := seedReportingSensor(t, db, tenant, tenablesc.ToolName)
	const hosts, license = 40, 10
	for i := range hosts {
		if _, err := db.ExecContext(ctx, `INSERT INTO assets (id, tenant_id, name, asset_type, status, criticality)
			VALUES ($1, $2, $3, 'host', 'active', 'medium')`, shared.NewID().String(), tenant.String(),
			fmt.Sprintf("10.20.0.%d", i+1)); err != nil {
			t.Fatalf("seed asset: %v", err)
		}
	}
	intRepo := postgres.NewIntegrationRepository(pg)
	intg := integration.NewIntegration(shared.NewID(), tenant, "sc", integration.CategorySecurity,
		integration.ProviderTenable, integration.AuthTypeAPIKey)
	intg.SetConfig(map[string]any{"engine": "tenable_sc", "execution_mode": "sensor", "sensor_id": sensorID.String(),
		"coverage_enabled": true, "coverage_policy_id": float64(1000003), "coverage_repository_id": float64(5),
		"batch_size": float64(256), "coverage_rotation": "recycle", "coverage_rotation_acknowledged": true})
	intg.SetConnected()
	intg.SetMetadata(map[string]any{"tenable_sync": map[string]any{"licensed_ips": license, "active_ips": 0}})
	if err := intRepo.Create(ctx, intg); err != nil {
		t.Fatal(err)
	}
	cmdRepo := postgres.NewCommandRepository(pg)
	covRepo := postgres.NewScanCoverageRepository(pg)
	connector := tenablesc.NewService(intRepo, postgres.NewSensorRepository(pg), cmdRepo, postgres.NewFindingRepository(pg), nil, logger.NewNop())
	connector.SetCoverageLedger(covRepo)
	sched := controller.NewCoverageScheduler(intRepo, covRepo, coverageDispatcher{connector},
		&controller.CoverageSchedulerConfig{Gate: newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
			scansvc.WithAttributionGate(ownershipGate(db))), Connector: connector})

	// The simulated Tenable.sc: active addresses outside and inside the
	// rotation repository.
	rotationRepo := 0
	assessedTimes := map[string]int{}
	latest := func() (shared.ID, tenablesc.ScanPayload) {
		t.Helper()
		var (
			id      string
			payload []byte
		)
		if err := db.QueryRowContext(ctx, `SELECT id, payload FROM commands WHERE tenant_id = $1 AND type = 'connector_scan'
			ORDER BY created_at DESC LIMIT 1`, tenant.String()).Scan(&id, &payload); err != nil {
			t.Fatalf("read batch: %v", err)
		}
		var p tenablesc.ScanPayload
		_ = json.Unmarshal(payload, &p)
		cid, _ := shared.IDFromString(id)
		return cid, p
	}
	runConnector := func(id shared.ID, p tenablesc.ScanPayload) {
		t.Helper()
		if !p.RotationRepository || p.LicenseGuard == nil {
			t.Fatalf("a recycle batch must name the rotation repository and carry the guard: %+v", p)
		}
		if p.RecycleRepository {
			rotationRepo = 0
		}
		before := rotationRepo
		if free := license - rotationRepo; free < p.LicenseGuard.NewAddresses+p.LicenseGuard.Headroom {
			t.Fatalf("the platform sent a batch the guard would refuse: free %d, needs %+v", free, *p.LicenseGuard)
		}
		outs := make([]map[string]string, 0, len(p.Targets))
		for _, tg := range p.Targets {
			assessedTimes[tg]++
			outs = append(outs, map[string]string{"target": tg, "state": "done"})
		}
		rotationRepo += len(p.Targets)
		if rotationRepo > license {
			t.Fatalf("license exceeded: %d active", rotationRepo)
		}
		res, _ := json.Marshal(map[string]any{"target_outcomes": outs, "metadata": map[string]any{
			"licensed_ips": license, "active_ips_before": before, "active_ips": rotationRepo, "coverage": "full"}})
		if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'completed', result = $3 WHERE tenant_id = $1 AND id = $2`,
			tenant.String(), id.String(), res); err != nil {
			t.Fatal(err)
		}
	}

	batches := 0
	for range 10 {
		// Each pass settles the previous batch (and checks the cycle), then
		// dispatches the next one.
		if n, err := sched.Reconcile(ctx); err != nil || n != 1 {
			t.Fatalf("batch %d: n=%d err=%v", batches+1, n, err)
		}
		stored, _ := intRepo.GetByTenantAndID(ctx, tenant, intg.ID())
		if st := tenablesc.State(stored); st.Cycle >= 2 {
			break // this batch opens the next cycle
		}
		id, p := latest()
		if batches > 0 && !p.RecycleRepository {
			t.Fatalf("batch %d after an ingested batch must recycle", batches+1)
		}
		runConnector(id, p)
		batches++
	}
	if batches != hosts/license {
		t.Fatalf("%d batches, want %d", batches, hosts/license)
	}
	for i := range hosts {
		if n := assessedTimes[fmt.Sprintf("10.20.0.%d", i+1)]; n != 1 {
			t.Fatalf("host %d assessed %d times in the cycle", i+1, n)
		}
	}
	stored, _ := intRepo.GetByTenantAndID(ctx, tenant, intg.ID())
	if st := tenablesc.State(stored); st.Cycle != 2 || st.CycleAssessed != 0 {
		t.Fatalf("the cycle did not roll over: %+v", st)
	}

	// The next cycle's first batch fails after launching: rotation stalls.
	id, _ := latest()
	if _, err := db.ExecContext(ctx, `UPDATE commands SET status = 'failed', error_message = 'read scan result 9: unreadable row' WHERE tenant_id = $1 AND id = $2`,
		tenant.String(), id.String()); err != nil {
		t.Fatal(err)
	}
	if n, _ := sched.Reconcile(ctx); n != 0 {
		t.Fatal("dispatched after a failed batch")
	}
	stored, _ = intRepo.GetByTenantAndID(ctx, tenant, intg.ID())
	if st := tenablesc.State(stored); st.RotationStalled == "" || st.RecycleNext {
		t.Fatalf("rotation must stall without recycling: %+v", st)
	}
}
