package integration

// Scope exclusions were enforced only at scan trigger (RFC-042 F16): ingest
// and POST /pipelines/runs ignored them. These tests run the real services on
// a migrated database with approved exclusions. Design:
// docs/rfcs/RFC-042-asset-inventory-v2.md.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/openctemio/ctis"

	"github.com/openctemio/openctem/api/internal/app/ingest"
	pipelinesvc "github.com/openctemio/openctem/api/internal/app/pipeline"
	scansvc "github.com/openctemio/openctem/api/internal/app/scan"
	scopesvc "github.com/openctemio/openctem/api/internal/app/scope"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// seedApprovedExclusion inserts an exclusion in effect (approved by someone
// other than the requester, as the approval workflow requires).
func seedApprovedExclusion(t *testing.T, db *sql.DB, tenant shared.ID, typ, pattern string) {
	t.Helper()
	if _, err := db.ExecContext(context.Background(),
		`INSERT INTO scope_exclusions (tenant_id, exclusion_type, pattern, reason, status, approved_by, approved_at, created_by)
		 VALUES ($1, $2, $3, 'test', 'active', 'approver', NOW(), 'requester')`,
		tenant.String(), typ, pattern); err != nil {
		t.Fatalf("seed exclusion %s: %v", pattern, err)
	}
}

func scopeService(db *sql.DB) *scopesvc.Service {
	pg := &postgres.DB{DB: db}
	return scopesvc.NewService(postgres.NewScopeTargetRepository(pg), postgres.NewScopeExclusionRepository(pg),
		nil, postgres.NewAssetRepository(pg), logger.NewNop())
}

func TestIngest_ExcludedAssetsAreNotAdded(t *testing.T) {
	r := newV2Rig(t, ingest.DefaultBlindingGuard())
	tn := r.newTenant("nmap")
	ctx := context.Background()
	db := &postgres.DB{DB: r.db}
	svc := ingest.NewService(
		postgres.NewAssetRepository(db), postgres.NewFindingRepository(db),
		postgres.NewVulnerabilityRepository(db), postgres.NewComponentRepository(db),
		postgres.NewSensorRepository(db), postgres.NewBranchRepository(db), postgres.NewTenantRepository(db),
		postgres.NewAuditRepository(db), logger.NewNop())
	svc.SetExclusionSource(scopeService(r.db))
	tid := tn.tenant
	agt := &sensor.Sensor{ID: tn.sensor, TenantID: &tid, Type: sensor.SensorTypeWorker, Status: sensor.SensorStatusActive}
	ingestReport := func(assets []ctis.Asset, findings ...ctis.Finding) *ingest.Output {
		t.Helper()
		rep := &ctis.Report{Version: "1.0", Tool: &ctis.Tool{Name: "nmap"}, Assets: assets, Findings: findings,
			Metadata: ctis.ReportMetadata{Timestamp: time.Now().UTC()}}
		out, err := svc.Ingest(ctx, agt, ingest.Input{Report: rep})
		if err != nil {
			t.Fatalf("Ingest: %v", err)
		}
		return out
	}
	assetNames := func() []string {
		t.Helper()
		rows, err := r.db.QueryContext(ctx, `SELECT name FROM assets WHERE tenant_id = $1 ORDER BY name`, tid.String())
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var names []string
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				t.Fatal(err)
			}
			names = append(names, n)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		return names
	}

	// Known before the exclusion was approved: ingest must not delete it.
	ingestReport([]ctis.Asset{{ID: "old", Type: ctis.AssetTypeHost, Value: "old.example.com"}})

	seedApprovedExclusion(t, r.db, tid, "domain", "blocked.example.com")
	seedApprovedExclusion(t, r.db, tid, "domain", "old.example.com")
	seedApprovedExclusion(t, r.db, tid, "cidr", "198.51.100.0/24")

	out := ingestReport([]ctis.Asset{
		{ID: "ok", Type: ctis.AssetTypeHost, Value: "ok.example.com", Properties: ctis.Properties{"ip": "203.0.113.5"}},
		{ID: "blocked", Type: ctis.AssetTypeHost, Value: "blocked.example.com"},
		{ID: "via-ip", Type: ctis.AssetTypeHost, Value: "edge.example.com", Properties: ctis.Properties{"ip": "198.51.100.7"}},
		{ID: "old", Type: ctis.AssetTypeHost, Value: "old.example.com"},
	}, ctis.Finding{Type: ctis.FindingTypeVulnerability, Title: "on an excluded host", Severity: ctis.SeverityHigh,
		RuleID: "excluded-rule", AssetRef: "blocked"})

	if got, want := assetNames(), []string{"ok.example.com", "old.example.com"}; !slices.Equal(got, want) {
		t.Fatalf("assets = %v, want %v: a host matching an exclusion by name or address must not be added, and an existing one is kept", got, want)
	}
	if out.AssetsSkippedExcluded != 2 {
		t.Fatalf("assets_skipped_excluded = %d, want 2", out.AssetsSkippedExcluded)
	}
	var findings int
	if err := r.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM findings WHERE tenant_id = $1`, tid.String()).Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if findings != 0 || out.FindingsSkipped != 1 {
		t.Fatalf("findings stored = %d, skipped = %d; the excluded host's finding must be skipped, not attached elsewhere", findings, out.FindingsSkipped)
	}
}

func TestPipelineRun_TargetsPassTheScanGate(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	tenant := seedLifecycleTenant(ctx, t, db)
	pg := &postgres.DB{DB: db}

	templateID := shared.NewID()
	if _, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_templates (id, tenant_id, name, description, is_active) VALUES ($1, $2, 'gate test', '', TRUE)`,
		templateID.String(), tenant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx,
		`INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 'scan', 'Scan', '', 1, 'nuclei')`,
		shared.NewID().String(), templateID.String()); err != nil {
		t.Fatal(err)
	}
	seedApprovedExclusion(t, db, tenant, "domain", "blocked.example.com")
	// The run starts with no user: free text must match a scope target (D9).
	seedScopeTarget(t, db, tenant, "domain", "*.example.com")

	gate := newTriggerServiceWith(db, scansvc.WithScopeExclusionFilter(scopeService(db)),
		scansvc.WithActScope(actScopeChecker(db)))
	svc := pipelinesvc.NewService(
		postgres.NewPipelineTemplateRepository(pg), postgres.NewPipelineStepRepository(pg),
		postgres.NewPipelineRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg),
		nil, logger.New(logger.Config{Level: "error"}),
		pipelinesvc.WithTargetGate(gate),
	)
	trigger := func(runContext map[string]any) error {
		_, err := svc.TriggerPipeline(ctx, pipelinesvc.TriggerPipelineInput{
			TenantID: tenant.String(), TemplateID: templateID.String(), TriggerType: "api", Context: runContext,
		})
		return err
	}

	// A private address outside every zone, loopback and the metadata
	// address are refused, as at scan create.
	for _, target := range []string{"10.0.0.5", "127.0.0.1", "169.254.169.254"} {
		err := trigger(map[string]any{"targets": []any{"ok.example.com", target}})
		if !errors.Is(err, shared.ErrValidation) {
			t.Fatalf("target %s: err = %v, want a validation refusal", target, err)
		}
	}
	if n := countRows(t, db, `SELECT COUNT(*) FROM commands WHERE tenant_id = $1`, tenant); n != 0 {
		t.Fatalf("%d command(s) created for refused runs", n)
	}

	// Every target excluded: refused.
	if err := trigger(map[string]any{"target": "blocked.example.com"}); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("all targets excluded: err = %v, want a validation refusal", err)
	}

	// Excluded targets are dropped; a caller-supplied zone is ignored.
	forged := shared.NewID().String()
	if err := trigger(map[string]any{
		"targets":      []any{"blocked.example.com", "ok.example.com"},
		"scan_zone_id": forged,
	}); err != nil {
		t.Fatalf("trigger: %v", err)
	}
	var payload []byte
	var zone sql.NullString
	if err := db.QueryRowContext(ctx,
		`SELECT payload, scan_zone_id FROM commands WHERE tenant_id = $1`, tenant.String()).Scan(&payload, &zone); err != nil {
		t.Fatalf("read command: %v", err)
	}
	var p struct {
		Targets []string       `json:"targets"`
		Context map[string]any `json:"context"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(p.Targets, []string{"ok.example.com"}) {
		t.Fatalf("command targets = %v, want only ok.example.com", p.Targets)
	}
	if ctxTargets, _ := json.Marshal(p.Context["targets"]); string(ctxTargets) != `["ok.example.com"]` {
		t.Fatalf("command context targets = %s, want only ok.example.com", ctxTargets)
	}
	if zone.Valid || p.Context["scan_zone_id"] != nil {
		t.Fatalf("caller-supplied zone %s reached the command (scan_zone_id=%v, context=%v)", forged, zone, p.Context["scan_zone_id"])
	}
}

func countRows(t *testing.T, db *sql.DB, q string, tenant shared.ID) int {
	t.Helper()
	var n int
	if err := db.QueryRowContext(context.Background(), q, tenant.String()).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// newTriggerServiceWith is newTriggerService with extra options.
func newTriggerServiceWith(db *sql.DB, opts ...scansvc.ServiceOption) *scansvc.Service {
	pg := &postgres.DB{DB: db}
	return scansvc.NewService(
		postgres.NewScanRepository(pg),
		postgres.NewPipelineTemplateRepository(pg),
		nil,
		postgres.NewPipelineRunRepository(pg),
		postgres.NewPipelineStepRepository(pg),
		postgres.NewStepRunRepository(pg),
		postgres.NewCommandRepository(pg),
		nil, nil,
		postgres.NewToolRepository(pg),
		nil,
		availableSensors{},
		nil,
		logger.New(logger.Config{Level: "error"}),
		opts...,
	)
}
