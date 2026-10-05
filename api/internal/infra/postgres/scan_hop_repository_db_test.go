package postgres

import (
	"context"
	"database/sql"
	"errors"
	"testing"

	_ "github.com/lib/pq"

	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// hopTenant is one tenant with a run, a step run, a command of it and
// assets.
type hopTenant struct {
	tenant, sensor, run, stepRun, command shared.ID
	assets                                []shared.ID
}

func hopExec(t *testing.T, db *sql.DB, q string, args ...any) {
	t.Helper()
	for i, a := range args {
		if id, ok := a.(shared.ID); ok {
			args[i] = id.String()
		}
	}
	if _, err := db.ExecContext(context.Background(), q, args...); err != nil {
		t.Fatalf("fixture: %v\n%s", err, q)
	}
}

func newHopTenant(t *testing.T, db *sql.DB, assets int) *hopTenant {
	t.Helper()
	h := &hopTenant{tenant: shared.NewID(), sensor: shared.NewID(), run: shared.NewID(), stepRun: shared.NewID(), command: shared.NewID()}
	tpl, step := shared.NewID(), shared.NewID()
	hopExec(t, db, `INSERT INTO tenants (id, name, slug) VALUES ($1, $2, $2)`, h.tenant, "hop-"+h.tenant.String())
	t.Cleanup(func() {
		ctx := context.Background()
		_, _ = db.ExecContext(ctx, "DELETE FROM ingest_reports WHERE tenant_id = $1", h.tenant.String())
		_, _ = db.ExecContext(ctx, "DELETE FROM pipeline_runs WHERE tenant_id = $1", h.tenant.String())
		_, _ = db.ExecContext(ctx, "DELETE FROM pipeline_templates WHERE tenant_id = $1", h.tenant.String())
		_, _ = db.ExecContext(ctx, "DELETE FROM tenants WHERE id = $1", h.tenant.String())
	})
	hopExec(t, db, `INSERT INTO sensors (id, tenant_id, name, api_key_hash, api_key_prefix, status)
		VALUES ($1, $2, 'hop-sensor', $3, 'p', 'active')`, h.sensor, h.tenant, "h-"+h.sensor.String())
	hopExec(t, db, `INSERT INTO pipeline_templates (id, tenant_id, name) VALUES ($1, $2, $3)`, tpl, h.tenant, "hop "+tpl.String())
	hopExec(t, db, `INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, step_order, capabilities)
		VALUES ($1, $2, 'subs', 'subs', 1, ARRAY['subdomain'])`, step, tpl)
	hopExec(t, db, `INSERT INTO pipeline_runs (id, pipeline_id, tenant_id, trigger_type, status) VALUES ($1, $2, $3, 'manual', 'running')`,
		h.run, tpl, h.tenant)
	hopExec(t, db, `INSERT INTO step_runs (id, pipeline_run_id, step_id, step_key, step_order, status) VALUES ($1, $2, $3, 'subs', 1, 'completed')`,
		h.stepRun, h.run, step)
	hopExec(t, db, `INSERT INTO commands (id, tenant_id, sensor_id, type, status, payload, step_run_id)
		VALUES ($1, $2, $3, 'scan', 'completed', '{}', $4)`, h.command, h.tenant, h.sensor, h.stepRun)
	for i := 0; i < assets; i++ {
		a := shared.NewID()
		hopExec(t, db, `INSERT INTO assets (id, tenant_id, name, asset_type) VALUES ($1, $2, $3, 'subdomain')`,
			a, h.tenant, "h"+a.String()+".acme.test")
		h.assets = append(h.assets, a)
	}
	return h
}

func openHopDB(t *testing.T) *sql.DB {
	t.Helper()
	url := testdb.URL()
	if url == "" {
		t.Skip("DATABASE_URL not set; skipping scan hop repository DB test")
	}
	db, err := sql.Open("postgres", url)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := db.PingContext(context.Background()); err != nil {
		t.Skipf("cannot reach DATABASE_URL: %v", err)
	}
	return db
}

// Outputs are recorded and read only inside the tenant: a step run or an
// asset of another tenant writes nothing, and reads with another tenant's id
// return nothing.
func TestScanHops_OutputsAreTenantScoped(t *testing.T) {
	db := openHopDB(t)
	repo := NewScanHopRepository(&DB{DB: db})
	ctx := context.Background()
	a, b := newHopTenant(t, db, 3), newHopTenant(t, db, 1)

	n, err := repo.RecordStepOutputs(ctx, a.tenant, a.stepRun, append(a.assets, b.assets...))
	if err != nil || n != 3 {
		t.Fatalf("recorded %d, %v; want A's 3 assets only", n, err)
	}
	if n, _ := repo.RecordStepOutputs(ctx, a.tenant, a.stepRun, a.assets); n != 0 {
		t.Fatalf("re-recording added %d rows", n)
	}
	// B's tenant cannot write onto A's step run, and A cannot onto B's.
	if n, _ := repo.RecordStepOutputs(ctx, b.tenant, a.stepRun, b.assets); n != 0 {
		t.Fatal("another tenant wrote outputs onto a step run")
	}
	if n, _ := repo.RecordStepOutputs(ctx, a.tenant, b.stepRun, a.assets); n != 0 {
		t.Fatal("outputs written onto another tenant's step run")
	}
	got, total, err := repo.ListStepOutputs(ctx, a.tenant, a.run, []shared.ID{a.stepRun}, 2)
	if err != nil || len(got) != 2 || total != 3 {
		t.Fatalf("list = %d of %d, %v", len(got), total, err)
	}
	if got, total, _ := repo.ListStepOutputs(ctx, b.tenant, a.run, []shared.ID{a.stepRun}, 10); len(got) != 0 || total != 0 {
		t.Fatal("another tenant read A's outputs")
	}
	// A soft-deleted asset is no output any more.
	hopExec(t, db, `UPDATE assets SET deleted_at = NOW() WHERE id = $1`, a.assets[0])
	if _, total, _ := repo.ListStepOutputs(ctx, a.tenant, a.run, []shared.ID{a.stepRun}, 10); total != 2 {
		t.Fatalf("total after a delete = %d", total)
	}
	// The composite foreign key refuses a cross-tenant row whatever writes it.
	_, err = db.ExecContext(ctx, `INSERT INTO scan_step_outputs (tenant_id, run_id, step_run_id, asset_id) VALUES ($1, $2, $3, $4)`,
		b.tenant.String(), a.run.String(), a.stepRun.String(), b.assets[0].String())
	if err == nil {
		t.Fatal("a row pointing at another tenant's run was accepted")
	}
}

// A stage of a run is planned once: the second save writes nothing; the
// plan, its counts and its targets read back in the tenant only.
func TestScanHops_StagePlanExactlyOnce(t *testing.T) {
	db := openHopDB(t)
	repo := NewScanHopRepository(&DB{DB: db})
	ctx := context.Background()
	a, b := newHopTenant(t, db, 2), newHopTenant(t, db, 0)

	asset := a.assets[0]
	plan := &pipeline.StagePlan{TenantID: a.tenant, RunID: a.run, StageKey: "dns", Stage: "resolve.dns", Tool: "dnsx",
		Chained: true, Inputs: 3, Planned: 2, MaxHop: 1, Skipped: map[string]int{"unconfirmed": 1}}
	rows := []pipeline.RunTarget{
		{TargetKey: "acme.test", Origin: pipeline.TargetOriginSeed, Decision: pipeline.TargetPlanned, Reason: pipeline.ReasonSeed},
		{TargetKey: "x.acme.test", AssetID: &asset, Origin: pipeline.TargetOriginDerived, ParentStageKey: "subs",
			Relation: "subdomain_of", Hop: 1, Decision: pipeline.TargetPlanned, Reason: pipeline.ReasonPassiveAllowed},
		{TargetKey: "y.acme.test", Origin: pipeline.TargetOriginDerived, Hop: 1, Decision: pipeline.TargetSkipped, Reason: pipeline.ReasonUnconfirmed},
	}
	ok, err := repo.SaveStagePlan(ctx, plan, rows)
	if err != nil || !ok {
		t.Fatalf("first save: %v %v", ok, err)
	}
	if ok, err := repo.SaveStagePlan(ctx, plan, rows); err != nil || ok {
		t.Fatalf("second save planned again: %v %v", ok, err)
	}
	// Another tenant cannot plan a stage of A's run.
	other := *plan
	other.TenantID, other.StageKey = b.tenant, "ports"
	if ok, _ := repo.SaveStagePlan(ctx, &other, nil); ok {
		t.Fatal("another tenant planned a stage of A's run")
	}

	plans, err := repo.ListStagePlans(ctx, a.tenant, a.run)
	if err != nil || len(plans) != 1 {
		t.Fatalf("plans = %v, %v", plans, err)
	}
	if p := plans[0]; p.Planned != 2 || p.Inputs != 3 || p.Skipped["unconfirmed"] != 1 || !p.Chained || p.Tool != "dnsx" {
		t.Fatalf("plan = %+v", p)
	}
	if plans, _ := repo.ListStagePlans(ctx, b.tenant, a.run); len(plans) != 0 {
		t.Fatal("another tenant read A's plans")
	}
	planned, err := repo.PlannedTargets(ctx, a.tenant, a.run, []string{"dns"})
	if err != nil || len(planned) != 2 {
		t.Fatalf("planned targets = %v, %v", planned, err)
	}
	if planned, _ := repo.PlannedTargets(ctx, b.tenant, a.run, []string{"dns"}); len(planned) != 0 {
		t.Fatal("another tenant read A's targets")
	}
}

// Pending ingest is a v2 report of the step's commands still open; a
// command resolves to its run and step in its own tenant only.
func TestScanHops_PendingIngestAndCommandLookup(t *testing.T) {
	db := openHopDB(t)
	repo := NewScanHopRepository(&DB{DB: db})
	ctx := context.Background()
	a, b := newHopTenant(t, db, 0), newHopTenant(t, db, 0)

	if p, err := repo.PendingStepIngest(ctx, a.tenant, []shared.ID{a.stepRun}); err != nil || p {
		t.Fatalf("pending with no report: %v %v", p, err)
	}
	report := shared.NewID()
	hopExec(t, db, `INSERT INTO ingest_reports (id, tenant_id, sensor_id, report_id, command_id, state, media_type, header_digest, expires_at)
		VALUES ($1, $2, $3, $4, $5, 'processing', 'application/vnd.ctis+json', 'd', NOW() + interval '1 hour')`,
		report, a.tenant, a.sensor, shared.NewID(), a.command)
	if p, _ := repo.PendingStepIngest(ctx, a.tenant, []shared.ID{a.stepRun}); !p {
		t.Fatal("a processing report is not pending")
	}
	if p, _ := repo.PendingStepIngest(ctx, b.tenant, []shared.ID{a.stepRun}); p {
		t.Fatal("another tenant sees A's pending report")
	}
	hopExec(t, db, `UPDATE ingest_reports SET state = 'completed' WHERE id = $1`, report)
	if p, _ := repo.PendingStepIngest(ctx, a.tenant, []shared.ID{a.stepRun}); p {
		t.Fatal("a completed report is still pending")
	}

	run, key, err := repo.StepRunOfCommand(ctx, a.tenant, a.command)
	if err != nil || run != a.run || key != "subs" {
		t.Fatalf("command -> %s %q %v", run, key, err)
	}
	if _, _, err := repo.StepRunOfCommand(ctx, b.tenant, a.command); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant resolved A's command: %v", err)
	}
}
