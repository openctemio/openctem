package integration

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"testing"

	"github.com/google/uuid"
	_ "github.com/lib/pq"

	pipelineapp "github.com/openctemio/openctem/api/internal/app/pipeline"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Tenants could delete the shared system pipeline templates (the fixed Quick
// Scan template among them) and add, change or delete their steps; and a
// tenant deactivating its own custom tool named like a platform tool
// deactivated every other tenant's pipelines using that name.
func TestPlatformPipelineWrites(t *testing.T) {
	dsn := testdb.URL()
	if dsn == "" {
		t.Skip("DATABASE_URL not set; skipping platform pipeline DB test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Ping(); err != nil {
		testdb.Skipf(t, "database not available: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.ExecContext(ctx, q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	const systemTenant = "00000000-0000-0000-0000-000000000000"
	exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'System', 'system') ON CONFLICT (id) DO NOTHING`, systemTenant)
	tenantA, tenantB := uuid.NewString(), uuid.NewString()
	for _, tid := range []string{tenantA, tenantB} {
		exec(`INSERT INTO tenants (id, name, slug) VALUES ($1, 'Pipeline IT', $2)`, tid, "pl-it-"+strings.ReplaceAll(tid[:13], "-", ""))
	}
	sysTpl, sysStep := uuid.NewString(), uuid.NewString()
	exec(`INSERT INTO pipeline_templates (id, tenant_id, name, description, is_system_template, is_active) VALUES ($1, $2, 'IT system template', 'IT', TRUE, TRUE)`, sysTpl, systemTenant)
	exec(`INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 'scan', 'Scan', '', 1, 'nuclei')`, sysStep, sysTpl)
	pipelineOf := func(tid string) string {
		id := uuid.NewString()
		exec(`INSERT INTO pipeline_templates (id, tenant_id, name, description, is_active) VALUES ($1, $2, 'IT pipeline', 'IT', TRUE)`, id, tid)
		exec(`INSERT INTO pipeline_steps (id, pipeline_id, step_key, name, description, step_order, tool) VALUES ($1, $2, 's1', 'S1', '', 1, 'nuclei')`, uuid.NewString(), id)
		return id
	}
	plA, plB := pipelineOf(tenantA), pipelineOf(tenantB)
	t.Cleanup(func() {
		c := context.Background()
		_, _ = db.ExecContext(c, `DELETE FROM pipeline_steps WHERE pipeline_id = ANY($1)`, "{"+sysTpl+","+plA+","+plB+"}")
		_, _ = db.ExecContext(c, `DELETE FROM pipeline_templates WHERE id = ANY($1)`, "{"+sysTpl+","+plA+","+plB+"}")
		_, _ = db.ExecContext(c, `DELETE FROM tenants WHERE id = ANY($1)`, "{"+tenantA+","+tenantB+"}")
	})

	pg := &postgres.DB{DB: db}
	steps := postgres.NewPipelineStepRepository(pg)
	svc := pipelineapp.NewService(postgres.NewPipelineTemplateRepository(pg), steps,
		postgres.NewPipelineRunRepository(pg), postgres.NewStepRunRepository(pg), nil, nil, nil, logger.NewNop())

	forbidden := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, shared.ErrForbidden) {
			t.Fatalf("%s: want forbidden, got %v", what, err)
		}
	}
	forbidden("delete system template", svc.DeleteTemplate(ctx, tenantB, sysTpl))
	_, err = svc.AddStep(ctx, pipelineapp.AddStepInput{TenantID: tenantB, TemplateID: sysTpl, StepKey: "evil", Name: "evil", Tool: "nuclei"})
	forbidden("add step to system template", err)
	_, err = svc.UpdateStep(ctx, sysStep, pipelineapp.AddStepInput{TenantID: tenantB, TemplateID: sysTpl, StepKey: "scan", Name: "renamed", Tool: "nuclei"})
	forbidden("update system step", err)
	forbidden("delete system step", svc.DeleteStep(ctx, tenantB, sysStep))
	var name string
	var n int
	_ = db.QueryRowContext(ctx, `SELECT s.name, (SELECT COUNT(*) FROM pipeline_steps WHERE pipeline_id = $1) FROM pipeline_steps s WHERE s.id = $2`, sysTpl, sysStep).Scan(&name, &n)
	if name != "Scan" || n != 1 {
		t.Fatalf("system template changed: step name %q, %d steps", name, n)
	}

	// Tool deactivation cascades only within the tool's tenant.
	count, ids, err := svc.DeactivatePipelinesByTool(ctx, shared.MustIDFromString(tenantB), "nuclei")
	if err != nil {
		t.Fatal(err)
	}
	if count != 1 || len(ids) != 1 || ids[0].String() != plB {
		t.Fatalf("tenant B deactivation touched %v (count %d), want only %s", ids, count, plB)
	}
	var activeA bool
	_ = db.QueryRowContext(ctx, `SELECT is_active FROM pipeline_templates WHERE id = $1`, plA).Scan(&activeA)
	if !activeA {
		t.Fatal("tenant A's pipeline was deactivated by tenant B's tool")
	}
}
