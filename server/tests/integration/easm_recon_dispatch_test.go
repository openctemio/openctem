package integration

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A run of the EASM recon workflows starts on the standard sensor tool set:
// the root steps dispatch their default tools, and the optional steps that
// wait for a tool (takeover check, screenshots) neither refuse the run nor
// fail a step. Subdomains starts with subdomain discovery; Web starts with
// the web probe; Deep recon starts discovery and registration data in
// parallel.
func TestEASMRecon_RunDispatchesRootSteps(t *testing.T) {
	db := openLifecycleDB(t)
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	runs := scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg), postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg), postgres.NewStepRunRepository(pg),
		postgres.NewSensorRepository(pg), postgres.NewCommandRepository(pg), nil, logger.New(logger.Config{Level: "error"}),
		scanrun.WithTargetGate(newTriggerService(db)),
		scanrun.WithToolRepo(postgres.NewToolRepository(pg)),
	)

	cases := []struct {
		name     string
		template string
		target   string
		tools    []string
	}{
		{"Subdomains", "a0000002-0000-0000-0000-000000000012", "recon-dispatch.example.com", []string{"subfinder"}},
		{"Web", "a0000002-0000-0000-0000-000000000014", "https://recon-dispatch.example.com", []string{"httpx"}},
		{"Deep recon", "a0000002-0000-0000-0000-000000000015", "recon-dispatch.example.com", []string{"rdap", "subfinder"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tenant := seedLifecycleTenant(ctx, t, db)
			run, err := runs.TriggerPipeline(ctx, scanrun.TriggerRunInput{
				TenantID: tenant.String(), TemplateID: tc.template, TriggerType: "api",
				Context: map[string]any{"targets": []any{tc.target}},
			})
			if err != nil {
				t.Fatalf("trigger %s: %v", tc.name, err)
			}
			if got := commandTools(ctx, t, db, tenant.String()); !slices.Equal(got, tc.tools) {
				t.Fatalf("%s dispatched %v, want %v", tc.name, got, tc.tools)
			}
			var failed int
			if err := db.QueryRowContext(ctx,
				`SELECT count(*) FROM scan_run_steps WHERE scan_run_id = $1 AND status = 'failed'`, run.ID.String()).Scan(&failed); err != nil {
				t.Fatalf("read step runs: %v", err)
			}
			if failed != 0 {
				t.Fatalf("%s: %d step(s) failed at start", tc.name, failed)
			}
		})
	}
}

// commandTools are the scanner names of the tenant's commands, sorted.
func commandTools(ctx context.Context, t *testing.T, db *sql.DB, tenant string) []string {
	t.Helper()
	rows, err := db.QueryContext(ctx,
		`SELECT COALESCE(payload->>'scanner', '') FROM commands WHERE tenant_id = $1 ORDER BY 1`, tenant)
	if err != nil {
		t.Fatalf("read commands: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}
