package integration

import (
	"context"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/internal/app"
	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Every system template copies into a tenant and saves with the real
// validator: no step pins a tool (so none can be missing on the tenant's
// sensors), every step runs a catalog capability, and the settings are the
// capability's standard params. The owner's case: "Full Reconnaissance"
// pinned gowitness and wappalyzer, and a copy refused to save with
// "tool not found in registry: gowitness".
func TestSystemTemplates_AreAnyToolCapabilityStepsThatSave(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	pg := &postgres.DB{DB: db}
	ctx := context.Background()

	validator := app.NewScanWorkflowSecurityValidatorAdapter(
		app.NewSecurityValidator(postgres.NewToolRepository(pg), logger.NewNop()))
	svc := scanrun.NewService(
		postgres.NewScanWorkflowRepository(pg),
		postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewScanRunRepository(pg),
		postgres.NewStepRunRepository(pg),
		nil,
		postgres.NewCommandRepository(pg),
		validator,
		logger.NewNop(),
		scanrun.WithToolRepo(postgres.NewToolRepository(pg)),
	)
	templates := postgres.NewScanWorkflowRepository(pg)

	rows, err := db.Query(`SELECT id, name FROM scan_workflows WHERE is_system_template AND id::text LIKE 'a000000%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	tenant := shared.NewID().String()
	n := 0
	for rows.Next() {
		var idStr, name string
		if err := rows.Scan(&idStr, &name); err != nil {
			t.Fatal(err)
		}
		id, _ := shared.IDFromString(idStr)
		tpl, err := templates.GetWithSteps(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		inputs := make([]scanrun.AddStepInput, 0, len(tpl.Steps))
		for _, s := range tpl.Steps {
			if s.Tool != "" {
				t.Errorf("%s / %s pins %q: a template step runs on any tool", name, s.StepKey, s.Tool)
			}
			if _, ok := stage.ForStep(s.Tool, s.Capabilities); !ok {
				t.Errorf("%s / %s runs no catalog capability: %v", name, s.StepKey, s.Capabilities)
			}
			inputs = append(inputs, scanrun.AddStepInput{
				TenantID: tenant, StepKey: s.StepKey, Name: s.Name, Order: s.StepOrder,
				Tool: s.Tool, Capabilities: s.Capabilities, Config: s.Config,
				TimeoutSeconds: s.TimeoutSeconds, DependsOn: s.DependsOn,
			})
		}
		if err := svc.ValidateSteps(ctx, inputs); err != nil {
			t.Errorf("a copy of %q does not save: %v", name, err)
		}
		if rep := stage.ValidateGraph(scanrun.StepsGraph(tpl.Steps)); !rep.Valid() {
			t.Errorf("%q fails the graph check: %+v", name, rep.Errors)
		}
		if strings.Contains(strings.ToLower(tpl.Description), "dalfox") || strings.Contains(tpl.Description, "(subfinder)") {
			t.Errorf("%q still describes tools it no longer pins: %s", name, tpl.Description)
		}
		n++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if n < 6 {
		t.Fatalf("only %d system templates checked", n)
	}
}
