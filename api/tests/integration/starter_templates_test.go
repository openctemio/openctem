package integration

import (
	"context"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// The starter workflows (migration 001201) are capability graphs: each one
// passes the graph check, every step is a capability node with no pinned
// tool, and the planner resolves a seeded platform tool for every step.
func TestStarterTemplates_ValidAndRunnable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	templates := postgres.NewScanWorkflowRepository(pg)
	tools := postgres.NewToolRepository(pg)

	want := map[string]int{
		"a0000002-0000-0000-0000-000000000001": 3, // Discover
		"a0000002-0000-0000-0000-000000000002": 5, // Discover + Vuln
		"a0000002-0000-0000-0000-000000000003": 3, // Web app
		"a0000002-0000-0000-0000-000000000004": 3, // Network
		"a0000002-0000-0000-0000-000000000005": 4, // Code / CI
	}
	for idStr, steps := range want {
		id, _ := shared.IDFromString(idStr)
		tpl, err := templates.GetWithSteps(ctx, id)
		if err != nil {
			t.Fatalf("%s: %v", idStr, err)
		}
		if !tpl.IsSystemTemplate || !tpl.IsActive || len(tpl.Steps) != steps {
			t.Fatalf("%s (%s): system=%v active=%v steps=%d", idStr, tpl.Name, tpl.IsSystemTemplate, tpl.IsActive, len(tpl.Steps))
		}
		rep := stage.ValidateGraph(scanrun.StepsGraph(tpl.Steps))
		if !rep.Valid() || len(rep.Warnings) != 0 {
			t.Fatalf("%s: graph errors %+v warnings %+v", tpl.Name, rep.Errors, rep.Warnings)
		}
		for _, st := range tpl.Steps {
			if st.Tool != "" || len(st.Capabilities) != 1 {
				t.Fatalf("%s/%s: not a capability node (tool %q caps %v)", tpl.Name, st.StepKey, st.Tool, st.Capabilities)
			}
			got, err := scanapp.ResolveStepTool(ctx, tools, shared.NewID(), st)
			if err != nil {
				t.Fatalf("%s/%s: no tool resolves: %v", tpl.Name, st.StepKey, err)
			}
			if got.Capability() != st.Capabilities[0]+"@1" {
				t.Fatalf("%s/%s: resolved %s for %s", tpl.Name, st.StepKey, got.Capability(), st.Capabilities[0])
			}
		}
	}

	// The presets they replace are kept, inactive.
	var active int
	if err := db.QueryRow(`SELECT count(*) FROM scan_workflows WHERE id IN (
		'a0000001-0000-0000-0000-000000000001','a0000001-0000-0000-0000-000000000002',
		'a0000001-0000-0000-0000-000000000003','a0000001-0000-0000-0000-000000000006') AND is_active`).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 0 {
		t.Fatalf("%d replaced presets are still active", active)
	}
}
