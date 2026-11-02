package integration

import (
	"context"
	"encoding/json"
	"slices"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
)

// The EASM recon set (migration easm_workflow_depth_templates): Passive
// discovery, Subdomains, Standard recon, Web and Deep recon.
var easmReconTemplates = map[string]string{
	"a0000002-0000-0000-0000-000000000006": "Passive discovery",
	"a0000002-0000-0000-0000-000000000012": "Subdomains",
	"a0000002-0000-0000-0000-000000000013": "Standard recon",
	"a0000002-0000-0000-0000-000000000014": "Web",
	"a0000002-0000-0000-0000-000000000015": "Deep recon",
}

// Each recon workflow passes the graph check (optional steps that wait for
// a tool are the only warnings), has no intrusive step, turns on delta
// gating and continue-on-failure, and every step that is not optional
// resolves a seeded platform tool at every depth (the depth's params never
// make the default tool ineligible).
func TestEASMReconTemplates_ValidAndRunnable(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	pg := &postgres.DB{DB: db}
	templates := postgres.NewScanWorkflowRepository(pg)
	tools := postgres.NewToolRepository(pg)

	for idStr, name := range easmReconTemplates {
		id, _ := shared.IDFromString(idStr)
		tpl, err := templates.GetWithSteps(ctx, id)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tpl.Name != name || !tpl.IsSystemTemplate || !tpl.IsActive || !slices.Contains(tpl.Tags, "easm-recon") {
			t.Fatalf("%s: name %q system %v active %v tags %v", idStr, tpl.Name, tpl.IsSystemTemplate, tpl.IsActive, tpl.Tags)
		}
		if !tpl.Settings.DeltaGating || !tpl.Settings.ContinueOnFailedDependency {
			t.Fatalf("%s: settings %+v", name, tpl.Settings)
		}
		rep := stage.ValidateGraph(scanrun.StepsGraph(tpl.Steps))
		if !rep.Valid() {
			t.Fatalf("%s: graph errors %+v", name, rep.Errors)
		}
		for _, w := range rep.Warnings {
			if w.Code != stage.IssueWaitsForTool {
				t.Fatalf("%s: unexpected warning %+v", name, w)
			}
		}
		for _, st := range tpl.Steps {
			if st.Tool != "" || len(st.Capabilities) != 1 {
				t.Fatalf("%s/%s: not a capability node", name, st.StepKey)
			}
			if scanapp.StepIntensityTier(st) >= int(stage.TierIntrusive) {
				t.Fatalf("%s/%s: intrusive step in a recon workflow", name, st.StepKey)
			}
			if err := st.RunPolicy.Validate(); err != nil {
				t.Fatalf("%s/%s: %v", name, st.StepKey, err)
			}
			// An optional step on a planned capability waits for a tool; one
			// on a routed capability (the takeover check) resolves its tool
			// like any step and is skipped only when that tool is missing.
			if st.RunPolicy.Optional && stage.IsPlanned(stage.Key(st.Capabilities[0])) {
				continue
			}
			for _, d := range scanworkflow.Depths() {
				at := *st
				at.Config = st.RunPolicy.ConfigAt(st.Config, d)
				got, err := scanapp.ResolveStepTool(ctx, tools, shared.NewID(), &at)
				if err != nil {
					t.Fatalf("%s/%s at %s: no tool resolves: %v", name, st.StepKey, d, err)
				}
				if got.Capability() != st.Capabilities[0]+"@1" {
					t.Fatalf("%s/%s: resolved %s", name, st.StepKey, got.Capability())
				}
			}
		}
	}
}

// The depth always changes what runs: for each recon workflow the steps
// that run and the params they get differ between passive, standard and
// deep. A depth at which no first step can run (Web at passive) is refused
// when a scan is saved, which is also a different outcome.
func TestEASMReconTemplates_DepthChangesWhatRuns(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()
	ctx := context.Background()
	templates := postgres.NewScanWorkflowRepository(&postgres.DB{DB: db})

	for idStr, name := range easmReconTemplates {
		id, _ := shared.IDFromString(idStr)
		tpl, err := templates.GetWithSteps(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		plans := map[scanworkflow.Depth]string{}
		for _, d := range scanworkflow.Depths() {
			type planned struct {
				Step   string
				Params map[string]any
				Cap    int
			}
			var plan []planned
			rootRuns := false
			for _, st := range tpl.Steps {
				if st.RunPolicy.DepthSkipReason(d, scanapp.StepIntensityTier(st)) != "" {
					continue
				}
				if len(st.DependsOn) == 0 {
					rootRuns = true
				}
				o := st.RunPolicy.Overlay(d)
				plan = append(plan, planned{Step: st.StepKey, Params: o.Params, Cap: o.MaxTargets})
			}
			if !rootRuns {
				plans[d] = "refused: no first step runs"
				continue
			}
			b, _ := json.Marshal(plan)
			plans[d] = string(b)
		}
		if plans[scanworkflow.DepthPassive] == plans[scanworkflow.DepthStandard] ||
			plans[scanworkflow.DepthStandard] == plans[scanworkflow.DepthDeep] {
			t.Fatalf("%s: a depth does not change what runs:\npassive  %s\nstandard %s\ndeep     %s", name,
				plans[scanworkflow.DepthPassive], plans[scanworkflow.DepthStandard], plans[scanworkflow.DepthDeep])
		}
	}
}
