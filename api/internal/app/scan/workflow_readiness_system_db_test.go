package scan_test

import (
	"context"
	"database/sql"
	"slices"
	"testing"

	_ "github.com/lib/pq"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/internal/testdb"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	sensordom "github.com/openctemio/openctem/api/pkg/domain/sensor"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/stage"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// standardSensorTools are the tools every standard sensor image advertises.
var standardSensorTools = []string{"nuclei", "subfinder", "dnsx", "naabu", "httpx", "katana", "rdap", "asn", "reach-probe"}

// Every active system workflow, as seeded by the migrations, can run for an
// organization whose sensors carry the standard tool set: none is blocked.
// The EASM recon workflows are ready, and each optional step whose
// capability no installed tool implements yet is reported skipped (the run
// skips it with the reason), never blocking its workflow.
func TestSystemWorkflows_ReadyOnStandardSensor(t *testing.T) {
	dbURL := testdb.URL()
	if dbURL == "" {
		t.Skip("DATABASE_URL not set; skipping DB-backed test")
	}
	raw, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	defer raw.Close()
	if err := raw.Ping(); err != nil {
		t.Skipf("cannot reach test DB: %v", err)
	}
	ctx := context.Background()
	db := &postgres.DB{DB: raw}
	repo := postgres.NewScanWorkflowRepository(db)

	statuses := map[string]sensordom.ToolStatus{}
	for _, name := range standardSensorTools {
		statuses[name] = sensordom.ToolReady
	}
	svc := scanapp.NewService(nil, repo, nil, nil, nil, nil, nil, nil, postgres.NewToolRepository(db), nil, nil, logger.NewNop(),
		scanapp.WithReadinessSources(
			func(context.Context, shared.ID) (map[string]sensordom.ToolStatus, error) { return statuses, nil },
			func(context.Context, shared.ID) (bool, bool, []string, error) { return false, false, nil, nil },
		))

	tenant := shared.NewID()
	active := true
	list, err := repo.ListWithSystemTemplates(ctx, tenant, scanworkflow.Filter{IsActive: &active}, pagination.New(1, 500))
	if err != nil {
		t.Fatalf("list workflows: %v", err)
	}
	var workflows []*scanworkflow.Workflow
	for _, w := range list.Data {
		// The quick-scan carrier (one step naming the bare "scan"
		// capability) is not a workflow a scan can pick: quick scans name
		// their scanner. It stays blocked by design.
		if !w.IsSystemTemplate || slices.Contains(w.Tags, "quick-scan") {
			continue
		}
		full, err := repo.GetWithSteps(ctx, w.ID)
		if err != nil {
			t.Fatalf("load %s: %v", w.Name, err)
		}
		workflows = append(workflows, full)
	}
	if len(workflows) == 0 {
		t.Fatal("no active system workflow seeded")
	}
	readiness, err := svc.WorkflowReadiness(ctx, tenant, workflows)
	if err != nil || readiness == nil {
		t.Fatalf("readiness: %v (nil %v)", err, readiness == nil)
	}

	// The EASM recon set. Each one leaves out exactly its optional steps
	// whose capability is planned (no tool implements it yet).
	recon := map[string]bool{"Subdomains": true, "Web": true, "Standard recon": true, "Deep recon": true}
	seen := map[string]bool{}
	skippedTotal := 0
	for _, w := range workflows {
		r := readiness[w.ID]
		if r == nil {
			t.Fatalf("%s: no readiness", w.Name)
		}
		if r.State == scanapp.ReadinessBlocked {
			t.Errorf("%s is blocked on the standard sensor: %+v", w.Name, r.Steps)
		}
		if !recon[w.Name] {
			continue
		}
		var want []string
		for _, st := range w.Steps {
			if st.RunPolicy.Optional && len(st.Capabilities) == 1 && stage.IsPlanned(stage.Key(st.Capabilities[0])) {
				want = append(want, st.StepKey)
			}
		}
		seen[w.Name] = true
		if r.State != scanapp.ReadinessReady {
			t.Errorf("%s: state %s, want ready: %+v", w.Name, r.State, r.Steps)
		}
		var skipped []string
		for _, st := range r.Steps {
			switch st.State {
			case scanapp.ReadinessSkipped:
				if !st.Optional || st.Reason == "" || st.Code == "" || st.Capability == "" {
					t.Errorf("%s/%s: a skipped step must be optional and say why: %+v", w.Name, st.StepKey, st)
				}
				skipped = append(skipped, st.StepKey)
			case scanapp.ReadinessReady:
			default:
				t.Errorf("%s/%s: state %s (%s)", w.Name, st.StepKey, st.State, st.Reason)
			}
		}
		skippedTotal += len(skipped)
		if !sameSet(skipped, want) {
			t.Errorf("%s: skipped %v, want %v", w.Name, skipped, want)
		}
	}
	// Screenshots have no tool yet: the set must exercise a skipped step.
	if stage.IsPlanned("capture.screenshot") && skippedTotal == 0 {
		t.Error("no recon workflow reported a skipped optional step")
	}
	for name := range recon {
		if !seen[name] {
			t.Errorf("system workflow %q is not seeded or not active", name)
		}
	}
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}
