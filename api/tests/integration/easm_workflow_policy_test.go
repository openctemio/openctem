package integration

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/internal/app/scanrun"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A copy of Standard recon keeps its steps' run policies and its run rules;
// a settings save from a client that does not send the run rules keeps
// them; a step update without a policy keeps it; depth params with tool
// extras are refused; another tenant does not see the copy.
func TestEASMWorkflowPolicy_CopyAndEdit(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	tenantA := createTestTenant(t, db, "easm-policy-a")
	tenantB := createTestTenant(t, db, "easm-policy-b")
	t.Cleanup(func() {
		for _, tn := range []shared.ID{tenantA, tenantB} {
			_, _ = db.Exec(`DELETE FROM scans WHERE tenant_id=$1`, tn.String())
			_, _ = db.Exec(`DELETE FROM scan_workflows WHERE tenant_id=$1`, tn.String())
			_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tn.String())
		}
	})
	pg := &postgres.DB{DB: db}
	repo := postgres.NewScanWorkflowRepository(pg)
	svc := scanrun.NewService(repo, postgres.NewScanWorkflowStepRepository(pg), postgres.NewScanRunRepository(pg),
		postgres.NewStepRunRepository(pg), nil, postgres.NewCommandRepository(pg), acceptingStepValidator{},
		logger.New(logger.Config{Level: "error"}), scanrun.WithVersionStore(repo))

	copyA, err := svc.CloneTemplate(ctx, scanrun.CloneTemplateInput{TenantID: tenantA.String(),
		TemplateID: "a0000002-0000-0000-0000-000000000013", NewName: "recon-a"})
	if err != nil {
		t.Fatal(err)
	}
	load := func() *scanworkflow.Workflow {
		t.Helper()
		if _, err := svc.GetTemplate(ctx, tenantA.String(), copyA.ID.String()); err != nil {
			t.Fatal(err)
		}
		w, err := repo.GetWithSteps(ctx, copyA.ID)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	got := load()
	if !got.Settings.DeltaGating || !got.Settings.ContinueOnFailedDependency {
		t.Fatalf("copy settings = %+v", got.Settings)
	}
	steps := map[string]*scanworkflow.Step{}
	for _, st := range got.Steps {
		steps[st.StepKey] = st
	}
	if steps["crawl"].RunPolicy.MinDepth != scanworkflow.DepthDeep || !steps["screenshots"].RunPolicy.Optional ||
		steps["ports"].RunPolicy.Overlay(scanworkflow.DepthDeep).Params["top_n"] != float64(1000) {
		t.Fatalf("copy lost its run policies: crawl %+v screenshots %+v ports %+v",
			steps["crawl"].RunPolicy, steps["screenshots"].RunPolicy, steps["ports"].RunPolicy)
	}

	// Another tenant does not see the copy.
	if _, err := svc.GetTemplate(ctx, tenantB.String(), copyA.ID.String()); err == nil {
		t.Fatal("tenant B read tenant A's copy")
	}

	// A settings save without the run rules keeps them; naming one changes it.
	if _, err := svc.UpdateTemplate(ctx, scanrun.UpdateTemplateInput{TenantID: tenantA.String(), TemplateID: copyA.ID.String(),
		Settings: &scanworkflow.Settings{MaxParallelSteps: 2, TimeoutSeconds: 3600}}); err != nil {
		t.Fatal(err)
	}
	off := false
	if _, err := svc.UpdateTemplate(ctx, scanrun.UpdateTemplateInput{TenantID: tenantA.String(), TemplateID: copyA.ID.String(),
		ContinueOnFailedDependency: &off}); err != nil {
		t.Fatal(err)
	}
	got = load()
	if !got.Settings.DeltaGating || got.Settings.ContinueOnFailedDependency || got.Settings.MaxParallelSteps != 2 {
		t.Fatalf("settings after saves = %+v", got.Settings)
	}

	// A step update that does not name the policy keeps it.
	ports := steps["ports"]
	if _, err := svc.UpdateStep(ctx, ports.ID.String(), scanrun.AddStepInput{TenantID: tenantA.String(),
		TemplateID: copyA.ID.String(), Name: "Ports", MaxRetries: 1}); err != nil {
		t.Fatal(err)
	}
	got = load()
	for _, st := range got.Steps {
		if st.StepKey == "ports" && st.RunPolicy.Overlay(scanworkflow.DepthDeep).Params["top_n"] != float64(1000) {
			t.Fatalf("step update dropped the policy: %+v", st.RunPolicy)
		}
	}

	// Depth params are standard params only.
	bad := scanworkflow.RunPolicy{Depths: map[scanworkflow.Depth]scanworkflow.DepthOverlay{
		scanworkflow.DepthDeep: {Params: map[string]any{"x": map[string]any{"naabu": map[string]any{"rate": 1}}}}}}
	_, err = svc.UpdateStep(ctx, ports.ID.String(), scanrun.AddStepInput{TenantID: tenantA.String(),
		TemplateID: copyA.ID.String(), RunPolicy: &bad, MaxRetries: 1})
	if !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("tool extras in depth params: %v", err)
	}
}

// A scan stores its depth; the database refuses a depth outside the set.
func TestScanDepth_Stored(t *testing.T) {
	db := setupTestDB(t)
	t.Cleanup(func() { db.Close() })
	ctx := context.Background()
	tenant := createTestTenant(t, db, "easm-depth")
	t.Cleanup(func() {
		_, _ = db.Exec(`DELETE FROM scans WHERE tenant_id=$1`, tenant.String())
		_, _ = db.Exec(`DELETE FROM tenants WHERE id=$1`, tenant.String())
	})
	scans := postgres.NewScanRepository(&postgres.DB{DB: db})
	wf, _ := shared.IDFromString("a0000002-0000-0000-0000-000000000013")
	sc, err := scan.NewScan(tenant, "recon depth", shared.ID{}, scan.ScanTypeWorkflow)
	if err != nil {
		t.Fatal(err)
	}
	sc.ScanWorkflowID = &wf
	sc.Targets = []string{"example.com"}
	if err := sc.SetDepth("deep"); err != nil {
		t.Fatal(err)
	}
	if err := scans.Create(ctx, sc); err != nil {
		t.Fatal(err)
	}
	back, err := scans.GetByTenantAndID(ctx, tenant, sc.ID)
	if err != nil || back.EffectiveDepth() != scanworkflow.DepthDeep {
		t.Fatalf("depth read back = %v, %v", back, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE scans SET depth = 'full' WHERE id = $1`, sc.ID.String()); err == nil {
		t.Fatal("the database accepted depth 'full'")
	}
	if err := sc.SetDepth("full"); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("SetDepth(full) = %v", err)
	}
}
