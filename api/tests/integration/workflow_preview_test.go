package integration

import (
	"context"
	"errors"
	"fmt"
	"testing"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// A workflow preview reads only the caller's workflows (and the system
// ones), resolves every step as the trigger would, and bounds its sample.
func TestWorkflowPreview(t *testing.T) {
	p := newScanWorkflowSaveHarness(t, "workflow-preview")
	ctx := context.Background()
	pg := &postgres.DB{DB: p.db}
	svc := scanapp.NewService(
		postgres.NewScanRepository(pg),
		postgres.NewScanWorkflowRepository(pg),
		postgres.NewAssetGroupRepository(pg),
		postgres.NewScanRunRepository(pg),
		postgres.NewScanWorkflowStepRepository(pg),
		postgres.NewStepRunRepository(pg),
		postgres.NewCommandRepository(pg),
		nil, nil,
		postgres.NewToolRepository(pg),
		nil, nil, nil,
		logger.NewNop(),
		allowAllTargetChecks()...,
	)

	targets := make([]string, 0, 30)
	for i := range 30 {
		targets = append(targets, fmt.Sprintf("host-%d.example.com", i))
	}

	// A starter (system) workflow previews for any tenant.
	out, err := svc.PreviewWorkflow(ctx, scanapp.WorkflowPreviewInput{
		TenantID: p.tenant.String(), ScanWorkflowID: "a0000002-0000-0000-0000-000000000002", Targets: targets,
	})
	if err != nil {
		t.Fatalf("preview: %v", err)
	}
	if len(out.Nodes) != 5 {
		t.Fatalf("nodes = %d, want 5", len(out.Nodes))
	}
	for _, n := range out.Nodes {
		if n.Tool == "" || n.Capability == "" || n.Tier == "" || n.Blocking != nil {
			t.Fatalf("node %+v: want a resolved tool, capability and tier", n)
		}
	}
	// Chunk sizes come from the capability: DNS resolution is cut in 200s,
	// vulnerability templates in 25s.
	for _, n := range out.Nodes {
		want := map[string]int{"dns": 200, "ports": 50, "http": 200, "vulns": 25, "subdomains": 50}[n.StepKey]
		if n.ChunkSize != want {
			t.Errorf("step %s chunk size = %d, want %d", n.StepKey, n.ChunkSize, want)
		}
	}
	if out.Targets == nil || out.Targets.ResolvedTargets != 30 || len(out.Targets.Targets) > 20 {
		t.Fatalf("targets: resolved %d, sampled %d (want 30, at most 20)", out.Targets.ResolvedTargets, len(out.Targets.Targets))
	}

	// The tenant's own workflow previews; another tenant's is not found.
	id, _ := p.create()
	if _, err := svc.PreviewWorkflow(ctx, scanapp.WorkflowPreviewInput{TenantID: p.tenant.String(), ScanWorkflowID: id, Targets: targets[:1]}); err != nil {
		t.Fatalf("own workflow: %v", err)
	}
	other := createTestTenant(t, p.db, "workflow-preview-other")
	t.Cleanup(func() { _, _ = p.db.Exec(`DELETE FROM tenants WHERE id=$1`, other.String()) })
	_, err = svc.PreviewWorkflow(ctx, scanapp.WorkflowPreviewInput{TenantID: other.String(), ScanWorkflowID: id, Targets: targets[:1]})
	if !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("other tenant's workflow: err = %v, want not found", err)
	}
}
