package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app/scancoverage"
	"github.com/openctemio/api/pkg/domain/integration"
	"github.com/openctemio/api/pkg/domain/shared"
)

// --- fakes ---------------------------------------------------------------

type fakeIntegrationLister struct {
	result integration.ListResult
	err    error
}

func (f *fakeIntegrationLister) List(_ context.Context, _ integration.Filter) (integration.ListResult, error) {
	return f.result, f.err
}

type fakeCoverageRepo struct {
	candidates []scancoverage.Candidate
	active     int
	marked     []scancoverage.DispatchRecord
}

func (f *fakeCoverageRepo) ListCandidates(_ context.Context, _ shared.ID, _ int) ([]scancoverage.Candidate, error) {
	return f.candidates, nil
}
func (f *fakeCoverageRepo) ActiveIPs(_ context.Context, _ shared.ID) (int, error) {
	return f.active, nil
}
func (f *fakeCoverageRepo) MarkDispatched(_ context.Context, rec scancoverage.DispatchRecord) error {
	f.marked = append(f.marked, rec)
	return nil
}

type fakeDispatcher struct {
	calls []scancoverage.DispatchTenableInput
}

func (f *fakeDispatcher) DispatchTenableScan(_ context.Context, in scancoverage.DispatchTenableInput) (shared.ID, string, error) {
	f.calls = append(f.calls, in)
	return shared.NewID(), "sess-x", nil
}

func tenableIntegration(t *testing.T, tenant shared.ID, cfg map[string]any) *integration.Integration {
	t.Helper()
	intg := integration.NewIntegration(
		shared.NewID(), tenant, "tenable", integration.CategorySecurity,
		integration.ProviderTenable, integration.AuthTypeAPIKey,
	)
	intg.SetConfig(cfg)
	return intg
}

// --- tests ---------------------------------------------------------------

func TestCoverageScheduler_DrivesUnlimitedEngine(t *testing.T) {
	tenant := shared.NewID()
	lister := &fakeIntegrationLister{result: integration.ListResult{
		Data: []*integration.Integration{
			tenableIntegration(t, tenant, map[string]any{
				"engine":           "nessus_pro",
				"coverage_enabled": true,
				"batch_size":       float64(2),
			}),
		},
		Total: 1,
	}}
	repo := &fakeCoverageRepo{candidates: []scancoverage.Candidate{
		{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"},
		{AssetID: "a2", Target: "10.0.0.2", Criticality: "critical"},
		{AssetID: "a3", Target: "10.0.0.3", Criticality: "low"},
	}}
	disp := &fakeDispatcher{}
	c := NewCoverageScheduler(lister, repo, disp, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 dispatch, got %d", n)
	}
	if len(disp.calls) != 1 || len(disp.calls[0].Targets) != 2 {
		t.Fatalf("expected batch of 2, got %+v", disp.calls)
	}
	if disp.calls[0].TenantID != tenant {
		t.Fatal("tenant not forwarded")
	}
	if len(repo.marked) != 1 || len(repo.marked[0].AssetIDs) != 2 {
		t.Fatalf("cursor not advanced: %+v", repo.marked)
	}
}

func TestCoverageScheduler_SkipsWhenCoverageDisabled(t *testing.T) {
	tenant := shared.NewID()
	lister := &fakeIntegrationLister{result: integration.ListResult{
		Data: []*integration.Integration{
			// coverage_enabled defaults false → must not be auto-rotated.
			tenableIntegration(t, tenant, map[string]any{"engine": "nessus_pro"}),
		},
		Total: 1,
	}}
	disp := &fakeDispatcher{}
	c := NewCoverageScheduler(lister, &fakeCoverageRepo{}, disp, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 0 || len(disp.calls) != 0 {
		t.Fatalf("disabled coverage must not dispatch, got %d", n)
	}
}

func TestCoverageScheduler_SkipsCappedEngine(t *testing.T) {
	tenant := shared.NewID()
	lister := &fakeIntegrationLister{result: integration.ListResult{
		Data: []*integration.Integration{
			// .sc is capped — not yet supported, must be skipped even if enabled.
			tenableIntegration(t, tenant, map[string]any{
				"engine":           "tenable_sc",
				"coverage_enabled": true,
				"license_cap":      float64(500),
			}),
		},
		Total: 1,
	}}
	repo := &fakeCoverageRepo{candidates: []scancoverage.Candidate{
		{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"},
	}}
	disp := &fakeDispatcher{}
	c := NewCoverageScheduler(lister, repo, disp, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 0 || len(disp.calls) != 0 {
		t.Fatalf("capped engine must be skipped until accounting ships, got %d", n)
	}
}

func TestCoverageScheduler_PinsAgentFromConfig(t *testing.T) {
	tenant := shared.NewID()
	agent := shared.NewID()
	lister := &fakeIntegrationLister{result: integration.ListResult{
		Data: []*integration.Integration{
			tenableIntegration(t, tenant, map[string]any{
				"engine":           "nessus_pro",
				"coverage_enabled": true,
				"agent_id":         agent.String(),
			}),
		},
		Total: 1,
	}}
	repo := &fakeCoverageRepo{candidates: []scancoverage.Candidate{
		{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"},
	}}
	disp := &fakeDispatcher{}
	c := NewCoverageScheduler(lister, repo, disp, nil)

	if _, err := c.Reconcile(context.Background()); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if len(disp.calls) != 1 || disp.calls[0].AgentID == nil || *disp.calls[0].AgentID != agent {
		t.Fatalf("pinned agent_id must be forwarded, got %+v", disp.calls)
	}
}

func TestCoverageScheduler_InvalidConfigSkipped(t *testing.T) {
	tenant := shared.NewID()
	lister := &fakeIntegrationLister{result: integration.ListResult{
		Data: []*integration.Integration{
			tenableIntegration(t, tenant, map[string]any{"engine": "bogus", "coverage_enabled": true}),
		},
		Total: 1,
	}}
	disp := &fakeDispatcher{}
	c := NewCoverageScheduler(lister, &fakeCoverageRepo{}, disp, nil)

	n, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	if n != 0 || len(disp.calls) != 0 {
		t.Fatalf("invalid config must be skipped, got %d", n)
	}
}

func TestCoverageScheduler_ListErrorPropagates(t *testing.T) {
	lister := &fakeIntegrationLister{err: errors.New("db down")}
	c := NewCoverageScheduler(lister, &fakeCoverageRepo{}, &fakeDispatcher{}, nil)
	if _, err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("integration list error must propagate")
	}
}

func TestCoverageScheduler_Meta(t *testing.T) {
	c := NewCoverageScheduler(&fakeIntegrationLister{}, &fakeCoverageRepo{}, &fakeDispatcher{}, nil)
	if c.Name() != "coverage-scheduler" {
		t.Fatalf("name: %q", c.Name())
	}
	if c.Interval() <= 0 {
		t.Fatal("interval should default to a positive duration")
	}
}
