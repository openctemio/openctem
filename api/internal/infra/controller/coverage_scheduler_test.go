package controller

import (
	"context"
	"errors"
	"testing"
	"time"

	scanapp "github.com/openctemio/openctem/api/internal/app/scan"
	"github.com/openctemio/openctem/api/internal/app/scancoverage"
	"github.com/openctemio/openctem/api/internal/app/tenablesc"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
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
func (f *fakeCoverageRepo) ClaimBatch(_ context.Context, _ shared.ID, batch []scancoverage.Candidate, _ time.Time) ([]string, error) {
	out := make([]string, 0, len(batch))
	for _, c := range batch {
		out = append(out, c.AssetID)
	}
	return out, nil
}

func (f *fakeCoverageRepo) ReleaseBatch(context.Context, shared.ID, []scancoverage.Candidate, time.Time) error {
	return nil
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

// fakeConnector answers CoverageStatus per integration id.
type fakeConnector struct {
	status map[shared.ID]tenablesc.CoverageStatus
	err    error
}

func (f *fakeConnector) CoverageStatus(_ context.Context, intg *integration.Integration) (tenablesc.CoverageStatus, error) {
	if f.err != nil {
		return tenablesc.CoverageStatus{}, f.err
	}
	return f.status[intg.ID()], nil
}

func connectorIntegration(t *testing.T, tenant shared.ID) *integration.Integration {
	t.Helper()
	return tenableIntegration(t, tenant, map[string]any{
		"engine": "tenable_sc", "execution_mode": "sensor", "sensor_id": shared.NewID().String(),
		"coverage_enabled": true, "coverage_policy_id": float64(1), "coverage_repository_id": float64(5),
	})
}

func ready(licensed, active, batch int) tenablesc.CoverageStatus {
	return tenablesc.CoverageStatus{
		Ready:        true,
		Policy:       scancoverage.LicensePolicy{Mode: scancoverage.LicenseActiveIPCap, Cap: licensed},
		ActiveIPs:    active,
		DefaultBatch: batch,
	}
}

func threeCandidates() *fakeCoverageRepo {
	return &fakeCoverageRepo{candidates: []scancoverage.Candidate{
		{AssetID: "a1", Target: "10.0.0.1", Criticality: "high"},
		{AssetID: "a2", Target: "10.0.0.2", Criticality: "critical"},
		{AssetID: "a3", Target: "10.0.0.3", Criticality: "low"},
	}}
}

// A connector batch is sized by Tenable.sc's license: 10 licensed, 8 active
// leaves room for 2 addresses. It names the integration and pins no sensor
// itself (the connector command is pinned by the connector).
func TestCoverageScheduler_ConnectorBatchWithinLicense(t *testing.T) {
	tenant := shared.NewID()
	intg := connectorIntegration(t, tenant)
	lister := &fakeIntegrationLister{result: integration.ListResult{Data: []*integration.Integration{intg}, Total: 1}}
	repo := threeCandidates()
	repo.active = 999 // the repository's count is not used any more
	disp := &fakeDispatcher{}
	conn := &fakeConnector{status: map[shared.ID]tenablesc.CoverageStatus{intg.ID(): ready(10, 8, 256)}}
	c := NewCoverageScheduler(lister, repo, disp, &CoverageSchedulerConfig{Gate: allowAllGate{}, Connector: conn})

	n, err := c.Reconcile(context.Background())
	if err != nil || n != 1 {
		t.Fatalf("reconcile: n=%d err=%v", n, err)
	}
	call := disp.calls[0]
	if len(call.Targets) != 2 || call.TenantID != tenant || call.IntegrationID == nil || *call.IntegrationID != intg.ID() || call.SensorID != nil {
		t.Fatalf("dispatch %+v", call)
	}
	if call.Targets[0] != "10.0.0.2" {
		t.Fatalf("most critical first, got %v", call.Targets)
	}
	if len(repo.marked) != 1 || len(repo.marked[0].AssetIDs) != 2 {
		t.Fatalf("cursor not advanced: %+v", repo.marked)
	}
}

func TestCoverageScheduler_NothingWhenNotReadyOrFull(t *testing.T) {
	for name, st := range map[string]tenablesc.CoverageStatus{
		"previous batch open": {Reason: "the previous coverage batch is still running"},
		"license full":        ready(10, 10, 256),
	} {
		t.Run(name, func(t *testing.T) {
			intg := connectorIntegration(t, shared.NewID())
			lister := &fakeIntegrationLister{result: integration.ListResult{Data: []*integration.Integration{intg}, Total: 1}}
			disp := &fakeDispatcher{}
			conn := &fakeConnector{status: map[shared.ID]tenablesc.CoverageStatus{intg.ID(): st}}
			c := NewCoverageScheduler(lister, threeCandidates(), disp, &CoverageSchedulerConfig{Gate: allowAllGate{}, Connector: conn})
			if n, err := c.Reconcile(context.Background()); err != nil || n != 0 || len(disp.calls) != 0 {
				t.Fatalf("n=%d err=%v calls=%d", n, err, len(disp.calls))
			}
		})
	}
}

// Nessus Pro integrations have no runner since sensor v0.8.0: never driven.
func TestCoverageScheduler_IgnoresNonConnectors(t *testing.T) {
	nessus := tenableIntegration(t, shared.NewID(), map[string]any{"engine": "nessus_pro", "coverage_enabled": true})
	lister := &fakeIntegrationLister{result: integration.ListResult{Data: []*integration.Integration{nessus}, Total: 1}}
	disp := &fakeDispatcher{}
	conn := &fakeConnector{status: map[shared.ID]tenablesc.CoverageStatus{nessus.ID(): ready(10, 0, 256)}}
	c := NewCoverageScheduler(lister, threeCandidates(), disp, &CoverageSchedulerConfig{Gate: allowAllGate{}, Connector: conn})
	if n, _ := c.Reconcile(context.Background()); n != 0 || len(disp.calls) != 0 {
		t.Fatal("a Nessus Pro integration was driven")
	}
}

func TestCoverageScheduler_OneConnectorPerTenant(t *testing.T) {
	tenant := shared.NewID()
	first, second := connectorIntegration(t, tenant), connectorIntegration(t, tenant)
	lister := &fakeIntegrationLister{result: integration.ListResult{Data: []*integration.Integration{first, second}, Total: 2}}
	disp := &fakeDispatcher{}
	conn := &fakeConnector{status: map[shared.ID]tenablesc.CoverageStatus{first.ID(): ready(10, 0, 256), second.ID(): ready(10, 0, 256)}}
	c := NewCoverageScheduler(lister, threeCandidates(), disp, &CoverageSchedulerConfig{Gate: allowAllGate{}, Connector: conn})
	if n, _ := c.Reconcile(context.Background()); n != 1 || *disp.calls[0].IntegrationID != first.ID() {
		t.Fatalf("n=%d calls=%+v", n, disp.calls)
	}
}

func TestCoverageScheduler_WithoutConnectorNothingRuns(t *testing.T) {
	intg := connectorIntegration(t, shared.NewID())
	lister := &fakeIntegrationLister{result: integration.ListResult{Data: []*integration.Integration{intg}, Total: 1}}
	disp := &fakeDispatcher{}
	c := NewCoverageScheduler(lister, threeCandidates(), disp, &CoverageSchedulerConfig{Gate: allowAllGate{}})
	if n, _ := c.Reconcile(context.Background()); n != 0 {
		t.Fatal("dispatched without a connector")
	}
}

func TestCoverageScheduler_ListErrorPropagates(t *testing.T) {
	lister := &fakeIntegrationLister{err: errors.New("db down")}
	c := NewCoverageScheduler(lister, &fakeCoverageRepo{}, &fakeDispatcher{},
		&CoverageSchedulerConfig{Gate: allowAllGate{}, Connector: &fakeConnector{}})
	if _, err := c.Reconcile(context.Background()); err == nil {
		t.Fatal("integration list error must propagate")
	}
}

func TestCoverageScheduler_Meta(t *testing.T) {
	c := NewCoverageScheduler(&fakeIntegrationLister{}, &fakeCoverageRepo{}, &fakeDispatcher{}, &CoverageSchedulerConfig{Gate: allowAllGate{}})
	if c.Name() != "coverage-scheduler" {
		t.Fatalf("name: %q", c.Name())
	}
	if c.Interval() <= 0 {
		t.Fatal("interval should default to a positive duration")
	}
}

// allowAllGate lets every target through, unzoned.
type allowAllGate struct{}

func (allowAllGate) ResolveDispatchTargets(_ context.Context, in scanapp.DispatchTargetsInput) (*scanapp.DispatchTargets, error) {
	return &scanapp.DispatchTargets{Allowed: in.Targets}, nil
}
