package controller

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/internal/app/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// --- mocks ----------------------------------------------------------

// chainVerifierMock implements the controller's chainVerifier
// interface without pulling in a real AuditService / DB. One call per
// tenant; results[tenantID] drives the returned ChainVerifyResult,
// errs[tenantID] forces an error.
type chainVerifierMock struct {
	results map[string]*audit.ChainVerifyResult
	errs    map[string]error
	calls   []string // ordered list of tenant IDs we were asked about
}

func (m *chainVerifierMock) VerifyChain(_ context.Context, tenantID shared.ID, _ int) (*audit.ChainVerifyResult, error) {
	id := tenantID.String()
	m.calls = append(m.calls, id)
	if err, ok := m.errs[id]; ok && err != nil {
		return nil, err
	}
	if r, ok := m.results[id]; ok {
		return r, nil
	}
	// Default: clean chain.
	return &audit.ChainVerifyResult{TenantID: id, OK: true}, nil
}

// tenantListerMock only implements the slice of tenant.Repository the
// controller actually calls (ListActiveTenantIDs). The rest panics
// if touched — that's the point: a test that drifts into other repo
// methods gets a loud failure, not a subtle misread.
type tenantListerMock struct {
	tenant.Repository // embeds interface so we only need to implement the one method
	ids               []shared.ID
	err               error
}

func (m *tenantListerMock) ListActiveTenantIDs(_ context.Context) ([]shared.ID, error) {
	if m.err != nil {
		return nil, m.err
	}
	return m.ids, nil
}

// --- helpers --------------------------------------------------------

func mkTenantIDs(n int) []shared.ID {
	out := make([]shared.ID, n)
	for i := range out {
		out[i] = shared.NewID()
	}
	return out
}

func newTestController(t *testing.T, verifier chainVerifier, tenants tenant.Repository) *AuditChainVerifyController {
	t.Helper()
	c := &AuditChainVerifyController{
		audit:   verifier,
		tenants: tenants,
		config: &AuditChainVerifyControllerConfig{
			PerTenantLimit: 1000,
		},
		logger: logger.NewNop(),
	}
	return c
}

// --- identity -------------------------------------------------------

func TestAuditChainVerify_NameAndInterval(t *testing.T) {
	c := NewAuditChainVerifyController(nil, nil, nil)
	if c.Name() != "audit-chain-verify" {
		t.Errorf("name: got %q", c.Name())
	}
	// Defaults applied when cfg is nil.
	if c.Interval() <= 0 {
		t.Errorf("interval should have a positive default; got %s", c.Interval())
	}
}

// --- happy path -----------------------------------------------------

func TestAuditChainVerify_CleanChain_NoErrors(t *testing.T) {
	ids := mkTenantIDs(3)
	tenants := &tenantListerMock{ids: ids}
	verifier := &chainVerifierMock{}

	c := newTestController(t, verifier, tenants)
	processed, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if processed != 3 {
		t.Errorf("processed: want 3, got %d", processed)
	}
	if len(verifier.calls) != 3 {
		t.Errorf("verifier called %d times, want 3", len(verifier.calls))
	}
}

// --- break detection ------------------------------------------------

func TestAuditChainVerify_BreaksStillCountAsProcessed(t *testing.T) {
	ids := mkTenantIDs(2)
	tenants := &tenantListerMock{ids: ids}
	verifier := &chainVerifierMock{
		results: map[string]*audit.ChainVerifyResult{
			ids[0].String(): {TenantID: ids[0].String(), OK: true},
			ids[1].String(): {
				TenantID: ids[1].String(),
				OK:       false,
				Breaks: []audit.ChainBreak{
					{AuditLogID: "log-1", ChainPosition: 42, Reason: "hash_mismatch"},
				},
			},
		},
	}

	c := newTestController(t, verifier, tenants)
	processed, err := c.Reconcile(context.Background())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	// Breaks don't abort the loop: a tenant with a broken chain still
	// counts as "processed" because we successfully called
	// VerifyChain. The break is emitted via the logger (tested via
	// absence of error below — visual SIEM alerting is out of scope
	// for unit tests).
	if processed != 2 {
		t.Errorf("processed: want 2 (both tenants visited), got %d", processed)
	}
}

// --- error handling -------------------------------------------------

func TestAuditChainVerify_PerTenantErrorSkipsButContinues(t *testing.T) {
	ids := mkTenantIDs(3)
	tenants := &tenantListerMock{ids: ids}
	verifier := &chainVerifierMock{
		errs: map[string]error{
			ids[1].String(): errors.New("verify failed"),
		},
	}

	c := newTestController(t, verifier, tenants)
	processed, err := c.Reconcile(context.Background())
	// A per-tenant error is logged + skipped, not propagated.
	if err != nil {
		t.Fatalf("per-tenant error should not fail the run, got %v", err)
	}
	// processed counts only successful verifications; tenant[1] failed.
	if processed != 2 {
		t.Errorf("processed: want 2 (one failure skipped), got %d", processed)
	}
	// All three were attempted though.
	if len(verifier.calls) != 3 {
		t.Errorf("verifier should have been called for all 3 tenants even after one errored; got %d", len(verifier.calls))
	}
}

func TestAuditChainVerify_TenantListError_Propagates(t *testing.T) {
	tenants := &tenantListerMock{err: errors.New("list failed")}
	verifier := &chainVerifierMock{}

	c := newTestController(t, verifier, tenants)
	processed, err := c.Reconcile(context.Background())
	if err == nil {
		t.Fatal("list error must propagate — we cannot audit what we cannot enumerate")
	}
	if processed != 0 {
		t.Errorf("processed should be 0 on list error, got %d", processed)
	}
	if len(verifier.calls) != 0 {
		t.Errorf("verifier must NOT be called when we can't list tenants")
	}
}

// --- cancellation ---------------------------------------------------

func TestAuditChainVerify_ContextCancelled_StopsMidLoop(t *testing.T) {
	ids := mkTenantIDs(5)
	tenants := &tenantListerMock{ids: ids}
	verifier := &chainVerifierMock{}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Reconcile runs

	c := newTestController(t, verifier, tenants)
	processed, err := c.Reconcile(ctx)
	// Controller returns ctx.Err() rather than running with cancelled
	// context — matches the pattern established by other controllers.
	if err == nil {
		t.Fatal("cancelled context should surface ctx.Err()")
	}
	if processed != 0 {
		t.Errorf("processed: want 0, got %d (controller should bail on first ctx check)", processed)
	}
}

// --- nil-safety -----------------------------------------------------

func TestNewAuditChainVerifyController_DefaultsApplied(t *testing.T) {
	c := NewAuditChainVerifyController(nil, nil, nil)
	if c.config.Interval <= 0 {
		t.Errorf("interval default missing; got %v", c.config.Interval)
	}
	if c.config.PerTenantLimit <= 0 {
		t.Errorf("per-tenant limit default missing; got %d", c.config.PerTenantLimit)
	}
	if c.logger == nil {
		t.Error("logger default missing")
	}
}
