package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// branchOnlyStubRepo marks some findings branch-only and promotes some
// fingerprints, recording the tenant every call was made for.
type branchOnlyStubRepo struct {
	stubFindingRepository
	marked      map[shared.ID]bool
	lookupErr   error
	promote     []shared.ID
	promotedFPs []string
	loaded      []*vulnerability.Finding
	tenants     []shared.ID
}

func (s *branchOnlyStubRepo) BranchOnlyIDs(_ context.Context, tenantID shared.ID, ids []shared.ID) (map[shared.ID]bool, error) {
	s.tenants = append(s.tenants, tenantID)
	if s.lookupErr != nil {
		return nil, s.lookupErr
	}
	out := map[shared.ID]bool{}
	for _, id := range ids {
		if s.marked[id] {
			out[id] = true
		}
	}
	return out, nil
}

func (s *branchOnlyStubRepo) PromoteBranchOnlyByFingerprints(_ context.Context, tenantID shared.ID, fps []string) ([]shared.ID, error) {
	s.tenants = append(s.tenants, tenantID)
	s.promotedFPs = fps
	return s.promote, nil
}

func (s *branchOnlyStubRepo) GetByIDs(_ context.Context, tenantID shared.ID, _ []shared.ID) ([]*vulnerability.Finding, error) {
	s.tenants = append(s.tenants, tenantID)
	return s.loaded, nil
}

func newTestFinding(t *testing.T, tenant shared.ID) *vulnerability.Finding {
	t.Helper()
	f, err := vulnerability.NewFinding(tenant, shared.NewID(), vulnerability.FindingSourceSAST, "semgrep", vulnerability.SeverityHigh, "m")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWithoutBranchOnly_DropsMarkedFindings(t *testing.T) {
	tenant := shared.NewID()
	a, b := newTestFinding(t, tenant), newTestFinding(t, tenant)
	repo := &branchOnlyStubRepo{marked: map[shared.ID]bool{b.ID(): true}}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())

	got := p.withoutBranchOnly(context.Background(), tenant, []*vulnerability.Finding{a, b})
	if len(got) != 1 || got[0].ID() != a.ID() {
		t.Fatalf("got %d findings, want only the counting one", len(got))
	}
	reopened := p.reopenedWithoutBranchOnly(context.Background(), tenant,
		[]vulnerability.ReopenedFinding{{ID: a.ID()}, {ID: b.ID()}})
	if len(reopened) != 1 || reopened[0].ID != a.ID() {
		t.Fatalf("reopened = %+v, want only the counting one", reopened)
	}
	for _, tid := range repo.tenants {
		if tid != tenant {
			t.Fatalf("lookup ran for tenant %s, want %s", tid, tenant)
		}
	}
}

func TestWithoutBranchOnly_LookupFailureKeepsAll(t *testing.T) {
	tenant := shared.NewID()
	a := newTestFinding(t, tenant)
	repo := &branchOnlyStubRepo{marked: map[shared.ID]bool{a.ID(): true}, lookupErr: errors.New("db down")}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())
	if got := p.withoutBranchOnly(context.Background(), tenant, []*vulnerability.Finding{a}); len(got) != 1 {
		t.Fatal("a failed lookup must not drop a finding's workflows")
	}
}

func TestPromoteBranchOnly_RunsWorkflowsForPromoted(t *testing.T) {
	tenant := shared.NewID()
	promoted := newTestFinding(t, tenant)
	repo := &branchOnlyStubRepo{promote: []shared.ID{promoted.ID()}, loaded: []*vulnerability.Finding{promoted}}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop())
	var called []*vulnerability.Finding
	p.SetFindingCreatedCallback(func(_ context.Context, tid shared.ID, fs []*vulnerability.Finding) {
		if tid != tenant {
			t.Fatalf("callback tenant %s", tid)
		}
		called = fs
	})

	br := shared.NewID()
	p.promoteBranchOnly(context.Background(), tenant, []vulnerability.BranchOccurrenceUpsert{
		{Fingerprint: "fp1", BranchID: br}, {Fingerprint: "fp1", BranchID: br}, {Fingerprint: "fp2", BranchID: br},
	})
	if len(repo.promotedFPs) != 2 {
		t.Fatalf("promote asked for %v, want each fingerprint once", repo.promotedFPs)
	}
	if len(called) != 1 || called[0].ID() != promoted.ID() {
		t.Fatalf("workflows ran for %d findings, want the promoted one", len(called))
	}

	// Nothing promoted: no workflow.
	repo.promote, called = nil, nil
	p.promoteBranchOnly(context.Background(), tenant, []vulnerability.BranchOccurrenceUpsert{{Fingerprint: "fp3", BranchID: br}})
	if called != nil {
		t.Fatal("workflows ran with nothing promoted")
	}
}
