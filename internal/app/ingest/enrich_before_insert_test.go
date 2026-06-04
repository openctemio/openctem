package ingest

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/api/pkg/domain/asset"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

type stubEnrichClassifier struct {
	called   bool
	gotCount int
}

func (s *stubEnrichClassifier) EnrichAndClassifyBatch(_ context.Context, _ shared.ID, findings []*vulnerability.Finding, _ map[shared.ID]*asset.Asset) error {
	s.called = true
	s.gotCount = len(findings)
	return nil
}

type stubSLAApplierForEnrich struct{ called bool }

func (s *stubSLAApplierForEnrich) ApplyBatch(_ context.Context, _ shared.ID, _ []*vulnerability.Finding) error {
	s.called = true
	return nil
}

// Only GetByID is exercised by enrichAndClassify; embed the interface so the
// rest of asset.Repository is satisfied without hand-writing every method.
type stubAssetRepoGetByID struct{ asset.Repository }

func (stubAssetRepoGetByID) GetByID(_ context.Context, _, _ shared.ID) (*asset.Asset, error) {
	return nil, errors.New("not found")
}

func makeEnrichFindings(t *testing.T, n int) []*vulnerability.Finding {
	t.Helper()
	out := make([]*vulnerability.Finding, 0, n)
	for i := 0; i < n; i++ {
		f, err := vulnerability.NewFinding(
			shared.NewID(), shared.NewID(),
			vulnerability.FindingSourceSecret, "gitleaks",
			vulnerability.SeverityHigh, "test finding",
		)
		if err != nil {
			t.Fatalf("NewFinding: %v", err)
		}
		out = append(out, f)
	}
	return out
}

// With a classifier (and SLA applier) wired, enrichAndClassify must run both —
// this is what lets the subsequent batch INSERT carry the enriched fields
// instead of a per-finding UPDATE pass.
func TestEnrichAndClassify_RunsClassifierAndSLA(t *testing.T) {
	repo := &stubFindingRepository{}
	classifier := &stubEnrichClassifier{}
	sla := &stubSLAApplierForEnrich{}
	p := NewFindingProcessor(repo, nil, stubAssetRepoGetByID{}, logger.NewNop())
	p.SetPriorityClassifier(classifier)
	p.SetSLAApplier(sla)

	findings := makeEnrichFindings(t, 3)
	p.enrichAndClassify(context.Background(), shared.NewID(), findings)

	if !classifier.called {
		t.Fatal("expected priority classifier to be invoked")
	}
	if classifier.gotCount != 3 {
		t.Fatalf("classifier got %d findings, want 3", classifier.gotCount)
	}
	if !sla.called {
		t.Fatal("expected SLA applier to be invoked")
	}
}

// With no classifier wired, enrichAndClassify is a no-op and must not touch the
// (nil) asset repo — guards the pre-insert call added to the hot path.
func TestEnrichAndClassify_NoClassifier_NoOp(t *testing.T) {
	repo := &stubFindingRepository{}
	p := NewFindingProcessor(repo, nil, nil, logger.NewNop()) // nil asset repo on purpose
	// Must not panic despite the nil asset repo.
	p.enrichAndClassify(context.Background(), shared.NewID(), makeEnrichFindings(t, 2))
}
