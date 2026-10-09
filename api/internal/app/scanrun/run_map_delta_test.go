package scanrun

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanrun"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// oneTenantRun serves one run, to its own tenant only.
type oneTenantRun struct {
	scanrun.RunRepository
	run *scanrun.Run
}

func (r oneTenantRun) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*scanrun.Run, error) {
	if tenantID != r.run.TenantID || id != r.run.ID {
		return nil, shared.ErrNotFound
	}
	return r.run, nil
}

func (r oneTenantRun) GetWithStepRuns(context.Context, shared.ID) (*scanrun.Run, error) {
	return r.run, nil
}

func deltaFixture() (*Service, *memHops, *scanrun.Run) {
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), Status: scanrun.RunStatusCompleted}
	hops := newMemHops()
	return &Service{runRepo: oneTenantRun{run: run}, hops: hops, logger: logger.NewNop()}, hops, run
}

// The map carries the previous run of the scan and each step's comparison
// with it; without one, neither.
func TestGetRunMap_ComparesWithThePreviousRun(t *testing.T) {
	s, hops, run := deltaFixture()
	ctx := context.Background()

	m, err := s.GetRunMap(ctx, run.TenantID.String(), run.ID.String(), nil)
	if err != nil || !m.PreviousRunID.IsZero() || len(m.Deltas) != 0 {
		t.Fatalf("no previous run: %+v, %v", m, err)
	}

	hops.previous = shared.NewID()
	hops.deltas = []scanrun.StepOutputDelta{{StepKey: "subs", Previous: 4, Added: 1, Gone: 2}}
	m, err = s.GetRunMap(ctx, run.TenantID.String(), run.ID.String(), nil)
	if err != nil || m.PreviousRunID != hops.previous || len(m.Deltas) != 1 || m.Deltas[0].Gone != 2 {
		t.Fatalf("with a previous run: %+v, %v", m, err)
	}

	// Another tenant's caller never reaches the run.
	if _, err := s.GetRunMap(ctx, shared.NewID().String(), run.ID.String(), nil); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant map: %v, want not found", err)
	}
}

// The preview is capped, keeps the order the store gives (new first), and is
// not found for another tenant.
func TestPreviewStepOutputs(t *testing.T) {
	s, hops, run := deltaFixture()
	ctx := context.Background()
	hops.previous = shared.NewID()
	for i := 0; i < MaxStepOutputPreview+5; i++ {
		hops.preview = append(hops.preview, scanrun.StepOutput{AssetID: shared.NewID(), Name: "a", New: i == 0})
	}

	p, err := s.PreviewStepOutputs(ctx, run.TenantID.String(), run.ID.String(), "subs", nil, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.Outputs) != MaxStepOutputPreview || p.Total != MaxStepOutputPreview+5 || !p.Outputs[0].New {
		t.Fatalf("preview = %d of %d", len(p.Outputs), p.Total)
	}
	if p.PreviousRunID != hops.previous {
		t.Fatalf("previous = %s", p.PreviousRunID)
	}
	if p, _ := s.PreviewStepOutputs(ctx, run.TenantID.String(), run.ID.String(), "subs", nil, 3); len(p.Outputs) != 3 {
		t.Fatalf("limit 3 gave %d", len(p.Outputs))
	}
	if _, err := s.PreviewStepOutputs(ctx, shared.NewID().String(), run.ID.String(), "subs", nil, 3); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant preview: %v, want not found", err)
	}
}
