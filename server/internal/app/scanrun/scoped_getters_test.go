package scanrun

// A run and a workflow are read inside one organization: the tenant is part of
// the getters' signatures, so a caller cannot read either by its id alone.

import (
	"context"
	"errors"
	"testing"

	"github.com/openctemio/openctem/server/pkg/domain/scanrun"
	"github.com/openctemio/openctem/server/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
	"github.com/openctemio/openctem/server/pkg/logger"
)

// workflowsByID serves workflows by id alone, as the repository's
// GetWithSteps does (system workflows have no tenant).
type workflowsByID struct {
	scanworkflow.Repository
	byID map[shared.ID]*scanworkflow.Workflow
}

func (r workflowsByID) GetWithSteps(_ context.Context, id shared.ID) (*scanworkflow.Workflow, error) {
	if w, ok := r.byID[id]; ok {
		return w, nil
	}
	return nil, shared.ErrNotFound
}

func TestGetTemplateWithSteps_OtherTenantsWorkflowIsNotFound(t *testing.T) {
	a, b := shared.NewID(), shared.NewID()
	private := &scanworkflow.Workflow{ID: shared.NewID(), TenantID: a}
	system := &scanworkflow.Workflow{ID: shared.NewID(), IsSystemTemplate: true}
	s := &Service{logger: logger.NewNop(), templateRepo: workflowsByID{byID: map[shared.ID]*scanworkflow.Workflow{
		private.ID: private, system.ID: system,
	}}}
	ctx := context.Background()

	if w, err := s.GetTemplateWithSteps(ctx, a.String(), private.ID.String()); err != nil || w != private {
		t.Fatalf("the owner reads its workflow: %v, %v", w, err)
	}
	if _, err := s.GetTemplateWithSteps(ctx, b.String(), private.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant read a private workflow by id: err = %v, want not found", err)
	}
	if w, err := s.GetTemplateWithSteps(ctx, b.String(), system.ID.String()); err != nil || w != system {
		t.Fatalf("a system workflow is shared: %v, %v", w, err)
	}
	if _, err := s.GetTemplateWithSteps(ctx, b.String(), shared.NewID().String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("an unknown id: err = %v, want the same not found", err)
	}
	if _, err := s.GetTemplateWithSteps(ctx, "", private.ID.String()); !errors.Is(err, shared.ErrValidation) {
		t.Fatalf("no tenant: err = %v, want validation", err)
	}
}

func TestGetRunWithSteps_OtherTenantsRunIsNotFound(t *testing.T) {
	run := &scanrun.Run{ID: shared.NewID(), TenantID: shared.NewID(), Status: scanrun.RunStatusCompleted}
	s := &Service{logger: logger.NewNop(), runRepo: oneTenantRun{run: run}}
	ctx := context.Background()

	if got, err := s.GetRunWithSteps(ctx, run.TenantID.String(), run.ID.String()); err != nil || got != run {
		t.Fatalf("the owner reads its run: %v, %v", got, err)
	}
	if _, err := s.GetRunWithSteps(ctx, shared.NewID().String(), run.ID.String()); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("another tenant read a run by id: err = %v, want not found", err)
	}
}
