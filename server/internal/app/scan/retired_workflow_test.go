package scan

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openctemio/openctem/api/pkg/domain/scanworkflow"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// retiredStub serves one workflow as a system template.
type retiredStub struct {
	scanworkflow.Repository
	wf *scanworkflow.Workflow
}

func (r retiredStub) GetByTenantAndID(context.Context, shared.ID, shared.ID) (*scanworkflow.Workflow, error) {
	return nil, shared.ErrNotFound
}

func (r retiredStub) GetSystemTemplateByID(context.Context, shared.ID) (*scanworkflow.Workflow, error) {
	return r.wf, nil
}

// A retired system workflow cannot start a new scan, and the refusal names
// its replacement; an active one is usable.
func TestUsableWorkflow_RefusesRetiredSystemWorkflow(t *testing.T) {
	sup := shared.NewID()
	retired := &scanworkflow.Workflow{ID: shared.NewID(), Name: "Discover", IsSystemTemplate: true, IsActive: false,
		SupersededBy: &sup, SupersededByName: "Subdomains"}
	s := &Service{templateRepo: retiredStub{wf: retired}}

	_, err := s.usableWorkflow(context.Background(), shared.NewID(), retired.ID)
	if !errors.Is(err, shared.ErrValidation) || !strings.Contains(err.Error(), `replaced by "Subdomains"`) {
		t.Fatalf("retired workflow: %v, want a validation error naming the replacement", err)
	}

	active := &scanworkflow.Workflow{ID: shared.NewID(), Name: "Subdomains", IsSystemTemplate: true, IsActive: true}
	s = &Service{templateRepo: retiredStub{wf: active}}
	if _, err := s.usableWorkflow(context.Background(), shared.NewID(), active.ID); err != nil {
		t.Fatalf("active workflow: %v", err)
	}
}
