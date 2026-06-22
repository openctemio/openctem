package jira

import (
	"context"
	"testing"

	"github.com/openctemio/api/pkg/domain/shared"
)

// ParseMappingConfig reads config.ticketing.project_key into DefaultProjectKey.
func TestParseMappingConfig_DefaultProjectKey(t *testing.T) {
	m := ParseMappingConfig(map[string]any{
		"ticketing": map[string]any{
			"project_key": " SEC ", // surrounding space must be trimmed
		},
	})
	if m.DefaultProjectKey != "SEC" {
		t.Fatalf("DefaultProjectKey = %q, want SEC", m.DefaultProjectKey)
	}
}

// With no project_key in config, DefaultProjectKey stays empty (defaults don't
// invent one).
func TestParseMappingConfig_NoProjectKey(t *testing.T) {
	m := ParseMappingConfig(map[string]any{"ticketing": map[string]any{}})
	if m.DefaultProjectKey != "" {
		t.Fatalf("DefaultProjectKey = %q, want empty", m.DefaultProjectKey)
	}
}

// When the request omits project_key, CreateTicketFromFinding falls back to the
// tenant's configured default project (and default issue type).
func TestCreateTicketFromFinding_FallsBackToDefaultProject(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{finding: buildFinding(t)}
	s := newSync(repo, client)
	mapping := DefaultMappingConfig()
	mapping.DefaultProjectKey = "PAY"
	mapping.DefaultIssueType = "Task"
	s.SetMappingResolver(stubMappingResolver{mapping: mapping})

	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
		// ProjectKey deliberately omitted
	}); err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.lastInput.ProjectKey != "PAY" {
		t.Fatalf("ProjectKey = %q, want PAY (the configured default)", client.lastInput.ProjectKey)
	}
	if client.lastInput.IssueType != "Task" {
		t.Fatalf("IssueType = %q, want Task (the configured default)", client.lastInput.IssueType)
	}
}

// An explicit project_key in the request overrides the configured default.
func TestCreateTicketFromFinding_ExplicitProjectOverridesDefault(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{finding: buildFinding(t)}
	s := newSync(repo, client)
	mapping := DefaultMappingConfig()
	mapping.DefaultProjectKey = "PAY"
	s.SetMappingResolver(stubMappingResolver{mapping: mapping})

	if _, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:   shared.NewID().String(),
		FindingID:  shared.NewID().String(),
		ProjectKey: "SEC",
	}); err != nil {
		t.Fatalf("CreateTicketFromFinding: %v", err)
	}
	if client.lastInput.ProjectKey != "SEC" {
		t.Fatalf("ProjectKey = %q, want SEC (explicit request wins)", client.lastInput.ProjectKey)
	}
}

// With neither an explicit project_key nor a configured default, creation is a
// validation error (we don't guess where the ticket goes).
func TestCreateTicketFromFinding_NoProjectAnywhereIsValidationError(t *testing.T) {
	client := &stubCreateClient{}
	repo := &stubFindingRepo{finding: buildFinding(t)}
	s := newSync(repo, client)
	// no mapping resolver → default mapping has empty DefaultProjectKey

	_, err := s.CreateTicketFromFinding(context.Background(), CreateTicketInput{
		TenantID:  shared.NewID().String(),
		FindingID: shared.NewID().String(),
	})
	if err == nil {
		t.Fatal("expected validation error when no project is available")
	}
	if client.calls != 0 {
		t.Fatalf("must not call CreateIssue without a project; got %d calls", client.calls)
	}
}

// listProjectsStub returns a fixed project list for the ListProjects wiring test.
type listProjectsStub struct {
	stubCreateClient
	projects []ProjectRef
}

func (c *listProjectsStub) ListProjects(_ context.Context) ([]ProjectRef, error) {
	return c.projects, nil
}

// SyncService.ListProjects resolves the client and returns its projects.
func TestListProjects_ReturnsClientProjects(t *testing.T) {
	client := &listProjectsStub{projects: []ProjectRef{
		{ID: "1", Key: "SEC", Name: "Security"},
		{ID: "2", Key: "PAY", Name: "Payments"},
	}}
	s := newSync(&stubFindingRepo{}, client)

	got, err := s.ListProjects(context.Background(), shared.NewID())
	if err != nil {
		t.Fatalf("ListProjects: %v", err)
	}
	if len(got) != 2 || got[0].Key != "SEC" || got[1].Key != "PAY" {
		t.Fatalf("unexpected projects: %+v", got)
	}
}

// With no client wired and no resolver, ListProjects surfaces
// ErrNoTicketingIntegration rather than panicking.
func TestListProjects_NoIntegration(t *testing.T) {
	s := newSync(&stubFindingRepo{}, nil)
	if _, err := s.ListProjects(context.Background(), shared.NewID()); err == nil {
		t.Fatal("expected ErrNoTicketingIntegration")
	}
}
