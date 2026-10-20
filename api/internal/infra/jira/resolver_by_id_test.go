package jira

import (
	"context"
	"errors"
	"testing"

	appjira "github.com/openctemio/openctem/api/internal/app/jira"
	"github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// byIDRepo answers GetByTenantAndID like the postgres repository: an
// integration of another tenant is not found.
type byIDRepo struct {
	integration.Repository
	rows []*integration.Integration
}

func (r *byIDRepo) GetByTenantAndID(_ context.Context, tenantID, id integration.ID) (*integration.Integration, error) {
	for _, i := range r.rows {
		if i.ID() == id && i.TenantID() == tenantID {
			return i, nil
		}
	}
	return nil, integration.ErrIntegrationNotFound
}

// ResolveByID serves exactly the named integration of the tenant: another
// tenant's integration, a missing one, another provider or a disconnected
// one is ErrNoTicketingIntegration, never a fallback to another integration.
func TestResolveByID_NamedIntegrationOnly(t *testing.T) {
	creds := `{"email":"sec@acme.com","api_token":"abc123"}`
	a := newJiraIntegration(t, integration.StatusConnected, "https://a.atlassian.net/", creds, nil)
	b := newJiraIntegration(t, integration.StatusConnected, "https://b.atlassian.net", creds, nil)
	off := newJiraIntegration(t, integration.StatusDisconnected, "https://c.atlassian.net", creds, nil)
	r := newResolver(&byIDRepo{rows: []*integration.Integration{a, b, off}})
	ctx := context.Background()

	c, err := r.ResolveByID(ctx, b.TenantID(), b.ID())
	if err != nil {
		t.Fatal(err)
	}
	if ii, ok := c.(appjira.IssueIdentifier); !ok || ii.IntegrationID() != b.ID() || ii.SiteURL() != "https://b.atlassian.net" {
		t.Fatalf("resolved %+v, want integration b", c)
	}
	for name, tc := range map[string]struct{ tenant, id shared.ID }{
		"another tenant's integration": {a.TenantID(), b.ID()},
		"missing integration":          {b.TenantID(), shared.NewID()},
		"disconnected integration":     {off.TenantID(), off.ID()},
	} {
		if _, err := r.ResolveByID(ctx, tc.tenant, tc.id); !errors.Is(err, appjira.ErrNoTicketingIntegration) {
			t.Errorf("%s: err = %v, want ErrNoTicketingIntegration", name, err)
		}
	}
}

// ResolveMappingByID loads the mapping of the named integration in any
// status, with its site; another tenant's integration is refused.
func TestResolveMappingByID(t *testing.T) {
	off := newJiraIntegration(t, integration.StatusDisconnected, "https://a.atlassian.net/", "",
		map[string]any{"ticketing": map[string]any{"project_key": "SEC"}})
	r := newResolver(&byIDRepo{rows: []*integration.Integration{off}})
	m, err := r.ResolveMappingByID(context.Background(), off.TenantID(), off.ID())
	if err != nil {
		t.Fatal(err)
	}
	if m.SiteURL != "https://a.atlassian.net" || m.DefaultProjectKey != "SEC" {
		t.Fatalf("mapping %+v", m)
	}
	if _, err := r.ResolveMappingByID(context.Background(), shared.NewID(), off.ID()); !errors.Is(err, appjira.ErrNoTicketingIntegration) {
		t.Fatalf("cross-tenant mapping: %v", err)
	}
}
