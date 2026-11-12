package integration

import (
	"context"
	"errors"
	"testing"

	integrationdom "github.com/openctemio/openctem/api/pkg/domain/integration"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// tenantOnlyRepo answers only tenant-scoped lookups; an unscoped GetByID
// fails the test.
type tenantOnlyRepo struct {
	integrationdom.Repository
	t     *testing.T
	owner shared.ID
	id    shared.ID
}

func (r *tenantOnlyRepo) GetByTenantAndID(_ context.Context, tenantID, id shared.ID) (*integrationdom.Integration, error) {
	if !tenantID.Equals(r.owner) || !id.Equals(r.id) {
		return nil, integrationdom.ErrIntegrationNotFound
	}
	return nil, errors.New("owner lookup reached (not needed by this test)")
}

func (r *tenantOnlyRepo) GetByID(context.Context, shared.ID) (*integrationdom.Integration, error) {
	r.t.Fatal("scmClientForIntegration used an unscoped GetByID")
	return nil, nil
}

// The SCM client for branch sync is built from an integration loaded with the
// caller's tenant: another tenant's integration is not found, so its
// credentials are never decrypted (RFC-049 F-13).
func TestSCMClientForIntegration_TenantScoped(t *testing.T) {
	owner, other, id := shared.NewID(), shared.NewID(), shared.NewID()
	repo := &tenantOnlyRepo{t: t, owner: owner, id: id}
	svc := NewIntegrationService(repo, nil, nil, logger.NewNop())

	if _, err := svc.scmClientForIntegration(context.Background(), other, id); !errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("cross-tenant lookup: err = %v, want not found", err)
	}
	if _, err := svc.scmClientForIntegration(context.Background(), owner, id); err == nil || errors.Is(err, shared.ErrNotFound) {
		t.Fatalf("owner lookup: err = %v, want the owner's integration to be looked up", err)
	}
}
