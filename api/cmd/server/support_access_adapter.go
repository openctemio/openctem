package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/supportaccess"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// tenantNames resolves an organization's display name for support access
// notices and audit rows.
type tenantNames struct{ repo *postgres.TenantRepository }

var _ supportaccess.TenantNames = tenantNames{}

func (t tenantNames) TenantName(ctx context.Context, id shared.ID) (string, error) {
	tn, err := t.repo.GetByID(ctx, id)
	if err != nil {
		return "", err
	}
	return tn.Name(), nil
}
