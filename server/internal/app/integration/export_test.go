package integration

import (
	"context"

	"github.com/openctemio/openctem/server/internal/infra/scm"
	"github.com/openctemio/openctem/server/pkg/domain/shared"
)

// UpsertRepositoryAssetForTest exposes upsertRepositoryAsset to the
// DB-backed tests of this directory.
func (s *IntegrationService) UpsertRepositoryAssetForTest(ctx context.Context, tenantID shared.ID, r scm.Repository) (bool, error) {
	return s.upsertRepositoryAsset(ctx, tenantID, r)
}
