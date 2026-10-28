package main

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/supportaccess"
	"github.com/openctemio/openctem/api/internal/infra/postgres"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
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

// newSupportAccessService wires the support access service (handlers and the
// session sweeper share one wiring); nil when a dependency is missing.
func newSupportAccessService(repos *Repositories, svc *Services, log *logger.Logger) *supportaccess.Service {
	if repos.SupportAccess == nil || repos.SupportRead == nil || svc.Audit == nil {
		return nil
	}
	var mailer supportaccess.Mailer
	if svc.Email != nil {
		mailer = svc.Email
	}
	return supportaccess.NewService(repos.SupportAccess, repos.SupportRead, repos.Admin, svc.Audit,
		repos.AdminAuditLog, repos.Tenant, tenantNames{repo: repos.Tenant}, mailer, log)
}
