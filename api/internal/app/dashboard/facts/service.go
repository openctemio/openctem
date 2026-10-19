// Package facts is the "Rebuild dashboard data" action over the dashboard
// fact layer (api/docs/architecture/dashboards.md, "Facts maintainer"). The
// request is recorded here; the dashboard-facts-reconcile controller runs the
// rebuild. The tenant always comes from the authenticated caller (the
// organization's session, or the console's path organization after the
// console checked it exists).
package facts

import (
	"context"
	"fmt"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/dashboardfact"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Store is the storage the service needs (*postgres.DashboardFactsRepository).
type Store interface {
	RequestRebuild(ctx context.Context, tenantID shared.ID, interval time.Duration) (time.Time, error)
	Status(ctx context.Context, tenantID shared.ID, interval time.Duration) (dashboardfact.Status, error)
}

// Auditor records the request in the organization's audit log.
type Auditor interface {
	LogEvent(ctx context.Context, actx auditapp.AuditContext, event auditapp.AuditEvent) error
}

// Origin says who asked.
type Origin string

const (
	// OriginOrganization is an owner or administrator of the organization.
	OriginOrganization Origin = "organization"
	// OriginConsole is a platform administrator in the console.
	OriginConsole Origin = "console"
)

// Service records rebuild requests and reads the fact status.
type Service struct {
	store  Store
	audit  Auditor
	logger *logger.Logger
}

// NewService creates the service. audit may be nil (no audit row; tests).
func NewService(store Store, audit Auditor, log *logger.Logger) *Service {
	if log == nil {
		log = logger.NewNop()
	}
	return &Service{store: store, audit: audit, logger: log}
}

// RequestRebuild asks for a full rebuild of the tenant's dashboard facts. At
// most one request per tenant per hour is accepted, whoever asks; a refused
// request returns a *dashboardfact.TooSoonError. An accepted one is audited
// in the organization's log.
func (s *Service) RequestRebuild(ctx context.Context, tenantID shared.ID, origin Origin, actx auditapp.AuditContext) (dashboardfact.Status, error) {
	if tenantID.IsZero() {
		return dashboardfact.Status{}, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	if _, err := s.store.RequestRebuild(ctx, tenantID, dashboardfact.RebuildInterval); err != nil {
		return dashboardfact.Status{}, err
	}
	actx.TenantID = tenantID.String()
	ev := auditapp.NewSuccessEvent(auditdom.ActionDashboardDataRebuildRequested, auditdom.ResourceTypeDashboardData, tenantID.String()).
		WithMessage("Dashboard data rebuild requested").
		WithMetadata("origin", string(origin)).
		WithSeverity(auditdom.SeverityLow)
	if s.audit != nil {
		if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
			s.logger.Warn("failed to record dashboard rebuild audit event", "error", err)
		}
	}
	return s.store.Status(ctx, tenantID, dashboardfact.RebuildInterval)
}

// Status returns the tenant's dashboard fact status.
func (s *Service) Status(ctx context.Context, tenantID shared.ID) (dashboardfact.Status, error) {
	if tenantID.IsZero() {
		return dashboardfact.Status{}, fmt.Errorf("%w: tenant id is required", shared.ErrValidation)
	}
	return s.store.Status(ctx, tenantID, dashboardfact.RebuildInterval)
}
