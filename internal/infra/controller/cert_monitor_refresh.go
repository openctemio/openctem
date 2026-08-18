package controller

import (
	"context"
	"time"

	certmonitorapp "github.com/openctemio/api/internal/app/certmonitor"
	"github.com/openctemio/api/pkg/domain/tenant"
	"github.com/openctemio/api/pkg/logger"
)

// CertMonitorControllerConfig configures the periodic Certificate-Transparency
// discovery sweep.
type CertMonitorControllerConfig struct {
	// Interval is how often the sweep runs across all tenants. Default: 24h.
	// CT data changes slowly (certs are issued/renewed on the order of days), so
	// a daily cadence mirrors the threat-intel / CTEM-ID feed refreshes.
	Interval time.Duration

	// Logger for structured output. Defaults to NewNop when nil.
	Logger *logger.Logger
}

// CertMonitorController periodically runs the CT discovery sweep for every
// active tenant. For each tenant it queries crt.sh for that tenant's domain
// assets and emits ExposureEvents (subdomain_discovered + certificate_expiring).
//
// A background controller (not the ingest hot path) is used because the sweep
// makes bounded, rate-limited outbound calls to a public feed and must not slow
// ingest. Each tenant is handled serially; a failure on one tenant is logged and
// skipped (fail-open) so it never halts the others. Only an unrecoverable
// tenant-list failure is returned so the runner retries next tick.
type CertMonitorController struct {
	service    *certmonitorapp.Service
	tenantRepo tenant.Repository
	config     *CertMonitorControllerConfig
	logger     *logger.Logger
}

// NewCertMonitorController constructs the controller.
func NewCertMonitorController(
	service *certmonitorapp.Service,
	tenantRepo tenant.Repository,
	config *CertMonitorControllerConfig,
) *CertMonitorController {
	if config == nil {
		config = &CertMonitorControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 24 * time.Hour
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &CertMonitorController{
		service:    service,
		tenantRepo: tenantRepo,
		config:     config,
		logger:     config.Logger.With("controller", "cert-monitor"),
	}
}

// Name implements controller.Controller.
func (c *CertMonitorController) Name() string { return "cert-monitor" }

// Interval implements controller.Controller.
func (c *CertMonitorController) Interval() time.Duration { return c.config.Interval }

// Reconcile runs the CT sweep for every active tenant. Returns the number of
// tenants that emitted at least one exposure. Per-tenant errors are logged and
// skipped; only a tenant-list failure is returned.
func (c *CertMonitorController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil || c.tenantRepo == nil {
		return 0, nil
	}

	tenantIDs, err := c.tenantRepo.ListActiveTenantIDs(ctx)
	if err != nil {
		return 0, err
	}

	swept := 0
	for _, tenantID := range tenantIDs {
		if err := ctx.Err(); err != nil {
			return swept, err
		}
		n, err := c.service.MonitorTenant(ctx, tenantID)
		if err != nil {
			c.logger.Warn("cert-monitor sweep failed; continuing with next tenant",
				"tenant_id", tenantID.String(), "error", err)
			continue
		}
		if n > 0 {
			swept++
			c.logger.Info("cert-monitor emitted exposures",
				"tenant_id", tenantID.String(), "exposures", n)
		}
	}
	return swept, nil
}
