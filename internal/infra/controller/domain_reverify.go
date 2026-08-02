package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/internal/app/auth/domainverify"
	"github.com/openctemio/api/pkg/logger"
)

// DomainReverifyControllerConfig configures the DomainReverifyController.
type DomainReverifyControllerConfig struct {
	// Interval is how often the re-verify sweep runs. Default: 12h.
	Interval time.Duration
	// Staleness is how long since the last check before a verified domain is
	// re-verified. Default: 24h.
	Staleness time.Duration
	// BatchSize caps rows processed per sweep. Default: 100.
	BatchSize int
	// Logger for logging.
	Logger *logger.Logger
}

// DomainReverifyController periodically re-verifies domains that were previously
// proven via DNS TXT. If a domain's TXT record has since disappeared (a lapsed
// or hijacked domain), it is downgraded to failed so it loses SSO JIT authority
// (fail-closed).
type DomainReverifyController struct {
	service *domainverify.Service
	config  *DomainReverifyControllerConfig
	logger  *logger.Logger
}

// NewDomainReverifyController creates a new DomainReverifyController.
func NewDomainReverifyController(
	service *domainverify.Service,
	config *DomainReverifyControllerConfig,
) *DomainReverifyController {
	if config == nil {
		config = &DomainReverifyControllerConfig{}
	}
	if config.Interval == 0 {
		config.Interval = 12 * time.Hour
	}
	if config.Staleness == 0 {
		config.Staleness = 24 * time.Hour
	}
	if config.BatchSize == 0 {
		config.BatchSize = 100
	}
	if config.Logger == nil {
		config.Logger = logger.NewNop()
	}
	return &DomainReverifyController{
		service: service,
		config:  config,
		logger:  config.Logger,
	}
}

// Name returns the controller name.
func (c *DomainReverifyController) Name() string { return "domain-reverify" }

// Interval returns the reconciliation interval.
func (c *DomainReverifyController) Interval() time.Duration { return c.config.Interval }

// Reconcile re-verifies due domains and downgrades any whose TXT record vanished.
func (c *DomainReverifyController) Reconcile(ctx context.Context) (int, error) {
	if c.service == nil {
		return 0, nil
	}
	changed, err := c.service.ReverifyDue(ctx, c.config.Staleness, c.config.BatchSize)
	if err != nil {
		c.logger.Error("domain re-verify sweep failed", "error", err)
		return 0, err
	}
	if changed > 0 {
		c.logger.Info("domain re-verify sweep completed", "status_changes", changed)
	}
	return changed, nil
}
