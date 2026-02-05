package app

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
	"github.com/openctemio/api/pkg/logger"
)

// FindingLifecycleScheduler manages background tasks for finding lifecycle.
// This includes expiring findings on feature branches that have been inactive.
type FindingLifecycleScheduler struct {
	findingRepo  vulnerability.FindingRepository
	tenantLister TenantLister
	logger       *logger.Logger

	config FindingLifecycleSchedulerConfig
	stopCh chan struct{}
	wg     sync.WaitGroup
}

// TenantLister provides a list of active tenant IDs.
type TenantLister interface {
	// ListActiveTenantIDs returns all active tenant IDs for batch processing.
	ListActiveTenantIDs(ctx context.Context) ([]shared.ID, error)
}

// FindingLifecycleSchedulerConfig holds configuration for the scheduler.
type FindingLifecycleSchedulerConfig struct {
	// CheckInterval is how often to run lifecycle tasks (default: 1 hour)
	CheckInterval time.Duration

	// DefaultExpiryDays is the default number of days after which
	// feature branch findings are expired if not seen (default: 30)
	// Individual branches can override this via retention_days setting.
	DefaultExpiryDays int

	// Enabled controls whether the scheduler runs (default: true)
	Enabled bool
}

// DefaultFindingLifecycleSchedulerConfig returns default configuration.
func DefaultFindingLifecycleSchedulerConfig() FindingLifecycleSchedulerConfig {
	return FindingLifecycleSchedulerConfig{
		CheckInterval:     1 * time.Hour,
		DefaultExpiryDays: 30,
		Enabled:           true,
	}
}

// NewFindingLifecycleScheduler creates a new scheduler.
func NewFindingLifecycleScheduler(
	findingRepo vulnerability.FindingRepository,
	tenantLister TenantLister,
	cfg FindingLifecycleSchedulerConfig,
	log *logger.Logger,
) *FindingLifecycleScheduler {
	if cfg.CheckInterval == 0 {
		cfg.CheckInterval = 1 * time.Hour
	}
	if cfg.DefaultExpiryDays == 0 {
		cfg.DefaultExpiryDays = 30
	}

	return &FindingLifecycleScheduler{
		findingRepo:  findingRepo,
		tenantLister: tenantLister,
		logger:       log.With("component", "finding_lifecycle_scheduler"),
		config:       cfg,
		stopCh:       make(chan struct{}),
	}
}

// Start starts the scheduler.
func (s *FindingLifecycleScheduler) Start() {
	if !s.config.Enabled {
		s.logger.Info("finding lifecycle scheduler disabled")
		return
	}

	s.wg.Add(1)
	go s.run()
	s.logger.Info("finding lifecycle scheduler started",
		"interval", s.config.CheckInterval,
		"default_expiry_days", s.config.DefaultExpiryDays,
	)
}

// Stop stops the scheduler gracefully.
// Safe to call even if Start() was never called (e.g. when Enabled=false).
func (s *FindingLifecycleScheduler) Stop() {
	if !s.config.Enabled {
		return
	}
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("finding lifecycle scheduler stopped")
}

func (s *FindingLifecycleScheduler) run() {
	defer s.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("finding lifecycle scheduler panicked", "panic", r)
		}
	}()

	ticker := time.NewTicker(s.config.CheckInterval)
	defer ticker.Stop()

	// Run immediately on start
	s.safeExpireFeatureBranchFindings()

	for {
		select {
		case <-ticker.C:
			s.safeExpireFeatureBranchFindings()
		case <-s.stopCh:
			return
		}
	}
}

// safeExpireFeatureBranchFindings wraps expireFeatureBranchFindings with panic recovery
// so a single iteration panic doesn't crash the scheduler goroutine.
func (s *FindingLifecycleScheduler) safeExpireFeatureBranchFindings() {
	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("panic during feature branch expiry", "panic", r)
		}
	}()
	s.expireFeatureBranchFindings()
}

// expireFeatureBranchFindings expires stale findings on feature branches.
func (s *FindingLifecycleScheduler) expireFeatureBranchFindings() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Get all active tenant IDs
	tenantIDs, err := s.tenantLister.ListActiveTenantIDs(ctx)
	if err != nil {
		s.logger.Error("failed to list tenant IDs for feature branch expiry", "error", err)
		return
	}

	if len(tenantIDs) == 0 {
		return
	}

	totalExpired := int64(0)
	tenantsProcessed := 0

	for _, tenantID := range tenantIDs {
		expired, err := s.findingRepo.ExpireFeatureBranchFindings(ctx, tenantID, s.config.DefaultExpiryDays)
		if err != nil {
			s.logger.Error("failed to expire feature branch findings",
				"tenant_id", tenantID.String(),
				"error", err,
			)
			continue
		}

		if expired > 0 {
			s.logger.Info("expired feature branch findings",
				"tenant_id", tenantID.String(),
				"count", expired,
			)
			// Record metric
			FindingsExpired.WithLabelValues(tenantID.String(), "feature_branch").Add(float64(expired))
		}

		totalExpired += expired
		tenantsProcessed++
	}

	if totalExpired > 0 {
		s.logger.Info("feature branch expiry cycle completed",
			"tenants_processed", tenantsProcessed,
			"total_expired", totalExpired,
		)
	}
}
