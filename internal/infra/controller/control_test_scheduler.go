package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/simulation"
	"github.com/openctemio/api/pkg/logger"
)

// ControlTestSchedulerController automatically marks control tests as overdue
// when they have not been run within the configured stale window.
//
// Design:
//   - Runs every 24 hours (daily sweep).
//   - Any control test not tested for >StaleDays days is reset to "untested"
//     so it surfaces in the Detection Coverage dashboard.
//   - Never blocks other operations — failures are logged and skipped.
type ControlTestSchedulerController struct {
	repo   simulation.ControlTestRepository
	config *ControlTestSchedulerConfig
	logger *logger.Logger
}

// ControlTestSchedulerConfig configures the controller.
type ControlTestSchedulerConfig struct {
	// Interval is how often the scheduler runs (default: 24 hours).
	Interval time.Duration

	// StaleDays is the number of days without a test before a control test
	// is considered overdue and reset to "untested" (default: 30).
	StaleDays int

	// BatchSize is the maximum number of overdue tests to process per cycle (default: 500).
	BatchSize int

	// Logger is passed by the controller manager.
	Logger *logger.Logger
}

// NewControlTestSchedulerController creates a new controller.
func NewControlTestSchedulerController(
	repo simulation.ControlTestRepository,
	cfg *ControlTestSchedulerConfig,
) *ControlTestSchedulerController {
	if cfg.Interval == 0 {
		cfg.Interval = 24 * time.Hour
	}
	if cfg.StaleDays == 0 {
		cfg.StaleDays = 30
	}
	if cfg.BatchSize == 0 {
		cfg.BatchSize = 500
	}
	return &ControlTestSchedulerController{
		repo:   repo,
		config: cfg,
		logger: cfg.Logger,
	}
}

// Name implements Controller.
func (c *ControlTestSchedulerController) Name() string { return "control-test-scheduler" }

// Interval implements Controller.
func (c *ControlTestSchedulerController) Interval() time.Duration { return c.config.Interval }

// Reconcile finds all overdue control tests and resets their status to "untested".
// Returns the count of tests marked overdue.
func (c *ControlTestSchedulerController) Reconcile(ctx context.Context) (int, error) {
	overdueTests, err := c.repo.ListOverdue(ctx, c.config.StaleDays, c.config.BatchSize)
	if err != nil {
		return 0, err
	}

	if len(overdueTests) == 0 {
		return 0, nil
	}

	marked := 0
	for _, ct := range overdueTests {
		if err := c.repo.MarkOverdue(ctx, ct.TenantID, ct.ControlTestID); err != nil {
			c.logger.Warn("failed to mark control test overdue",
				"tenant_id", ct.TenantID.String(),
				"control_test_id", ct.ControlTestID.String(),
				"name", ct.Name,
				"error", err,
			)
			continue
		}

		c.logger.Info("control test marked overdue",
			"tenant_id", ct.TenantID.String(),
			"control_test_id", ct.ControlTestID.String(),
			"framework", ct.Framework,
			"name", ct.Name,
			"days_since_tested", ct.DaysSinceTested,
		)
		marked++
	}

	if marked > 0 {
		c.logger.Info("control test scheduler cycle completed",
			"overdue_found", len(overdueTests),
			"marked_untested", marked,
			"stale_days", c.config.StaleDays,
		)
	}

	return marked, nil
}
