package scan

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"

	"github.com/openctemio/openctem/api/pkg/domain/pipeline"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ScanScheduler periodically checks for due scans and triggers them.
type ScanScheduler struct {
	scanRepo    scan.Repository
	scanService *Service
	logger      *logger.Logger

	interval    time.Duration
	batchSize   int
	stopCh      chan struct{}
	wg          sync.WaitGroup
	runningRuns sync.Map // map[shared.ID]bool - tracks scans with active runs
}

// ScanSchedulerConfig holds configuration for the scan scheduler.
type ScanSchedulerConfig struct {
	// CheckInterval is how often to check for due scans (default: 1 minute)
	CheckInterval time.Duration
	// BatchSize is the max number of scans to process per cycle (default: 50)
	BatchSize int
}

// NewScanScheduler creates a new ScanScheduler.
func NewScanScheduler(
	scanRepo scan.Repository,
	scanService *Service,
	cfg ScanSchedulerConfig,
	log *logger.Logger,
) *ScanScheduler {
	interval := cfg.CheckInterval
	if interval == 0 {
		interval = time.Minute
	}

	batchSize := cfg.BatchSize
	if batchSize == 0 {
		batchSize = 50
	}

	return &ScanScheduler{
		scanRepo:    scanRepo,
		scanService: scanService,
		logger:      log.With("component", "scan_scheduler"),
		interval:    interval,
		batchSize:   batchSize,
		stopCh:      make(chan struct{}),
	}
}

// Start starts the scan scheduler.
func (s *ScanScheduler) Start() {
	s.wg.Add(1)
	go s.run()
	s.logger.Info("scan scheduler started", "interval", s.interval, "batch_size", s.batchSize)
}

// Stop stops the scan scheduler gracefully.
func (s *ScanScheduler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
	s.logger.Info("scan scheduler stopped")
}

func (s *ScanScheduler) run() {
	defer s.wg.Done()

	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()

	// Once at startup, not every tick: this is a configuration defect, not an
	// event. Repeating it every minute would train people to scroll past it,
	// which is how the condition survived unnoticed in the first place.
	s.reportInertScheduledScans()

	// Run immediately on start
	s.checkAndTrigger()

	for {
		select {
		case <-ticker.C:
			s.checkAndTrigger()
		case <-s.stopCh:
			return
		}
	}
}

// reportInertScheduledScans logs any active scan that declares a schedule but
// has no next_run_at.
//
// Such a scan is silently unreachable: ListDueForExecution requires
// next_run_at IS NOT NULL, so it is never selected, never runs, and never
// errors — while every screen still labels it "daily" or "weekly". Nothing in
// the system said so until this call existed.
//
// Reported, not repaired — see CountScheduledWithoutNextRun for why filling the
// field in automatically is the wrong move.
func (s *ScanScheduler) reportInertScheduledScans() {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	count, names, err := s.scanRepo.CountScheduledWithoutNextRun(ctx)
	if err != nil {
		s.logger.Error("failed to check for inert scheduled scans", "error", err)
		return
	}
	if count == 0 {
		return
	}

	s.logger.Warn("scans declare a schedule but have no next_run_at, so they will never run; "+
		"re-save each one to recompute it",
		"count", count, "scans", names)
}

func (s *ScanScheduler) checkAndTrigger() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	now := time.Now()

	// Find scans that are due
	dueScans, err := s.scanRepo.ListDueForExecution(ctx, now)
	if err != nil {
		s.logger.Error("failed to list due scans", "error", err)
		return
	}

	if len(dueScans) == 0 {
		return
	}

	s.logger.Info("found due scans", "count", len(dueScans))

	// Process up to batchSize scans
	processed := 0
	for _, sc := range dueScans {
		if processed >= s.batchSize {
			break
		}

		// Skip if already running
		if s.isRunning(sc.ID) {
			s.logger.Debug("scan already has active run, skipping", "scan_id", sc.ID.String())
			continue
		}

		// Trigger scan in goroutine
		go s.triggerScan(sc)
		processed++
	}

	if processed > 0 {
		s.logger.Info("triggered scans", "count", processed)
	}
}

func (s *ScanScheduler) triggerScan(sc *scan.Scan) {
	// Mark as running to prevent double-trigger within this process
	s.runningRuns.Store(sc.ID, true)
	defer s.runningRuns.Delete(sc.ID)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	if sc.NextRunAt == nil {
		return // not due; ListDueForExecution never returns this
	}

	// Claim this occurrence: move next_run_at forward only if it still holds
	// the value we were handed. Exactly one scheduler (on any replica) wins;
	// the move also keeps the next polling cycle from picking it up again.
	occurrence := *sc.NextRunAt
	nextRunAt := sc.CalculateNextRunAt()
	claimed, err := s.scanRepo.ClaimScheduledRun(ctx, sc.ID, occurrence, nextRunAt)
	if err != nil {
		s.logger.Error("failed to claim scheduled run", "scan_id", sc.ID.String(), "error", err)
		return
	}
	if !claimed {
		s.logger.Debug("scheduled run already claimed (another instance, or the scan changed)", "scan_id", sc.ID.String())
		return
	}

	// Trigger the scan
	_, err = s.scanService.TriggerScan(ctx, TriggerScanExecInput{
		TenantID: sc.TenantID.String(),
		ScanID:   sc.ID.String(),
		Context: map[string]any{
			"triggered_by": "scheduler",
			"scheduled_at": time.Now().Unix(),
		},
		TriggerType:   pipeline.TriggerTypeSchedule,
		SkipIfRunning: true,
		// The run records the occurrence it serves; a second run for the
		// same occurrence is refused by UNIQUE(scan_id, scheduled_for).
		ScheduledFor: &occurrence,
	})
	if errors.Is(err, pipeline.ErrOccurrenceAlreadyRun) {
		// Another scheduler instance already started this occurrence (the
		// next_run_at claim makes this rare; the unique index makes it
		// impossible to double-fire). Nothing to record: that run is real.
		metrics.ScanScheduleOutcomes.WithLabelValues(sc.TenantID.String(), "duplicate_occurrence").Inc()
		s.logger.Info("scheduled run skipped: this occurrence already has a run",
			"scan_id", sc.ID.String(), "scheduled_for", occurrence)
		return
	}
	if errors.Is(err, ErrScanRunInProgress) {
		// Overlap policy (D4): skip this occurrence and say so. Not recorded in
		// last_run_status, which belongs to the run that is still going.
		metrics.ScanScheduleOutcomes.WithLabelValues(sc.TenantID.String(), "skipped_overlap").Inc()
		s.logger.Info("scheduled run skipped: the previous run is still active",
			"scan_id", sc.ID.String(), "scan_name", sc.Name, "next_run_at", nextRunAt)
		s.scanService.recordScheduledOutcome(ctx, sc, "Scheduled run skipped: the previous run is still active", err)
		return
	}
	if err != nil {
		s.logger.Error("failed to trigger scan",
			"scan_id", sc.ID.String(),
			"scan_name", sc.Name,
			"error", err,
		)
		metrics.ScanScheduleOutcomes.WithLabelValues(sc.TenantID.String(), "failed").Inc()
		// Record the failure in the scan's own state. next_run_at was already
		// advanced above (to avoid re-trigger storms), so without this a scan
		// that can never start — e.g. NO_SENSOR_AVAILABLE, which recurred silently
		// for three nights on the demo deployment — looks identical to one that
		// simply has not run yet: next run scheduled, last run blank. Best-effort;
		// a failure to record must not mask the original trigger error.
		if recErr := s.scanRepo.RecordTriggerFailure(ctx, sc.ID, "failed"); recErr != nil {
			s.logger.Error("failed to record scan trigger failure",
				"scan_id", sc.ID.String(), "error", recErr)
		}
		// And in the audit log, with the reason: the scan's state only says
		// "failed", and the server log is not where a tenant looks.
		s.scanService.recordScheduledOutcome(ctx, sc, "Scheduled run could not start: "+err.Error(), err)
		return
	}

	// Record metric
	metrics.ScansScheduled.WithLabelValues(sc.TenantID.String()).Inc()
	metrics.ScanScheduleOutcomes.WithLabelValues(sc.TenantID.String(), "triggered").Inc()

	s.logger.Info("scan triggered by scheduler",
		"scan_id", sc.ID.String(),
		"scan_name", sc.Name,
		"next_run_at", nextRunAt,
	)
}

func (s *ScanScheduler) isRunning(scanID shared.ID) bool {
	_, ok := s.runningRuns.Load(scanID)
	return ok
}
