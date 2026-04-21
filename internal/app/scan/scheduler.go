package scan

import (
	"github.com/openctemio/api/internal/metrics"
	"context"
	"sync"
	"time"

	
	"github.com/openctemio/api/pkg/domain/scan"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
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

	// Acquire distributed advisory lock to prevent double-trigger across multiple
	// API replicas. If another instance is already triggering this scan, skip it.
	acquired, err := s.scanRepo.TryLockScanForScheduler(ctx, sc.ID)
	if err != nil {
		s.logger.Error("failed to acquire scheduler lock", "scan_id", sc.ID.String(), "error", err)
		return
	}
	if !acquired {
		s.logger.Debug("scan locked by another scheduler instance, skipping", "scan_id", sc.ID.String())
		return
	}
	defer func() {
		if unlockErr := s.scanRepo.UnlockScanForScheduler(ctx, sc.ID); unlockErr != nil {
			s.logger.Error("failed to release scheduler lock", "scan_id", sc.ID.String(), "error", unlockErr)
		}
	}()

	// Update next_run_at immediately to prevent re-trigger on the next polling cycle.
	// (The advisory lock prevents concurrent triggers; this update prevents the same
	// instance from picking it up again on the next cycle.)
	nextRunAt := sc.CalculateNextRunAt()
	if err := s.scanRepo.UpdateNextRunAt(ctx, sc.ID, nextRunAt); err != nil {
		s.logger.Error("failed to update next_run_at", "scan_id", sc.ID.String(), "error", err)
	}

	// Trigger the scan
	_, err = s.scanService.TriggerScan(ctx, TriggerScanExecInput{
		TenantID: sc.TenantID.String(),
		ScanID:   sc.ID.String(),
		Context: map[string]any{
			"triggered_by": "scheduler",
			"scheduled_at": time.Now().Unix(),
		},
	})
	if err != nil {
		s.logger.Error("failed to trigger scan",
			"scan_id", sc.ID.String(),
			"scan_name", sc.Name,
			"error", err,
		)
		return
	}

	// Record metric
	metrics.ScansScheduled.WithLabelValues(sc.TenantID.String()).Inc()

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
