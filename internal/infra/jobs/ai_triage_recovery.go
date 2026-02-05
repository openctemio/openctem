package jobs

import (
	"context"
	"sync"
	"time"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/internal/config"
	"github.com/openctemio/api/pkg/logger"
)

// AITriageRecoveryJob periodically recovers stuck AI triage jobs.
// Jobs are considered stuck if they've been in pending/processing state for too long.
type AITriageRecoveryJob struct {
	triageService *app.AITriageService
	config        *config.AITriageConfig
	logger        *logger.Logger
	stopCh        chan struct{}
	wg            sync.WaitGroup
}

// NewAITriageRecoveryJob creates a new AITriageRecoveryJob.
func NewAITriageRecoveryJob(
	triageService *app.AITriageService,
	cfg *config.AITriageConfig,
	log *logger.Logger,
) *AITriageRecoveryJob {
	return &AITriageRecoveryJob{
		triageService: triageService,
		config:        cfg,
		logger:        log.With("component", "ai-triage-recovery"),
		stopCh:        make(chan struct{}),
	}
}

// Start starts the recovery job in a background goroutine.
func (j *AITriageRecoveryJob) Start() {
	if !j.config.RecoveryEnabled {
		j.logger.Info("ai triage recovery job is disabled")
		return
	}

	interval := j.config.RecoveryInterval
	if interval == 0 {
		interval = 5 * time.Minute // Default
	}

	stuckDuration := j.config.RecoveryStuckDuration
	if stuckDuration == 0 {
		stuckDuration = 15 * time.Minute // Default
	}

	j.logger.Info("starting ai triage recovery job",
		"interval", interval,
		"stuck_duration", stuckDuration,
		"batch_size", j.config.RecoveryBatchSize,
	)

	j.wg.Add(1)
	go j.run(interval, stuckDuration)
}

// Stop stops the recovery job gracefully.
func (j *AITriageRecoveryJob) Stop() {
	j.logger.Info("stopping ai triage recovery job")
	close(j.stopCh)
	j.wg.Wait()
	j.logger.Info("ai triage recovery job stopped")
}

func (j *AITriageRecoveryJob) run(interval, stuckDuration time.Duration) {
	defer j.wg.Done()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Run immediately on start
	j.recoverStuckJobs(stuckDuration)

	for {
		select {
		case <-ticker.C:
			j.recoverStuckJobs(stuckDuration)
		case <-j.stopCh:
			return
		}
	}
}

func (j *AITriageRecoveryJob) recoverStuckJobs(stuckDuration time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	batchSize := j.config.RecoveryBatchSize
	if batchSize <= 0 {
		batchSize = 50 // Default
	}

	output, err := j.triageService.RecoverStuckJobs(ctx, app.RecoverStuckJobsInput{
		StuckDuration: stuckDuration,
		Limit:         batchSize,
	})
	if err != nil {
		j.logger.Error("failed to recover stuck triage jobs", "error", err)
		return
	}

	if output.Total > 0 {
		j.logger.Info("recovered stuck triage jobs",
			"total", output.Total,
			"recovered", output.Recovered,
			"skipped", output.Skipped,
			"errors", output.Errors,
		)
	}
}
