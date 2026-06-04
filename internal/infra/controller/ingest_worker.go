package controller

import (
	"context"
	"time"

	"github.com/openctemio/api/pkg/domain/ingestjob"
	"github.com/openctemio/api/pkg/logger"
)

// IngestJobQueue is the slice of the ingest-job repository the worker needs.
type IngestJobQueue interface {
	ClaimBatch(ctx context.Context, workerID string, limit int) ([]*ingestjob.Job, error)
	Complete(ctx context.Context, id ingestjob.ID, result []byte) error
	Fail(ctx context.Context, id ingestjob.ID, errMsg string, availableAt time.Time, dead bool) error
	ReleaseStale(ctx context.Context, olderThan time.Duration) (int, error)
}

// IngestJobProcessor processes a claimed job (parse payload + ingest) and
// returns the result counts to persist on completion.
type IngestJobProcessor interface {
	Process(ctx context.Context, job *ingestjob.Job) ([]byte, error)
}

// IngestWorkerControllerConfig configures the async-ingest worker (RFC-005).
type IngestWorkerControllerConfig struct {
	// Interval between drain cycles. Default: 2s.
	Interval time.Duration
	// BatchSize is how many jobs to claim per ClaimBatch. Default: 5.
	BatchSize int
	// MaxPerTick caps how many jobs one Reconcile drains so a huge backlog
	// doesn't monopolize the goroutine forever. Default: 50.
	MaxPerTick int
	// LeaseTimeout: processing jobs whose lock is older than this are reclaimed
	// (worker crash recovery). Default: 5m.
	LeaseTimeout time.Duration
	// WorkerID identifies this replica's worker in locked_by. Default: "ingest-worker".
	WorkerID string
	Logger   *logger.Logger
}

// IngestWorkerController drains the ingest_jobs queue: it reclaims stale jobs,
// claims pending ones (bounded), and runs each through the ingest pipeline,
// marking them completed or failed (with backoff / dead). Bounded concurrency
// (one job at a time per replica, BatchSize/MaxPerTick caps) is the core
// backpressure that protects the DB pool under heavy ingest load.
type IngestWorkerController struct {
	queue     IngestJobQueue
	processor IngestJobProcessor
	cfg       *IngestWorkerControllerConfig
	logger    *logger.Logger
}

// NewIngestWorkerController constructs the controller, applying defaults.
func NewIngestWorkerController(queue IngestJobQueue, processor IngestJobProcessor, cfg *IngestWorkerControllerConfig) *IngestWorkerController {
	if cfg == nil {
		cfg = &IngestWorkerControllerConfig{}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = 2 * time.Second
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 5
	}
	if cfg.MaxPerTick <= 0 {
		cfg.MaxPerTick = 50
	}
	if cfg.LeaseTimeout <= 0 {
		cfg.LeaseTimeout = 5 * time.Minute
	}
	if cfg.WorkerID == "" {
		cfg.WorkerID = "ingest-worker"
	}
	log := cfg.Logger
	if log == nil {
		log = logger.NewNop()
	}
	return &IngestWorkerController{queue: queue, processor: processor, cfg: cfg, logger: log}
}

// Name implements controller.Controller.
func (c *IngestWorkerController) Name() string { return "ingest-worker" }

// Interval implements controller.Controller.
func (c *IngestWorkerController) Interval() time.Duration { return c.cfg.Interval }

// Reconcile reclaims stale jobs then drains pending jobs up to MaxPerTick.
func (c *IngestWorkerController) Reconcile(ctx context.Context) (int, error) {
	if released, err := c.queue.ReleaseStale(ctx, c.cfg.LeaseTimeout); err != nil {
		c.logger.Warn("ingest: release stale jobs failed", "error", err)
	} else if released > 0 {
		c.logger.Info("ingest: reclaimed stale jobs", "count", released)
	}

	processed := 0
	for processed < c.cfg.MaxPerTick {
		if ctx.Err() != nil {
			return processed, ctx.Err()
		}
		jobs, err := c.queue.ClaimBatch(ctx, c.cfg.WorkerID, c.cfg.BatchSize)
		if err != nil {
			return processed, err
		}
		if len(jobs) == 0 {
			break
		}
		for _, job := range jobs {
			c.processOne(ctx, job)
			processed++
		}
	}
	return processed, nil
}

// processOne runs a single job and records the outcome.
func (c *IngestWorkerController) processOne(ctx context.Context, job *ingestjob.Job) {
	result, err := c.processor.Process(ctx, job)
	if err != nil {
		// attempts was already incremented by ClaimBatch; dead once it reaches
		// the ceiling.
		dead := job.Attempts() >= job.MaxAttempts()
		retryAt := time.Now().Add(ingestjob.Backoff(job.Attempts()))
		if failErr := c.queue.Fail(ctx, job.ID(), err.Error(), retryAt, dead); failErr != nil {
			c.logger.Error("ingest: failed to mark job failed", "job_id", job.ID().String(), "error", failErr)
		} else {
			c.logger.Warn("ingest: job processing failed",
				"job_id", job.ID().String(), "attempts", job.Attempts(), "dead", dead, "error", err)
		}
		return
	}
	if err := c.queue.Complete(ctx, job.ID(), result); err != nil {
		c.logger.Error("ingest: failed to mark job complete", "job_id", job.ID().String(), "error", err)
	}
}
