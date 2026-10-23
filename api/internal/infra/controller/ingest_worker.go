package controller

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/openctemio/openctem/api/internal/metrics"
	"github.com/openctemio/openctem/api/pkg/domain/ingestjob"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// IngestJobQueue is the slice of the ingest-job repository the worker needs.
type IngestJobQueue interface {
	ClaimBatch(ctx context.Context, workerID string, limit int) ([]*ingestjob.Job, error)
	Complete(ctx context.Context, id ingestjob.ID, attempts int, result []byte) error
	Fail(ctx context.Context, id ingestjob.ID, attempts int, errMsg, publicErr string, availableAt time.Time, dead bool) error
	Renew(ctx context.Context, id ingestjob.ID, attempts int) error
	ReleaseStale(ctx context.Context, olderThan time.Duration) (int, []*ingestjob.Job, error)
	CountPending(ctx context.Context) (int, error)
}

// IngestJobProcessor processes a claimed job (parse payload + ingest) and
// returns the result counts to persist on completion.
type IngestJobProcessor interface {
	Process(ctx context.Context, job *ingestjob.Job) ([]byte, error)
}

// DeadLetterer is told when a job failed for good, so the upload's receipt
// (or the CI run waiting on it) records the failure.
type DeadLetterer interface {
	DeadLetter(ctx context.Context, job *ingestjob.Job, publicErr string)
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
	// RenewEvery is how often a processing job's lease is renewed while it
	// runs. Default: LeaseTimeout/3.
	RenewEvery time.Duration
	// MaxJobDuration is the hard cap on one job's processing, however
	// often its lease is renewed. Default: 30m.
	MaxJobDuration time.Duration
	// WorkerID identifies this replica's worker in locked_by. Default: "ingest-worker".
	WorkerID string
	// Workers is how many jobs this replica processes at once (each claims
	// one job at a time; jobs of one scope never run together). Default: 1.
	Workers int
	Logger  *logger.Logger
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
	if cfg.RenewEvery <= 0 {
		cfg.RenewEvery = cfg.LeaseTimeout / 3
	}
	if cfg.MaxJobDuration <= 0 {
		cfg.MaxJobDuration = 30 * time.Minute
	}
	if cfg.WorkerID == "" {
		cfg.WorkerID = "ingest-worker"
	}
	if cfg.Workers <= 0 {
		cfg.Workers = 1
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

// ReconcileTimeout implements controller.ReconcileTimeouter. The short poll
// Interval is only how often we LOOK for work; a drain cycle then runs claimed
// jobs through the full ingest pipeline, which routinely takes far longer than
// the interval. A cycle claims new jobs for one lease window; each job holds
// its lease by renewing it while it runs and is capped by MaxJobDuration, so
// the cycle ends at most that long after the window closes.
func (c *IngestWorkerController) ReconcileTimeout() time.Duration {
	return c.cfg.LeaseTimeout + c.cfg.MaxJobDuration
}

// Reconcile reclaims stale jobs, then drains pending jobs with Workers
// goroutines, at most MaxPerTick jobs in all. Each goroutine claims one job
// at a time, so a claimed job is always being worked on (it holds its
// scope) and the claim's lane and tenant order decides what runs next.
func (c *IngestWorkerController) Reconcile(ctx context.Context) (int, error) {
	released, dead, err := c.queue.ReleaseStale(ctx, c.cfg.LeaseTimeout)
	switch {
	case err != nil:
		c.logger.Warn("ingest: release stale jobs failed", "error", err)
	case released > 0 || len(dead) > 0:
		c.logger.Info("ingest: reclaimed stale jobs", "released", released, "dead", len(dead))
	}
	// A job whose lease expired on its last attempt (a payload that kills
	// the worker) is dead: its owner is told once.
	for _, job := range dead {
		metrics.IngestJobsProcessedTotal.WithLabelValues("dead").Inc()
		if dl, ok := c.processor.(DeadLetterer); ok {
			dl.DeadLetter(ctx, job, ingestjob.ErrorApplyFailed)
		}
	}

	// Periodic processor housekeeping (protocol v2: expire uncommitted
	// reports past their window, RFC-026 §3.5).
	if hk, ok := c.processor.(interface{ Housekeep(context.Context) }); ok {
		hk.Housekeep(ctx)
	}

	// Refresh the queue-depth gauge (key backpressure signal).
	if depth, err := c.queue.CountPending(ctx); err == nil {
		metrics.IngestQueueDepth.Set(float64(depth))
	}

	start := time.Now()
	var (
		processed atomic.Int64
		mu        sync.Mutex
		firstErr  error
		wg        sync.WaitGroup
	)
	for range c.cfg.Workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for processed.Load() < int64(c.cfg.MaxPerTick) && ctx.Err() == nil && time.Since(start) < c.cfg.LeaseTimeout {
				jobs, err := c.queue.ClaimBatch(ctx, c.cfg.WorkerID, 1)
				if err != nil {
					mu.Lock()
					if firstErr == nil {
						firstErr = err
					}
					mu.Unlock()
					return
				}
				if len(jobs) == 0 {
					return
				}
				for _, job := range jobs {
					c.processOne(ctx, job)
					processed.Add(1)
				}
			}
		}()
	}
	wg.Wait()
	if firstErr == nil && ctx.Err() != nil {
		firstErr = ctx.Err()
	}
	return int(processed.Load()), firstErr
}

// processOne runs a single job and records the outcome. While the job runs
// its lease is renewed; a lost lease cancels the work and nothing is written.
func (c *IngestWorkerController) processOne(ctx context.Context, job *ingestjob.Job) {
	jobCtx, cancel := context.WithTimeoutCause(ctx, c.cfg.MaxJobDuration,
		errors.New("ingest job exceeded its maximum duration"))
	jobCtx, cancelCause := context.WithCancelCause(jobCtx)
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		c.renewLoop(jobCtx, cancelCause, job)
	}()
	result, err := c.processor.Process(jobCtx, job)
	lost := errors.Is(context.Cause(jobCtx), ingestjob.ErrLeaseLost)
	cancelCause(nil)
	cancel()
	<-renewDone
	if lost {
		c.leaseLost(job)
		return
	}
	if err != nil {
		// attempts was already incremented by ClaimBatch; dead once it reaches
		// the ceiling. A permanent error (an unreadable upload, a report
		// outside the run's repository) is dead at once: a retry cannot fix
		// it, and its fixed code is what the client sees.
		dead := job.Attempts() >= job.MaxAttempts()
		publicErr := ""
		var perm *ingestjob.PermanentError
		if errors.As(err, &perm) {
			dead, publicErr = true, perm.Code
		} else if dead {
			publicErr = ingestjob.ErrorApplyFailed
		}
		retryAt := time.Now().Add(ingestjob.BackoffFor(job.Kind(), job.Attempts()))
		failErr := c.queue.Fail(ctx, job.ID(), job.Attempts(), err.Error(), publicErr, retryAt, dead)
		if errors.Is(failErr, ingestjob.ErrLeaseLost) {
			c.leaseLost(job)
			return
		}
		if failErr != nil {
			c.logger.Error("ingest: failed to mark job failed", "job_id", job.ID().String(), "error", failErr)
		} else {
			c.logger.Warn("ingest: job processing failed",
				"job_id", job.ID().String(), "attempts", job.Attempts(), "dead", dead, "error", err)
		}
		outcome := "retried"
		if dead {
			outcome = "dead"
			if dl, ok := c.processor.(DeadLetterer); ok {
				dl.DeadLetter(ctx, job, publicErr)
			}
		}
		metrics.IngestJobsProcessedTotal.WithLabelValues(outcome).Inc()
		return
	}
	if err := c.queue.Complete(ctx, job.ID(), job.Attempts(), result); err != nil {
		if errors.Is(err, ingestjob.ErrLeaseLost) {
			c.leaseLost(job)
			return
		}
		c.logger.Error("ingest: failed to mark job complete", "job_id", job.ID().String(), "error", err)
		return
	}
	metrics.IngestJobsProcessedTotal.WithLabelValues("completed").Inc()
	// End-to-end latency: enqueue (created_at) to completion.
	metrics.IngestJobDurationSeconds.Observe(time.Since(job.CreatedAt()).Seconds())
}

// renewLoop keeps the job's lease while it runs. When the lease is lost it
// cancels the job's context with ErrLeaseLost; a failed renewal for any
// other reason is retried at the next tick (the lease still has time).
func (c *IngestWorkerController) renewLoop(ctx context.Context, cancel context.CancelCauseFunc, job *ingestjob.Job) {
	t := time.NewTicker(c.cfg.RenewEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			err := c.queue.Renew(ctx, job.ID(), job.Attempts())
			switch {
			case err == nil:
			case errors.Is(err, ingestjob.ErrLeaseLost):
				cancel(ingestjob.ErrLeaseLost)
				return
			case ctx.Err() == nil:
				c.logger.Warn("ingest: renew lease failed", "job_id", job.ID().String(), "error", err)
			}
		}
	}
}

func (c *IngestWorkerController) leaseLost(job *ingestjob.Job) {
	c.logger.Warn("ingest: lease lost; the job is not written by this attempt",
		"job_id", job.ID().String(), "attempts", job.Attempts())
	metrics.IngestJobsProcessedTotal.WithLabelValues("lease_lost").Inc()
}
