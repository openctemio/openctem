package controller

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/logger"
)

// B1 + B2 (Q1/WS-C): periodic sweep that reclassifies open findings so
// EPSS / KEV / rule / compensating-control changes take effect without
// waiting for the next ingest.
//
// The naive version would iterate every open finding on every tick —
// too expensive. Instead the controller consumes a "reason" queue
// maintained by the producing services (threat intel refresh, rule
// CRUD, control activation). Each entry declares: "tenant T, rows
// matching predicate P need reclassification".
//
// This file defines the controller shell + the queue contract. The
// actual reclassify-a-finding work plugs back into
// PriorityClassificationService via the ReclassifyBatch hook.
//
// Why not just call EnrichAndClassifyBatch directly? Because sweep
// runs must not block ingest; they process findings in bounded chunks
// with backoff, and they must emit `priority_changed` events only on
// real transitions (publisher in the service already handles that —
// see internal/app/priority_classification_service.go).

// ReclassifyReasonKind enumerates why a sweep was enqueued.
type ReclassifyReasonKind string

const (
	ReasonEPSSRefresh   ReclassifyReasonKind = "epss_refresh"
	ReasonKEVRefresh    ReclassifyReasonKind = "kev_refresh"
	ReasonRuleChanged   ReclassifyReasonKind = "rule_changed"
	ReasonControlChange ReclassifyReasonKind = "control_change"
	ReasonAssetChange   ReclassifyReasonKind = "asset_change"
	ReasonManual        ReclassifyReasonKind = "manual"
)

// ReclassifyRequest describes one unit of sweep work.
//
// Scope dimensions (all optional; nil/empty = broadest match within tenant):
//   - CVEIDs  — only findings matching these CVEs (typical EPSS/KEV path).
//   - AssetIDs — only findings on these assets (typical control/asset path).
//   - RuleID   — evaluated by the running service against each finding.
//
// Batching is the caller's responsibility — a giant EPSS refresh should
// split into per-tenant requests; the controller treats each request
// atomically.
type ReclassifyRequest struct {
	TenantID  shared.ID
	Reason    ReclassifyReasonKind
	CVEIDs    []string
	AssetIDs  []shared.ID
	RuleID    *shared.ID
	EnqueueAt time.Time
}

// ReclassifyQueue is the minimal contract for the in/out queue.
// Implementations may be Redis lists, Postgres advisory-locked rows,
// or an in-memory channel for tests.
type ReclassifyQueue interface {
	// Enqueue adds a reclassify request. MUST be safe for concurrent use.
	Enqueue(ctx context.Context, req ReclassifyRequest) error
	// DequeueBatch pops up to `max` requests. An empty slice (no error)
	// means "nothing to do this tick". Implementations should return
	// quickly (non-blocking).
	DequeueBatch(ctx context.Context, max int) ([]ReclassifyRequest, error)
}

// Reclassifier applies one request: it loads the matching open findings
// and invokes the PriorityClassificationService on them. Kept as a
// narrow interface so the controller has no knowledge of the app-layer
// service or its repo dependencies.
type Reclassifier interface {
	// ReclassifyForRequest processes a single request. Returns the
	// number of findings re-examined (not necessarily changed — a
	// sweep that re-confirms the same class is still "work done").
	ReclassifyForRequest(ctx context.Context, req ReclassifyRequest) (int, error)
}

// PriorityReclassifyConfig configures the sweep controller.
type PriorityReclassifyConfig struct {
	// Interval between sweep ticks. Default 5m.
	Interval time.Duration
	// BatchSize is the max number of requests drained per tick.
	// Default 64.
	BatchSize int
	// Logger (optional; defaults to no-op).
	Logger *logger.Logger
}

// PriorityReclassifyController drains the queue and dispatches each
// request to the Reclassifier.
type PriorityReclassifyController struct {
	queue        ReclassifyQueue
	reclassifier Reclassifier
	config       *PriorityReclassifyConfig
	logger       *logger.Logger
}

// NewPriorityReclassifyController wires the controller.
func NewPriorityReclassifyController(
	queue ReclassifyQueue,
	reclassifier Reclassifier,
	cfg *PriorityReclassifyConfig,
) *PriorityReclassifyController {
	if cfg == nil {
		cfg = &PriorityReclassifyConfig{}
	}
	if cfg.Interval == 0 {
		cfg.Interval = 5 * time.Minute
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = 64
	}
	if cfg.Logger == nil {
		cfg.Logger = logger.NewNop()
	}
	return &PriorityReclassifyController{
		queue:        queue,
		reclassifier: reclassifier,
		config:       cfg,
		logger:       cfg.Logger.With("controller", "priority-reclassify"),
	}
}

// Name returns the controller name.
func (c *PriorityReclassifyController) Name() string { return "priority-reclassify" }

// Interval returns the sweep interval.
func (c *PriorityReclassifyController) Interval() time.Duration { return c.config.Interval }

// Reconcile drains up to BatchSize requests from the queue and applies
// each. Returns the total number of findings re-examined across all
// drained requests (for metrics).
func (c *PriorityReclassifyController) Reconcile(ctx context.Context) (int, error) {
	if c.queue == nil || c.reclassifier == nil {
		return 0, nil
	}

	reqs, err := c.queue.DequeueBatch(ctx, c.config.BatchSize)
	if err != nil {
		return 0, fmt.Errorf("dequeue: %w", err)
	}
	if len(reqs) == 0 {
		return 0, nil
	}

	totalReexamined := 0
	for _, req := range reqs {
		if ctx.Err() != nil {
			break
		}
		n, err := c.reclassifier.ReclassifyForRequest(ctx, req)
		totalReexamined += n
		if err != nil {
			// Individual failures do not abort the batch — the
			// next tick picks up whatever remained.
			c.logger.Warn("reclassify request failed",
				"tenant_id", req.TenantID.String(),
				"reason", string(req.Reason),
				"error", err,
			)
			continue
		}
		c.logger.Debug("reclassify request processed",
			"tenant_id", req.TenantID.String(),
			"reason", string(req.Reason),
			"reexamined", n,
		)
	}
	return totalReexamined, nil
}
