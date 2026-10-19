package sla

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// F3 wire: concrete Applier that the ingest processor calls
// to compute and attach a deadline to each newly-classified finding.
//
// This is the "wire" that turns F3 from a domain primitive
// (Service.CalculateSLADeadlineForPriority exists) into actual
// behavior (findings get their sla_deadline column populated using
// priority class, with severity as fallback).
//
// Previously the SLA deadline was never computed at ingest — the
// sla_deadline column stayed NULL, so SLA escalation never fired on
// newly ingested findings. That was a silent gap.

// DeadlineCalculator is the narrow surface the applier needs. The
// production implementation is *Service; tests inject a fake so
// they don't have to stand up the full service graph.
type DeadlineCalculator interface {
	CalculateSLADeadlineForPriority(
		ctx context.Context,
		tenantID, assetID, priorityClass string,
		severity vulnerability.Severity,
		detectedAt time.Time,
	) (time.Time, error)
}

// batchDeadlineSource is optionally implemented by the calculator (*Service)
// to resolve a whole batch's deadlines from policies loaded once.
type batchDeadlineSource interface {
	SLADeadlineFunc(ctx context.Context, tenantID string) (DeadlineFunc, error)
}

// Applier is the concrete implementation of the ingest package's
// Applier interface. Kept in the app package (not ingest) so
// ingest doesn't depend on Service; the calculator contract is
// narrow.
type Applier struct {
	calc DeadlineCalculator
}

// NewApplier wires the calculator into an ingest-ready applier.
// *Service satisfies DeadlineCalculator directly.
func NewApplier(calc DeadlineCalculator) *Applier {
	return &Applier{calc: calc}
}

// ApplyBatch computes each finding's SLA deadline from its priority class
// (severity as fallback) and the tenant's policy
// (docs/architecture/scoring-versions.md, "SLA on a priority change"):
//
//   - no deadline yet: first_detected_at + SLA;
//   - a deadline already set (an open finding being recomputed): only
//     tighten, to min(old deadline, now + SLA). A priority rise late in a
//     finding's life gets the new SLA from now, never a deadline in the past;
//     a priority drop or a longer policy never moves the deadline later
//     (that would hide overdue work). An extension is an explicit decision,
//     not a side effect;
//   - a closed finding keeps its deadline.
//
// Per-finding failures are skipped; an error is returned only if all fail.
// A NULL asset id is acceptable (the calculator falls back to the tenant's
// default policy).
func (a *Applier) ApplyBatch(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error {
	if a.calc == nil || len(findings) == 0 {
		return nil
	}

	tid := tenantID.String()
	// One policy load for the whole batch when the calculator supports it;
	// otherwise (tests, or a failed load) one lookup per finding.
	compute := func(assetID, priorityClass string, sev vulnerability.Severity, detectedAt time.Time) (time.Time, error) {
		return a.calc.CalculateSLADeadlineForPriority(ctx, tid, assetID, priorityClass, sev, detectedAt)
	}
	if b, ok := a.calc.(batchDeadlineSource); ok {
		if fn, err := b.SLADeadlineFunc(ctx, tid); err == nil {
			compute = fn
		}
	}
	now := time.Now().UTC()
	var applied, failed int
	for _, f := range findings {
		old := f.SLADeadline()
		if old != nil && f.IsClosed() {
			applied++
			continue
		}
		priorityClass := ""
		if pc := f.PriorityClass(); pc != nil {
			priorityClass = string(*pc)
		}
		assetID := ""
		if !f.AssetID().IsZero() {
			assetID = f.AssetID().String()
		}

		// A recompute counts the new SLA from now (tighten only).
		start := f.FirstDetectedAt()
		if old != nil {
			start = now
		}
		deadline, err := compute(assetID, priorityClass, f.Severity(), start)
		if err != nil {
			failed++
			continue
		}
		if deadline.IsZero() {
			// No SLA for this finding (informational, info days = 0): no new
			// deadline (an existing one is kept, never extended or removed).
			applied++
			continue
		}
		if old != nil && !deadline.Before(*old) {
			applied++
			continue
		}
		f.SetSLADeadline(deadline)
		applied++
	}
	if applied == 0 && failed > 0 {
		return fmt.Errorf("sla deadline: all %d findings failed", failed)
	}
	return nil
}

// RelaxForDecision recomputes the deadline of each open finding from its
// first detection and its current priority class, and moves it LATER when
// that window ends later than the stored deadline. It is the explicit
// extension ApplyBatch never makes: only an analyst's severity downgrade
// that the organization's approval policy allowed calls it
// (docs/architecture/finding-severity-override.md). Counting from the first
// detection, not from now, means a downgrade never restarts the clock.
func (a *Applier) RelaxForDecision(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error {
	if a.calc == nil {
		return nil
	}
	tid := tenantID.String()
	for _, f := range findings {
		if f.IsClosed() {
			continue
		}
		priorityClass := ""
		if pc := f.PriorityClass(); pc != nil {
			priorityClass = string(*pc)
		}
		assetID := ""
		if !f.AssetID().IsZero() {
			assetID = f.AssetID().String()
		}
		deadline, err := a.calc.CalculateSLADeadlineForPriority(ctx, tid, assetID, priorityClass, f.Severity(), f.FirstDetectedAt())
		if err != nil {
			return fmt.Errorf("sla deadline: %w", err)
		}
		if deadline.IsZero() {
			continue
		}
		if old := f.SLADeadline(); old == nil || deadline.After(*old) {
			f.SetSLADeadline(deadline)
		}
	}
	return nil
}
