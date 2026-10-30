package sla

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
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
// to resolve a whole batch's deadlines and known exploited caps from
// policies loaded once.
type batchDeadlineSource interface {
	SLABatchFuncs(ctx context.Context, tenantID string) (DeadlineFunc, KEVCapFunc, error)
}

// kevCapSource is optionally implemented by the calculator (*Service) to read
// the known exploited deadline cap of one finding's policy. A calculator
// without it gets the platform default (DefaultKEVCapDays).
type kevCapSource interface {
	KEVCapDays(ctx context.Context, tenantID, assetID string) (int, error)
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
//   - a closed finding keeps its deadline;
//   - known exploited cap (docs/architecture/scoring-versions.md, "Known
//     exploited deadline cap"): a finding whose CVE is in CISA KEV is due at
//     most cap days after the platform first sees it as KEV. The cap counts
//     from the same start as the class window (first detection for a first
//     deadline, now on a recompute), so a KEV flag that arrives later
//     tightens the deadline to now + cap at the pass that first sees it, and
//     later passes never move it. It takes part in the same tighten-only
//     minimum, so it never extends a deadline; a cap of 0 turns it off, and a
//     finding the policy gives no SLA (informational, info days = 0) stays
//     without a deadline. A deadline the cap decided is marked
//     (SLAKEVCapped) so the finding can say why it is shorter.
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
	kevCap := a.singleKEVCap(ctx, tid)
	if b, ok := a.calc.(batchDeadlineSource); ok {
		if fn, capFn, err := b.SLABatchFuncs(ctx, tid); err == nil {
			compute, kevCap = fn, capFn
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
		capped := false
		if f.IsInKEV() {
			if days := kevCap(assetID); days > 0 {
				if c := start.Add(time.Duration(days) * 24 * time.Hour); c.Before(deadline) {
					deadline, capped = c, true
				}
			}
		}
		if old != nil && !deadline.Before(*old) {
			applied++
			continue
		}
		if capped {
			f.SetSLADeadlineKEVCapped(deadline)
		} else {
			f.SetSLADeadline(deadline)
		}
		applied++
	}
	if applied == 0 && failed > 0 {
		return fmt.Errorf("sla deadline: all %d findings failed", failed)
	}
	return nil
}

// singleKEVCap reads one finding's known exploited cap from the calculator,
// or the platform default when it has no such lookup.
func (a *Applier) singleKEVCap(ctx context.Context, tenantID string) KEVCapFunc {
	src, ok := a.calc.(kevCapSource)
	if !ok {
		return func(string) int { return sladom.DefaultKEVCapDays }
	}
	return func(assetID string) int {
		days, err := src.KEVCapDays(ctx, tenantID, assetID)
		if err != nil {
			// The policy could not be read: no cap on this pass. A default
			// cap written now would stick (deadlines only tighten); the next
			// pass applies the policy's own cap.
			return 0
		}
		return days
	}
}

// RelaxForDecision recomputes the deadline of each open finding from its
// first detection and its current priority class, and moves it LATER when
// that window ends later than the stored deadline. It is the explicit
// extension ApplyBatch never makes: only an analyst's severity downgrade
// that the organization's approval policy allowed calls it
// (docs/architecture/finding-severity-override.md). Counting from the first
// detection, not from now, means a downgrade never restarts the clock. The
// known exploited cap still bounds it: a KEV finding is never relaxed past
// first detection + cap, so a deadline the cap set is kept.
func (a *Applier) RelaxForDecision(ctx context.Context, tenantID shared.ID, findings []*vulnerability.Finding) error {
	if a.calc == nil {
		return nil
	}
	tid := tenantID.String()
	kevCap := a.singleKEVCap(ctx, tid)
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
		capped := false
		if f.IsInKEV() {
			if days := kevCap(assetID); days > 0 {
				if c := f.FirstDetectedAt().Add(time.Duration(days) * 24 * time.Hour); c.Before(deadline) {
					deadline, capped = c, true
				}
			}
		}
		if old := f.SLADeadline(); old == nil || deadline.After(*old) {
			if capped {
				f.SetSLADeadlineKEVCapped(deadline)
			} else {
				f.SetSLADeadline(deadline)
			}
		}
	}
	return nil
}
