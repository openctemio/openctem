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

// ApplyBatch iterates each finding, computes the deadline using
// priority class + severity, and writes it with SetSLADeadline.
// Errors on a per-finding basis are logged via the SLA service's
// own logger (via returned error from Calculate — this function
// swallows individual failures and keeps processing the rest, but
// returns an aggregate error if ALL failed).
//
// A NULL asset id on a finding is acceptable — the underlying
// service falls back to the tenant default policy.
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
	var applied, failed int
	for _, f := range findings {
		priorityClass := ""
		if pc := f.PriorityClass(); pc != nil {
			priorityClass = string(*pc)
		}
		assetID := ""
		if !f.AssetID().IsZero() {
			assetID = f.AssetID().String()
		}

		deadline, err := compute(assetID, priorityClass, f.Severity(), f.FirstDetectedAt())
		if err != nil {
			failed++
			continue
		}
		if deadline.IsZero() {
			// No SLA for this finding (informational, info days = 0): the
			// deadline stays NULL and sla_status stays not_applicable.
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
