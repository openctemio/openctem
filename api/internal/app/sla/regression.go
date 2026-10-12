package sla

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	sladom "github.com/openctemio/openctem/api/pkg/domain/sla"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// RegressionStore reads reopened findings and writes their fresh deadline.
// Implemented by *postgres.FindingSLARestartRepository.
type RegressionStore interface {
	// LoadRegressionCandidates returns the given findings of the tenant that
	// are open (a closed finding has no running SLA).
	LoadRegressionCandidates(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID) ([]sladom.RegressionCandidate, error)
	// RestartSLA writes the deadline (status on_track) and an sla_restarted
	// activity in one transaction, only while the finding is still open.
	// Returns whether it wrote.
	RestartSLA(ctx context.Context, tenantID shared.ID, r sladom.RegressionRestart) (bool, error)
}

// RegressionRestarter gives each regressed finding a fresh SLA deadline,
// computed by the tenant's SLA policy (priority class first, then severity) from
// the moment it was reopened (RFC-039 D2).
type RegressionRestarter struct {
	calc   DeadlineCalculator
	store  RegressionStore
	now    func() time.Time
	logger *logger.Logger
}

// NewRegressionRestarter wires the restarter. *Service is the calculator.
func NewRegressionRestarter(calc DeadlineCalculator, store RegressionStore, log *logger.Logger) *RegressionRestarter {
	return &RegressionRestarter{calc: calc, store: store, now: time.Now, logger: log.With("component", "sla-regression")}
}

// RestartForRegression restarts the SLA of the given reopened findings.
// trigger is what detected the regression ("scan" or "retest"). Returns how
// many deadlines were written; a failure on one finding never stops the rest.
func (r *RegressionRestarter) RestartForRegression(ctx context.Context, tenantID shared.ID, findingIDs []shared.ID, trigger string) (int, error) {
	if len(findingIDs) == 0 {
		return 0, nil
	}
	candidates, err := r.store.LoadRegressionCandidates(ctx, tenantID, findingIDs)
	if err != nil {
		return 0, fmt.Errorf("load regressed findings: %w", err)
	}
	now := r.now().UTC()
	restarted := 0
	for _, c := range candidates {
		sev, err := vulnerability.ParseSeverity(c.Severity)
		if err != nil {
			sev = vulnerability.SeverityMedium
		}
		assetID := ""
		if !c.AssetID.IsZero() {
			assetID = c.AssetID.String()
		}
		deadline, err := r.calc.CalculateSLADeadlineForPriority(ctx, tenantID.String(), assetID, c.PriorityClass, sev, now)
		if err != nil {
			r.logger.Warn("regression SLA: deadline not computed", "finding_id", c.FindingID.String(), "error", err)
			continue
		}
		if deadline.IsZero() {
			continue // no SLA for this finding (informational, info days = 0)
		}
		ok, err := r.store.RestartSLA(ctx, tenantID, sladom.RegressionRestart{
			FindingID: c.FindingID, Deadline: deadline, PreviousDeadline: c.SLADeadline,
			PreviousStatus: c.SLAStatus, Trigger: trigger, RestartedAt: now,
		})
		if err != nil {
			r.logger.Warn("regression SLA: deadline not written", "finding_id", c.FindingID.String(), "error", err)
			continue
		}
		if ok {
			restarted++
		}
	}
	return restarted, nil
}
