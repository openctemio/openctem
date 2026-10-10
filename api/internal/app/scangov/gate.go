package scangov

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/scan"
	"github.com/openctemio/openctem/api/pkg/domain/scangov"
)

// CheckRun is the gate every run of a scan passes (manual, scheduled,
// quick, a start after approval): it answers nil when the organization's
// mode is Off, when the rules require no approval for the definition, or
// when an approval authorizes the definition's digest now and meets the
// current requirement; otherwise SCAN_APPROVAL_PENDING (a request for this
// definition waits) or SCAN_APPROVAL_REQUIRED. A run-only approval is
// consumed here, atomically. Any read error refuses the run.
func (s *Service) CheckRun(ctx context.Context, sc *scan.Scan, def scangov.Definition, facts scangov.Facts, actor string) error {
	m, st, err := s.rules(ctx, sc.TenantID)
	if err != nil {
		return fmt.Errorf("scan approval could not be checked, run refused: %w", err)
	}
	if m == scangov.ModeOff {
		return nil
	}
	if err := s.requireRepo(); err != nil {
		return fmt.Errorf("scan approval could not be checked, run refused: %w", err)
	}
	fallback := actor
	if fallback == "" {
		fallback = creatorOf(sc)
	}
	facts, err = s.withRequester(ctx, sc.TenantID, st.Rules, facts, fallback, s.clock())
	if err != nil {
		return fmt.Errorf("scan approval could not be checked, run refused: %w", err)
	}
	ev := scangov.Evaluate(m, st.Rules, facts)
	actx := auditapp.AuditContext{ActorID: actor}
	if !ev.Required {
		if len(ev.Monitored) > 0 {
			s.logAudit(ctx, actx, sc.TenantID, auditapp.NewSuccessEvent(audit.ActionScanApprovalMonitored, audit.ResourceTypeScanConfig, sc.ID.String()).
				WithResourceName(sc.Name).
				WithMessage("A monitor-mode approval rule caught this run; it was not held").
				WithMetadata("rules", ruleNames(ev.Monitored)))
		}
		return nil
	}
	now, digest := s.clock(), def.Digest()
	approved, err := s.repo.ApprovedFor(ctx, sc.TenantID, sc.ID, digest)
	if err != nil {
		return fmt.Errorf("scan approval could not be checked, run refused: %w", err)
	}
	if approved != nil && approved.Authorizes(digest, now) && satisfies(approved, ev) {
		if approved.Evaluation.Validity != scangov.ValidityRun {
			return nil
		}
		ok, err := s.repo.Consume(ctx, sc.TenantID, approved.ID, now)
		if err != nil {
			return fmt.Errorf("scan approval could not be checked, run refused: %w", err)
		}
		if ok {
			return nil
		}
	}
	pending, err := s.repo.Pending(ctx, sc.TenantID, sc.ID)
	if err != nil {
		return fmt.Errorf("scan approval could not be checked, run refused: %w", err)
	}
	refusal := scangov.ErrApprovalRequired
	if pending != nil && pending.IsPending(now) && pending.Digest == digest {
		refusal = scangov.ErrApprovalPending
	}
	s.logAudit(ctx, actx, sc.TenantID, auditapp.NewFailureEvent(audit.ActionScanApprovalRefused, audit.ResourceTypeScanConfig, sc.ID.String(), refusal).
		WithResourceName(sc.Name).
		WithMessage("Run refused: the scan needs an approval it does not have").
		WithMetadata("rules", ruleNames(ev.Matched)))
	return refusal
}
