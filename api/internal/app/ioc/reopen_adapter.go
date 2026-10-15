package ioc

import (
	"context"
	"errors"
	"fmt"

	auditsvc "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// FindingRepo is the narrow surface the adapter needs — load, persist,
// and flag a decision for review. *postgres.FindingRepository satisfies it
// structurally.
type FindingRepo interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
	Update(ctx context.Context, f *vulnerability.Finding) error
	RaiseDecisionReview(ctx context.Context, tenantID, findingID shared.ID, reason string, evidence map[string]any) (bool, error)
}

// decisionReviewIOCMatch is the review reason an IOC match raises on a
// decided finding (postgres.DecisionReviewIOCMatch).
const decisionReviewIOCMatch = "ioc_match"

// AuditLogger is the narrow surface the adapter uses to record the
// reopen. *app.AuditService satisfies it structurally.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx auditsvc.AuditContext, event auditsvc.AuditEvent) error
}

// reopenAdapter implements FindingReopener on top of the existing
// finding repository and audit service. Kept in this package so the
// correlator's interface is the only contract the outside world
// sees; the concrete wiring is the adapter's job.
type reopenAdapter struct {
	findings FindingRepo
	auditor  AuditLogger
}

// NewFindingReopener returns a FindingReopener backed by the real
// finding repo + audit service. Pass a nil auditor to skip audit
// logging (not recommended; B6 promises an audit trail).
func NewFindingReopener(repo FindingRepo, auditor AuditLogger) FindingReopener {
	return &reopenAdapter{findings: repo, auditor: auditor}
}

// ReopenForIOCMatch loads the finding, checks it's actually closed,
// transitions it to in_progress, persists, then emits the audit
// event. Returns (true, nil) on a real reopen; (false, nil) when the
// finding was already open (benign no-op).
func (a *reopenAdapter) ReopenForIOCMatch(
	ctx context.Context,
	tenantID, findingID shared.ID,
	reason string,
) (bool, error) {
	f, err := a.findings.GetByID(ctx, tenantID, findingID)
	if err != nil {
		return false, fmt.Errorf("load finding: %w", err)
	}
	// Defence in depth — the tenant-scoped GetByID already guarantees
	// the finding belongs to this tenant, but re-check so a mis-sized
	// mock in tests can't hide a real bug.
	if f.TenantID() != tenantID {
		return false, errors.New("ioc reopen: tenant mismatch")
	}
	prev := f.Status()
	if !prev.IsClosed() {
		return false, nil
	}
	// A person's decision (false positive, accepted risk, duplicate) is never
	// reversed by a correlator: the match raises a review flag, with a
	// timeline entry, for a person with the approve permission to decide.
	// Only a finding closed as fixed reopens (the match is evidence it is
	// not fixed).
	if vulnerability.IsDispositionedStatus(prev) {
		raised, err := a.findings.RaiseDecisionReview(ctx, tenantID, findingID, decisionReviewIOCMatch,
			map[string]any{"match": reason})
		if err != nil {
			return false, fmt.Errorf("flag decision for review: %w", err)
		}
		if raised && a.auditor != nil {
			ev := auditsvc.NewSuccessEvent(audit.ActionFindingStatusChanged, audit.ResourceTypeFinding, findingID.String()).
				WithMessage("decision flagged for review: "+reason).
				WithMetadata("decision_status", string(prev)).
				WithMetadata("source", "ioc_correlator").
				WithSeverity(audit.SeverityHigh)
			_ = a.auditor.LogEvent(ctx, auditsvc.AuditContext{TenantID: tenantID.String()}, ev)
		}
		return false, nil
	}
	// Domain workflow only allows closed → confirmed (back to triage).
	// The operator triages again and re-drives through in_progress /
	// fix_applied. Forcing all closed states through this one edge
	// keeps the transition graph simple and auditable.
	if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, reason, nil); err != nil {
		return false, fmt.Errorf("transition: %w", err)
	}
	// The reopen and its timeline entry commit together.
	moveCtx := vulnerability.WithStatusTransition(ctx, vulnerability.StatusTransition{
		Source: "ioc_correlator", Reason: "ioc_match", ActorName: "system: IOC correlator", Message: reason,
	})
	if err := a.findings.Update(moveCtx, f); err != nil {
		return false, fmt.Errorf("persist reopen: %w", err)
	}

	if a.auditor != nil {
		ev := auditsvc.NewSuccessEvent(audit.ActionFindingStatusChanged, audit.ResourceTypeFinding, findingID.String()).
			WithMessage(reason).
			WithMetadata("previous_status", string(prev)).
			WithMetadata("new_status", string(vulnerability.FindingStatusConfirmed)).
			WithMetadata("source", "ioc_correlator").
			WithSeverity(audit.SeverityHigh)
		_ = a.auditor.LogEvent(ctx, auditsvc.AuditContext{TenantID: tenantID.String()}, ev)
	}
	return true, nil
}
