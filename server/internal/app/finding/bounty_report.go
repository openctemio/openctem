package finding

// Report fields of findings filed from a bug-bounty or disclosure program.
// https://github.com/openctemio/openctem/blob/develop/api/docs/rfcs/RFC-121-bug-bounty-reports.md

import (
	"context"
	"fmt"
	"time"

	"github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// ErrBountyTriageRequired: setting or changing a report's reward or
// disclosure is a triage decision (findings:triage), not an edit.
var ErrBountyTriageRequired = shared.NewDomainError("TRIAGE_PERMISSION_REQUIRED",
	"Setting or changing the reward or disclosure needs the findings:triage permission", shared.ErrForbidden)

// UpdateBountyReportInput replaces the report object of a bug_bounty finding.
type UpdateBountyReportInput struct {
	TenantID  string
	FindingID string
	Report    vulnerability.BountyReport
	// CanTriage: the caller holds findings:triage (reward and disclosure).
	CanTriage bool
	ActorID   string
	Audit     audit.AuditContext
}

// UpdateBountyReport replaces the report object of a bug_bounty finding in
// the caller's tenant and data scope (out of scope: not found). Intake and
// ref cannot change once set; a reward or disclosure change needs
// CanTriage. Every change is audited with its old and new values.
func (s *VulnerabilityService) UpdateBountyReport(ctx context.Context, in UpdateBountyReportInput) (*vulnerability.Finding, error) {
	tenantID, err := shared.IDFromString(in.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id format", shared.ErrValidation)
	}
	id, err := shared.IDFromString(in.FindingID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	f, err := s.findingRepo.GetByID(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	if err := s.assertFindingScope(ctx, f); err != nil {
		return nil, err
	}
	if f.Source() != vulnerability.FindingSourceBugBounty {
		return nil, vulnerability.ErrBountyReportSource
	}
	old := f.BountyReport()
	next := in.Report.Normalized()
	var prev vulnerability.BountyReport
	if old != nil {
		prev = *old
	}
	if (!next.RewardEqual(prev) || !next.DisclosureEqual(prev)) && !in.CanTriage {
		return nil, ErrBountyTriageRequired
	}
	if err := f.SetBountyReport(next, time.Now()); err != nil {
		return nil, err
	}
	stored := f.BountyReport()
	changes := bountyReportChanges(old, stored)
	if len(changes) == 0 {
		return f, nil
	}
	if err := s.findingRepo.Update(ctx, f); err != nil {
		return nil, err
	}
	s.auditBountyReport(ctx, in.Audit, in.TenantID, in.ActorID, f, stored, changes)
	return f, nil
}

// applyBountyReportOnCreate attaches the report of a new finding: only to a
// bug_bounty finding, and a reward or disclosure only with CanTriage.
func applyBountyReportOnCreate(f *vulnerability.Finding, r *vulnerability.BountyReport, canTriage bool) error {
	if r == nil {
		return nil
	}
	if f.Source() != vulnerability.FindingSourceBugBounty {
		return vulnerability.ErrBountyReportSource
	}
	if r.Normalized().SetsRewardOrDisclosure() && !canTriage {
		return ErrBountyTriageRequired
	}
	return f.SetBountyReport(*r, time.Now())
}

// autoTriageAllowed reports whether a new finding may go to AI triage
// automatically. A bug-bounty report is text written by an outside person:
// it goes to AI triage only when someone asks for it.
func autoTriageAllowed(f *vulnerability.Finding) bool {
	return f.Source() != vulnerability.FindingSourceBugBounty
}

// bountyFieldChange is one changed report field in the audit row.
type bountyFieldChange struct {
	Old any `json:"old"`
	New any `json:"new"`
}

// bountyReportChanges lists the fields that differ between two report
// objects (nil: none), as their stored values.
func bountyReportChanges(old, next *vulnerability.BountyReport) map[string]bountyFieldChange {
	var a, b map[string]any
	if old != nil {
		a = old.Meta()
	}
	if next != nil {
		b = next.Meta()
	}
	out := map[string]bountyFieldChange{}
	for k, v := range b {
		if fmt.Sprint(a[k]) != fmt.Sprint(v) {
			out[k] = bountyFieldChange{Old: a[k], New: v}
		}
	}
	for k, v := range a {
		if _, ok := b[k]; !ok {
			out[k] = bountyFieldChange{Old: v, New: nil}
		}
	}
	return out
}

func (s *VulnerabilityService) auditBountyReport(ctx context.Context, actx audit.AuditContext, tenantID, actorID string,
	f *vulnerability.Finding, r *vulnerability.BountyReport, changes map[string]bountyFieldChange) {
	if s.auditService == nil || r == nil {
		return
	}
	if actx.TenantID == "" {
		actx.TenantID = tenantID
	}
	if actx.ActorID == "" {
		actx.ActorID = actorID
	}
	sev := auditdom.SeverityLow
	if _, ok := changes["reward"]; ok {
		sev = auditdom.SeverityMedium
	}
	if _, ok := changes["disclosure"]; ok {
		sev = auditdom.SeverityMedium
	}
	event := audit.NewSuccessEvent(auditdom.ActionFindingBountyReportChanged, auditdom.ResourceTypeFinding, f.ID().String()).
		WithMessage("Changed the bug-bounty report fields of a finding").
		WithMetadata("intake", r.Intake).
		WithMetadata("ref", r.Ref).
		WithMetadata("changes", changes).
		WithSeverity(sev)
	if err := s.auditService.LogEvent(ctx, actx, event); err != nil {
		s.logger.Warn("failed to audit bounty report change", "error", err)
	}
}
