package finding

import (
	"context"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	auditdom "github.com/openctemio/openctem/api/pkg/domain/audit"

	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AssertFindingForFixWork is AssertFindingAccess for a route of the fix
// workflow: a finding outside the caller's data scope is admitted too when
// the caller owns a live remediation task holding it (viaTask). A pentest
// finding is never admitted through the relation: its campaign membership
// rule decides.
func (s *VulnerabilityService) AssertFindingForFixWork(ctx context.Context, tenantID, findingID shared.ID) (bool, error) {
	if err := s.AssertFindingAccess(ctx, tenantID, findingID); err == nil {
		return false, nil
	}
	if s.dataScope == nil {
		return false, shared.ErrNotFound
	}
	// The relation query leaves pentest findings out; the by-id guard has
	// already refused this one on its own rule.
	return s.dataScope.AssertFindingForFixWork(ctx, tenantID, findingID)
}

// viaTaskOwner reports whether the request reaches finding f through the
// task-owner relation (set by the by-id guard, re-checked here).
func (s *VulnerabilityService) viaTaskOwner(ctx context.Context, f *vulnerability.Finding) bool {
	return s.dataScope != nil && !isPentest(f) && s.dataScope.TaskOwnerMay(ctx, f.TenantID(), f.ID())
}

// visibleForMove keeps the findings in the caller's data scope, plus, for a
// person, the ones in a live task they own: the engine then allows them the
// fix moves only (facts.TaskOwnerOnly), so a disposition or a resolve on such
// a finding is refused with its own reason.
func (s *VulnerabilityService) visibleForMove(ctx context.Context, tenantID shared.ID, actor vulnerability.TransitionActor,
	findings []*vulnerability.Finding,
) (map[shared.ID]*vulnerability.Finding, error) {
	out, err := s.visibleFindings(ctx, tenantID, findings)
	if err != nil {
		return nil, err
	}
	for id := range s.taskOwnedOutsideScope(ctx, tenantID, actor, findings, out) {
		for _, f := range findings {
			if f.ID() == id {
				out[id] = f
			}
		}
	}
	return out, nil
}

// taskOwnedOutsideScope returns the findings among findings, not in inScope,
// that the actor reaches as the owner of a live task holding them. Only a
// person acting as the request's caller qualifies; a pentest finding never.
func (s *VulnerabilityService) taskOwnedOutsideScope(ctx context.Context, tenantID shared.ID, actor vulnerability.TransitionActor,
	findings []*vulnerability.Finding, inScope map[shared.ID]*vulnerability.Finding,
) map[shared.ID]bool {
	out := map[shared.ID]bool{}
	if s.dataScope == nil || !actor.IsPerson() {
		return out
	}
	if c := s.dataScope.CallerOf(ctx); c.APIKey || c.UserID != actor.UserID.String() {
		return out
	}
	var rest []shared.ID
	for _, f := range findings {
		if _, ok := inScope[f.ID()]; !ok && !isPentest(f) {
			rest = append(rest, f.ID())
		}
	}
	if len(rest) == 0 {
		return out
	}
	owned, err := s.dataScope.OwnedViaTask(ctx, tenantID, actor.UserID, rest)
	if err != nil {
		s.logger.Warn("task ownership check failed", "error", err)
		return out
	}
	for _, id := range rest {
		if owned(id) {
			out[id] = true
		}
	}
	return out
}

// taskOwnerOnly marks, for the facts of a move, the findings the actor
// reaches only as the owner of a live task holding them.
func (s *VulnerabilityService) taskOwnerOnly(ctx context.Context, tenantID shared.ID, actor vulnerability.TransitionActor,
	findings []*vulnerability.Finding,
) map[shared.ID]bool {
	if s.dataScope == nil || !actor.IsPerson() || len(findings) == 0 {
		return nil
	}
	inScope, err := s.visibleFindings(ctx, tenantID, findings)
	if err != nil {
		return nil
	}
	return s.taskOwnedOutsideScope(ctx, tenantID, actor, findings, inScope)
}

// auditTaskOwnerMove records that the actor moved finding f to status to as
// the owner of a live task holding it, the finding being outside their data
// scope (best effort: the move already happened and has its own activity).
func (s *VulnerabilityService) auditTaskOwnerMove(ctx context.Context, actorID string, f *vulnerability.Finding, from, to vulnerability.FindingStatus) {
	if s.auditService == nil || f == nil {
		return
	}
	event := auditapp.NewSuccessEvent(auditdom.ActionRemediationTaskOwnerMoved, auditdom.ResourceTypeFinding, f.ID().String()).
		WithMessage("Task owner moved a finding of their task that is outside their data scope").
		WithSeverity(auditdom.SeverityMedium).
		WithMetadata("from", string(from)).
		WithMetadata("to", string(to)).
		WithMetadata("asset_id", f.AssetID().String())
	if err := s.auditService.LogEvent(ctx, auditapp.AuditContext{TenantID: f.TenantID().String(), ActorID: actorID}, event); err != nil {
		s.logger.Warn("failed to audit a task owner's move", "error", err)
	}
}
