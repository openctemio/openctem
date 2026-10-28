package finding

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AIActions are the finding paths the AI apply engine uses
// (docs/architecture/ai-analysis.md). Every change goes through the same
// service method, rules and approvals as a change made by hand.
type AIActions struct{ S *VulnerabilityService }

var _ aianalysis.FindingActions = AIActions{}

// ChangeSeverityAsPerson changes the severity as the person.
func (a AIActions) ChangeSeverityAsPerson(ctx context.Context, tenantID, findingID, actorID shared.ID, severity string, restore bool, reason string, canApprove bool) (aianalysis.SeverityChange, error) {
	res, err := a.S.ChangeFindingSeverity(ctx, ChangeSeverityInput{
		TenantID:   tenantID.String(),
		FindingID:  findingID.String(),
		ActorID:    actorID.String(),
		Severity:   severity,
		Restore:    restore,
		Reason:     reason,
		CanApprove: canApprove,
		Audit:      auditapp.AuditContext{TenantID: tenantID.String(), ActorID: actorID.String()},
	})
	if err != nil {
		return aianalysis.SeverityChange{}, err
	}
	out := aianalysis.SeverityChange{Applied: res.Applied}
	if res.Request != nil {
		id := res.Request.ID
		out.RequestID = &id
	}
	return out, nil
}

// RequestFalsePositiveAsPerson asks for the false-positive status as the person.
func (a AIActions) RequestFalsePositiveAsPerson(ctx context.Context, tenantID, findingID, actorID shared.ID, closureReason, justification string, canApprove bool) (shared.ID, error) {
	ap, err := a.S.RequestApproval(ctx, RequestApprovalInput{
		TenantID:        tenantID.String(),
		FindingID:       findingID.String(),
		RequestedStatus: string(vulnerability.FindingStatusFalsePositive),
		Justification:   justification,
		RequestedBy:     actorID.String(),
		ClosureReason:   closureReason,
		CanApprove:      canApprove,
	})
	if err != nil {
		return shared.ID{}, err
	}
	return ap.ID, nil
}

// ProposeFalsePositiveAsAI opens a pending false-positive request as the AI actor.
func (a AIActions) ProposeFalsePositiveAsAI(ctx context.Context, tenantID, findingID shared.ID, likelihood float64, rationale string) (*shared.ID, error) {
	return a.S.proposeFalsePositiveFromAI(ctx, tenantID, findingID, likelihood, rationale)
}
