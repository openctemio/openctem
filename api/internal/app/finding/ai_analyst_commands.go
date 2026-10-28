package finding

import (
	"context"

	"github.com/openctemio/openctem/api/internal/app/aianalysis"
	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/vulnerability"
)

// AIAnalystCommands are the finding commands an AI analyst calls
// (docs/architecture/ai-analysis.md). They are the same service methods a
// person's request reaches, with the analyst as the actor. The analyst never
// approves: every call passes CanApprove=false, so a change that lowers risk
// always becomes a request a person decides. The caller (the executor) has
// checked the analyst's effective permission and data scope, and put the AI
// provenance in ctx.
type AIAnalystCommands struct {
	Findings *VulnerabilityService
}

var _ aianalysis.FindingCommands = AIAnalystCommands{}

// aiFalsePositiveReason is the closure reason of an AI false-positive
// request: the detection is in error. The person who decides may change it.
const aiFalsePositiveReason = string(vulnerability.ClosureReasonDetectionError)

func auditFor(tenantID, actorID shared.ID) auditapp.AuditContext {
	return auditapp.AuditContext{TenantID: tenantID.String(), ActorID: actorID.String()}
}

// Comment adds an internal comment by the analyst: shown to members, never
// sent to a ticket, integration or external notifier.
func (c AIAnalystCommands) Comment(ctx context.Context, tenantID, findingID, actorID shared.ID, text string) error {
	_, err := c.Findings.AddFindingCommentWithInput(ctx, AddFindingCommentInput{
		TenantID: tenantID.String(), FindingID: findingID.String(), AuthorID: actorID.String(), Content: text,
		IsInternal: true, ActingUserID: actorID.String(),
	})
	return err
}

// SetStatus moves the finding through the lifecycle engine as the analyst
// (no verify, fix-apply or approve permission: those are people's).
func (c AIAnalystCommands) SetStatus(ctx context.Context, tenantID, findingID, actorID shared.ID, status string) error {
	_, err := c.Findings.UpdateFindingStatus(ctx, findingID.String(), tenantID.String(), UpdateFindingStatusInput{
		Status: status, ActorID: actorID.String(),
	})
	return err
}

// ChangeSeverity changes the severity as the analyst; a downgrade the policy
// gates becomes a severity request (requested true).
func (c AIAnalystCommands) ChangeSeverity(ctx context.Context, tenantID, findingID, actorID shared.ID, severity, reason string) (bool, error) {
	res, err := c.Findings.ChangeFindingSeverity(ctx, ChangeSeverityInput{
		TenantID: tenantID.String(), FindingID: findingID.String(), ActorID: actorID.String(),
		Severity: severity, Reason: reason, CanApprove: false, Audit: auditFor(tenantID, actorID),
	})
	if err != nil {
		return false, err
	}
	return res.Request != nil, nil
}

// RequestFalsePositive opens a false-positive approval request by the
// analyst; it always waits for a person.
func (c AIAnalystCommands) RequestFalsePositive(ctx context.Context, tenantID, findingID, actorID shared.ID, justification string) error {
	_, err := c.Findings.RequestApproval(ctx, RequestApprovalInput{
		TenantID: tenantID.String(), FindingID: findingID.String(),
		RequestedStatus: string(vulnerability.FindingStatusFalsePositive), Justification: justification,
		RequestedBy: actorID.String(), ClosureReason: aiFalsePositiveReason, CanApprove: false,
	})
	return err
}
