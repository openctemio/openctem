package ioc

import (
	"context"
	"errors"
	"fmt"

	"github.com/openctemio/api/internal/app"
	"github.com/openctemio/api/pkg/domain/audit"
	"github.com/openctemio/api/pkg/domain/shared"
	"github.com/openctemio/api/pkg/domain/vulnerability"
)

// FindingRepo is the narrow surface the adapter needs — load +
// persist. *postgres.FindingRepository satisfies it structurally.
type FindingRepo interface {
	GetByID(ctx context.Context, tenantID, id shared.ID) (*vulnerability.Finding, error)
	Update(ctx context.Context, f *vulnerability.Finding) error
}

// AuditLogger is the narrow surface the adapter uses to record the
// reopen. *app.AuditService satisfies it structurally.
type AuditLogger interface {
	LogEvent(ctx context.Context, actx app.AuditContext, event app.AuditEvent) error
}

// CampaignReopener reopens any completed remediation campaign that tracked the
// regressed finding, so a runtime re-open flows through to the mobilization
// state. *app.RemediationCampaignService satisfies it. Optional — nil skips it.
type CampaignReopener interface {
	ReopenCampaignsForFinding(ctx context.Context, tenantID, findingID shared.ID, reason string) (int, error)
}

// reopenAdapter implements FindingReopener on top of the existing
// finding repository and audit service. Kept in this package so the
// correlator's interface is the only contract the outside world
// sees; the concrete wiring is the adapter's job.
type reopenAdapter struct {
	findings  FindingRepo
	auditor   AuditLogger
	campaigns CampaignReopener // optional — reopen campaigns tracking the finding
}

// SetCampaignReopener wires the (optional) campaign-reopen side effect. Set at
// the composition root once the remediation service exists.
func (a *reopenAdapter) SetCampaignReopener(r CampaignReopener) { a.campaigns = r }

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
	// Domain workflow only allows closed → confirmed (back to triage).
	// The operator triages again and re-drives through in_progress /
	// fix_applied. Forcing all closed states through this one edge
	// keeps the transition graph simple and auditable.
	if err := f.TransitionStatus(vulnerability.FindingStatusConfirmed, reason, nil); err != nil {
		return false, fmt.Errorf("transition: %w", err)
	}
	if err := a.findings.Update(ctx, f); err != nil {
		return false, fmt.Errorf("persist reopen: %w", err)
	}

	if a.auditor != nil {
		ev := app.NewSuccessEvent(audit.ActionFindingStatusChanged, audit.ResourceTypeFinding, findingID.String()).
			WithMessage(reason).
			WithMetadata("previous_status", string(prev)).
			WithMetadata("new_status", string(vulnerability.FindingStatusInProgress)).
			WithMetadata("source", "ioc_correlator").
			WithSeverity(audit.SeverityHigh)
		_ = a.auditor.LogEvent(ctx, app.AuditContext{TenantID: tenantID.String()}, ev)
	}

	// A resolved finding just regressed — reopen any completed campaign that was
	// tracking it so mobilization reflects the re-open. Best-effort; a failure
	// here must not fail the finding reopen itself.
	if a.campaigns != nil {
		if _, cerr := a.campaigns.ReopenCampaignsForFinding(ctx, tenantID, findingID, reason); cerr != nil {
			// logged by the reopener; nothing else to do here
			_ = cerr
		}
	}
	return true, nil
}
