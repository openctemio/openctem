package tenant

import (
	"context"
	"fmt"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	tenantdom "github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ErrCriticalAutoCloseOwnerOnly: only the organization owner may let a plain
// covered scan close critical, P0 and KEV findings.
var ErrCriticalAutoCloseOwnerOnly = fmt.Errorf("%w: only the organization owner can let scans close critical findings without review", shared.ErrForbidden)

// GetClosureSettings returns the organization's closing policy. It also
// serves the ingest evaluator and the verification plan.
func (s *TenantService) GetClosureSettings(ctx context.Context, tenantID string) (*tenantdom.ClosureSettings, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	t, err := s.repo.GetByID(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	cs := t.TypedSettings().Closure
	return &cs, nil
}

// UpdateClosureSettings replaces the organization's closing policy.
// Loosening it (more automation, or critical findings out of review) needs a
// recent authentication, is audited high and tells every owner and
// administrator; turning critical auto-close on is for the owner only.
// Tightening is immediate and audited at the normal severity.
func (s *TenantService) UpdateClosureSettings(
	ctx context.Context,
	tenantID string,
	cs tenantdom.ClosureSettings,
	actx auditapp.AuditContext,
) (*tenantdom.ClosureSettings, error) {
	if err := cs.Validate(); err != nil {
		return nil, err
	}
	var before tenantdom.ClosureSettings
	loosened := false
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionClosure, func(t *tenantdom.Tenant) error {
		before = t.TypedSettings().Closure
		if cs.CriticalAutoClose && !before.CriticalAutoClose {
			if err := s.requireOrgOwner(ctx, t.ID(), actx.ActorID); err != nil {
				return err
			}
		}
		loosened = before.Loosens(cs)
		if loosened {
			if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
				return err
			}
		}
		return t.UpdateClosureSettings(cs)
	})
	if err != nil {
		return nil, err
	}

	after := t.TypedSettings().Closure
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantClosureUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, after)).
		WithMessage("Closing mode updated").
		WithMetadata("mode_before", string(before.EffectiveMode())).
		WithMetadata("mode_after", string(after.EffectiveMode())).
		WithMetadata("critical_auto_close_before", before.CriticalAutoClose).
		WithMetadata("critical_auto_close_after", after.CriticalAutoClose).
		WithMetadata("loosened", loosened)
	if loosened {
		event = event.WithSeverity(audit.SeverityHigh)
		s.notifyPolicyLoosened(ctx, tenantID, actx, "Closing mode loosened",
			fmt.Sprintf("how findings close (mode %s, critical findings without review: %t)", after.EffectiveMode(), after.CriticalAutoClose),
			"/findings")
	}
	s.logAudit(ctx, actx, event)
	return &after, nil
}

// requireOrgOwner refuses unless actorID is an active owner of the
// organization. A system path (no human actor) is refused too.
func (s *TenantService) requireOrgOwner(ctx context.Context, tenantID shared.ID, actorID string) error {
	uid, err := shared.IDFromString(actorID)
	if err != nil || uid.IsZero() {
		return ErrCriticalAutoCloseOwnerOnly
	}
	m, err := s.repo.GetMembership(ctx, uid, tenantID)
	if err != nil || m == nil || !m.IsActive() || !m.IsOwner() {
		return ErrCriticalAutoCloseOwnerOnly
	}
	return nil
}
