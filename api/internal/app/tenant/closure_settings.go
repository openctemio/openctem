package tenant

import (
	"context"
	"fmt"
	"time"

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
	cs := t.TypedSettings().Closure.ViewAt(time.Now())
	return &cs, nil
}

// UpdateClosureSettings chooses the organization's closing policy.
// Loosening it (more automation, or critical findings out of review) needs a
// recent authentication, waits tenant.ClosureRelaxationDelay before it takes
// effect, is audited high and tells every owner and administrator; turning
// critical auto-close on is for the owner only. Tightening is immediate,
// cancels a waiting loosening and is audited at the normal severity.
// It returns the policy in force with the waiting loosening, if any.
func (s *TenantService) UpdateClosureSettings(
	ctx context.Context,
	tenantID string,
	cs tenantdom.ClosureSettings,
	actx auditapp.AuditContext,
) (*tenantdom.ClosureSettings, error) {
	next := tenantdom.ClosureSettings{Mode: cs.Mode, CriticalAutoClose: cs.CriticalAutoClose}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	now := time.Now()
	var before tenantdom.ClosureSettings
	loosened := false
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionClosure, func(t *tenantdom.Tenant) error {
		stored := t.TypedSettings().Closure
		before = stored.EffectiveAt(now)
		if next.CriticalAutoClose && !before.CriticalAutoClose {
			if err := s.requireOrgOwner(ctx, t.ID(), actx.ActorID); err != nil {
				return err
			}
		}
		loosened = before.Loosens(next)
		if loosened {
			if err := s.requireStepUp(ctx, actx.ActorID); err != nil {
				return err
			}
		}
		if _, err := stored.Choose(next, now); err != nil {
			return err
		}
		return t.UpdateClosureSettings(stored)
	})
	if err != nil {
		return nil, err
	}

	view := t.TypedSettings().Closure.ViewAt(now)
	actx.TenantID = tenantID
	event := auditapp.NewSuccessEvent(audit.ActionTenantClosureUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(before, next)).
		WithMessage("Closing mode updated").
		WithMetadata("mode_before", string(before.EffectiveMode())).
		WithMetadata("mode_after", string(next.EffectiveMode())).
		WithMetadata("critical_auto_close_before", before.CriticalAutoClose).
		WithMetadata("critical_auto_close_after", next.CriticalAutoClose).
		WithMetadata("loosened", loosened)
	if loosened && view.PendingAt != nil {
		at := view.PendingAt.UTC().Format(time.RFC3339)
		event = event.WithSeverity(audit.SeverityHigh).WithMetadata("takes_effect_at", at)
		s.notifyPolicyLoosened(ctx, tenantID, actx, "Closing mode loosened",
			fmt.Sprintf("how findings close (mode %s, critical findings without review: %t), taking effect at %s unless an owner or administrator cancels it",
				next.EffectiveMode(), next.CriticalAutoClose, at),
			"/settings/closing-findings")
	}
	s.logAudit(ctx, actx, event)
	return &view, nil
}

// CancelPendingClosureSettings drops a waiting loosening of the closing
// policy; the policy in force stays. Audited; tightening, so no step-up.
// It returns the policy in force.
func (s *TenantService) CancelPendingClosureSettings(ctx context.Context, tenantID string, actx auditapp.AuditContext) (*tenantdom.ClosureSettings, error) {
	now := time.Now()
	canceled := false
	var dropped tenantdom.ClosureSettings
	t, err := s.writeSettingsSection(ctx, tenantID, tenantdom.SectionClosure, func(t *tenantdom.Tenant) error {
		stored := t.TypedSettings().Closure
		dropped, _, _ = stored.PendingIn(now)
		canceled = stored.CancelPending(now)
		return t.UpdateClosureSettings(stored)
	})
	if err != nil {
		return nil, err
	}
	view := t.TypedSettings().Closure.ViewAt(now)
	if canceled {
		actx.TenantID = tenantID
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionTenantClosureUpdated, audit.ResourceTypeTenant, tenantID).
			WithMessage("Waiting closing mode change canceled").
			WithMetadata("canceled_mode", string(dropped.EffectiveMode())).
			WithMetadata("canceled_critical_auto_close", dropped.CriticalAutoClose).
			WithMetadata("mode_after", string(view.EffectiveMode())))
	}
	return &view, nil
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
