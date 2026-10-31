package tenantai

// Automatic AI triage policy (docs/architecture/ai-triage.md, "Automatic
// triage"): whether new findings are sent to the AI provider without a person
// asking, for which severities, and after what delay.
//
// Security model: the route needs an owner or administrator with
// settings:write. A change that sends more without a person asking (turning
// it on, adding a severity while on) is a loosening: it needs a recent
// re-authentication, is audited at high severity and every owner and
// administrator is told. Tightening (off, fewer severities) and the delay
// need neither, so turning it off in an incident is one click.

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// LooseningNotifier tells the organization's owners and administrators that
// a policy was loosened (*tenant.TenantService).
type LooseningNotifier interface {
	NotifyPolicyLoosened(ctx context.Context, tenantID string, actx auditapp.AuditContext, title, what, url string)
}

// ErrAutoTriageUnavailable: the store cannot write the policy.
var ErrAutoTriageUnavailable = fmt.Errorf("%w: automatic triage policy store not wired", shared.ErrInternal)

// SetStepUpGate wires the recent re-authentication asked for a loosening.
// Without it (a service built outside the HTTP server) the check is skipped.
func (s *Service) SetStepUpGate(g shared.RecentAuthGate) { s.stepUp = g }

// SetLooseningNotifier wires the owner and administrator notice.
func (s *Service) SetLooseningNotifier(n LooseningNotifier) { s.notifier = n }

// SetAutoTriageDefaults wires the platform defaults that apply to keys an
// organization never saved.
func (s *Service) SetAutoTriageDefaults(fn func() tenant.AISettings) { s.defaults = fn }

func (s *Service) autoTriageDefaults() tenant.AISettings {
	if s.defaults == nil {
		return tenant.AISettings{}
	}
	return s.defaults()
}

// AutoTriageView is the policy in force with the platform defaults applied.
type AutoTriageView struct {
	tenant.AutoTriagePolicy
	// Loosened reports that the saved change was a loosening (audited high,
	// owners and administrators told).
	Loosened bool
}

// GetAutoTriage returns the automatic triage policy in force.
func (s *Service) GetAutoTriage(ctx context.Context, tenantID string) (tenant.AutoTriagePolicy, error) {
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return tenant.AutoTriagePolicy{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	a, err := s.repo.Get(ctx, tid, s.autoTriageDefaults())
	if err != nil {
		return tenant.AutoTriagePolicy{}, err
	}
	p := a.AutoTriagePolicy()
	if n, err := p.Normalized(); err == nil {
		p = n
	}
	return p, nil
}

// SaveAutoTriage replaces the automatic triage policy (every key written).
func (s *Service) SaveAutoTriage(ctx context.Context, tenantID string, in tenant.AutoTriagePolicy, actx auditapp.AuditContext) (AutoTriageView, error) {
	store, ok := s.repo.(tenant.AutoTriagePolicyRepository)
	if !ok {
		return AutoTriageView{}, ErrAutoTriageUnavailable
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return AutoTriageView{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	next, err := in.Normalized()
	if err != nil {
		return AutoTriageView{}, err
	}
	before, err := s.GetAutoTriage(ctx, tenantID)
	if err != nil {
		return AutoTriageView{}, err
	}
	loosened := tenant.AutoTriageLoosened(before, next)
	if loosened {
		// A loosening is a person's decision: never made without one, and
		// never on a stale sign-in.
		if actx.ActorID == "" {
			return AutoTriageView{}, ErrNoActor
		}
		if s.stepUp != nil {
			if err := s.stepUp.RequireRecentAuth(ctx, actx.ActorID); err != nil {
				return AutoTriageView{}, err
			}
		}
	}
	if err := store.SaveAutoTriagePolicy(ctx, tid, next); err != nil {
		return AutoTriageView{}, err
	}

	actx.TenantID = tenantID
	severity := audit.SeverityMedium
	if loosened {
		severity = audit.SeverityHigh
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionAIAutoTriageUpdated, audit.ResourceTypeTenant, tenantID).
		WithChanges(auditapp.DiffChanges(
			map[string]any{"enabled": before.Enabled, "severities": before.Severities, "delay_seconds": before.DelaySeconds},
			map[string]any{"enabled": next.Enabled, "severities": next.Severities, "delay_seconds": next.DelaySeconds})).
		WithMetadata("loosened", loosened).
		WithMessage(autoTriageMessage(before, next, loosened)).
		WithSeverity(severity))
	if loosened && s.notifier != nil {
		s.notifier.NotifyPolicyLoosened(ctx, tenantID, actx, "Automatic AI triage widened",
			fmt.Sprintf("automatic AI triage: new %s findings are now sent to the AI provider without a person asking",
				strings.Join(next.Severities, ", ")), "/settings/ai")
	}
	return AutoTriageView{AutoTriagePolicy: next, Loosened: loosened}, nil
}

func autoTriageMessage(before, next tenant.AutoTriagePolicy, loosened bool) string {
	switch {
	case !before.Enabled && next.Enabled:
		return "Automatic AI triage turned on"
	case before.Enabled && !next.Enabled:
		return "Automatic AI triage turned off"
	case loosened:
		return "Automatic AI triage widened to more severities"
	default:
		return "Automatic AI triage policy changed"
	}
}
