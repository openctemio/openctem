package tenantai

// Per-use-case AI settings (docs/architecture/ai-use-cases.md): for triage,
// remediation steps and summary, whether results wait for a person or apply
// on their own, the most sensitive data class sent, and the minimum
// confidence to apply on its own.
//
// Security model: reading needs settings:read; writing needs an owner or
// administrator with settings:write (route). A loosening (auto-apply on,
// ceiling above internal, lower confidence while auto-applying) is a
// person's decision on a fresh sign-in: it needs a recent re-authentication,
// is audited critical and every owner and administrator is told. Tightening
// (off, suggest, a lower ceiling) needs neither, so it is one click in an
// incident. The executors read the setting at every run (fail closed: an
// unreadable setting refuses the run).

import (
	"context"
	"fmt"
	"strings"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
)

// ErrUseCasesUnavailable: the store cannot read or write use case settings.
var ErrUseCasesUnavailable = fmt.Errorf("%w: AI use case store not wired", shared.ErrInternal)

// UseCaseView is one use case as an administrator sees it.
type UseCaseView struct {
	UseCase aidom.UseCase
	aidom.UseCaseSetting
	// Effective is the mode in force: off while AI is turned off for the
	// organization, whatever the stored mode.
	Effective aidom.UseCaseMode
	// Loosened (answer of a change) lists why the change was a loosening.
	Loosened []string
}

// UseCaseInput is a change of one use case.
type UseCaseInput struct {
	Mode          string
	Ceiling       string
	MinConfidence float64
}

func (s *Service) useCaseStore() (aidom.UseCaseRepository, bool) {
	r, ok := s.repo.(aidom.UseCaseRepository)
	return r, ok
}

// UseCases lists every use case in display order with the setting in force.
func (s *Service) UseCases(ctx context.Context, tenantID string) ([]UseCaseView, error) {
	store, ok := s.useCaseStore()
	if !ok {
		return nil, ErrUseCasesUnavailable
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	settings, err := s.repo.Get(ctx, tid, tenant.AISettings{})
	if err != nil {
		return nil, err
	}
	pol, err := store.GetUseCases(ctx, tid)
	if err != nil {
		return nil, err
	}
	on := settings.EffectiveMode() != tenant.AIModeDisabled
	out := make([]UseCaseView, 0, len(aidom.UseCases()))
	for _, uc := range aidom.UseCases() {
		set := pol.For(uc)
		eff := set.Mode
		if !on {
			eff = aidom.UseCaseOff
		}
		out = append(out, UseCaseView{UseCase: uc, UseCaseSetting: set, Effective: eff})
	}
	return out, nil
}

// UseCaseSetting returns one use case's setting for an executor. It does not
// look at the organization's consent (the executor checks that itself).
func (s *Service) UseCaseSetting(ctx context.Context, tenantID shared.ID, uc aidom.UseCase) (aidom.UseCaseSetting, error) {
	store, ok := s.useCaseStore()
	if !ok {
		return aidom.UseCaseSetting{}, ErrUseCasesUnavailable
	}
	pol, err := store.GetUseCases(ctx, tenantID)
	if err != nil {
		return aidom.UseCaseSetting{}, err
	}
	return pol.For(uc), nil
}

// SaveUseCase changes one use case. Turning auto-apply on (also after an
// automatic downgrade) clears the downgrade and restarts the window of
// decisions that can trigger the next one.
func (s *Service) SaveUseCase(ctx context.Context, tenantID, useCase string, in UseCaseInput, actx auditapp.AuditContext) (UseCaseView, error) {
	store, ok := s.useCaseStore()
	if !ok {
		return UseCaseView{}, ErrUseCasesUnavailable
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return UseCaseView{}, fmt.Errorf("%w: invalid id format", shared.ErrValidation)
	}
	uc, err := aidom.ParseUseCase(useCase)
	if err != nil {
		return UseCaseView{}, err
	}
	pol, err := store.GetUseCases(ctx, tid)
	if err != nil {
		return UseCaseView{}, err
	}
	before := pol.For(uc)
	next := before
	next.Mode, next.Ceiling, next.MinConfidence = aidom.UseCaseMode(in.Mode), aidom.DataClass(in.Ceiling), in.MinConfidence
	if err := next.Validate(); err != nil {
		return UseCaseView{}, err
	}
	loosened := aidom.UseCaseLoosened(before, next)
	if len(loosened) > 0 {
		// A loosening is a person's decision, never on a stale sign-in.
		if actx.ActorID == "" {
			return UseCaseView{}, ErrNoActor
		}
		if s.stepUp != nil {
			if err := s.stepUp.RequireRecentAuth(ctx, actx.ActorID); err != nil {
				return UseCaseView{}, err
			}
		}
	}
	now := s.now().UTC()
	switch {
	case next.Mode == aidom.UseCaseAutoApply && before.Mode != aidom.UseCaseAutoApply:
		next.AutoApplySince = &now
		next.DowngradedAt, next.DowngradeReason, next.DowngradeDecisions, next.DowngradeOverrides = nil, "", 0, 0
	case next.Mode != aidom.UseCaseAutoApply:
		next.AutoApplySince = nil
	}
	next.UpdatedAt, next.UpdatedBy = &now, actx.ActorID
	if err := store.SaveUseCase(ctx, tid, uc, next); err != nil {
		return UseCaseView{}, err
	}

	actx.TenantID = tenantID
	severity := audit.SeverityMedium
	if len(loosened) > 0 {
		severity = audit.SeverityCritical
	}
	s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionAIUseCaseUpdated, audit.ResourceTypeTenant, tenantID).
		WithResourceName(string(uc)).
		WithChanges(auditapp.DiffChanges(
			map[string]any{"mode": string(before.Mode), "ceiling": string(before.Ceiling), "min_confidence": before.MinConfidence},
			map[string]any{"mode": string(next.Mode), "ceiling": string(next.Ceiling), "min_confidence": next.MinConfidence})).
		WithMetadata("use_case", string(uc)).
		WithMetadata("loosened", loosened).
		WithMessage(useCaseMessage(uc, before, next, loosened)).
		WithSeverity(severity))
	if len(loosened) > 0 && s.notifier != nil {
		s.notifier.NotifyPolicyLoosened(ctx, tenantID, actx, "AI use case widened",
			fmt.Sprintf("AI use case %s: %s", uc, strings.Join(loosenedText(loosened, next), "; ")),
			"/settings/ai?tab=use-cases")
	}
	return UseCaseView{UseCase: uc, UseCaseSetting: next, Effective: next.Mode, Loosened: loosened}, nil
}

func useCaseMessage(uc aidom.UseCase, before, next aidom.UseCaseSetting, loosened []string) string {
	switch {
	case before.Mode != next.Mode:
		return fmt.Sprintf("AI use case %s changed from %s to %s", uc, before.Mode, next.Mode)
	case len(loosened) > 0:
		return fmt.Sprintf("AI use case %s widened", uc)
	default:
		return fmt.Sprintf("AI use case %s settings changed", uc)
	}
}

func loosenedText(reasons []string, next aidom.UseCaseSetting) []string {
	out := make([]string, 0, len(reasons))
	for _, r := range reasons {
		switch r {
		case aidom.LoosenAutoApplyOn:
			out = append(out, "results now apply without a person when they only add information")
		case aidom.LoosenCeilingRaised:
			out = append(out, fmt.Sprintf("data up to %s is now sent to the AI provider", next.Ceiling))
		case aidom.LoosenConfidenceLower:
			out = append(out, fmt.Sprintf("results now apply on their own from confidence %.2f", next.MinConfidence))
		}
	}
	return out
}

// SweepUseCaseDowngrades falls every use case in auto-apply back to suggest
// when people overrode too many of its results (aidom.OverrideStats), and
// returns how many fell back. Each fall-back is audited
// (ai_use_case.downgraded) and shown on the settings page. A
// system job: it reads every organization, each query scoped to one.
func (s *Service) SweepUseCaseDowngrades(ctx context.Context) (int, error) {
	store, ok := s.useCaseStore()
	if !ok {
		return 0, nil
	}
	stats, ok := s.repo.(aidom.OverrideStatsReader)
	if !ok {
		return 0, nil
	}
	list, err := store.ListAutoApply(ctx, 5000)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, item := range list {
		if item.Setting.AutoApplySince == nil {
			continue
		}
		st, err := stats.OverrideStats(ctx, item.TenantID, item.UseCase, *item.Setting.AutoApplySince, aidom.DowngradeWindow)
		if err != nil {
			s.log.Warn("AI use case override stats failed", "tenant_id", item.TenantID.String(), "use_case", string(item.UseCase), "error", err)
			continue
		}
		if !st.ShouldDowngrade() {
			continue
		}
		now := s.now().UTC()
		next := item.Setting
		next.Mode, next.AutoApplySince = aidom.UseCaseSuggest, nil
		next.DowngradedAt, next.DowngradeReason = &now, aidom.DowngradeReasonOverrides
		next.DowngradeDecisions, next.DowngradeOverrides = st.Decisions, st.Overrides
		next.UpdatedAt, next.UpdatedBy = &now, ""
		done, err := store.DowngradeUseCase(ctx, item.TenantID, item.UseCase, item.Setting, next)
		if err != nil {
			s.log.Warn("AI use case downgrade failed", "tenant_id", item.TenantID.String(), "use_case", string(item.UseCase), "error", err)
			continue
		}
		if !done {
			continue // changed since it was read: the next sweep looks again
		}
		n++
		tid := item.TenantID.String()
		actx := auditapp.AuditContext{TenantID: tid}
		s.logAudit(ctx, actx, auditapp.NewSuccessEvent(audit.ActionAIUseCaseDowngraded, audit.ResourceTypeTenant, tid).
			WithResourceName(string(item.UseCase)).
			WithChanges(auditapp.DiffChanges(map[string]any{"mode": string(aidom.UseCaseAutoApply)}, map[string]any{"mode": string(aidom.UseCaseSuggest)})).
			WithMetadata("use_case", string(item.UseCase)).
			WithMetadata("decisions", st.Decisions).
			WithMetadata("overrides", st.Overrides).
			WithMetadata("reason", aidom.DowngradeReasonOverrides).
			WithMessage(fmt.Sprintf("AI use case %s fell back from auto-apply to suggest: people overrode %d of its last %d results",
				item.UseCase, st.Overrides, st.Decisions)).
			WithSeverity(audit.SeverityHigh))
	}
	return n, nil
}
