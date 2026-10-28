package aianalysis

import (
	"context"
	"errors"
	"fmt"
	"time"

	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// Principal is an analyst resolved for one run: what it may do now and who
// answers for it. Every command the executor calls for the analyst passes
// through Require and AssertFinding first.
type Principal struct {
	Analyst *aidom.Analyst
	// People are the accountable people at this moment.
	People      []shared.ID
	permissions map[string]bool
	scope       FindingScope
}

// Can reports whether the analyst holds an effective permission.
func (p *Principal) Can(perm string) bool { return p.permissions[perm] }

// Permissions lists the effective permissions.
func (p *Principal) Permissions() []string {
	out := make([]string, 0, len(p.permissions))
	for k := range p.permissions {
		out = append(out, k)
	}
	return out
}

// Require refuses an action the analyst may not take.
func (p *Principal) Require(perm string) error {
	if !p.Can(perm) {
		return fmt.Errorf("%w (%s)", aidom.ErrNotAllowed, perm)
	}
	return nil
}

// AssertFinding refuses a finding outside the analyst's own data scope, or
// outside the scope of every accountable person (out of scope reads as not
// found).
func (p *Principal) AssertFinding(ctx context.Context, findingID shared.ID) error {
	if err := p.scope.AssertFindingForUser(ctx, p.Analyst.TenantID, p.Analyst.ID, findingID); err != nil {
		return err
	}
	for _, person := range p.People {
		err := p.scope.AssertFindingForUser(ctx, p.Analyst.TenantID, person, findingID)
		if err == nil {
			return nil
		}
		if !errors.Is(err, shared.ErrNotFound) {
			return err
		}
	}
	return fmt.Errorf("%w: finding not found", shared.ErrNotFound)
}

// Provenance is what the analyst's changes in run carry.
func (p *Principal) Provenance(run *aidom.Run) aidom.Provenance {
	return aidom.Provenance{
		AnalystID: p.Analyst.ID, AnalystName: p.Analyst.Name, RunID: run.ID, Executor: run.Executor,
		Provider: run.Provider, Model: run.Model, PromptTemplateID: run.PromptTemplateID,
		PromptTemplateDigest: run.PromptTemplateDigest, Accountable: p.Analyst.Owners, TriggeredBy: run.TriggeredBy,
	}
}

// Principal resolves an analyst for a run, fail closed: the organization
// consented to AI, the analyst is active, at least one accountable owner is
// active, the attestation is fresh, and something is left of its preset once
// the ceiling (what the accountable people hold) and the deny list are
// applied. A failed check pauses the analyst (audited) and returns a
// PausedError.
func (s *Service) Principal(ctx context.Context, tenantID, analystID shared.ID) (*Principal, error) {
	// Read-only assistance runs under the viewer and never becomes an analyst.
	if err := aidom.RefuseAssist(ctx); err != nil {
		return nil, err
	}
	if s.consent != nil {
		ok, err := s.consent.AIConsented(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return nil, fmt.Errorf("%w: AI is off for this organization", shared.ErrConflict)
		}
	}
	a, err := s.analysts.Get(ctx, tenantID, analystID)
	if err != nil {
		return nil, err
	}
	if a.Status != aidom.StatusActive {
		return nil, &aidom.PausedError{Reason: a.PauseReason}
	}
	now := s.now()
	people, err := s.analysts.PeopleOf(ctx, tenantID, a.Owners, now)
	if err != nil {
		return nil, err
	}
	if r := a.HealthReason(now, len(people)); r != "" {
		if err := s.pauseFor(ctx, a, r); err != nil {
			return nil, err
		}
		return nil, &aidom.PausedError{Reason: r}
	}
	// The analyst's permissions come from its preset in code; it holds no
	// database role (a trigger refuses one), so nothing outside this service
	// can widen it.
	all, ceil, err := s.ceiling(ctx, tenantID, people)
	if err != nil {
		return nil, err
	}
	eff := aidom.Effective(a.Preset.Permissions(), all, ceil)
	if len(eff) == 0 {
		if err := s.pauseFor(ctx, a, aidom.PauseNoPermissions); err != nil {
			return nil, err
		}
		return nil, &aidom.PausedError{Reason: aidom.PauseNoPermissions}
	}
	perms := make(map[string]bool, len(eff))
	for _, p := range eff {
		perms[p] = true
	}
	return &Principal{Analyst: a, People: people, permissions: perms, scope: s.scope}, nil
}

// DefaultAnalyst picks the analyst for a finding when the trigger names none:
// the first active analyst (by name) that may read the finding.
func (s *Service) DefaultAnalyst(ctx context.Context, tenantID, findingID shared.ID) (*Principal, error) {
	list, err := s.analysts.List(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	var lastPaused error
	for _, a := range list {
		if a.Status != aidom.StatusActive {
			continue
		}
		p, err := s.Principal(ctx, tenantID, a.ID)
		if err != nil {
			var pe *aidom.PausedError
			if errors.As(err, &pe) {
				lastPaused = err
				continue
			}
			return nil, err
		}
		if err := p.AssertFinding(ctx, findingID); err == nil {
			return p, nil
		} else if !errors.Is(err, shared.ErrNotFound) {
			return nil, err
		}
	}
	if lastPaused != nil {
		return nil, lastPaused
	}
	return nil, aidom.ErrAnalystNotFound
}

// ErrBudget: the analyst used its runs for this hour or its tokens for this
// month.
var ErrBudget = fmt.Errorf("%w: the AI analyst reached its limit", shared.ErrConflict)

// StartRunInput starts a run.
type StartRunInput struct {
	Principal   *Principal
	UseCase     aidom.UseCase
	Kind        string
	SubjectType aidom.SubjectType
	SubjectID   shared.ID
	Executor    aidom.Executor
	DataClass   aidom.DataClass
	Trigger     aidom.Trigger
	TriggeredBy *shared.ID
}

// StartRun records a running run for the principal after its budgets: runs
// this hour and tokens this month. The accountable owners are snapshotted on
// the run.
func (s *Service) StartRun(ctx context.Context, in StartRunInput) (*aidom.Run, error) {
	if err := aidom.RefuseAssist(ctx); err != nil {
		return nil, err
	}
	a := in.Principal.Analyst
	now := s.now().UTC()
	runs, _, err := s.runs.Usage(ctx, a.TenantID, a.ID, now.Add(-time.Hour))
	if err != nil {
		return nil, err
	}
	if runs >= a.RunsPerHour {
		return nil, ErrBudget
	}
	if a.TokensMonth > 0 {
		monthStart := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
		_, tokens, err := s.runs.Usage(ctx, a.TenantID, a.ID, monthStart)
		if err != nil {
			return nil, err
		}
		if tokens >= a.TokensMonth {
			return nil, ErrBudget
		}
	}
	deadline := now.Add(aidom.RunDeadline)
	run := &aidom.Run{
		ID: shared.NewID(), TenantID: a.TenantID, AnalystID: &a.ID, UseCase: in.UseCase, Kind: in.Kind,
		SubjectType: in.SubjectType, SubjectID: in.SubjectID, Executor: in.Executor, Status: aidom.RunRunning,
		DataClass: in.DataClass, Trigger: in.Trigger, TriggeredBy: in.TriggeredBy, Accountable: a.Owners,
		DeadlineAt: &deadline, StartedAt: &now,
	}
	if err := s.runs.CreateRun(ctx, run); err != nil {
		return nil, err
	}
	return run, nil
}

// FinishRun stores a run's outcome.
func (s *Service) FinishRun(ctx context.Context, run *aidom.Run) error {
	if run.CompletedAt == nil && !run.Status.IsLive() {
		now := s.now().UTC()
		run.CompletedAt = &now
	}
	return s.runs.UpdateRun(ctx, run)
}

// GetRun returns one run; the caller must be able to see its subject.
func (s *Service) GetRun(ctx context.Context, tenantID, viewerID, runID shared.ID) (*aidom.Run, error) {
	run, err := s.runs.GetRun(ctx, tenantID, runID)
	if err != nil {
		return nil, err
	}
	// Only subjects with a scope check are readable; any other subject type
	// answers not found until it has one.
	if run.SubjectType != aidom.SubjectFinding || s.scope == nil {
		return nil, aidom.ErrRunNotFound
	}
	if err := s.scope.AssertFindingForUser(ctx, tenantID, viewerID, run.SubjectID); err != nil {
		return nil, aidom.ErrRunNotFound
	}
	return run, nil
}

// ListRunsForFinding lists a finding's runs, newest first; the caller must
// be able to see the finding.
func (s *Service) ListRunsForFinding(ctx context.Context, tenantID, viewerID, findingID shared.ID) ([]*aidom.Run, error) {
	if s.scope != nil {
		if err := s.scope.AssertFindingForUser(ctx, tenantID, viewerID, findingID); err != nil {
			return nil, err
		}
	}
	return s.runs.ListRunsBySubject(ctx, tenantID, aidom.SubjectFinding, findingID, 20)
}
