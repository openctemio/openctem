// Package aianalysis manages AI agents: service accounts that take part in
// triage like a person (same commands, permissions, approvals and audit; the
// only difference is the AI label and provenance), each with accountable
// owners who answer for its results, and the ledger of their runs.
// Design: docs/architecture/ai-analysis.md.
package aianalysis

import (
	"context"
	"fmt"
	"strings"
	"time"

	auditapp "github.com/openctemio/openctem/api/internal/app/audit"
	aidom "github.com/openctemio/openctem/api/pkg/domain/aianalysis"
	"github.com/openctemio/openctem/api/pkg/domain/audit"
	"github.com/openctemio/openctem/api/pkg/domain/serviceaccount"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// ConsentReader answers whether the organization consented to AI.
type ConsentReader interface {
	AIConsented(ctx context.Context, tenantID shared.ID) (bool, error)
}

// SettingsConsent reads consent from the organization's AI settings: AI is
// consented when the organization opted in and did not turn AI off.
type SettingsConsent struct{ Repo tenant.AISettingsRepository }

// AIConsented implements ConsentReader.
func (c SettingsConsent) AIConsented(ctx context.Context, tenantID shared.ID) (bool, error) {
	if c.Repo == nil {
		return false, nil
	}
	a, err := c.Repo.Get(ctx, tenantID, tenant.AISettings{})
	if err != nil {
		return false, err
	}
	return a.EffectiveMode() != tenant.AIModeDisabled, nil
}

// PermissionHolder answers what a member holds now; all is true for an owner
// or administrator, who holds every permission (apikey.HolderPermissions).
type PermissionHolder interface {
	HeldPermissions(ctx context.Context, tenantID, userID shared.ID) (all bool, perms []string, err error)
}

// FindingScope answers whether a person (or service account) may see a
// finding (datascope.Enforcer.AssertFindingForUser); out of scope is a not
// found error.
type FindingScope interface {
	AssertFindingForUser(ctx context.Context, tenantID, userID, findingID shared.ID) error
}

// Service manages AI agents and their runs.
type Service struct {
	aiAgents aidom.AIAgentRepository
	runs     aidom.RunRepository
	holder   PermissionHolder
	scope    FindingScope
	consent  ConsentReader
	audit    *auditapp.AuditService
	now      func() time.Time
	logger   *logger.Logger
}

// New wires the service.
func New(aiAgents aidom.AIAgentRepository, runs aidom.RunRepository, holder PermissionHolder,
	scope FindingScope, consent ConsentReader, audit *auditapp.AuditService, log *logger.Logger,
) *Service {
	return &Service{
		aiAgents: aiAgents, runs: runs, holder: holder, scope: scope, consent: consent,
		audit: audit, now: time.Now, logger: log.With("service", "ai_analysis"),
	}
}

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

func (s *Service) log(ctx context.Context, actx auditapp.AuditContext, action audit.Action, a *aidom.AIAgent, msg string, meta map[string]any) {
	if s.audit == nil {
		return
	}
	ev := auditapp.NewSuccessEvent(action, audit.ResourceTypeAIAnalysis, a.ID.String()).
		WithResourceName(a.Name).WithMessage(msg)
	for k, v := range meta {
		ev = ev.WithMetadata(k, v)
	}
	if err := s.audit.LogEvent(ctx, actx, ev); err != nil {
		s.logger.Error("failed to log audit event", "action", string(action), "error", err)
	}
}

func tenantOf(actx auditapp.AuditContext) (shared.ID, error) {
	tid, err := shared.IDFromString(actx.TenantID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return tid, nil
}

func actorOf(actx auditapp.AuditContext) (shared.ID, error) {
	uid, err := shared.IDFromString(actx.ActorID)
	if err != nil {
		return shared.ID{}, fmt.Errorf("%w: a person must make this change", shared.ErrValidation)
	}
	return uid, nil
}

// OwnerInput names one owner.
type OwnerInput struct {
	Kind string `json:"kind" validate:"required,oneof=user team"`
	ID   string `json:"id" validate:"required,uuid"`
}

const maxOwners = 20

func parseOwners(in []OwnerInput) ([]aidom.OwnerRef, error) {
	if len(in) == 0 {
		return nil, aidom.ErrOwnerRequired
	}
	if len(in) > maxOwners {
		return nil, fmt.Errorf("%w: at most %d owners", shared.ErrValidation, maxOwners)
	}
	out := make([]aidom.OwnerRef, 0, len(in))
	for _, o := range in {
		id, err := shared.IDFromString(o.ID)
		if err != nil {
			return nil, fmt.Errorf("%w: invalid owner id", shared.ErrValidation)
		}
		switch aidom.OwnerKind(o.Kind) {
		case aidom.OwnerUser, aidom.OwnerTeam:
		default:
			return nil, fmt.Errorf("%w: an owner is a user or a team", shared.ErrValidation)
		}
		out = append(out, aidom.OwnerRef{Kind: aidom.OwnerKind(o.Kind), ID: id})
	}
	return out, nil
}

// ceiling is the union of what the people hold.
func (s *Service) ceiling(ctx context.Context, tenantID shared.ID, people []shared.ID) (bool, []string, error) {
	seen := map[string]bool{}
	var out []string
	for _, p := range people {
		all, perms, err := s.holder.HeldPermissions(ctx, tenantID, p)
		if err != nil {
			return false, nil, err
		}
		if all {
			return true, nil, nil
		}
		for _, x := range perms {
			if !seen[x] {
				seen[x] = true
				out = append(out, x)
			}
		}
	}
	return false, out, nil
}

// checkCeiling refuses a role no accountable person could hold.
func (s *Service) checkCeiling(ctx context.Context, tenantID shared.ID, owners []aidom.OwnerRef, role []string) error {
	people, err := s.aiAgents.PeopleOf(ctx, tenantID, owners, s.now())
	if err != nil {
		return err
	}
	if len(people) == 0 {
		return fmt.Errorf("%w: no owner is an active person or a team with active members", shared.ErrValidation)
	}
	all, ceil, err := s.ceiling(ctx, tenantID, people)
	if err != nil {
		return err
	}
	if above := aidom.AboveCeiling(role, all, ceil); len(above) > 0 {
		return fmt.Errorf("%w: no accountable owner holds %s", shared.ErrValidation, strings.Join(above, ", "))
	}
	return nil
}

// checkGrantor refuses a preset whose permissions the acting person does not
// hold: nobody gives an AI agent more than they could do themselves.
func (s *Service) checkGrantor(ctx context.Context, tenantID, actor shared.ID, perms []string) error {
	all, held, err := s.holder.HeldPermissions(ctx, tenantID, actor)
	if err != nil {
		return err
	}
	if missing := aidom.AboveCeiling(perms, all, held); len(missing) > 0 {
		return fmt.Errorf("%w: you do not hold %s", shared.ErrForbidden, strings.Join(missing, ", "))
	}
	return nil
}

// CreateInput creates an AI agent.
type CreateInput struct {
	Name        string       `json:"name" validate:"required,max=100"`
	Description string       `json:"description" validate:"max=500"`
	Role        string       `json:"role" validate:"omitempty,oneof=analyst remediator reporter hunter router"`
	Preset      string       `json:"preset" validate:"required,oneof=suggest triage"`
	Owners      []OwnerInput `json:"owners" validate:"required,min=1,max=20,dive"`
}

// Create makes a service account with the given preset and accountable
// owners. The preset's permissions must be held by the acting person and by
// at least one accountable person.
func (s *Service) Create(ctx context.Context, in CreateInput, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	actor, err := actorOf(actx)
	if err != nil {
		return nil, err
	}
	name, err := serviceaccount.ValidateName(in.Name)
	if err != nil {
		return nil, err
	}
	if len(in.Description) > 500 {
		return nil, fmt.Errorf("%w: the description is too long", shared.ErrValidation)
	}
	role, err := aidom.ParseRole(in.Role)
	if err != nil {
		return nil, err
	}
	preset, err := aidom.ParsePreset(in.Preset)
	if err != nil {
		return nil, err
	}
	owners, err := parseOwners(in.Owners)
	if err != nil {
		return nil, err
	}
	perms := preset.Permissions()
	if err := s.checkGrantor(ctx, tid, actor, perms); err != nil {
		return nil, err
	}
	if err := s.checkCeiling(ctx, tid, owners, perms); err != nil {
		return nil, err
	}
	now := s.now().UTC()
	a := &aidom.AIAgent{
		ID: shared.NewID(), TenantID: tid, Name: name, Description: in.Description, Role: role, Preset: preset,
		Status: aidom.StatusActive, DataClassCeiling: aidom.DataClassInternal, Executor: aidom.ExecutorBuiltin,
		RunsPerHour: aidom.DefaultRunsPerHour, ActionsPerHour: aidom.DefaultActionsPerHour,
		AttestedAt: now, AttestDueAt: now.Add(aidom.AttestationPeriod), CreatedBy: &actor,
	}
	if err := s.aiAgents.Create(ctx, aidom.NewAIAgent{AIAgent: a, Owners: owners}); err != nil {
		return nil, err
	}
	out, err := s.aiAgents.Get(ctx, tid, a.ID)
	if err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIAgentCreated, out, fmt.Sprintf("AI agent %q created", out.Name),
		map[string]any{"role": string(role), "preset": string(preset), "owners": ownerIDs(out.Owners)})
	return out, nil
}

func ownerIDs(o []aidom.OwnerRef) []string {
	out := make([]string, 0, len(o))
	for _, x := range o {
		out = append(out, string(x.Kind)+":"+x.ID.String())
	}
	return out
}

// Get returns one AI agent of the organization.
func (s *Service) Get(ctx context.Context, tenantID, id shared.ID) (*aidom.AIAgent, error) {
	return s.aiAgents.Get(ctx, tenantID, id)
}

// List returns the organization's AI agents.
func (s *Service) List(ctx context.Context, tenantID shared.ID) ([]*aidom.AIAgent, error) {
	return s.aiAgents.List(ctx, tenantID)
}

// ReplaceOwners replaces an AI agent's owners. The AI agent's current role must stay
// within what the new owners hold. An AI agent paused for want of an owner
// runs again.
func (s *Service) ReplaceOwners(ctx context.Context, id shared.ID, in []OwnerInput, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	actor, err := actorOf(actx)
	if err != nil {
		return nil, err
	}
	a, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	owners, err := parseOwners(in)
	if err != nil {
		return nil, err
	}
	if err := s.checkCeiling(ctx, tid, owners, a.Preset.Permissions()); err != nil {
		return nil, err
	}
	if err := s.aiAgents.SetOwners(ctx, tid, id, owners, actor); err != nil {
		return nil, err
	}
	if a.Status == aidom.StatusPaused && a.PauseReason == aidom.PauseNoActiveOwner {
		if _, err := s.aiAgents.SetStatus(ctx, tid, id, []aidom.Status{aidom.StatusPaused}, aidom.StatusActive, ""); err != nil {
			return nil, err
		}
	}
	out, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIAgentOwnersChanged, out, fmt.Sprintf("Accountable owners of AI agent %q changed", out.Name),
		map[string]any{"from": ownerIDs(a.Owners), "to": ownerIDs(out.Owners)})
	return out, nil
}

// ChangePreset moves an AI agent to another preset.
func (s *Service) ChangePreset(ctx context.Context, id shared.ID, presetName string, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	a, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	preset, err := aidom.ParsePreset(presetName)
	if err != nil {
		return nil, err
	}
	actor, err := actorOf(actx)
	if err != nil {
		return nil, err
	}
	perms := preset.Permissions()
	if err := s.checkGrantor(ctx, tid, actor, perms); err != nil {
		return nil, err
	}
	if err := s.checkCeiling(ctx, tid, a.Owners, perms); err != nil {
		return nil, err
	}
	if err := s.aiAgents.SetPreset(ctx, tid, id, preset); err != nil {
		return nil, err
	}
	out, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIAgentRoleChanged, out, fmt.Sprintf("AI agent %q moved to preset %s", out.Name, preset),
		map[string]any{"from": string(a.Preset), "to": string(preset)})
	return out, nil
}

// Attest records that the actor, an accountable person (or an
// administrator, actorIsAdmin), confirms the AI agent's role, scope and
// behavior for another period. An AI agent paused because its attestation
// ran out runs again.
func (s *Service) Attest(ctx context.Context, id shared.ID, actorIsAdmin bool, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	actor, err := actorOf(actx)
	if err != nil {
		return nil, err
	}
	a, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	if !actorIsAdmin {
		if err := s.requireAccountable(ctx, id, actx); err != nil {
			return nil, err
		}
	}
	now := s.now().UTC()
	if err := s.aiAgents.Attest(ctx, tid, id, actor, now, now.Add(aidom.AttestationPeriod)); err != nil {
		return nil, err
	}
	if a.Status == aidom.StatusPaused && a.PauseReason == aidom.PauseAttestationExpired {
		if _, err := s.aiAgents.SetStatus(ctx, tid, id, []aidom.Status{aidom.StatusPaused}, aidom.StatusActive, ""); err != nil {
			return nil, err
		}
	}
	out, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	s.log(ctx, actx, audit.ActionAIAgentAttested, out, fmt.Sprintf("AI agent %q attested", out.Name),
		map[string]any{"attest_due_at": out.AttestDueAt.Format(time.RFC3339)})
	return out, nil
}

// requireAccountable refuses an actor who is not an accountable person of
// the AI agent now.
func (s *Service) requireAccountable(ctx context.Context, id shared.ID, actx auditapp.AuditContext) error {
	tid, err := tenantOf(actx)
	if err != nil {
		return err
	}
	actor, err := actorOf(actx)
	if err != nil {
		return err
	}
	a, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return err
	}
	people, err := s.aiAgents.PeopleOf(ctx, tid, a.Owners, s.now())
	if err != nil {
		return err
	}
	if !containsID(people, actor) {
		return fmt.Errorf("%w: only an accountable owner or an administrator may do this", shared.ErrForbidden)
	}
	return nil
}

func containsID(ids []shared.ID, id shared.ID) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

// Pause stops an AI agent until someone resumes it. An accountable person
// may pause their AI agent; anyone else needs canManage.
func (s *Service) Pause(ctx context.Context, id shared.ID, canManage bool, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	if !canManage {
		if err := s.requireAccountable(ctx, id, actx); err != nil {
			return nil, err
		}
	}
	return s.setStatus(ctx, id, []aidom.Status{aidom.StatusActive}, aidom.StatusPaused, aidom.PauseAdmin,
		audit.ActionAIAgentPaused, actx)
}

// Disable is the AI agent's kill switch: nothing runs until an administrator
// enables it again with a fresh step-up.
func (s *Service) Disable(ctx context.Context, id shared.ID, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	return s.setStatus(ctx, id, []aidom.Status{aidom.StatusActive, aidom.StatusPaused}, aidom.StatusDisabled, aidom.PauseAdmin,
		audit.ActionAIAgentDisabled, actx)
}

// Resume runs a paused or disabled AI agent again, once nothing keeps it
// paused (an active owner, a fresh attestation).
func (s *Service) Resume(ctx context.Context, id shared.ID, actx auditapp.AuditContext) (*aidom.AIAgent, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	a, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	people, err := s.aiAgents.PeopleOf(ctx, tid, a.Owners, s.now())
	if err != nil {
		return nil, err
	}
	if r := a.HealthReason(s.now(), len(people)); r != "" {
		return nil, &aidom.PausedError{Reason: r}
	}
	return s.setStatus(ctx, id, []aidom.Status{aidom.StatusPaused, aidom.StatusDisabled}, aidom.StatusActive, "",
		audit.ActionAIAgentResumed, actx)
}

func (s *Service) setStatus(ctx context.Context, id shared.ID, from []aidom.Status, to aidom.Status, reason aidom.PauseReason,
	action audit.Action, actx auditapp.AuditContext,
) (*aidom.AIAgent, error) {
	tid, err := tenantOf(actx)
	if err != nil {
		return nil, err
	}
	moved, err := s.aiAgents.SetStatus(ctx, tid, id, from, to, reason)
	if err != nil {
		return nil, err
	}
	out, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return nil, err
	}
	if !moved {
		return out, nil
	}
	s.log(ctx, actx, action, out, fmt.Sprintf("AI agent %q is %s", out.Name, to), map[string]any{"reason": string(reason)})
	return out, nil
}

// Delete removes an AI agent and its service account; its runs and every
// change it made stay in the history.
func (s *Service) Delete(ctx context.Context, id shared.ID, actx auditapp.AuditContext) error {
	tid, err := tenantOf(actx)
	if err != nil {
		return err
	}
	a, err := s.aiAgents.Get(ctx, tid, id)
	if err != nil {
		return err
	}
	if err := s.aiAgents.Delete(ctx, tid, id); err != nil {
		return err
	}
	s.log(ctx, actx, audit.ActionAIAgentDeleted, a, fmt.Sprintf("AI agent %q deleted", a.Name), nil)
	return nil
}

// pauseFor pauses an active AI agent for a platform reason and audits it as
// a system action.
func (s *Service) pauseFor(ctx context.Context, a *aidom.AIAgent, reason aidom.PauseReason) error {
	moved, err := s.aiAgents.SetStatus(ctx, a.TenantID, a.ID, []aidom.Status{aidom.StatusActive}, aidom.StatusPaused, reason)
	if err != nil {
		return err
	}
	if moved {
		a.Status, a.PauseReason = aidom.StatusPaused, reason
		s.log(ctx, auditapp.AuditContext{TenantID: a.TenantID.String(), ActorEmail: "system:ai-agent"},
			audit.ActionAIAgentPaused, a, fmt.Sprintf("AI agent %q paused: %s", a.Name, reason),
			map[string]any{"reason": string(reason)})
	}
	return nil
}

// Sweep pauses every active AI agent that has no active owner left or whose
// attestation ran out (a system job; the run-start check does the same per
// run, fail closed). It returns how many it paused.
func (s *Service) Sweep(ctx context.Context) (int, error) {
	list, err := s.aiAgents.ListActive(ctx, 0)
	if err != nil {
		return 0, err
	}
	paused := 0
	for _, a := range list {
		people, err := s.aiAgents.PeopleOf(ctx, a.TenantID, a.Owners, s.now())
		if err != nil {
			s.logger.Error("AI agent sweep: owners lookup failed", "ai_agent_id", a.ID.String(), "error", err)
			continue
		}
		if r := a.HealthReason(s.now(), len(people)); r != "" {
			if err := s.pauseFor(ctx, a, r); err != nil {
				s.logger.Error("AI agent sweep: pause failed", "ai_agent_id", a.ID.String(), "error", err)
				continue
			}
			paused++
		}
	}
	return paused, nil
}
