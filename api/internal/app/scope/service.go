// Package scope implements the application service for the scope bounded context — orchestrates pkg/domain/scope entities and cross-cutting concerns (audit, notifications, RBAC).
package scope

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/asset"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
	"github.com/openctemio/openctem/api/pkg/pagination"
)

// Service handles scope configuration business operations.
type Service struct {
	targetRepo    scopedom.TargetRepository
	exclusionRepo scopedom.ExclusionRepository
	assetRepo     asset.Repository
	logger        *logger.Logger

	// Entry policy (entries.go): settings, administrators, notices, step-up.
	settings SettingsReader
	admins   AdminDirectory
	inApp    InAppNotifier
	stepUp   shared.RecentAuthGate
	// Approvers (approvers.go): who may approve, the authenticator check
	// for an owner's own approval, approval emails and channels.
	approvers  ApproverDirectory
	totp       TOTPVerifier
	mail       ApprovalMailer
	channels   ChannelNotifier
	webBaseURL string
	// auditor records the system decisions (attestation.go).
	auditor SystemAuditor
	// guardrails are the platform's scope guardrails (nil: the defaults).
	guardrails *scopedom.Guardrails
	// Coverage of the inventory (GetStats): counted in SQL over the
	// caller's data scope.
	coverage  CoverageCounter
	dataScope DataScopeResolver
	// The scope join after a committed change (join.go).
	joiner  ScopeJoiner
	visible VisibleAssetCounter
}

// NewService creates a new Service.
func NewService(
	targetRepo scopedom.TargetRepository,
	exclusionRepo scopedom.ExclusionRepository,
	assetRepo asset.Repository,
	log *logger.Logger,
) *Service {
	return &Service{
		targetRepo:    targetRepo,
		exclusionRepo: exclusionRepo,
		assetRepo:     assetRepo,
		logger:        log.With("service", "scope"),
	}
}

// =============================================================================
// Target Operations
// =============================================================================

// CreateTargetInput represents the input for creating a scope target.
type CreateTargetInput struct {
	TenantID    string   `validate:"required,uuid"`
	TargetType  string   `validate:"required"`
	Pattern     string   `validate:"required,max=500"`
	Description string   `validate:"max=1000"`
	Priority    int      `validate:"min=0,max=100"`
	Tags        []string `validate:"max=20,dive,max=50"`
	CreatedBy   string   `validate:"max=200"`

	// Entry fields (RFC-054 §6.1).
	Reason        string `validate:"max=1000"`
	ExpiresAt     *time.Time
	ExpiresInDays *int
	MaxTier       string `validate:"omitempty,oneof=t0 t1 t2 T0 T1 T2"`
	// Actor is the caller (zero: a system path, effective at once).
	Actor Actor
	// Origin is the creating path (empty: manual, request or system from
	// the actor).
	Origin scopedom.Origin
	// Discovery: discovery from the entry (nil: on). It runs only for a
	// permanent domain entry (research/53 SC1).
	Discovery *bool
}

// CreateTarget creates a scope entry: effective at once, pending approval,
// or a member's pending request (entries.go).
func (s *Service) CreateTarget(ctx context.Context, input CreateTargetInput) (*scopedom.Target, error) {
	s.logger.Info("creating scope target", "type", logSafe(input.TargetType), "pattern", logSafe(input.Pattern))

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	targetType, err := scopedom.ParseTargetType(input.TargetType)
	if err != nil {
		return nil, err // wraps shared.ErrValidation
	}

	// Check if pattern already exists
	exists, err := s.targetRepo.ExistsByPattern(ctx, tenantID, targetType, input.Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to check target existence: %w", err)
	}
	if exists {
		return nil, scopedom.ErrTargetAlreadyExists
	}

	g := scopedom.DefaultGuardrails()
	if s.guardrails != nil {
		g = *s.guardrails
	}
	if err := g.CheckPattern(targetType, input.Pattern); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	d, err := s.decideNewEntry(ctx, tenantID, targetType, input, now, false)
	if err != nil {
		return nil, err
	}
	target, err := scopedom.NewEntry(tenantID, targetType, input.Pattern, input.Description, input.CreatedBy, scopedom.EntryOptions{
		Reason: input.Reason, ExpiresAt: d.expiresAt, MaxTier: d.tier, ApprovalsRequired: d.approvals,
		IntrusivePermanent: d.intrusivePermanent, Now: now,
	})
	if err != nil {
		return nil, err
	}

	// Apply optional settings
	if input.Priority > 0 {
		if err := target.UpdatePriority(input.Priority); err != nil {
			return nil, err
		}
	}
	if len(input.Tags) > 0 {
		target.UpdateTags(input.Tags)
	}
	target.SetOrigin(entryOrigin(input.Origin, input.Actor, d.request))
	if input.Discovery != nil {
		target.SetDiscovery(*input.Discovery)
	}

	if err := s.targetRepo.Create(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to create scope target: %w", err)
	}

	switch {
	case target.IsPending():
		s.notifyRequested(ctx, target)
	case !input.Actor.system():
		s.notifyWidened(ctx, target, "Scope entry added")
	}
	if target.IsActive() {
		s.scheduleJoin(tenantID)
	}
	s.logger.Info("scope target created", "id", target.ID().String(), "pattern", logSafe(input.Pattern), "status", target.Status().String())
	return target, nil
}

// GetTarget retrieves a scope target by tenant ID and ID.
func (s *Service) GetTarget(ctx context.Context, tenantID string, targetID string) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
}

// UpdateTargetInput represents the input for updating a scope target.
type UpdateTargetInput struct {
	Description *string  `validate:"omitempty,max=1000"`
	Priority    *int     `validate:"omitempty,min=0,max=100"`
	Tags        []string `validate:"omitempty,max=20,dive,max=50"`

	// Entry fields (RFC-054 §6.1). A later or removed expiry, or a higher
	// tier, widens: it needs the approval permission and step-up and sends
	// the entry back to review when approvals are required.
	Reason        *string `validate:"omitempty,max=1000"`
	ExpiresAt     *time.Time
	ExpiresInDays *int
	ClearExpiry   bool
	MaxTier       *string `validate:"omitempty,oneof=t0 t1 t2 T0 T1 T2"`
	// Discovery switches discovery on or off. Turning it on widens what is
	// discovered (names under the entry join the inventory): approvers
	// only, with step-up, and every administrator is told; it does not send
	// the entry back to review (discovery is passive).
	Discovery *bool
	Actor     Actor
}

// UpdateTarget updates an existing scope target.
func (s *Service) UpdateTarget(ctx context.Context, targetID string, tenantID string, input UpdateTargetInput) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if input.Description != nil {
		target.UpdateDescription(*input.Description)
	}
	if input.Priority != nil {
		if err := target.UpdatePriority(*input.Priority); err != nil {
			return nil, err
		}
	}
	if input.Tags != nil {
		target.UpdateTags(input.Tags)
	}
	discoveryOn, err := s.applyDiscovery(ctx, target, input)
	if err != nil {
		return nil, err
	}
	widened, err := s.applyEntryUpdate(ctx, target, input)
	if err != nil {
		return nil, err
	}

	if err := s.targetRepo.Update(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to update scope target: %w", err)
	}
	if widened {
		if target.IsPending() {
			s.notifyRequested(ctx, target)
		} else if !input.Actor.system() {
			s.notifyWidened(ctx, target, "Scope entry widened")
		}
	} else if discoveryOn && !input.Actor.system() {
		s.notifyWidened(ctx, target, "Discovery turned on for a scope entry")
	}

	if target.IsActive() {
		s.scheduleJoin(target.TenantID())
	}
	s.logger.Info("scope target updated", "id", logSafe(targetID), "widened", widened)
	return target, nil
}

// applyDiscovery applies a discovery switch and reports whether it went from
// off to on (a widening: approvers with step-up only).
func (s *Service) applyDiscovery(ctx context.Context, t *scopedom.Target, in UpdateTargetInput) (bool, error) {
	if in.Discovery == nil || *in.Discovery == t.DiscoverySetting() {
		return false, nil
	}
	if !*in.Discovery {
		t.SetDiscovery(false) // narrowing
		return false, nil
	}
	if !in.Actor.system() && !in.Actor.CanApprove {
		return false, ErrWideningNeedsApprove
	}
	if err := s.requireStepUp(ctx, in.Actor); err != nil {
		return false, err
	}
	t.SetDiscovery(true)
	return true, nil
}

// applyEntryUpdate applies the entry fields of an update and reports whether
// the change widened the entry. Nothing is changed when the caller may not
// make the change.
func (s *Service) applyEntryUpdate(ctx context.Context, t *scopedom.Target, in UpdateTargetInput) (bool, error) {
	now := time.Now().UTC()
	tier := t.MaxTier()
	if in.MaxTier != nil {
		parsed, err := scopedom.ParseTier(*in.MaxTier)
		if err != nil {
			return false, err
		}
		tier = parsed
	}
	expiryChange := in.ClearExpiry || in.ExpiresAt != nil || in.ExpiresInDays != nil
	next := t.ExpiresAt()
	var pol *policy
	if expiryChange || tier == scopedom.TierIntrusive {
		p, err := s.loadPolicy(ctx, t.TenantID())
		if err != nil {
			return false, err
		}
		pol = &p
	}
	if expiryChange {
		next = nil
		if !in.ClearExpiry {
			var err error
			if next, err = resolveExpiry(*pol, tier, now, in.ExpiresAt, in.ExpiresInDays); err != nil {
				return false, err
			}
		}
	}
	if tier == scopedom.TierIntrusive {
		// The organization's t2 bound (RFC-054 §12.4) applies to the
		// expiry the entry will have, also when only the tier is raised.
		if next == nil && !pol.intrusivePermanent() {
			return false, scopedom.ErrIntrusiveNeeds
		}
		if maxDays, _ := pol.settings.T2Max(); next != nil && !pol.intrusivePermanent() &&
			tier > t.MaxTier() && next.After(now.Add(time.Duration(maxDays)*24*time.Hour+time.Minute)) {
			return false, fmt.Errorf("%w: at most %d days", scopedom.ErrIntrusiveTooLong, maxDays)
		}
	}
	// A higher tier, a later or removed expiry, or renewing an expired entry
	// widens.
	widen := tier > t.MaxTier() ||
		(expiryChange && (t.ExtendsExpiry(next) || t.Status() == scopedom.StatusExpired || t.ExpiredAt(now)))
	if widen {
		if t.Status() == scopedom.StatusRejected {
			return false, scopedom.ErrEntryRejected
		}
		if !in.Actor.system() && !in.Actor.CanApprove {
			return false, ErrWideningNeedsApprove
		}
		if err := s.requireStepUp(ctx, in.Actor); err != nil {
			return false, err
		}
	}
	if in.Reason != nil {
		if err := t.SetReason(*in.Reason, now); err != nil {
			return false, err
		}
	}
	t.SetMaxTier(tier, now)
	if expiryChange {
		t.SetExpiry(next, now)
	}
	if !widen {
		return false, nil
	}
	if t.Status() == scopedom.StatusInactive {
		// Widening the fields of a deactivated entry does not activate it;
		// activating it later is its own widening.
		return true, nil
	}
	p, err := s.loadPolicy(ctx, t.TenantID())
	if err != nil {
		return false, err
	}
	approvals := 0
	if !in.Actor.system() {
		approvals = p.approvals(t.MaxTier(), false)
	}
	t.Widen(in.Actor.UserID, approvals, now)
	return true, nil
}

// DeleteTarget deletes a scope target by ID with atomic tenant verification.
func (s *Service) DeleteTarget(ctx context.Context, targetID string, tenantID string) error {
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return shared.ErrNotFound
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	if err := s.targetRepo.Delete(ctx, parsedTenantID, parsedID); err != nil {
		return err
	}

	s.logger.Info("scope target deleted", "id", targetID)
	return nil
}

// ListTargetsInput represents the input for listing scope targets.
type ListTargetsInput struct {
	TenantID    string   `validate:"omitempty,uuid"`
	TargetTypes []string `validate:"max=20"`
	Statuses    []string `validate:"max=3"`
	Tags        []string `validate:"max=20,dive,max=50"`
	Search      string   `validate:"max=255"`
	Page        int      `validate:"min=0"`
	PerPage     int      `validate:"min=0,max=100"`
}

// ListTargets retrieves scope targets with filtering and pagination.
func (s *Service) ListTargets(ctx context.Context, input ListTargetsInput) (pagination.Result[*scopedom.Target], error) {
	filter := scopedom.TargetFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.TargetTypes) > 0 {
		types := make([]scopedom.TargetType, 0, len(input.TargetTypes))
		for _, t := range input.TargetTypes {
			if parsed, err := scopedom.ParseTargetType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.TargetTypes = types
	}

	if len(input.Statuses) > 0 {
		statuses := make([]scopedom.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			statuses = append(statuses, scopedom.Status(st))
		}
		filter.Statuses = statuses
	}

	if len(input.Tags) > 0 {
		filter.Tags = input.Tags
	}

	if input.Search != "" {
		filter.Search = &input.Search
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.targetRepo.List(ctx, filter, page)
}

// ListActiveTargets retrieves the tenant's scope targets in effect: active
// and not past their expiry. The repository filters on both; re-checking
// here keeps an expired or pending entry from ever reaching a matcher,
// whatever the repository returns.
func (s *Service) ListActiveTargets(ctx context.Context, tenantID string) ([]*scopedom.Target, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	all, err := s.targetRepo.ListActive(ctx, parsedID)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	out := all[:0:0]
	for _, t := range all {
		if t != nil && t.InEffect(now) {
			out = append(out, t)
		}
	}
	return out, nil
}

// ActivateTarget activates a scope target. Activation widens: an approver
// re-authenticates and the entry needs the tenant's approvals; anyone else
// may not activate (they request a new entry). An expired entry is renewed
// with a new expiry instead.
func (s *Service) ActivateTarget(ctx context.Context, targetID string, tenantID string, actor Actor) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	switch {
	case target.Status() == scopedom.StatusRejected:
		return nil, scopedom.ErrEntryRejected
	case target.Status() == scopedom.StatusExpired || target.ExpiredAt(now):
		return nil, scopedom.ErrEntryExpired
	case target.Status() == scopedom.StatusActive || target.IsPending():
		return target, nil // nothing to widen
	}
	if err := s.widenEntry(ctx, target, actor, now); err != nil {
		return nil, err
	}

	if err := s.targetRepo.Update(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to activate scope target: %w", err)
	}
	if target.IsPending() {
		s.notifyRequested(ctx, target)
	} else if !actor.system() {
		s.notifyWidened(ctx, target, "Scope entry activated")
	}

	if target.IsActive() {
		s.scheduleJoin(parsedTenantID)
	}
	s.logger.Info("scope target activated", "id", logSafe(targetID), "status", target.Status().String())
	return target, nil
}

// DeactivateTarget deactivates a scope target.
func (s *Service) DeactivateTarget(ctx context.Context, targetID string, tenantID string) (*scopedom.Target, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(targetID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	target, err := s.targetRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	target.Deactivate()

	if err := s.targetRepo.Update(ctx, target); err != nil {
		return nil, fmt.Errorf("failed to deactivate scope target: %w", err)
	}

	s.logger.Info("scope target deactivated", "id", targetID)
	return target, nil
}

// =============================================================================
// Exclusion Operations
// =============================================================================

// CreateExclusionInput represents the input for creating a scope exclusion.
type CreateExclusionInput struct {
	TenantID      string     `validate:"required,uuid"`
	ExclusionType string     `validate:"required"`
	Pattern       string     `validate:"required,max=500"`
	Reason        string     `validate:"required,max=1000"`
	ExpiresAt     *time.Time `validate:"omitempty"`
	CreatedBy     string     `validate:"max=200"`
	// PathPrefix and Methods make a `path` exclusion's web rule (RFC-056):
	// the pattern is then a host pattern.
	PathPrefix *string
	Methods    []string
	// Origin is the creating path (empty: manual).
	Origin scopedom.Origin
}

// entryOrigin is the origin a new entry records: the path's own when it
// names one, else a member's request, a system write, or a manual add.
func entryOrigin(given scopedom.Origin, actor Actor, request bool) scopedom.Origin {
	switch {
	case given.Valid():
		return given
	case request:
		return scopedom.OriginRequest
	case actor.system():
		return scopedom.OriginSystem
	}
	return scopedom.OriginManual
}

// CreateExclusion creates a new scope exclusion.
func (s *Service) CreateExclusion(ctx context.Context, input CreateExclusionInput) (*scopedom.Exclusion, error) {
	s.logger.Info("creating scope exclusion", "type", logSafe(input.ExclusionType), "pattern", logSafe(input.Pattern))

	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	exclusionType, err := scopedom.ParseExclusionType(input.ExclusionType)
	if err != nil {
		return nil, err // wraps shared.ErrValidation
	}

	web, err := webRuleFor(exclusionType, input.Pattern, input.PathPrefix, input.Methods)
	if err != nil {
		return nil, err
	}
	pattern := input.Pattern
	if web != nil {
		pattern = scopedom.PathRulePattern(pattern, web.PathPrefix)
	}
	exclusion, err := scopedom.NewExclusion(tenantID, exclusionType, pattern, input.Reason, input.ExpiresAt, input.CreatedBy)
	if err != nil {
		return nil, err
	}
	exclusion.SetWeb(web)
	exclusion.SetOrigin(input.Origin)

	if err := s.exclusionRepo.Create(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to create scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion created", "id", exclusion.ID().String(), "pattern", logSafe(input.Pattern))
	return exclusion, nil
}

// GetExclusion retrieves a scope exclusion by tenant ID and ID.
func (s *Service) GetExclusion(ctx context.Context, tenantID string, exclusionID string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}
	return s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
}

// UpdateExclusionInput represents the input for updating a scope exclusion.
type UpdateExclusionInput struct {
	Reason    *string    `validate:"omitempty,max=1000"`
	ExpiresAt *time.Time `validate:"omitempty"`
	// Reviewer is the caller; shortening the window of an exclusion in
	// effect needs Reviewer.CanApprove and someone other than the requester.
	Reviewer scopedom.Reviewer
}

// UpdateExclusion updates an existing scope exclusion.
func (s *Service) UpdateExclusion(ctx context.Context, exclusionID string, tenantID string, input UpdateExclusionInput) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if input.ExpiresAt != nil && exclusion.ShortensWindow(input.ExpiresAt) {
		if err := exclusion.AuthorizeReduction(input.Reviewer); err != nil {
			return nil, err
		}
		// Shortening an exclusion in effect widens scope: step-up (RFC-054 §6.2).
		if exclusion.InEffect() {
			if err := s.requireStepUp(ctx, Actor{UserID: input.Reviewer.UserID}); err != nil {
				return nil, err
			}
		}
	}
	if input.Reason != nil {
		exclusion.UpdateReason(*input.Reason)
	}
	if input.ExpiresAt != nil {
		exclusion.UpdateExpiresAt(input.ExpiresAt)
	}

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to update scope exclusion: %w", err)
	}

	s.scheduleJoin(parsedTenantID) // a shorter exclusion may let a name join
	s.logger.Info("scope exclusion updated", "id", logSafe(exclusionID))
	return exclusion, nil
}

// DeleteExclusion deletes a scope exclusion by ID with atomic tenant
// verification. Deleting an exclusion in effect needs the approval
// permission and someone other than the requester (AuthorizeReduction).
func (s *Service) DeleteExclusion(ctx context.Context, exclusionID string, tenantID string, reviewer scopedom.Reviewer) error {
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return shared.ErrNotFound
	}

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return err
	}
	if err := exclusion.AuthorizeReduction(reviewer); err != nil {
		return err
	}

	if err := s.exclusionRepo.Delete(ctx, parsedTenantID, parsedID); err != nil {
		return err
	}

	s.scheduleJoin(parsedTenantID)
	s.logger.Info("scope exclusion deleted", "id", logSafe(exclusionID))
	return nil
}

// ListExclusionsInput represents the input for listing scope exclusions.
type ListExclusionsInput struct {
	TenantID       string   `validate:"omitempty,uuid"`
	ExclusionTypes []string `validate:"max=20"`
	Statuses       []string `validate:"max=3"`
	IsApproved     *bool
	Search         string `validate:"max=255"`
	Page           int    `validate:"min=0"`
	PerPage        int    `validate:"min=0,max=100"`
}

// ListExclusions retrieves scope exclusions with filtering and pagination.
func (s *Service) ListExclusions(ctx context.Context, input ListExclusionsInput) (pagination.Result[*scopedom.Exclusion], error) {
	filter := scopedom.ExclusionFilter{}

	if input.TenantID != "" {
		filter.TenantID = &input.TenantID
	}

	if len(input.ExclusionTypes) > 0 {
		types := make([]scopedom.ExclusionType, 0, len(input.ExclusionTypes))
		for _, t := range input.ExclusionTypes {
			if parsed, err := scopedom.ParseExclusionType(t); err == nil {
				types = append(types, parsed)
			}
		}
		filter.ExclusionTypes = types
	}

	if len(input.Statuses) > 0 {
		statuses := make([]scopedom.Status, 0, len(input.Statuses))
		for _, st := range input.Statuses {
			statuses = append(statuses, scopedom.Status(st))
		}
		filter.Statuses = statuses
	}

	if input.IsApproved != nil {
		filter.IsApproved = input.IsApproved
	}

	if input.Search != "" {
		filter.Search = &input.Search
	}

	page := pagination.New(input.Page, input.PerPage)
	return s.exclusionRepo.List(ctx, filter, page)
}

// ListActiveExclusions retrieves all active scope exclusions for a tenant.
func (s *Service) ListActiveExclusions(ctx context.Context, tenantID string) ([]*scopedom.Exclusion, error) {
	parsedID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	return s.effectiveExclusions(ctx, parsedID)
}

// ApproveExclusion approves a pending scope exclusion and puts it into effect.
// The route requires attack_surface:scope:exclusions:approve; the requester
// cannot approve their own exclusion.
func (s *Service) ApproveExclusion(ctx context.Context, exclusionID string, tenantID string, approvedBy string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if err := exclusion.Approve(approvedBy); err != nil {
		return nil, err
	}

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to approve scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion approved", "id", logSafe(exclusionID), "approvedBy", logSafe(approvedBy))
	return exclusion, nil
}

// RejectExclusion declines a pending scope exclusion; it never takes effect.
// The route requires attack_surface:scope:exclusions:approve.
func (s *Service) RejectExclusion(ctx context.Context, exclusionID string, tenantID string, rejectedBy string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if err := exclusion.Reject(rejectedBy); err != nil {
		return nil, err
	}

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to reject scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion rejected", "id", logSafe(exclusionID), "rejectedBy", logSafe(rejectedBy))
	return exclusion, nil
}

// ActivateExclusion puts an approved scope exclusion back into effect.
func (s *Service) ActivateExclusion(ctx context.Context, exclusionID string, tenantID string) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if err := exclusion.Activate(); err != nil {
		return nil, err
	}

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to activate scope exclusion: %w", err)
	}

	s.logger.Info("scope exclusion activated", "id", logSafe(exclusionID))
	return exclusion, nil
}

// DeactivateExclusion takes a scope exclusion out of effect. That needs the
// approval permission and someone other than the requester
// (AuthorizeReduction).
func (s *Service) DeactivateExclusion(ctx context.Context, exclusionID string, tenantID string, reviewer scopedom.Reviewer) (*scopedom.Exclusion, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	parsedID, err := shared.IDFromString(exclusionID)
	if err != nil {
		return nil, shared.ErrNotFound
	}

	exclusion, err := s.exclusionRepo.GetByID(ctx, parsedTenantID, parsedID)
	if err != nil {
		return nil, err
	}

	if err := exclusion.AuthorizeReduction(reviewer); err != nil {
		return nil, err
	}
	if err := exclusion.Deactivate(); err != nil {
		return nil, err
	}

	if err := s.exclusionRepo.Update(ctx, exclusion); err != nil {
		return nil, fmt.Errorf("failed to deactivate scope exclusion: %w", err)
	}

	s.scheduleJoin(parsedTenantID)
	s.logger.Info("scope exclusion deactivated", "id", logSafe(exclusionID))
	return exclusion, nil
}

// ExpireOldExclusions marks expired exclusions as expired.
func (s *Service) ExpireOldExclusions(ctx context.Context) error {
	if err := s.exclusionRepo.ExpireOld(ctx); err != nil {
		return fmt.Errorf("failed to expire old exclusions: %w", err)
	}
	s.logger.Info("expired old exclusions")
	return nil
}

// =============================================================================
// Stats & Coverage Operations
// =============================================================================

// GetStats retrieves scope configuration statistics for a tenant.
func (s *Service) GetStats(ctx context.Context, tenantID string) (*scopedom.Stats, error) {
	targetFilter := scopedom.TargetFilter{TenantID: &tenantID}
	exclusionFilter := scopedom.ExclusionFilter{TenantID: &tenantID}

	totalTargets, err := s.targetRepo.Count(ctx, targetFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count targets: %w", err)
	}

	activeTargetFilter := scopedom.TargetFilter{
		TenantID: &tenantID,
		Statuses: []scopedom.Status{scopedom.StatusActive},
	}
	activeTargets, err := s.targetRepo.Count(ctx, activeTargetFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count active targets: %w", err)
	}

	totalExclusions, err := s.exclusionRepo.Count(ctx, exclusionFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count exclusions: %w", err)
	}

	activeExclusionFilter := scopedom.ExclusionFilter{
		TenantID: &tenantID,
		Statuses: []scopedom.Status{scopedom.StatusActive},
	}
	activeExclusions, err := s.exclusionRepo.Count(ctx, activeExclusionFilter)
	if err != nil {
		return nil, fmt.Errorf("failed to count active exclusions: %w", err)
	}

	inventory, err := s.inventoryCoverage(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	return &scopedom.Stats{
		TotalTargets:     totalTargets,
		ActiveTargets:    activeTargets,
		TotalExclusions:  totalExclusions,
		ActiveExclusions: activeExclusions,
		Coverage:         inventory.Percent(),
		Inventory:        inventory,
	}, nil
}

// CoverageCounter counts the scope coverage of the internet-facing
// inventory in the database (*postgres.ScopeCoverageRepository).
type CoverageCounter interface {
	CountCoverage(ctx context.Context, tenantID shared.ID, scope *shared.DataScope) (scopedom.InventoryCoverage, error)
}

// DataScopeResolver resolves the caller's Layer 2 data scope
// (*datascope.Enforcer); nil means unrestricted.
type DataScopeResolver interface {
	Resolve(ctx context.Context, tenantID shared.ID) (*shared.DataScope, error)
}

// SetCoverage wires the coverage count and the caller's data scope. Without
// a counter the coverage is reported as zero; without a resolver the count
// is refused (fail closed), so a restricted caller never sees tenant-wide
// numbers.
func (s *Service) SetCoverage(c CoverageCounter, ds DataScopeResolver) {
	s.coverage, s.dataScope = c, ds
}

// inventoryCoverage counts, in SQL and over the caller's data scope only,
// the internet-facing inventory and the part of it the active scope targets
// cover (research/53 S-3, SC8).
func (s *Service) inventoryCoverage(ctx context.Context, tenantID string) (scopedom.InventoryCoverage, error) {
	if s.coverage == nil {
		return scopedom.InventoryCoverage{}, nil
	}
	if s.dataScope == nil {
		return scopedom.InventoryCoverage{}, fmt.Errorf("scope coverage: the data scope is not configured")
	}
	tid, err := shared.IDFromString(tenantID)
	if err != nil {
		return scopedom.InventoryCoverage{}, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	ds, err := s.dataScope.Resolve(ctx, tid)
	if err != nil {
		return scopedom.InventoryCoverage{}, fmt.Errorf("resolve data scope: %w", err)
	}
	return s.coverage.CountCoverage(ctx, tid, ds)
}

// getAssetValues returns all values to check for an asset (name, URLs, etc).
func (s *Service) getAssetValues(a *asset.Asset) []string {
	return AssetMatchValues(a.Type().String(), a.Name(), a.Properties())
}

// repositoryMatchKeys are the repository properties that name the repository
// besides its asset name.
var repositoryMatchKeys = []string{"full_name", "web_url", "clone_url"}

// AssetMatchValues returns the values a scope target or exclusion is tested
// against for an asset: its name and, for a repository, its URLs.
func AssetMatchValues(assetType, name string, props map[string]any) []string {
	values := []string{name}
	if assetType != asset.AssetTypeRepository.String() || props == nil {
		return values
	}
	for _, key := range repositoryMatchKeys {
		if val, ok := props[key].(string); ok && val != "" {
			values = append(values, val)
		}
	}
	return values
}

// AssetExclusionValues is AssetMatchValues plus the addresses the asset is
// known to resolve to (asset.IPAddresses: ip_addresses and every synonym of
// it). A scanner handed the asset's name reaches those addresses, so an
// exclusion of any of them must exclude the asset. Matching more values can
// only exclude more (fail closed); it is used for exclusions only, never to
// put an asset in scope.
func AssetExclusionValues(assetType, name string, props map[string]any) []string {
	values := AssetMatchValues(assetType, name, props)
	return append(values, asset.IPAddresses(props)...)
}

// effectiveExclusions returns the tenant's exclusions that are in effect:
// approved, active and unexpired. The repository already filters on that;
// re-checking here keeps a pending or rejected exclusion from ever reaching a
// matcher, whatever the repository implementation returns.
func (s *Service) effectiveExclusions(ctx context.Context, tenantID shared.ID) ([]*scopedom.Exclusion, error) {
	all, err := s.exclusionRepo.ListActive(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	out := all[:0:0]
	for _, e := range all {
		if e != nil && e.IsActive() {
			out = append(out, e)
		}
	}
	return out, nil
}

// isAssetExcluded checks if any asset value matches any exclusion.
func (s *Service) isAssetExcluded(assetValues []string, exclusions []*scopedom.Exclusion) bool {
	for _, raw := range assetValues {
		for _, av := range exclusionMatchForms(raw) {
			for _, exclusion := range exclusions {
				if exclusion.Matches(av) {
					return true
				}
			}
		}
	}
	return false
}

// exclusionMatchForms returns the value itself plus the host it names when it
// is a URL ("https://host:8443/path") or a host:port. An exclusion names a
// host; without this a scan target written as a URL or with a port slipped past
// a domain/IP/CIDR exclusion of that same host. Matching more forms can only
// exclude more, never less (fail closed).
func exclusionMatchForms(value string) []string {
	v := strings.TrimSpace(value)
	forms := []string{v}
	host := asset.HostOf(v)
	if host != "" && !strings.EqualFold(host, v) {
		forms = append(forms, strings.ToLower(host))
	}
	return forms
}

// ExclusionCandidate is a minimal asset projection used to test scope
// exclusions from the scan target-selection path without importing the full
// asset entity. Values holds every matchable string for the asset (its name,
// and for repositories its URLs); an empty entry is ignored.
type ExclusionCandidate struct {
	ID     shared.ID
	Values []string
}

// ExcludedTargets returns the set of candidate IDs that match an ACTIVE scope
// exclusion for the tenant, the targets a scan must skip. Unlike
// FilterExcludedTargets it reports a failed lookup as an error, so the scan
// path can refuse to dispatch rather than scan something the tenant excluded
// (fail closed, RFC-023 D17).
func (s *Service) ExcludedTargets(ctx context.Context, tenantID string, candidates []ExclusionCandidate) (map[shared.ID]bool, error) {
	excluded := make(map[shared.ID]bool)
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	exclusions, err := s.effectiveExclusions(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("list active scope exclusions: %w", err)
	}
	for _, c := range candidates {
		if len(exclusions) > 0 && s.isAssetExcluded(c.Values, exclusions) {
			excluded[c.ID] = true
		}
	}
	return excluded, nil
}

// FilterExcludedTargets returns the set of candidate asset IDs that match an
// ACTIVE scope exclusion for the tenant — the assets a scan must skip.
//
// FAIL-OPEN by contract: an invalid tenant id, an exclusion-lookup error, or no
// active exclusions all yield an EMPTY set (nothing excluded). Scan dispatch
// uses ExcludedTargets instead, which fails closed.
func (s *Service) FilterExcludedTargets(ctx context.Context, tenantID string, candidates []ExclusionCandidate) map[shared.ID]bool {
	excluded := make(map[shared.ID]bool)

	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		s.logger.Warn("scope exclusion check skipped: invalid tenant id", "error", err)
		return excluded
	}

	exclusions, err := s.effectiveExclusions(ctx, parsedTenantID)
	if err != nil {
		s.logger.Warn("scope exclusion lookup failed; scanning all assets (fail-open)",
			"tenant_id", parsedTenantID.String(), "error", err)
		return excluded
	}
	if len(exclusions) == 0 {
		return excluded
	}

	for _, c := range candidates {
		if s.isAssetExcluded(c.Values, exclusions) {
			excluded[c.ID] = true
		}
	}
	return excluded
}

// CheckScope checks if an asset value is in scope.
func (s *Service) CheckScope(ctx context.Context, tenantID string, assetType string, value string) (*scopedom.MatchResult, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	// Get active targets
	targets, err := s.targetRepo.ListActive(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active targets: %w", err)
	}

	// Get active exclusions
	exclusions, err := s.effectiveExclusions(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active exclusions: %w", err)
	}

	result := &scopedom.MatchResult{
		InScope:             false,
		Excluded:            false,
		MatchedTargetIDs:    []shared.ID{},
		MatchedExclusionIDs: []shared.ID{},
	}

	// Check targets
	for _, target := range targets {
		if target.Matches(value) {
			result.InScope = true
			result.MatchedTargetIDs = append(result.MatchedTargetIDs, target.ID())
		}
	}

	// Check exclusions only if in scope
	if result.InScope {
		for _, exclusion := range exclusions {
			if exclusion.Matches(value) {
				result.Excluded = true
				result.MatchedExclusionIDs = append(result.MatchedExclusionIDs, exclusion.ID())
			}
		}
	}

	return result, nil
}

// =============================================================================
// Pattern Conflict Detection
// =============================================================================

// CheckPatternOverlaps checks if a new target pattern overlaps with existing patterns.
// Returns a list of warning messages describing the overlaps (non-blocking).
func (s *Service) CheckPatternOverlaps(ctx context.Context, tenantID string, targetType string, pattern string) ([]string, error) {
	parsedTenantID, err := shared.IDFromString(tenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}

	parsedTargetType, err := scopedom.ParseTargetType(targetType)
	if err != nil {
		return nil, err // wraps shared.ErrValidation
	}

	// Get all active targets for this tenant
	activeTargets, err := s.targetRepo.ListActive(ctx, parsedTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to list active targets: %w", err)
	}

	warnings := make([]string, 0)

	for _, existing := range activeTargets {
		if existing.TargetType() != parsedTargetType {
			continue
		}

		if existing.Pattern() == pattern {
			continue // Exact duplicate handled by ExistsByPattern check
		}

		// Check bidirectional: does the new pattern match the existing one, or vice versa?
		newMatchesExisting := scopedom.MatchesPattern(parsedTargetType, pattern, existing.Pattern())
		existingMatchesNew := scopedom.MatchesPattern(parsedTargetType, existing.Pattern(), pattern)

		switch {
		case newMatchesExisting && existingMatchesNew:
			warnings = append(warnings, fmt.Sprintf("Pattern %q is equivalent to existing pattern %q", pattern, existing.Pattern()))
		case newMatchesExisting:
			warnings = append(warnings, fmt.Sprintf("Pattern %q is a superset of existing pattern %q", pattern, existing.Pattern()))
		case existingMatchesNew:
			warnings = append(warnings, fmt.Sprintf("Pattern %q is a subset of existing pattern %q", pattern, existing.Pattern()))
		}
	}

	return warnings, nil
}

// logSafe strips CR and LF so a request-derived value cannot forge log lines.
// strings.ReplaceAll of "\n" and "\r" is the sanitizer CodeQL's
// go/log-injection query recognizes.
func logSafe(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	return strings.ReplaceAll(v, "\r", "")
}
