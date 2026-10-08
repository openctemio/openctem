package scope

// Scope entries: one-off expiry, requests, widening approvals, step-up and
// administrator notification (RFC-054 §6.1, §7; owner decisions S3, S5, S6).
//
// Widening (create, activate, a later or removed expiry, a higher tier) is
// the guarded direction:
//
//   - a caller holding attack_surface:scope:approve re-authenticates
//     (step-up) and the entry needs the tenant's approval count of other
//     approvers before it takes effect (0 = at once);
//   - a caller without it only REQUESTS a one-off entry for a single name or
//     address, with a reason; it needs at least one approver;
//   - every widening that takes effect, and every new request, notifies the
//     tenant's administrators.
//
// Narrowing (deactivate, delete, an earlier expiry, a lower tier) stays one
// click. A call with no actor is a system path: it widens at once.

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"time"

	notificationdom "github.com/openctemio/openctem/api/pkg/domain/notification"
	scopedom "github.com/openctemio/openctem/api/pkg/domain/scope"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/domain/tenant"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Actor is who changes a scope entry and whether they hold
// attack_surface:scope:approve. A zero Actor is the system.
type Actor struct {
	UserID     string
	CanApprove bool
}

func (a Actor) system() bool { return a.UserID == "" }

// SettingsReader reads the tenant's scope settings (*tenant.TenantService).
type SettingsReader interface {
	GetScopeSettings(ctx context.Context, tenantID string) (*tenant.ScopeSettings, error)
}

// AdminDirectory lists the tenant's active owners and administrators
// (*postgres.MemberLifecycleRepository).
type AdminDirectory interface {
	ActiveAdminIDs(ctx context.Context, tenantID shared.ID) ([]shared.ID, error)
}

// InAppNotifier delivers an in-app notification (*integration.NotificationService).
type InAppNotifier interface {
	Notify(ctx context.Context, params notificationdom.NotificationParams) error
}

// SetEntryPolicy wires the settings, the administrator directory and the
// in-app notifier. Without settings the defaults apply; without a directory
// the approval count assumes two administrators (one approval, the safe
// side) and nobody is notified.
func (s *Service) SetEntryPolicy(settings SettingsReader, admins AdminDirectory, inApp InAppNotifier) {
	s.settings, s.admins, s.inApp = settings, admins, inApp
}

// SetGuardrails sets the platform's scope guardrails (RFC-054 §8): checked on
// every new entry, whoever creates it. Nil: the built-in guardrails.
func (s *Service) SetGuardrails(g scopedom.Guardrails) { s.guardrails = &g }

// SetStepUpGate wires step-up re-authentication for widening. Without it a
// person's widening is refused (fail closed).
func (s *Service) SetStepUpGate(g shared.RecentAuthGate) { s.stepUp = g }

// Entry error codes (the handler answers them with their code).
var (
	ErrOneOffTooLong        = shared.NewDomainError("ONE_OFF_TOO_LONG", "the expiry is beyond the organization's one-off limit", shared.ErrValidation)
	ErrOneOffDisabled       = shared.NewDomainError("ONE_OFF_DISABLED", "one-off scope entries are turned off for this organization", shared.ErrValidation)
	ErrRequestNotAllowed    = shared.NewDomainError("REQUEST_NOT_ALLOWED", "members may not request scope entries in this organization; ask an administrator", shared.ErrForbidden)
	ErrRequestMustBeOneOff  = shared.NewDomainError("REQUEST_MUST_BE_ONE_OFF", "a request is for a one-off entry: set expires_in_days or expires_at", shared.ErrValidation)
	ErrRequestMustBeSingle  = shared.NewDomainError("REQUEST_MUST_BE_SINGLE", "a request is for one name or address, not a wildcard or a range", shared.ErrValidation)
	ErrRequestTier          = shared.NewDomainError("REQUEST_TIER", "a request may not ask for intrusive (t2) probes", shared.ErrValidation)
	ErrWideningNeedsApprove = shared.NewDomainError("WIDENING_NEEDS_APPROVER", "widening a scope entry needs the scope approval permission; ask an administrator", shared.ErrForbidden)
	ErrStepUpNotWired       = shared.NewDomainError("STEP_UP_UNAVAILABLE", "re-authentication is not available; widening is refused", shared.ErrForbidden)
)

// policy is what an entry decision needs from the tenant.
type policy struct {
	settings tenant.ScopeSettings
	admins   int
}

func (s *Service) loadPolicy(ctx context.Context, tenantID shared.ID) (policy, error) {
	p := policy{admins: 2}
	if s.settings != nil {
		st, err := s.settings.GetScopeSettings(ctx, tenantID.String())
		if err != nil {
			return p, fmt.Errorf("read scope settings: %w", err)
		}
		if st != nil {
			p.settings = *st
		}
	}
	if s.admins != nil {
		ids, err := s.admins.ActiveAdminIDs(ctx, tenantID)
		if err != nil {
			return p, fmt.Errorf("count administrators: %w", err)
		}
		p.admins = len(ids)
	}
	return p, nil
}

// approvals is the approval count for a widening of an entry of tier tier.
func (p policy) approvals(tier scopedom.Tier, request bool) int {
	n := p.settings.EffectiveApprovals(p.admins, tier == scopedom.TierIntrusive)
	if request && n < 1 {
		n = 1
	}
	return n
}

// requireStepUp asks the actor to have re-authenticated recently.
func (s *Service) requireStepUp(ctx context.Context, a Actor) error {
	if a.system() {
		return nil
	}
	if s.stepUp == nil {
		return ErrStepUpNotWired
	}
	return s.stepUp.RequireRecentAuth(ctx, a.UserID)
}

// resolveExpiry turns expires_in_days / expires_at into an expiry within the
// tenant's one-off bound (nil: permanent).
func resolveExpiry(p policy, now time.Time, at *time.Time, days *int) (*time.Time, error) {
	maxDays := p.settings.MaxDays()
	switch {
	case days != nil:
		if *days < 1 || *days > maxDays {
			return nil, fmt.Errorf("%w: expires_in_days must be between 1 and %d", ErrOneOffTooLong, maxDays)
		}
		e := now.Add(time.Duration(*days) * 24 * time.Hour)
		return &e, nil
	case at != nil:
		if !at.After(now) {
			return nil, fmt.Errorf("%w: expires_at must be in the future", shared.ErrValidation)
		}
		if at.After(now.Add(time.Duration(maxDays)*24*time.Hour + time.Minute)) {
			return nil, fmt.Errorf("%w: at most %d days", ErrOneOffTooLong, maxDays)
		}
		e := at.UTC()
		return &e, nil
	}
	return nil, nil
}

// singleTarget reports whether a pattern names one name or one address.
func singleTarget(t scopedom.TargetType, pattern string) bool {
	if strings.Contains(pattern, "*") {
		return false
	}
	switch t {
	case scopedom.TargetTypeDomain, scopedom.TargetTypeSubdomain, scopedom.TargetTypeURL,
		scopedom.TargetTypeWebsite, scopedom.TargetTypeAPI, scopedom.TargetTypeHost:
		return true
	case scopedom.TargetTypeIPAddress:
		_, err := netip.ParseAddr(strings.TrimSpace(pattern))
		return err == nil
	}
	return false
}

// entryDecision is how a new or widened entry is created.
type entryDecision struct {
	expiresAt *time.Time
	tier      scopedom.Tier
	approvals int
	request   bool
}

func (s *Service) decideNewEntry(ctx context.Context, tenantID shared.ID, targetType scopedom.TargetType, in CreateTargetInput, now time.Time, preview bool) (entryDecision, error) {
	var d entryDecision
	p, err := s.loadPolicy(ctx, tenantID)
	if err != nil {
		return d, err
	}
	tierText := in.MaxTier
	if tierText == "" {
		tierText = p.settings.Tier()
	}
	if d.tier, err = scopedom.ParseTier(tierText); err != nil {
		return d, err
	}
	if d.expiresAt, err = resolveExpiry(p, now, in.ExpiresAt, in.ExpiresInDays); err != nil {
		return d, err
	}
	if d.expiresAt != nil && p.settings.OneOffPolicy() == tenant.OneOffDisabled {
		return d, ErrOneOffDisabled
	}
	if in.Actor.system() {
		return d, nil
	}
	if !in.Actor.CanApprove {
		d.request = true
		switch {
		case p.settings.OneOffPolicy() != tenant.OneOffAdminsAndRequests:
			return d, ErrRequestNotAllowed
		case d.expiresAt == nil:
			return d, ErrRequestMustBeOneOff
		case !singleTarget(targetType, in.Pattern):
			return d, ErrRequestMustBeSingle
		case d.tier == scopedom.TierIntrusive:
			return d, ErrRequestTier
		case strings.TrimSpace(in.Reason) == "":
			return d, scopedom.ErrReasonRequiredFor
		}
	} else if !preview {
		if err := s.requireStepUp(ctx, in.Actor); err != nil {
			return d, err
		}
	}
	d.approvals = p.approvals(d.tier, d.request)
	return d, nil
}

// widenEntry applies a widening change made by actor: step-up and approvals
// for an approver; refused for anyone else (they request a new entry).
func (s *Service) widenEntry(ctx context.Context, t *scopedom.Target, actor Actor, now time.Time) error {
	if actor.system() {
		t.Widen("", 0, now)
		return nil
	}
	if !actor.CanApprove {
		return ErrWideningNeedsApprove
	}
	if err := s.requireStepUp(ctx, actor); err != nil {
		return err
	}
	p, err := s.loadPolicy(ctx, t.TenantID())
	if err != nil {
		return err
	}
	t.Widen(actor.UserID, p.approvals(t.MaxTier(), false), now)
	return nil
}

// TargetPreview is what CreateTarget would do, without saving or asking for
// step-up (the review-by-rule preview, RFC-054 §6.7).
type TargetPreview struct {
	Status            scopedom.Status
	ApprovalsRequired int
	StepUpRequired    bool
}

// PreviewTarget runs CreateTarget's checks (guardrails, one-off and request
// rules, approvals) and answers what it would create. An error is the
// refusal CreateTarget would give.
func (s *Service) PreviewTarget(ctx context.Context, input CreateTargetInput) (*TargetPreview, error) {
	tenantID, err := shared.IDFromString(input.TenantID)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	targetType, err := scopedom.ParseTargetType(input.TargetType)
	if err != nil {
		return nil, err // wraps shared.ErrValidation
	}
	if err := scopedom.ValidatePattern(targetType, input.Pattern); err != nil {
		return nil, err // wraps shared.ErrValidation
	}
	g := scopedom.DefaultGuardrails()
	if s.guardrails != nil {
		g = *s.guardrails
	}
	if err := g.CheckPattern(targetType, input.Pattern); err != nil {
		return nil, err
	}
	exists, err := s.targetRepo.ExistsByPattern(ctx, tenantID, targetType, input.Pattern)
	if err != nil {
		return nil, fmt.Errorf("failed to check target existence: %w", err)
	}
	if exists {
		return nil, scopedom.ErrTargetAlreadyExists
	}
	d, err := s.decideNewEntry(ctx, tenantID, targetType, input, time.Now().UTC(), true)
	if err != nil {
		return nil, err
	}
	out := &TargetPreview{Status: scopedom.StatusActive, ApprovalsRequired: d.approvals, StepUpRequired: input.Actor.CanApprove && !input.Actor.system()}
	if d.approvals > 0 {
		out.Status = scopedom.StatusPending
	}
	return out, nil
}

// ApproveTarget records the actor's approval of a pending entry. The route
// requires attack_surface:scope:approve and step-up. It reports whether the
// entry took effect.
func (s *Service) ApproveTarget(ctx context.Context, targetID, tenantID string, actor Actor) (*scopedom.Target, bool, error) {
	t, err := s.GetTarget(ctx, tenantID, targetID)
	if err != nil {
		return nil, false, err
	}
	if !actor.CanApprove || actor.system() {
		return nil, false, ErrWideningNeedsApprove
	}
	now := time.Now().UTC()
	effective, err := t.Approve(actor.UserID, now)
	if err != nil {
		return nil, false, err
	}
	if err := s.targetRepo.Update(ctx, t); err != nil {
		return nil, false, fmt.Errorf("failed to approve scope target: %w", err)
	}
	if effective {
		s.notifyWidened(ctx, t, "Scope entry approved and in effect")
		s.scheduleJoin(t.TenantID())
	}
	s.logger.Info("scope target approved", "id", logSafe(targetID), "effective", effective)
	return t, effective, nil
}

// RejectTarget declines a pending entry. The route requires
// attack_surface:scope:approve.
func (s *Service) RejectTarget(ctx context.Context, targetID, tenantID string, actor Actor) (*scopedom.Target, error) {
	t, err := s.GetTarget(ctx, tenantID, targetID)
	if err != nil {
		return nil, err
	}
	if !actor.CanApprove || actor.system() {
		return nil, ErrWideningNeedsApprove
	}
	if err := t.Reject(actor.UserID, time.Now().UTC()); err != nil {
		return nil, err
	}
	if err := s.targetRepo.Update(ctx, t); err != nil {
		return nil, fmt.Errorf("failed to reject scope target: %w", err)
	}
	s.logger.Info("scope target rejected", "id", logSafe(targetID))
	return t, nil
}

// EffectiveApprovals answers the settings view: the approval count a
// non-intrusive widening needs now, and the number of administrators.
func (s *Service) EffectiveApprovals(ctx context.Context, tenantID string) (approvals, admins int, err error) {
	id, err := shared.IDFromString(tenantID)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: invalid tenant id", shared.ErrValidation)
	}
	p, err := s.loadPolicy(ctx, id)
	if err != nil {
		return 0, 0, err
	}
	return p.approvals(scopedom.TierActive, false), p.admins, nil
}

// ExpireTargets marks entries past their expiry as expired (the sweep).
func (s *Service) ExpireTargets(ctx context.Context) (int64, error) {
	exp, ok := s.targetRepo.(interface {
		ExpireOld(ctx context.Context) (int64, error)
	})
	if !ok {
		return 0, nil
	}
	return exp.ExpireOld(ctx)
}

// notifyWidened tells every administrator that scope grew.
func (s *Service) notifyWidened(ctx context.Context, t *scopedom.Target, title string) {
	body := fmt.Sprintf("%s %s (%s, max tier %s)", t.TargetType(), t.Pattern(), describeExpiry(t), t.MaxTier())
	s.NotifyAdmins(ctx, t.TenantID(), title, body)
}

// notifyRequested tells the administrators that an entry waits for approval.
func (s *Service) notifyRequested(ctx context.Context, t *scopedom.Target) {
	body := fmt.Sprintf("%s %s (%s) needs %d approval(s). Reason: %s",
		t.TargetType(), t.Pattern(), describeExpiry(t), t.ApprovalsRequired(), t.Reason())
	s.NotifyAdmins(ctx, t.TenantID(), "Scope entry awaiting approval", body)
}

func describeExpiry(t *scopedom.Target) string {
	if t.ExpiresAt() == nil {
		return "permanent"
	}
	return "until " + t.ExpiresAt().UTC().Format(time.RFC3339)
}

// NotifyAdmins delivers an in-app notification to every active owner and
// administrator of the tenant. Best effort: the change already happened and
// is audited.
func (s *Service) NotifyAdmins(ctx context.Context, tenantID shared.ID, title, body string) {
	if s.admins == nil || s.inApp == nil {
		return
	}
	ids, err := s.admins.ActiveAdminIDs(ctx, tenantID)
	if err != nil {
		s.logger.Warn("scope notice: list administrators", "error", logger.SanitizeError(err))
		return
	}
	for _, id := range ids {
		uid := id
		if err := s.inApp.Notify(ctx, notificationdom.NotificationParams{
			TenantID: tenantID, Audience: notificationdom.AudienceUser, AudienceID: &uid,
			NotificationType: notificationdom.TypeScopeChange, Title: title, Body: body, Severity: "high",
			ResourceType: "scope", URL: "/scope",
		}); err != nil {
			s.logger.Warn("scope notice: in-app notification", "error", logger.SanitizeError(err))
		}
	}
}
