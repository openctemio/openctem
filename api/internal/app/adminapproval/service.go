// Package adminapproval is the four-eyes rule of the platform console: a
// catastrophic action by one super admin needs the approval of another
// (docs/architecture/platform-console.md, "Four-eyes approvals").
//
// Threat: one hijacked or rogue super admin session. With a second active,
// named super admin on the roster, such a session can no longer add a super
// admin, remove one, loosen the console sign-in, open sign-up or re-sign an
// organization's audit chain on its own.
//
// Rules:
//   - the requester asks with a reason (step-up at the route), another super
//     admin approves (fresh step-up at the route), the requester repeats the
//     action within ApprovalTTL and the action spends the approval;
//   - an approval is bound to (requester, action, exact target), is single
//     use and expires; nobody approves their own request;
//   - break-glass accounts never approve and do not count as a second admin:
//     their credentials are often held by the same people as a named account;
//   - when no other approver exists (a single super admin install) the action
//     runs on the requester's confirmation alone, with a critical audit row and
//     a notice to every administrator, and the console says how to add a
//     second super admin. Removing an approver is itself protected, so a
//     session cannot reach that state by demoting the others;
//   - every step writes a critical admin audit row first and refuses when the
//     row cannot be written.
package adminapproval

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openctemio/openctem/api/internal/app/adminconsole"
	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
	"github.com/openctemio/openctem/api/pkg/logger"
)

// Audit actions (all critical).
const (
	ActionRequested = "approval.requested"
	ActionApproved  = "approval.approved"
	ActionRejected  = "approval.rejected"
	ActionCanceled  = "approval.canceled"
	ActionUsed      = "approval.used"
	ActionReleased  = "approval.released"
	// ActionSingleAdmin records a protected action that ran without a second
	// approval because no other approver exists.
	ActionSingleAdmin = "approval.single_admin"
)

// Roster notice kinds for the administrators' e-mail.
const (
	NoticeRequested   = "approval_requested"
	NoticeDecided     = "approval_decided"
	NoticeSingleAdmin = "approval_single_admin"
)

// MaxReasonLength bounds the reason and decision note.
const MaxReasonLength = 1000

// historyWindow is how far back List goes for decided requests.
const historyWindow = 30 * 24 * time.Hour

// RosterNotifier tells the other administrators (the console service).
type RosterNotifier interface {
	NotifyRosterChange(ctx context.Context, actor *admin.AdminUser, kind, summary string, client adminconsole.ClientInfo)
}

// TenantNamer names an organization for an approval's target label.
type TenantNamer interface {
	TenantName(ctx context.Context, id shared.ID) (string, error)
}

// TenantNamerFunc adapts a function to TenantNamer.
type TenantNamerFunc func(ctx context.Context, id shared.ID) (string, error)

// TenantName calls f.
func (f TenantNamerFunc) TenantName(ctx context.Context, id shared.ID) (string, error) {
	return f(ctx, id)
}

// Grant is what the gate hands a protected action: the approval it spent, or
// the single-admin fallback.
type Grant struct {
	ApprovalID *shared.ID
	// SingleAdmin: no other approver exists; the action ran on the
	// requester's confirmation alone.
	SingleAdmin bool
}

// Status is the four-eyes state seen by one super admin.
type Status struct {
	// Active: at least one other administrator can approve the caller's
	// requests.
	Active bool
	// Approvers counts the active, named (not break-glass) super admins,
	// the caller included when eligible.
	Approvers int
	// OtherApprovers counts those who are not the caller.
	OtherApprovers int
}

// Service runs the approvals.
type Service struct {
	repo    admin.ApprovalRepository
	admins  admin.Repository
	audit   admin.AuditLogRepository
	notify  RosterNotifier
	tenants TenantNamer
	log     *logger.Logger
	now     func() time.Time
}

// NewService creates the service. audit is required: an approval step that
// cannot be audited does not happen.
func NewService(repo admin.ApprovalRepository, admins admin.Repository, audit admin.AuditLogRepository, log *logger.Logger) *Service {
	return &Service{repo: repo, admins: admins, audit: audit, log: log.With("service", "admin_approval"), now: time.Now}
}

// SetNotifier wires the administrators' notice.
func (s *Service) SetNotifier(n RosterNotifier) { s.notify = n }

// SetTenantNamer wires organization names for target labels.
func (s *Service) SetTenantNamer(t TenantNamer) { s.tenants = t }

// SetClock replaces the clock (tests).
func (s *Service) SetClock(now func() time.Time) { s.now = now }

// eligible reports whether a can approve: an active super admin (own role)
// who is not a break-glass account.
func eligible(a *admin.AdminUser) bool {
	return a != nil && a.IsActive() && a.Role() == admin.AdminRoleSuperAdmin && !a.IsBreakGlass()
}

// Status returns the four-eyes state for actor.
func (s *Service) Status(ctx context.Context, actor *admin.AdminUser) (Status, error) {
	active, err := s.admins.ListActive(ctx)
	if err != nil {
		return Status{}, fmt.Errorf("list administrators: %w", err)
	}
	var st Status
	for _, a := range active {
		if !eligible(a) {
			continue
		}
		st.Approvers++
		if actor == nil || a.ID() != actor.ID() {
			st.OtherApprovers++
		}
	}
	st.Active = st.OtherApprovers > 0
	return st, nil
}

// Require is the gate of a protected action. It spends the actor's approval
// for (action, target), or allows the single-admin fallback, or returns
// *admin.ApprovalRequiredError. Any other error refuses the action.
func (s *Service) Require(ctx context.Context, actor *admin.AdminUser, action admin.ApprovalAction, target string, client adminconsole.ClientInfo) (*Grant, error) {
	if actor == nil || !action.IsValid() || !action.ValidTarget(target) {
		return nil, admin.ErrInvalidApproval
	}
	st, err := s.Status(ctx, actor)
	if err != nil {
		return nil, err
	}
	label := s.label(ctx, target)
	if !st.Active {
		entry := s.entry(actor, ActionSingleAdmin, nil, action, client, map[string]any{
			"action": string(action), "target": target, "target_label": label,
		})
		if err := s.writeAudit(ctx, entry); err != nil {
			return nil, err
		}
		s.tell(ctx, actor, NoticeSingleAdmin, fmt.Sprintf(
			"%s (%s) without a second approval, because no other super admin can approve. Add a second super admin to turn on approvals",
			describe(action), display(target, label)), client)
		return &Grant{SingleAdmin: true}, nil
	}

	now := s.now()
	a, err := s.repo.Consume(ctx, actor.ID(), action, target, now)
	if errors.Is(err, admin.ErrApprovalNotFound) {
		required := &admin.ApprovalRequiredError{Action: action, Target: target, TargetLabel: label}
		if p, perr := s.repo.FindPending(ctx, actor.ID(), action, target, now); perr == nil {
			required.PendingID = &p.ID
		}
		return nil, required
	}
	if err != nil {
		return nil, fmt.Errorf("use approval: %w", err)
	}
	entry := s.entry(actor, ActionUsed, &a.ID, action, client, map[string]any{
		"action": string(action), "target": target, "target_label": a.TargetLabel, "approved_by": idString(a.DecidedBy),
	})
	if err := s.writeAudit(ctx, entry); err != nil {
		if rerr := s.repo.Release(ctx, a.ID); rerr != nil {
			s.log.Error("release approval after audit failure", "approval_id", a.ID.String(), "error", rerr)
		}
		return nil, err
	}
	return &Grant{ApprovalID: &a.ID}, nil
}

// Release gives a spent approval back when the protected action failed, so
// the requester can retry without asking again.
func (s *Service) Release(ctx context.Context, actor *admin.AdminUser, g *Grant, client adminconsole.ClientInfo) {
	if g == nil || g.ApprovalID == nil {
		return
	}
	if err := s.repo.Release(ctx, *g.ApprovalID); err != nil {
		s.log.Error("release approval", "approval_id", g.ApprovalID.String(), "error", err)
		return
	}
	entry := s.entry(actor, ActionReleased, g.ApprovalID, "", client, nil)
	entry.Severity = admin.SeverityInfo
	if err := s.writeAudit(ctx, entry); err != nil {
		s.log.Warn("audit approval release", "error", err)
	}
}

// Request asks the other super admins to approve action on target.
func (s *Service) Request(ctx context.Context, actor *admin.AdminUser, action admin.ApprovalAction, target, reason string, client adminconsole.ClientInfo) (*admin.Approval, error) {
	reason = strings.TrimSpace(reason)
	if actor == nil || !action.IsValid() || !action.ValidTarget(target) || reason == "" ||
		utf8.RuneCountInString(reason) > MaxReasonLength {
		return nil, admin.ErrInvalidApproval
	}
	st, err := s.Status(ctx, actor)
	if err != nil {
		return nil, err
	}
	if !st.Active {
		return nil, admin.ErrFourEyesInactive
	}
	now := s.now()
	if p, err := s.repo.FindPending(ctx, actor.ID(), action, target, now); err == nil {
		return p, nil // already asked: one open request per action and target
	}
	a := &admin.Approval{
		ID: shared.NewID(), Action: action, Target: target, TargetLabel: s.label(ctx, target),
		Reason: reason, RequestedBy: actor.ID(), RequestedAt: now, ExpiresAt: now.Add(admin.ApprovalTTL),
	}
	entry := s.entry(actor, ActionRequested, &a.ID, action, client, map[string]any{
		"action": string(action), "target": target, "target_label": a.TargetLabel, "reason": reason,
		"expires_at": a.ExpiresAt.UTC().Format(time.RFC3339),
	})
	if err := s.writeAudit(ctx, entry); err != nil {
		return nil, err
	}
	if err := s.repo.Create(ctx, a); err != nil {
		return nil, err
	}
	s.tell(ctx, actor, NoticeRequested, fmt.Sprintf(
		"asked another super admin to approve: %s (%s). Reason: %s. Approve or reject it in the console under Security > Approvals",
		describe(action), display(target, a.TargetLabel), clip(reason, 200)), client)
	return a, nil
}

// Approve records another super admin's approval.
func (s *Service) Approve(ctx context.Context, actor *admin.AdminUser, id shared.ID, note string, client adminconsole.ClientInfo) (*admin.Approval, error) {
	if !eligible(actor) {
		return nil, admin.ErrApproverNotEligible
	}
	return s.decide(ctx, actor, id, admin.DecisionApproved, note, client)
}

// Reject records a refusal by another super admin.
func (s *Service) Reject(ctx context.Context, actor *admin.AdminUser, id shared.ID, note string, client adminconsole.ClientInfo) (*admin.Approval, error) {
	if actor == nil || !actor.IsActive() || actor.Role() != admin.AdminRoleSuperAdmin {
		return nil, admin.ErrApproverNotEligible
	}
	return s.decide(ctx, actor, id, admin.DecisionRejected, note, client)
}

// Cancel withdraws the actor's own open request.
func (s *Service) Cancel(ctx context.Context, actor *admin.AdminUser, id shared.ID, client adminconsole.ClientInfo) (*admin.Approval, error) {
	return s.decide(ctx, actor, id, admin.DecisionCanceled, "", client)
}

func (s *Service) decide(ctx context.Context, actor *admin.AdminUser, id shared.ID, decision, note string, client adminconsole.ClientInfo) (*admin.Approval, error) {
	note = strings.TrimSpace(note)
	if actor == nil || utf8.RuneCountInString(note) > MaxReasonLength {
		return nil, admin.ErrInvalidApproval
	}
	cur, err := s.repo.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	switch {
	case decision == admin.DecisionCanceled && cur.RequestedBy != actor.ID():
		return nil, admin.ErrNotRequester
	case decision != admin.DecisionCanceled && cur.RequestedBy == actor.ID():
		return nil, admin.ErrSelfApproval
	case cur.Status(s.now()) != admin.ApprovalPending:
		return nil, admin.ErrApprovalNotPending
	}
	auditAction := map[string]string{
		admin.DecisionApproved: ActionApproved, admin.DecisionRejected: ActionRejected, admin.DecisionCanceled: ActionCanceled,
	}[decision]
	entry := s.entry(actor, auditAction, &cur.ID, cur.Action, client, map[string]any{
		"action": string(cur.Action), "target": cur.Target, "target_label": cur.TargetLabel,
		"requested_by": cur.RequestedBy.String(), "note": note,
	})
	if err := s.writeAudit(ctx, entry); err != nil {
		return nil, err
	}
	out, err := s.repo.Decide(ctx, id, actor.ID(), decision, note, s.now())
	if err != nil {
		return nil, err
	}
	if decision != admin.DecisionCanceled {
		requester := "an administrator"
		if r, err := s.admins.GetByID(ctx, cur.RequestedBy); err == nil {
			requester = r.Email()
		}
		s.tell(ctx, actor, NoticeDecided, fmt.Sprintf("%s the request of %s: %s (%s)",
			decision, requester, describe(cur.Action), display(cur.Target, cur.TargetLabel)), client)
	}
	return out, nil
}

// List returns open requests and those of the last 30 days, newest first.
func (s *Service) List(ctx context.Context) ([]*admin.Approval, error) {
	return s.repo.List(ctx, s.now().Add(-historyWindow), 200)
}

// Now is the service clock (statuses in responses).
func (s *Service) Now() time.Time { return s.now() }

func (s *Service) entry(actor *admin.AdminUser, action string, id *shared.ID, protected admin.ApprovalAction, client adminconsole.ClientInfo, body map[string]any) *admin.AuditLog {
	return admin.NewAuditLogBuilder(actor, action).
		Resource("admin_approval", id, string(protected)).
		Context(client.IP, client.UserAgent).
		Request("", "", body).
		Critical().
		Build()
}

// writeAudit writes the row or fails: an approval step without its audit row
// does not happen.
func (s *Service) writeAudit(ctx context.Context, entry *admin.AuditLog) error {
	if s.audit == nil {
		return errors.New("admin audit log is not configured")
	}
	if err := s.audit.Create(ctx, entry); err != nil {
		s.log.Error("audit approval step", "action", entry.Action, "error", err)
		return fmt.Errorf("write admin audit row: %w", err)
	}
	return nil
}

func (s *Service) tell(ctx context.Context, actor *admin.AdminUser, kind, summary string, client adminconsole.ClientInfo) {
	if s.notify != nil {
		s.notify.NotifyRosterChange(ctx, actor, kind, summary, client)
	}
}

// label names the administrator or organization a target points at, read on
// the server: a requester cannot describe their own target to the approver.
func (s *Service) label(ctx context.Context, target string) string {
	id, ok := admin.TargetID(target)
	if !ok {
		return ""
	}
	switch {
	case strings.HasPrefix(target, "admin:"):
		if a, err := s.admins.GetByID(ctx, id); err == nil {
			return fmt.Sprintf("%s (%s)", a.Email(), adminconsole.RoleLabel(a.Role()))
		}
	case strings.HasPrefix(target, "tenant:") && s.tenants != nil:
		if name, err := s.tenants.TenantName(ctx, id); err == nil {
			return name
		}
	}
	return ""
}

// describe is the English phrase of an action for notices.
func describe(a admin.ApprovalAction) string {
	switch a {
	case admin.ApprovalGrantSuperAdmin:
		return "make a super admin"
	case admin.ApprovalRevokeSuperAdmin:
		return "remove a super admin"
	case admin.ApprovalConsoleMFAOff:
		return "turn off the security-key requirement"
	case admin.ApprovalPlatformIdPRemove:
		return "remove or relax the administrators' identity provider"
	case admin.ApprovalSignupOpen:
		return "open sign-up"
	case admin.ApprovalAuditChainRebaseline:
		return "re-sign an organization's audit chain"
	}
	return string(a)
}

func display(target, label string) string {
	if label != "" {
		return label
	}
	return target
}

func clip(s string, n int) string {
	s = strings.NewReplacer("\r", " ", "\n", " ").Replace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n]) + "…"
}

func idString(id *shared.ID) string {
	if id == nil {
		return ""
	}
	return id.String()
}
