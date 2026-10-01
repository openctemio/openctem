package adminconsole

import (
	"context"
	"strings"
	"time"

	"github.com/openctemio/api/pkg/domain/admin"
	"github.com/openctemio/api/pkg/domain/shared"
)

// Break-glass (emergency access) administrators, RFC-022 revision 4. A
// break-glass administrator is a local super admin that is never bound to the
// platform IdP and is exempt from "require IdP", so it keeps working when the
// IdP is down. Every sign-in with one is alerted.

// Audit actions for break-glass administrators.
const (
	ActionBreakGlassSignIn = "console.break_glass_sign_in"
	ActionBreakGlassTested = "console.break_glass_tested"
)

// AlertBreakGlassSignIn is the stable value of the "alert" field on the WARN
// log line written for every break-glass sign-in. Log-based alerting can key
// on it even when no email channel is configured.
const AlertBreakGlassSignIn = "break_glass_sign_in"

// BreakGlassAlert describes one break-glass sign-in.
type BreakGlassAlert struct {
	AdminID    shared.ID
	AdminEmail string
	AdminName  string
	IP         string
	At         time.Time
	// Recipients are the other active administrators' emails.
	Recipients []string
}

// BreakGlassNotifier tells the other administrators about a break-glass
// sign-in. Implementations must not block the sign-in (send asynchronously).
type BreakGlassNotifier interface {
	NotifyBreakGlassSignIn(ctx context.Context, alert BreakGlassAlert) error
}

// SetBreakGlassNotifier wires the notifier (email in production).
func (s *Service) SetBreakGlassNotifier(n BreakGlassNotifier) { s.notifier = n }

// alertBreakGlass records a high-severity audit row, writes the WARN alert
// line, and notifies the other active administrators.
func (s *Service) alertBreakGlass(ctx context.Context, a *admin.AdminUser, client ClientInfo) {
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(a, ActionBreakGlassSignIn).
			Resource("admin_user", ptr(a.ID()), a.Email()).
			Context(client.IP, client.UserAgent).
			High().
			Build()
		s.writeAudit(ctx, ActionBreakGlassSignIn, entry)
	}

	recipients := []string{}
	if others, err := s.admins.ListActive(ctx); err != nil {
		s.log.Warn("list administrators for break-glass alert", "error", err)
	} else {
		for _, o := range others {
			if o.ID() != a.ID() {
				recipients = append(recipients, o.Email())
			}
		}
	}

	s.log.Warn("break-glass administrator signed in to the admin console",
		"alert", AlertBreakGlassSignIn,
		"admin_id", a.ID().String(),
		"admin_email", logSafe(a.Email()),
		"ip", logSafe(client.IP),
		"notified", len(recipients),
	)

	if s.notifier == nil || len(recipients) == 0 {
		return
	}
	if err := s.notifier.NotifyBreakGlassSignIn(ctx, BreakGlassAlert{
		AdminID:    a.ID(),
		AdminEmail: a.Email(),
		AdminName:  a.Name(),
		IP:         client.IP,
		At:         s.now(),
		Recipients: recipients,
	}); err != nil {
		s.log.Warn("notify administrators of break-glass sign-in", "alert", AlertBreakGlassSignIn, "error", err)
	}
}

// ConfirmBreakGlassTest records that target's last sign-in was a test. Another
// super admin confirms it (four eyes): an account cannot vouch for its own use.
func (s *Service) ConfirmBreakGlassTest(ctx context.Context, actor *admin.AdminUser, targetID shared.ID, client ClientInfo) (*admin.AdminUser, error) {
	if actor.ID() == targetID {
		return nil, admin.ErrCannotModifySelfBreakGlassTest
	}
	target, err := s.admins.GetByID(ctx, targetID)
	if err != nil {
		return nil, err
	}
	if !target.IsBreakGlass() {
		return nil, admin.ErrNotBreakGlass
	}
	used := target.LastUsedAt()
	if used == nil {
		return nil, admin.ErrNoBreakGlassSignIn
	}
	if err := s.admins.SetBreakGlassTestedAt(ctx, target.ID(), *used); err != nil {
		return nil, err
	}
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(actor, ActionBreakGlassTested).
			Resource("admin_user", ptr(target.ID()), target.Email()).
			Context(client.IP, client.UserAgent).
			Request("", "", map[string]interface{}{"sign_in_at": used.UTC().Format(time.RFC3339)}).
			Build()
		s.writeAudit(ctx, ActionBreakGlassTested, entry)
	}
	return s.admins.GetByID(ctx, targetID)
}

// logSafe strips CR/LF so a value cannot forge log lines.
func logSafe(v string) string {
	v = strings.ReplaceAll(v, "\n", "")
	v = strings.ReplaceAll(v, "\r", "")
	return v
}
