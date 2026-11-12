package adminconsole

import (
	"context"
	"time"

	"github.com/openctemio/openctem/api/pkg/domain/admin"
	"github.com/openctemio/openctem/api/pkg/domain/shared"
)

// A console sign-in from a network other than the administrator's last one
// is told to every administrator (RFC-022 revision 20): a stolen password and
// authenticator used from elsewhere shows up at once.

// ActionNewNetworkSignIn is the admin audit action of such a sign-in.
const ActionNewNetworkSignIn = "console.new_network_sign_in"

// AlertNewNetworkSignIn tags the log line operators alert on.
const AlertNewNetworkSignIn = "new_network_sign_in"

// NewNetworkAlert describes a console sign-in from a new network.
type NewNetworkAlert struct {
	AdminID    shared.ID
	AdminEmail string
	AdminName  string
	IP         string
	PreviousIP string
	At         time.Time
	// Recipients are every active administrator's email, the one who signed
	// in included.
	Recipients []string
}

// NewNetworkNotifier is implemented by a BreakGlassNotifier that can also
// tell the administrators about a sign-in from a new network.
type NewNetworkNotifier interface {
	NotifyNewNetworkSignIn(ctx context.Context, alert NewNetworkAlert) error
}

// noteSignInNetwork alerts when a verified console sign-in comes from another
// address than the administrator's last one. Break-glass sign-ins are alerted
// every time already; a first sign-in has nothing to compare with.
func (s *Service) noteSignInNetwork(ctx context.Context, a *admin.AdminUser, client ClientInfo) {
	prev := a.LastUsedIP()
	if a.IsBreakGlass() || prev == "" || client.IP == "" || prev == client.IP {
		return
	}
	if s.audit != nil {
		entry := admin.NewAuditLogBuilder(a, ActionNewNetworkSignIn).
			Resource("admin_user", ptr(a.ID()), a.Email()).
			Context(client.IP, client.UserAgent).
			Request("", "", map[string]any{"previous_ip": prev}).
			High().
			Build()
		s.writeAudit(ctx, ActionNewNetworkSignIn, entry)
	}
	recipients := []string{}
	if all, err := s.admins.ListActive(ctx); err != nil {
		s.log.Warn("list administrators for new-network alert", "error", err)
	} else {
		for _, o := range all {
			recipients = append(recipients, o.Email())
		}
	}
	s.log.Warn("administrator signed in to the admin console from a new network",
		"alert", AlertNewNetworkSignIn,
		"admin_id", a.ID().String(),
		"ip", logSafe(client.IP),
		"previous_ip", logSafe(prev),
		"notified", len(recipients),
	)
	n, ok := s.notifier.(NewNetworkNotifier)
	if !ok || len(recipients) == 0 {
		return
	}
	if err := n.NotifyNewNetworkSignIn(ctx, NewNetworkAlert{
		AdminID: a.ID(), AdminEmail: a.Email(), AdminName: a.Name(),
		IP: client.IP, PreviousIP: prev, At: s.now(), Recipients: recipients,
	}); err != nil {
		s.log.Warn("notify administrators of a new-network sign-in", "alert", AlertNewNetworkSignIn, "error", err)
	}
}
